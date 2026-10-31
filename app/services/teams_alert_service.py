"""
Teams Alerts pipeline:
  Teams message → parse → CloudPulse metrics → LLM analysis → PostgreSQL

Every alert message is stored and classified (cpu / memory / disk / availability /
errors / response_time / gc / other). Structured AIOps (Dynatrace) notifications are
parsed directly; other formats fall back to LLM extraction.

Repeat alerts are merged into incidents: same category + same target (host for host
resource alerts, project + impacted entity for application alerts). An incident clears
when its latest occurrence clears:
  - host cpu/memory/disk alerts: CloudPulse metrics back under teams.resolve_threshold
  - any alert: a later message reports its Dynatrace event IDs as RESOLVED
  - optionally: no new occurrence for teams.stale_clear_hours
  - manually from the UI

Metrics are fetched in-process via the Agent API payload builder. Scheduling is
DB-driven: a 15s tick reloads settings and runs the poll / resolve-check when due
(last-run times live in infraguardian_teams_jobs). Each job is guarded by a
PostgreSQL advisory lock so only one uvicorn worker runs it at a time.
"""
from __future__ import annotations
import json
import logging
import time
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import text

from app.database import AsyncSessionLocal, engine
from app.services import teams_service as ts
from app.services import llm_service as llm
import app.config as cfg

log = logging.getLogger(__name__)

_POLL_LOCK_ID    = 86940001
_RESOLVE_LOCK_ID = 86940002
_SCHEMA_LOCK_ID  = 86940003
TICK_SECONDS     = 15
PARSE_VERSION    = 3   # bump to re-parse and re-group stored alerts on next startup

# ─────────────────────────────────────────────────────────────────────────────
# Schema + settings bootstrap (called from lifespan)
# ─────────────────────────────────────────────────────────────────────────────

_SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS infraguardian_teams_seen (
        message_id  VARCHAR(255) PRIMARY KEY,
        seen_at     TIMESTAMPTZ DEFAULT NOW()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS infraguardian_teams_alerts (
        id           SERIAL PRIMARY KEY,
        message_id   VARCHAR(255) UNIQUE NOT NULL,
        received_at  TIMESTAMPTZ,
        raw_text     TEXT,
        sender       VARCHAR(255),
        server_name  VARCHAR(255),
        metric_type  VARCHAR(50),
        ig_data      JSONB,
        analysis     TEXT,
        severity     VARCHAR(20),
        jira_key     VARCHAR(50),
        jira_url     VARCHAR(500),
        resolved     BOOLEAN DEFAULT FALSE,
        resolved_at  TIMESTAMPTZ,
        created_at   TIMESTAMPTZ DEFAULT NOW()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_teams_alerts_resolved ON infraguardian_teams_alerts(resolved)",
    "CREATE INDEX IF NOT EXISTS idx_teams_alerts_received ON infraguardian_teams_alerts(received_at DESC)",
    """
    CREATE TABLE IF NOT EXISTS infraguardian_teams_jobs (
        job       VARCHAR(50) PRIMARY KEY,
        last_run  TIMESTAMPTZ
    )
    """,
    """
    INSERT INTO infraguardian_settings (key, value, category, description, is_secret) VALUES
    ('teams.enabled',              'true', 'teams', 'Poll the Teams alert chat (true/false)', FALSE),
    ('teams.chat_id',              '', 'teams', 'Teams chat ID to read alerts from (uses Entra app credentials)', FALSE),
    ('teams.poll_interval',        '60',   'teams', 'Poll interval in seconds (min 15)', FALSE),
    ('teams.resolve_interval_min', '15',   'teams', 'Minutes between auto-resolve re-checks of active alerts', FALSE),
    ('teams.resolve_threshold',    '90',   'teams', 'Host CPU/memory/disk alert auto-resolves when every metric is below this %', FALSE),
    ('teams.stale_clear_hours',    '0',    'teams', 'Auto-resolve non-metric incidents with no new occurrence for this many hours (0 = never)', FALSE)
    ON CONFLICT (key) DO NOTHING
    """,
    "UPDATE infraguardian_settings SET description = 'Poll interval in seconds (min 15)' WHERE key = 'teams.poll_interval'",
    "UPDATE infraguardian_settings SET description = 'Host CPU/memory/disk alert auto-resolves when every metric is below this %' WHERE key = 'teams.resolve_threshold'",
    # Incident grouping: repeat alerts of the same type on the same target share an incident_id
    "ALTER TABLE infraguardian_teams_alerts ADD COLUMN IF NOT EXISTS incident_id INTEGER",
    "CREATE INDEX IF NOT EXISTS idx_teams_alerts_incident ON infraguardian_teams_alerts(incident_id)",
    # Parsed alert fields
    "ALTER TABLE infraguardian_teams_alerts ADD COLUMN IF NOT EXISTS title         TEXT",
    "ALTER TABLE infraguardian_teams_alerts ADD COLUMN IF NOT EXISTS project       VARCHAR(255)",
    "ALTER TABLE infraguardian_teams_alerts ADD COLUMN IF NOT EXISTS entity        TEXT",
    "ALTER TABLE infraguardian_teams_alerts ADD COLUMN IF NOT EXISTS hosts         JSONB",
    "ALTER TABLE infraguardian_teams_alerts ADD COLUMN IF NOT EXISTS event_refs    JSONB",
    "ALTER TABLE infraguardian_teams_alerts ADD COLUMN IF NOT EXISTS alert_ref     VARCHAR(50)",
    "ALTER TABLE infraguardian_teams_alerts ADD COLUMN IF NOT EXISTS group_key     VARCHAR(500)",
    "ALTER TABLE infraguardian_teams_alerts ADD COLUMN IF NOT EXISTS metric_check  BOOLEAN DEFAULT FALSE",
    "ALTER TABLE infraguardian_teams_alerts ADD COLUMN IF NOT EXISTS ig_host       VARCHAR(255)",
    "ALTER TABLE infraguardian_teams_alerts ADD COLUMN IF NOT EXISTS resolved_by   VARCHAR(30)",
    "ALTER TABLE infraguardian_teams_alerts ADD COLUMN IF NOT EXISTS parse_version SMALLINT",
    "CREATE INDEX IF NOT EXISTS idx_teams_alerts_group ON infraguardian_teams_alerts(group_key, metric_type)",
    "CREATE INDEX IF NOT EXISTS idx_teams_alerts_events ON infraguardian_teams_alerts USING GIN (event_refs)",
]


async def ensure_schema() -> None:
    async with AsyncSessionLocal() as db:
        # Both uvicorn workers run this at startup; serialise so CREATE TABLE doesn't race
        await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _SCHEMA_LOCK_ID})
        for stmt in _SCHEMA:
            await db.execute(text(stmt))
        reparsed = await _backfill_parse(db)
        await _backfill_incidents(db, regroup_all=reparsed > 0)
        await db.commit()
    await cfg.invalidate_cache()


# ─────────────────────────────────────────────────────────────────────────────
# Host resolution against CloudPulse's server inventory
# ─────────────────────────────────────────────────────────────────────────────

def _short(host: str) -> str:
    return (host or "").strip().split(".")[0].lower()


_ig_hosts: dict[str, str] = {}
_ig_hosts_at = 0.0


async def _load_ig_hosts(db=None) -> dict[str, str]:
    """short hostname → server name as CloudPulse knows it (refreshed every 10 min)."""
    global _ig_hosts, _ig_hosts_at
    if _ig_hosts and time.time() - _ig_hosts_at < 600:
        return _ig_hosts
    sql = text("""
        SELECT DISTINCT server_name FROM infraguardian_capacity_daily
        WHERE report_date >= CURRENT_DATE - 14
    """)
    if db is None:
        async with AsyncSessionLocal() as s:
            rows = (await s.execute(sql)).fetchall()
    else:
        rows = (await db.execute(sql)).fetchall()
    _ig_hosts = {_short(r[0]): r[0] for r in rows if r[0]}
    _ig_hosts_at = time.time()
    return _ig_hosts


async def resolve_ig_host(name: str, db=None) -> Optional[str]:
    if not name:
        return None
    return (await _load_ig_hosts(db)).get(_short(name))


# ─────────────────────────────────────────────────────────────────────────────
# Turning a message into alert fields
# ─────────────────────────────────────────────────────────────────────────────

async def describe(raw_text: str, db=None, use_llm: bool = True) -> dict:
    """
    Extract alert fields from a Teams message: display name, category, severity,
    grouping key and whether it can be verified against CloudPulse metrics.
    """
    p = ts.parse_alert(raw_text)
    if p:
        hosts, entity, category = p["hosts"], p["entity"], p["category"]
        # A host resource alert: one host, and the entity is that host, or the title names
        # it, or the entity is itself a metric ("Memory usage", "CPU usage (Legacy)…")
        host_level = (category in ts.METRIC_CATEGORIES and len(hosts) == 1 and (
            not entity
            or _short(entity) == _short(hosts[0])
            or _short(hosts[0]) in p["title"].lower()
            or ts.classify(entity) == category))
        ig_host = await resolve_ig_host(hosts[0], db) if host_level else None
        if host_level:
            display, group_key = hosts[0], "host:" + _short(hosts[0])
        else:
            display = hosts[0] if len(hosts) == 1 and not entity else (entity or p["project"] or p["title"])
            group_key = "app:" + (p["project"] or "-").lower() + "|" + (entity or p["title"]).lower()
        return {
            "server_name": display[:255], "metric_type": category, "severity": p["severity"],
            "title": p["title"], "project": p["project"], "entity": entity, "hosts": hosts,
            "event_refs": p["hits"], "alert_ref": p["alert_ref"], "group_key": group_key[:500],
            "metric_check": bool(ig_host), "ig_host": ig_host, "all_resolved": p["all_resolved"],
        }

    # Unstructured message: LLM extraction with regex fallback
    ctx = await extract_alert_context(raw_text) if use_llm else {}
    server = ctx.get("server_name") or ts.extract_server_name(raw_text) or ""
    category = ctx.get("metric_type") if ctx.get("metric_type") in ts.METRIC_CATEGORIES else ts.classify(raw_text)
    ig_host = await resolve_ig_host(server, db) if category in ts.METRIC_CATEGORIES else None
    return {
        "server_name": (server or "UNKNOWN")[:255], "metric_type": category,
        "severity": ctx.get("severity") if ctx.get("severity") in ("critical", "warning", "info") else "warning",
        "title": raw_text[:200], "project": "", "entity": "", "hosts": [server] if server else [],
        "event_refs": [], "alert_ref": "", "group_key": ("host:" + _short(server)) if server else None,
        "metric_check": bool(ig_host), "ig_host": ig_host, "all_resolved": False,
    }


async def _backfill_parse(db) -> int:
    """(Re)parse stored alerts written by an older parser version. Returns rows updated."""
    rows = (await db.execute(text("""
        SELECT id, raw_text, server_name, metric_type, severity FROM infraguardian_teams_alerts
        WHERE parse_version IS DISTINCT FROM :v
    """), {"v": PARSE_VERSION})).fetchall()
    for r in rows:
        if ts.parse_alert(r.raw_text or ""):
            f = await describe(r.raw_text, db, use_llm=False)
        else:
            # Keep what the LLM extracted originally; just normalise the category
            f = await describe(r.raw_text or "", db, use_llm=False)
            if r.server_name and r.server_name != "UNKNOWN":
                f["server_name"] = r.server_name
                f["group_key"] = "host:" + _short(r.server_name)
                f["hosts"] = [r.server_name]
            if r.metric_type in ts.METRIC_CATEGORIES:
                f["metric_type"] = r.metric_type
            f["ig_host"] = await resolve_ig_host(f["server_name"], db) if f["metric_type"] in ts.METRIC_CATEGORIES else None
            f["metric_check"] = bool(f["ig_host"])
            f["severity"] = r.severity or f["severity"]
        await db.execute(text("""
            UPDATE infraguardian_teams_alerts SET
                server_name = :server_name, metric_type = :metric_type, title = :title,
                project = :project, entity = :entity, hosts = CAST(:hosts AS JSONB),
                event_refs = CAST(:event_refs AS JSONB), alert_ref = :alert_ref, group_key = :group_key,
                metric_check = :metric_check, ig_host = :ig_host, parse_version = :v,
                severity = CASE WHEN severity IN ('critical', 'warning', 'ok', 'info') THEN severity ELSE :sev END
            WHERE id = :id
        """), {**_db_fields(f), "id": r.id, "v": PARSE_VERSION, "sev": f["severity"]})
    if rows:
        log.info("Teams Alerts: parsed %d stored alert(s) with parser v%d", len(rows), PARSE_VERSION)
    return len(rows)


async def _backfill_incidents(db, regroup_all: bool = False) -> None:
    """
    Assign incident_id to alerts (all of them when the grouping key changed). Walking
    alerts oldest-first, an alert joins the previous incident for its category + target
    if that incident had not yet cleared when the alert arrived; else it starts a new one.
    """
    if regroup_all:
        await db.execute(text("UPDATE infraguardian_teams_alerts SET incident_id = NULL"))
    rows = (await db.execute(text("""
        SELECT id, group_key, metric_type, received_at, resolved, resolved_at
        FROM infraguardian_teams_alerts
        WHERE incident_id IS NULL
        ORDER BY received_at NULLS FIRST, id
    """))).fetchall()
    if not rows:
        return

    open_incidents: dict[tuple, tuple[int, Optional[datetime]]] = {}
    for r in rows:
        key = (r.group_key, r.metric_type)
        incident_id = r.id
        prev = open_incidents.get(key) if r.group_key else None
        if prev and (prev[1] is None or (r.received_at and prev[1] > r.received_at)):
            incident_id = prev[0]
        if r.group_key:
            open_incidents[key] = (incident_id, r.resolved_at if r.resolved else None)
        await db.execute(
            text("UPDATE infraguardian_teams_alerts SET incident_id = :inc WHERE id = :id"),
            {"inc": incident_id, "id": r.id},
        )

    # An incident's state follows its latest occurrence: clear stragglers of cleared incidents
    await db.execute(text("""
        WITH latest AS (
            SELECT DISTINCT ON (incident_id) incident_id, resolved, resolved_at
            FROM infraguardian_teams_alerts
            ORDER BY incident_id, received_at DESC NULLS LAST, id DESC
        )
        UPDATE infraguardian_teams_alerts a
        SET resolved = TRUE, resolved_at = COALESCE(a.resolved_at, l.resolved_at)
        FROM latest l
        WHERE a.incident_id = l.incident_id AND l.resolved AND NOT a.resolved
    """))
    log.info("Teams Alerts: grouped %d alert(s) into incidents", len(rows))


# ─────────────────────────────────────────────────────────────────────────────
# Storage helpers
# ─────────────────────────────────────────────────────────────────────────────

_COLS = ("id, message_id, received_at, raw_text, sender, server_name, metric_type, "
         "ig_data, analysis, severity, jira_key, jira_url, resolved, resolved_at, created_at, "
         "incident_id, title, project, entity, hosts, event_refs, alert_ref, metric_check, "
         "ig_host, resolved_by")


def _row_to_dict(row) -> dict:
    d = dict(row._mapping)
    for k in ("ig_data", "hosts", "event_refs"):
        if isinstance(d.get(k), str):
            try:
                d[k] = json.loads(d[k])
            except Exception:
                pass
    return d


def _db_fields(f: dict) -> dict:
    return {
        "server_name": f["server_name"], "metric_type": f["metric_type"], "title": f["title"],
        "project": f["project"], "entity": f["entity"], "hosts": json.dumps(f["hosts"]),
        "event_refs": json.dumps(f["event_refs"]), "alert_ref": f["alert_ref"],
        "group_key": f["group_key"], "metric_check": f["metric_check"], "ig_host": f["ig_host"],
    }


def _parse_ts(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


async def list_incidents(resolved: bool, limit: int = 500) -> list[dict]:
    """
    One entry per incident: its latest occurrence, plus `occurrence_count` and the
    earlier `occurrences` (newest first). The incident's state is the latest one's.
    """
    async with AsyncSessionLocal() as db:
        latest = (await db.execute(
            text(f"""
                SELECT * FROM (
                    SELECT DISTINCT ON (incident_id) {_COLS}
                    FROM infraguardian_teams_alerts
                    ORDER BY incident_id, received_at DESC NULLS LAST, id DESC
                ) l
                WHERE resolved = :r
                ORDER BY {'resolved_at' if resolved else 'received_at'} DESC NULLS LAST
                LIMIT :lim
            """),
            {"r": resolved, "lim": limit},
        )).fetchall()
        incidents = [_row_to_dict(r) for r in latest]
        if not incidents:
            return []

        members = (await db.execute(
            text("""
                SELECT id, incident_id, received_at, severity, sender, raw_text, title, jira_key, jira_url
                FROM infraguardian_teams_alerts
                WHERE incident_id = ANY(:ids)
                ORDER BY received_at DESC NULLS LAST, id DESC
            """),
            {"ids": [i["incident_id"] for i in incidents]},
        )).fetchall()

    by_incident: dict[int, list[dict]] = {}
    for m in members:
        by_incident.setdefault(m.incident_id, []).append(dict(m._mapping))
    for inc in incidents:
        occ = by_incident.get(inc["incident_id"], [])
        inc["occurrence_count"] = len(occ) or 1
        inc["first_seen"] = occ[-1]["received_at"] if occ else inc["received_at"]
        inc["occurrences"] = [o for o in occ if o["id"] != inc["id"]]
        # A ticket raised on any occurrence belongs to the incident
        if not inc.get("jira_key"):
            ticketed = next((o for o in occ if o.get("jira_key")), None)
            if ticketed:
                inc["jira_key"], inc["jira_url"] = ticketed["jira_key"], ticketed["jira_url"]
    return incidents


async def get_alert(alert_id: int) -> Optional[dict]:
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text(f"SELECT {_COLS} FROM infraguardian_teams_alerts WHERE id = :id"), {"id": alert_id}
        )
        row = result.fetchone()
        return _row_to_dict(row) if row else None


async def save_alert(message_id: str, received_at: str, raw_text: str, sender: str,
                     f: dict, ig_data: dict, analysis: str, severity: str) -> tuple[int, int]:
    """Store an alert and attach it to its incident. Returns (alert_id, incident_id)."""
    async with AsyncSessionLocal() as db:
        new_id = (await db.execute(
            text("""
                INSERT INTO infraguardian_teams_alerts
                    (message_id, received_at, raw_text, sender, server_name, metric_type,
                     ig_data, analysis, severity, title, project, entity, hosts, event_refs,
                     alert_ref, group_key, metric_check, ig_host, parse_version)
                VALUES (:mid, :recv, :raw, :sender, :server_name, :metric_type,
                        CAST(:ig AS JSONB), :analysis, :sev, :title, :project, :entity,
                        CAST(:hosts AS JSONB), CAST(:event_refs AS JSONB),
                        :alert_ref, :group_key, :metric_check, :ig_host, :v)
                ON CONFLICT (message_id) DO UPDATE SET
                    ig_data = EXCLUDED.ig_data, analysis = EXCLUDED.analysis, severity = EXCLUDED.severity
                RETURNING id
            """),
            {
                "mid": message_id, "recv": _parse_ts(received_at), "raw": raw_text, "sender": sender,
                "ig": json.dumps(ig_data, default=str), "analysis": analysis, "sev": severity,
                "v": PARSE_VERSION, **_db_fields(f),
            },
        )).scalar()

        # Join the open incident for the same category + target, else start a new one
        incident_id = (await db.execute(
            text("""
                UPDATE infraguardian_teams_alerts SET incident_id = COALESCE(
                    incident_id,
                    (SELECT incident_id FROM infraguardian_teams_alerts
                     WHERE id <> :id AND resolved = FALSE AND incident_id IS NOT NULL
                       AND CAST(:gk AS VARCHAR) IS NOT NULL AND group_key = :gk
                       AND metric_type = :metric
                     ORDER BY received_at DESC NULLS LAST LIMIT 1),
                    :id)
                WHERE id = :id
                RETURNING incident_id
            """),
            {"id": new_id, "gk": f["group_key"], "metric": f["metric_type"]},
        )).scalar()
        await db.commit()
    return new_id, incident_id


async def update_analysis(alert_id: int, ig_data: dict, analysis: str, severity: str) -> None:
    async with AsyncSessionLocal() as db:
        await db.execute(
            text("""
                UPDATE infraguardian_teams_alerts
                SET ig_data = CAST(:ig AS JSONB), analysis = :analysis, severity = :sev
                WHERE id = :id
            """),
            {"ig": json.dumps(ig_data, default=str), "analysis": analysis, "sev": severity, "id": alert_id},
        )
        await db.commit()


_SAME_INCIDENT = "incident_id = (SELECT incident_id FROM infraguardian_teams_alerts WHERE id = :id)"


async def set_jira(alert_id: int, jira_key: str, jira_url: str) -> None:
    """Link a ticket to every occurrence in the alert's incident."""
    async with AsyncSessionLocal() as db:
        await db.execute(
            text(f"UPDATE infraguardian_teams_alerts SET jira_key = :k, jira_url = :u WHERE {_SAME_INCIDENT}"),
            {"k": jira_key, "u": jira_url, "id": alert_id},
        )
        await db.commit()


async def mark_resolved(alert_id: int, resolved: bool, by: str = "manual") -> None:
    """Clear (or reopen) the alert's whole incident — every merged occurrence with it."""
    async with AsyncSessionLocal() as db:
        await db.execute(
            text(f"""
                UPDATE infraguardian_teams_alerts
                SET resolved = :r,
                    resolved_at = CASE WHEN :r THEN NOW() ELSE NULL END,
                    resolved_by = CASE WHEN :r THEN :by ELSE NULL END
                WHERE {_SAME_INCIDENT} AND resolved <> :r
            """),
            {"r": resolved, "id": alert_id, "by": by},
        )
        await db.commit()


async def _resolve_by_events(event_ids: list[str], keep_incident: Optional[int]) -> int:
    """Clear open incidents that contain any of these Dynatrace event IDs."""
    if not event_ids:
        return 0
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text("""
                UPDATE infraguardian_teams_alerts
                SET resolved = TRUE, resolved_at = NOW(), resolved_by = 'dynatrace'
                WHERE resolved = FALSE
                  AND incident_id <> COALESCE(CAST(:keep AS INTEGER), -1)
                  AND incident_id IN (
                      SELECT incident_id FROM infraguardian_teams_alerts
                      WHERE event_refs @> ANY(CAST(:needles AS JSONB[])))
                RETURNING incident_id
            """),
            {"keep": keep_incident,
             "needles": [json.dumps([{"id": e}]) for e in event_ids]},
        )
        cleared = {r[0] for r in result.fetchall()}
        await db.commit()
    if cleared:
        log.info("Teams Alerts: Dynatrace reported %s resolved — cleared %d incident(s)",
                 ", ".join(event_ids), len(cleared))
    return len(cleared)


async def _unseen_ids(message_ids: list[str]) -> set[str]:
    if not message_ids:
        return set()
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text("SELECT message_id FROM infraguardian_teams_seen WHERE message_id = ANY(:ids)"),
            {"ids": message_ids},
        )
        seen = {r[0] for r in result.fetchall()}
    return set(message_ids) - seen


async def _mark_seen(message_id: str) -> bool:
    """Mark a message seen. Returns False if another worker already claimed it."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text("""
                INSERT INTO infraguardian_teams_seen (message_id) VALUES (:mid)
                ON CONFLICT (message_id) DO NOTHING
                RETURNING message_id
            """),
            {"mid": message_id},
        )
        claimed = result.fetchone() is not None
        await db.commit()
        return claimed


# ─────────────────────────────────────────────────────────────────────────────
# CloudPulse metrics (in-process Agent API)
# ─────────────────────────────────────────────────────────────────────────────

async def get_server_metrics(server_name: str) -> dict[str, Any]:
    from app.routers.agent import _build_server_payload
    try:
        async with AsyncSessionLocal() as db:
            return await _build_server_payload(server_name, ["cpu", "memory", "disk", "process"], 60, db)
    except Exception as exc:
        log.exception("CloudPulse metrics lookup failed for %s", server_name)
        return {"error": str(exc)}


async def metrics_for(f: dict) -> dict[str, Any]:
    """Live CloudPulse data for the alert's host (or the first host IG knows), else {}."""
    host = f.get("ig_host")
    if not host:
        for h in (f.get("hosts") or [])[:5]:
            host = await resolve_ig_host(h)
            if host:
                break
    return await get_server_metrics(host) if host else {}


def _has_metrics(ig_data: dict) -> bool:
    rt = (ig_data or {}).get("realtime") or {}
    return bool((rt.get("memory") or {}).get("total_gb") or rt.get("disk"))


def is_condition_cleared(ig_data: dict, threshold: float) -> bool:
    """True only if CloudPulse has live data for the host and ALL metrics are below threshold."""
    if not ig_data or ig_data.get("error") or not _has_metrics(ig_data):
        return False
    if ig_data.get("overall_severity") in ("warning", "critical"):
        return False
    rt = ig_data.get("realtime", {}) or {}
    if (rt.get("cpu") or {}).get("avg_pct", 0) >= threshold:
        return False
    if (rt.get("memory") or {}).get("used_pct", 0) >= threshold:
        return False
    for disk in rt.get("disk", []) or []:
        if disk.get("used_pct", 0) >= threshold:
            return False
    return True


# ─────────────────────────────────────────────────────────────────────────────
# LLM prompts (via the shared llm_service)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_json(raw: str) -> Optional[dict]:
    start, end = raw.find("{"), raw.rfind("}") + 1
    if start >= 0 and end > start:
        return json.loads(raw[start:end])
    return None


async def extract_alert_context(message_text: str) -> dict:
    """Use the LLM to extract server_name, metric_type and severity from an unstructured alert."""
    system = """You are an infrastructure alert parser.
Extract key fields from a monitoring alert message.
Respond ONLY with valid JSON — no markdown, no explanation:
{
  "server_name": "<hostname or empty string>",
  "metric_type": "<cpu|memory|disk|unknown>",
  "severity": "<critical|warning|info|unknown>",
  "confidence": "<high|medium|low>"
}"""
    try:
        parsed = _extract_json(await llm.chat_completion(system, message_text))
        if parsed:
            return parsed
    except Exception as exc:
        log.warning("LLM alert extraction failed: %s", exc)
    return {"server_name": "", "metric_type": "unknown", "severity": "unknown", "confidence": "low"}


async def analyze_alert(server: str, metric_type: str, raw_message: str, ig_data: dict) -> str:
    """Concise root-cause analysis combining the Teams alert and live CloudPulse data."""
    system = """You are CloudPulse Assistant, a senior Windows infrastructure operations engineer.
Analyze the alert and server metrics data provided, and respond with a clear, structured report:

## Summary
One sentence describing the issue.

## Current State
Key metric values (use the CloudPulse data when present).

## Top Processes (if CPU or memory alert)
List 3-5 Windows processes most likely causing high CPU or memory usage on this type of server.
Format: - ProcessName.exe — reason it commonly causes high usage
Skip this section entirely if the alert is not about CPU or memory.

## Likely Root Causes
2-3 bullet points ranked by likelihood.

## Immediate Actions
Numbered list of concrete steps to resolve the issue right now.

## Preventive Measures
1-2 bullet points for long-term health.

Keep it concise. Use plain text, no JSON."""
    context = f"""Alert category: {metric_type}
Teams Alert Message:
{raw_message}

CloudPulse Live Data for {server}:
{json.dumps(ig_data, indent=2, default=str) if ig_data else "(no CloudPulse host data for this alert)"}
"""
    try:
        return await llm.chat_completion(system, context)
    except Exception as exc:
        log.warning("LLM analysis failed: %s", exc)
        return f"Analysis unavailable: {exc}"


# SR types offered to the LLM for alert tickets (subset of llm_service.SR_TYPES)
# IDs of SR types relevant to infrastructure alerts — update to match your Jira instance.
_ALERT_SR_TYPE_IDS: tuple[str, ...] = tuple(llm.SR_TYPES.keys())


def _format_metrics_block(metric_type: str, ig_data: dict) -> str:
    """Return a readable metrics block to inject into the Jira draft prompt."""
    rt = (ig_data or {}).get("realtime", {}) if isinstance(ig_data, dict) else {}
    lines: list[str] = []

    cpu = rt.get("cpu") or {}
    if cpu:
        lines.append(f"CPU: {cpu.get('avg_pct', 0):.1f}% (peak {cpu.get('max_pct', 0):.1f}%)")

    mem = rt.get("memory") or {}
    if mem:
        total = mem.get("total_gb", 0) or 0
        used  = mem.get("used_gb",  0) or 0
        free  = mem.get("free_gb",  0) or 0
        lines.append(
            f"Memory: {mem.get('used_pct', 0):.1f}% used"
            + (f" — {used:.1f} GB used / {total:.1f} GB total ({free:.1f} GB free)" if total else "")
        )

    disks = rt.get("disk") or []
    if disks:
        for d in disks:
            mount = d.get("mount", "?")
            total = d.get("total_gb", 0) or 0
            used  = d.get("used_gb",  0) or 0
            free  = d.get("free_gb",  0) or 0
            lines.append(
                f"Disk {mount}: {d.get('used_pct', 0):.1f}% used"
                + (f" — {used:.1f} GB used / {total:.1f} GB total ({free:.1f} GB free)" if total else "")
            )

    procs = rt.get("process") or []
    if procs and metric_type in ("cpu", "memory"):
        lines.append("Top processes:")
        for p in procs[:5]:
            cpu_s = f"CPU {p.get('cpu_pct', 0):.1f}%" if p.get("cpu_pct") is not None else ""
            mem_s = f"Mem {p.get('mem_mb', 0):.0f} MB" if p.get("mem_mb") is not None else ""
            detail = ", ".join(filter(None, [cpu_s, mem_s]))
            lines.append(f"  - {p.get('name', '?')}: {detail}")

    return "\n".join(lines) if lines else "(no live metrics available)"


async def generate_jira_draft(alert: dict) -> dict:
    """Ask the LLM for a Jira ticket draft pre-filled from the alert analysis."""
    server      = alert.get("server_name") or "UNKNOWN"
    metric_type = alert.get("metric_type") or "unknown"
    analysis    = alert.get("analysis") or ""
    ig_data     = alert.get("ig_data") or {}
    sr_types    = {k: llm.SR_TYPES[k] for k in _ALERT_SR_TYPE_IDS if k in llm.SR_TYPES}

    # Fetch processes for CPU / memory alerts if not already present
    rt = (ig_data or {}).get("realtime", {}) if isinstance(ig_data, dict) else {}
    if metric_type in ("cpu", "memory") and not rt.get("process"):
        host = alert.get("server_name")
        if host:
            try:
                async with AsyncSessionLocal() as _db:
                    from app.routers.agent import _build_server_payload
                    full = await _build_server_payload(host, ["process"], 60, _db)
                    rt["process"] = full.get("realtime", {}).get("process", [])
                    if isinstance(ig_data, dict):
                        ig_data.setdefault("realtime", {})["process"] = rt["process"]
            except Exception:
                pass

    metrics_block = _format_metrics_block(metric_type, ig_data)

    import app.config as _cfg
    org_name = await _cfg.get("org.name", "Your Organisation")
    default_sub_id   = next(iter(llm.SUBSIDIARIES), "")
    default_sub_name = llm.SUBSIDIARIES.get(default_sub_id, "")

    system = f"""You are a senior IT Service Management engineer at {org_name}.
Create a Jira Service Request from an infrastructure alert.

IMPORTANT: The description MUST include the exact metric values provided — CPU %, memory %, disk % and GB figures, and the top process list if given. Do not generalise or omit them.

SUBSIDIARIES (pick most relevant):
{json.dumps(llm.SUBSIDIARIES)}

SR TYPES (pick most relevant):
{json.dumps(sr_types)}

Respond ONLY with valid JSON:
{{
  "summary": "<concise ticket title max 80 chars>",
  "description": "<professional 3-4 paragraph description — include exact metric values>",
  "sr_type_id": "<id>",
  "sr_type_name": "<name>",
  "subsidiary_id": "{default_sub_id}",
  "subsidiary_name": "{default_sub_name}",
  "effort_hours": <number>
}}"""
    user = f"""Target: {server}
Category: {metric_type}
Alert: {alert.get('title') or ''}
Hosts: {', '.join(alert.get('hosts') or [])}

Live metrics (MUST appear in the description):
{metrics_block}

Analysis:
{analysis}"""
    try:
        parsed = _extract_json(await llm.chat_completion(system, user))
        if parsed:
            return parsed
    except Exception as exc:
        log.warning("Jira draft generation failed: %s", exc)

    return {
        "summary":         f"{metric_type.replace('_', ' ').upper()} alert on {server}"[:80],
        "description":     f"Live metrics:\n{metrics_block}\n\n{analysis}"[:1000] if analysis else f"Live metrics:\n{metrics_block}",
        "sr_type_id":      next(iter(llm.SR_TYPES), ""),
        "sr_type_name":    next(iter(llm.SR_TYPES.values()), "On Call Production Alert & Response"),
        "subsidiary_id":   next(iter(llm.SUBSIDIARIES), ""),
        "subsidiary_name": next(iter(llm.SUBSIDIARIES.values()), ""),
        "effort_hours":    1.0,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline
# ─────────────────────────────────────────────────────────────────────────────

async def process_message(msg: dict) -> bool:
    """Process one unseen Teams message. Returns True if an alert was stored."""
    msg_id     = msg.get("id", "")
    created_at = msg.get("createdDateTime", "")
    raw_text   = ts.extract_message_text(msg)
    sender     = ts.get_sender(msg)

    # Skip blanks, bot confirmations and non-alert chatter — but remember them
    if (not raw_text.strip()
            or any(w in sender.lower() for w in ("cloudpulse", "infrabot", "infraguardian"))
            or not (ts.parse_alert(raw_text) or ts.is_alert_message(raw_text))):
        await _mark_seen(msg_id)
        return False

    if not await _mark_seen(msg_id):
        return False

    f = await describe(raw_text)
    log.info("Processing Teams alert [%s] %s / %s (%s)", msg_id[:12], f["server_name"], f["metric_type"],
             "metric-verifiable" if f["metric_check"] else "event")

    severity = f["severity"]
    if f["all_resolved"]:
        # Pure recovery notice: record it, no analysis needed
        ig_data, analysis = {}, "✅ Recovery notification — all referenced events reported RESOLVED."
    else:
        ig_data = await metrics_for(f)
        if f["metric_check"] and ig_data.get("overall_severity") in ("warning", "critical"):
            severity = ig_data["overall_severity"]
        analysis = await analyze_alert(f["server_name"], f["metric_type"], raw_text, ig_data)

    alert_id, incident_id = await save_alert(msg_id, created_at, raw_text, sender, f, ig_data, analysis, severity)

    resolved_events = [h["id"] for h in f["event_refs"] if h["status"] in ts.CLEARED_STATUSES]
    await _resolve_by_events(resolved_events, keep_incident=None if f["all_resolved"] else incident_id)
    if f["all_resolved"]:
        await mark_resolved(alert_id, True, by="dynatrace")

    log.info("Stored Teams alert #%d (incident %d) for %s", alert_id, incident_id, f["server_name"])
    return True


async def reanalyze(alert: dict) -> dict:
    """Refresh CloudPulse data + LLM analysis for one stored alert."""
    f = {"ig_host": alert.get("ig_host"), "hosts": alert.get("hosts") or []}
    ig_data = await metrics_for(f)
    analysis = await analyze_alert(alert.get("server_name") or "", alert.get("metric_type") or "other",
                                   alert.get("raw_text") or "", ig_data)
    severity = alert.get("severity") or "warning"
    if alert.get("metric_check") and ig_data.get("overall_severity") in ("ok", "warning", "critical"):
        severity = ig_data["overall_severity"]
    await update_analysis(alert["id"], ig_data, analysis, severity)
    return {"ok": True, "analysis": analysis, "severity": severity}


async def _run_locked(lock_id: int, job: str, coro_fn, every_seconds: Optional[int] = None) -> Optional[int]:
    """
    Run coro_fn under a PostgreSQL advisory lock and record the run in infraguardian_teams_jobs.
    With every_seconds, only run if the last recorded run is at least that old.
    Returns None if another worker holds the lock or the job is not yet due.
    """
    # A dedicated connection: session-level advisory locks must be released on the
    # same connection that took them (a Session may swap pooled connections on commit).
    async with engine.connect() as lock_db:
        got = (await lock_db.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": lock_id})).scalar()
        await lock_db.commit()
        if not got:
            return None
        try:
            if every_seconds is not None:
                due = (await lock_db.execute(
                    text("""
                        SELECT COALESCE(MAX(last_run), 'epoch') <= NOW() - make_interval(secs => :s)
                        FROM infraguardian_teams_jobs WHERE job = :j
                    """),
                    {"j": job, "s": every_seconds},
                )).scalar()
                if not due:
                    return None
            await lock_db.execute(
                text("""
                    INSERT INTO infraguardian_teams_jobs (job, last_run) VALUES (:j, NOW())
                    ON CONFLICT (job) DO UPDATE SET last_run = NOW()
                """),
                {"j": job},
            )
            await lock_db.commit()
            return await coro_fn()
        finally:
            await lock_db.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": lock_id})
            await lock_db.commit()


async def _poll() -> int:
    try:
        messages = await ts.fetch_messages()
    except Exception as exc:
        log.error("Teams polling failed: %s", exc)
        return 0

    unseen = await _unseen_ids([m.get("id", "") for m in messages if m.get("id")])
    stored = 0
    # Oldest first so DB order is chronological
    for msg in reversed(messages):
        if msg.get("id") not in unseen:
            continue
        try:
            if await process_message(msg):
                stored += 1
        except Exception as exc:
            log.exception("Failed to process Teams message %s: %s", msg.get("id", "?"), exc)
    return stored


async def _resolve_check() -> int:
    """
    Clear open incidents whose latest occurrence is a host CPU/memory/disk alert that
    CloudPulse now shows healthy, plus (optionally) stale event incidents.
    """
    async with AsyncSessionLocal() as db:
        active = (await db.execute(text("""
            SELECT id, server_name, metric_type, ig_host, metric_check, received_at FROM (
                SELECT DISTINCT ON (incident_id) id, server_name, metric_type, ig_host,
                       metric_check, received_at, resolved
                FROM infraguardian_teams_alerts
                ORDER BY incident_id, received_at DESC NULLS LAST, id DESC
            ) l
            WHERE resolved = FALSE
        """))).fetchall()

    threshold   = await cfg.get_float("teams.resolve_threshold", 90.0)
    stale_hours = await cfg.get_float("teams.stale_clear_hours", 0.0)
    now = datetime.now().astimezone()
    resolved_count = 0
    for a in active:
        try:
            if a.metric_check and a.ig_host:
                if is_condition_cleared(await get_server_metrics(a.ig_host), threshold):
                    await mark_resolved(a.id, True, by="metrics")
                    log.info("Auto-resolved Teams incident of alert %d for %s (%s) — metrics cleared",
                             a.id, a.server_name, a.metric_type)
                    resolved_count += 1
            elif stale_hours > 0 and a.received_at and (now - a.received_at).total_seconds() > stale_hours * 3600:
                await mark_resolved(a.id, True, by="stale")
                log.info("Auto-resolved stale Teams incident of alert %d for %s (%s)",
                         a.id, a.server_name, a.metric_type)
                resolved_count += 1
        except Exception as exc:
            log.warning("Failed to check resolution for Teams alert %d (%s): %s", a.id, a.server_name, exc)
    if resolved_count:
        log.info("Auto-resolved %d Teams incident(s)", resolved_count)
    return resolved_count


async def poll_once() -> Optional[int]:
    """Manual poll: fetch new Teams messages now. None = another worker is polling."""
    return await _run_locked(_POLL_LOCK_ID, "poll", _poll)


async def check_and_resolve_active_alerts() -> Optional[int]:
    """Manual re-check of every active incident. None = a check is already running."""
    return await _run_locked(_RESOLVE_LOCK_ID, "resolve_check", _resolve_check)


async def scheduled_tick() -> None:
    """
    Runs every TICK_SECONDS in each worker. Reloads settings from the DB (so changes
    made in either worker apply within one tick) and runs whichever job is due.
    """
    try:
        await cfg.load_all()
    except Exception as exc:
        log.warning("Teams tick: settings reload failed: %s", exc)
        return
    if not await cfg.get_bool("teams.enabled", True):
        return
    poll_every    = max(TICK_SECONDS, await cfg.get_int("teams.poll_interval", 60))
    resolve_every = max(1, await cfg.get_int("teams.resolve_interval_min", 15)) * 60
    await _run_locked(_POLL_LOCK_ID, "poll", _poll, every_seconds=poll_every - 2)
    await _run_locked(_RESOLVE_LOCK_ID, "resolve_check", _resolve_check, every_seconds=resolve_every - 2)
