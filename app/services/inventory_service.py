"""
Server inventory: every Windows server CloudPulse monitors, with its IP, OS, vCPU,
memory and disk (refreshed from Elasticsearch + capacity data), plus admin-maintained
fields — project, environment, application, owner, criticality, notes.

Project / environment are suggested from the Elastic data-stream namespace
(e.g. "hrc_sc_prod_windows" → site HRC, project code "sc", environment "prod") through an
editable code → name map (inventory.project_map / inventory.env_map settings). Admin values
always win; the automatic refresh never overwrites them.
"""
from __future__ import annotations
import csv
import io
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import text

from app.database import AsyncSessionLocal
import app.config as cfg

log = logging.getLogger(__name__)
_SCHEMA_LOCK_ID = 86940030

EDITABLE = ["project", "environment", "application", "owner", "criticality", "notes"]
CRITICALITY = ["Critical", "High", "Medium", "Low"]

_SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS cloudpulse_server_inventory (
        server_key    VARCHAR(255) PRIMARY KEY,   -- lower-case short hostname
        server_name   VARCHAR(255) NOT NULL,      -- as CloudPulse / Elastic know it
        ip_address    VARCHAR(100),
        os_name       VARCHAR(255),
        vcpu          INTEGER,
        memory_gb     NUMERIC(10,2),
        disk_gb       NUMERIC(12,2),
        es_namespace  VARCHAR(255),
        site          VARCHAR(50),
        project       VARCHAR(255),
        environment   VARCHAR(100),
        application   VARCHAR(255),
        owner         VARCHAR(255),
        criticality   VARCHAR(30),
        notes         TEXT,
        monitored     BOOLEAN DEFAULT TRUE,
        last_seen     TIMESTAMPTZ,
        updated_by    VARCHAR(100),
        updated_at    TIMESTAMPTZ,
        created_at    TIMESTAMPTZ DEFAULT NOW()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_inventory_project ON cloudpulse_server_inventory(project)",
    """
    INSERT INTO cloudpulse_settings (key, value, category, description, is_secret) VALUES
    ('inventory.project_map', 'pay=Payments,crm=CRM,web=Web Portal',
     'inventory', 'Elastic namespace project code = project name (comma-separated) — used to suggest projects', FALSE),
    ('inventory.env_map', 'prod=Production,nprod=Non-Production,dr=DR,preprd=Pre-Production,uat=UAT,dev=Development,test=Test,stg=Staging',
     'inventory', 'Elastic namespace environment code = environment name (comma-separated)', FALSE)
    ON CONFLICT (key) DO NOTHING
    """,
]


async def ensure_schema() -> None:
    async with AsyncSessionLocal() as db:
        await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _SCHEMA_LOCK_ID})
        for stmt in _SCHEMA:
            await db.execute(text(stmt))
        await db.commit()
    await cfg.invalidate_cache()


def key_of(name: str) -> str:
    return (name or "").strip().split(".")[0].lower()


async def _maps() -> tuple[dict[str, str], dict[str, str]]:
    def parse(raw: str) -> dict[str, str]:
        out = {}
        for part in (raw or "").split(","):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip().lower()] = v.strip()
        return out
    return parse(await cfg.get("inventory.project_map", "")), parse(await cfg.get("inventory.env_map", ""))


def parse_namespace(ns: str, project_map: dict, env_map: dict) -> dict:
    """'dc1_pay_prod_windows' → {site: 'DC1', project: 'Payments', environment: 'Production'}"""
    parts = [p for p in (ns or "").lower().split("_") if p and p != "windows"]
    if not parts:
        return {"site": None, "project": None, "environment": None}
    site, rest = parts[0].upper(), parts[1:]
    env = None
    if rest and rest[-1] in env_map:
        env = env_map[rest[-1]]
        rest = rest[:-1]
    code = "_".join(rest)
    project = project_map.get(code) or (project_map.get(rest[-1]) if rest else None) or (code.upper() if code else None)
    return {"site": site, "project": project, "environment": env}


# ─────────────────────────────────────────────────────────────────────────────
# Automatic refresh (Elastic + capacity data) — never touches admin fields
# ─────────────────────────────────────────────────────────────────────────────

async def refresh() -> int:
    """Upsert every Windows server seen in Elastic in the last 24 h; returns servers seen."""
    from app.services.es_service import _post, _IDX_CPU, _SERVER_FILTER
    r = await _post(f"/{_IDX_CPU}/_search", {
        "size": 0,
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": "now-24h"}}}, _SERVER_FILTER]}},
        "aggs": {"hosts": {"terms": {"field": "host.name", "size": 2000}, "aggs": {
            "cores": {"max": {"field": "system.cpu.cores"}},
            "last": {"top_hits": {"size": 1, "sort": [{"@timestamp": "desc"}],
                                  "_source": ["host.ip", "host.os.name", "data_stream.namespace", "@timestamp"]}},
        }}},
    })
    buckets = r.get("aggregations", {}).get("hosts", {}).get("buckets", [])
    async with AsyncSessionLocal() as db:
        cap = {key_of(x.server_name): x for x in (await db.execute(text("""
            SELECT DISTINCT ON (server_name) server_name, total_mem_gb, total_disk_gb, host_ip
            FROM cloudpulse_capacity_daily ORDER BY server_name, report_date DESC
        """))).fetchall()}
        seen = set()
        for b in buckets:
            src = (b["last"]["hits"]["hits"] or [{}])[0].get("_source", {})
            host = src.get("host", {})
            ips = host.get("ip") or []
            ip = next((i for i in (ips if isinstance(ips, list) else [ips])   # routable IPv4 only
                       if i and ":" not in i and not i.startswith(("169.254.", "127."))), None)
            name = b["key"]
            k = key_of(name)
            c = cap.get(k)
            seen.add(k)
            await db.execute(text("""
                INSERT INTO cloudpulse_server_inventory
                    (server_key, server_name, ip_address, os_name, vcpu, memory_gb, disk_gb, es_namespace, site, monitored, last_seen)
                VALUES (:k, :n, :ip, :os, :cores, :mem, :disk, :ns, :site, TRUE, :seen)
                ON CONFLICT (server_key) DO UPDATE SET
                    server_name = EXCLUDED.server_name, ip_address = COALESCE(EXCLUDED.ip_address, cloudpulse_server_inventory.ip_address),
                    os_name = EXCLUDED.os_name, vcpu = COALESCE(EXCLUDED.vcpu, cloudpulse_server_inventory.vcpu),
                    memory_gb = COALESCE(EXCLUDED.memory_gb, cloudpulse_server_inventory.memory_gb),
                    disk_gb = COALESCE(EXCLUDED.disk_gb, cloudpulse_server_inventory.disk_gb),
                    es_namespace = EXCLUDED.es_namespace, site = EXCLUDED.site, monitored = TRUE, last_seen = EXCLUDED.last_seen
            """), {
                "k": k, "n": c.server_name if c else name, "ip": ip or (c.host_ip if c else None), "os": (host.get("os") or {}).get("name"),
                "cores": int(b["cores"]["value"]) if b["cores"]["value"] else None,
                "mem": float(c.total_mem_gb) if c and c.total_mem_gb else None,
                "disk": float(c.total_disk_gb) if c and c.total_disk_gb else None,
                "ns": (src.get("data_stream") or {}).get("namespace"),
                "site": ((src.get("data_stream") or {}).get("namespace") or "").split("_")[0].upper() or None,
                "seen": datetime.now(timezone.utc),
            })
        if seen:
            await db.execute(text("UPDATE cloudpulse_server_inventory SET monitored = FALSE WHERE server_key <> ALL(:keys)"),
                             {"keys": list(seen)})
        await db.commit()
    log.info("Server inventory refreshed: %d servers seen in Elastic", len(seen))
    return len(seen)


# ─────────────────────────────────────────────────────────────────────────────
# Reading
# ─────────────────────────────────────────────────────────────────────────────

_COLS = ("server_key, server_name, ip_address, os_name, vcpu, memory_gb, disk_gb, es_namespace, site, project, environment, "
         "application, owner, criticality, notes, monitored, last_seen, updated_by, updated_at")


async def list_servers() -> list[dict]:
    """All servers with effective project / environment (admin value, else namespace suggestion)."""
    pmap, emap = await _maps()
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(text(f"SELECT {_COLS} FROM cloudpulse_server_inventory ORDER BY server_name"))).fetchall()
    out = []
    for r in rows:
        d = {k: (float(v) if hasattr(v, "is_finite") else v) for k, v in r._mapping.items()}
        sug = parse_namespace(d.get("es_namespace"), pmap, emap)
        d["suggested_project"], d["suggested_environment"] = sug["project"], sug["environment"]
        d["project_effective"] = d.get("project") or sug["project"] or "Unassigned"
        d["environment_effective"] = d.get("environment") or sug["environment"] or ""
        d["project_source"] = "admin" if d.get("project") else "suggested" if sug["project"] else "none"
        out.append(d)
    return out


async def project_lookup() -> dict[str, dict]:
    """server_key → {project, environment, application, criticality} (effective values)."""
    return {s["server_key"]: {"project": s["project_effective"], "environment": s["environment_effective"],
                              "application": s.get("application"), "criticality": s.get("criticality")}
            for s in await list_servers()}


async def project_of(host: str, lookup: Optional[dict] = None) -> Optional[str]:
    lookup = lookup if lookup is not None else await project_lookup()
    p = (lookup.get(key_of(host)) or {}).get("project")
    return None if p in (None, "Unassigned") else p


async def projects() -> list[dict]:
    from collections import defaultdict
    agg: dict[str, dict] = defaultdict(lambda: {"servers": 0, "vcpu": 0, "memory_gb": 0.0, "disk_gb": 0.0, "environments": set()})
    for s in await list_servers():
        if not s.get("monitored"):
            continue
        a = agg[s["project_effective"]]
        a["servers"] += 1
        a["vcpu"] += s.get("vcpu") or 0
        a["memory_gb"] += s.get("memory_gb") or 0
        a["disk_gb"] += s.get("disk_gb") or 0
        if s["environment_effective"]:
            a["environments"].add(s["environment_effective"])
    return sorted([{"project": k, **v, "environments": sorted(v["environments"])} for k, v in agg.items()],
                  key=lambda x: (x["project"] == "Unassigned", -x["servers"]))


# ─────────────────────────────────────────────────────────────────────────────
# Editing — single server, CSV export / import
# ─────────────────────────────────────────────────────────────────────────────

async def update_server(server_key: str, fields: dict, user: str) -> bool:
    sets = {k: (v.strip() or None) if isinstance(v, str) else v for k, v in fields.items() if k in EDITABLE}
    if not sets:
        return False
    async with AsyncSessionLocal() as db:
        res = await db.execute(text(
            f"UPDATE cloudpulse_server_inventory SET {', '.join(f'{k} = :{k}' for k in sets)}, updated_by = :by, updated_at = NOW() "
            "WHERE server_key = :key RETURNING server_key"), {**sets, "by": user, "key": server_key})
        ok = res.fetchone() is not None
        await db.commit()
    return ok


CSV_COLUMNS = ["server_name", "ip_address", "os_name", "vcpu", "memory_gb", "disk_gb", "site", "es_namespace",
               "project", "environment", "application", "owner", "criticality", "notes"]


async def export_csv() -> bytes:
    """Inventory as CSV; project / environment pre-filled with suggestions where not yet set."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLUMNS)
    for s in await list_servers():
        if not s.get("monitored") and not s.get("project"):
            continue
        row = dict(s)
        row["project"] = s.get("project") or s.get("suggested_project") or ""
        row["environment"] = s.get("environment") or s.get("suggested_environment") or ""
        w.writerow(["" if row.get(c) is None else row.get(c) for c in CSV_COLUMNS])
    return ("﻿" + buf.getvalue()).encode("utf-8")


async def import_csv(raw: bytes, apply: bool, user: str) -> dict:
    """
    Match rows by server_name (short name, case-insensitive). Only the editable columns are read.
    Blank cell = leave unchanged; "-" = clear the value. With apply=False nothing is written.
    """
    content = raw.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(content))
    headers = [h.strip().lower() for h in (reader.fieldnames or [])]
    if "server_name" not in headers:
        return {"ok": False, "error": "CSV needs a 'server_name' column (download the inventory CSV as a template)."}
    current = {s["server_key"]: s for s in await list_servers()}
    changes, unknown, invalid, unchanged = [], [], [], 0
    for i, row in enumerate(reader, start=2):
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        name = row.get("server_name", "")
        if not name:
            continue
        k = key_of(name)
        if k not in current:
            unknown.append({"line": i, "server_name": name})
            continue
        diff = {}
        for f in EDITABLE:
            if f not in row:
                continue
            v = row[f]
            if v == "":
                continue
            new = None if v == "-" else v
            if f == "criticality" and new and new.capitalize() not in CRITICALITY:
                invalid.append({"line": i, "server_name": name, "error": f"criticality '{v}' — use {', '.join(CRITICALITY)}"})
                continue
            if f == "criticality" and new:
                new = new.capitalize()
            if (current[k].get(f) or None) != new:
                diff[f] = {"from": current[k].get(f), "to": new}
        if diff:
            changes.append({"server_key": k, "server_name": current[k]["server_name"], "changes": diff})
        else:
            unchanged += 1
    if apply:
        for c in changes:
            await update_server(c["server_key"], {f: (d["to"] or "") for f, d in c["changes"].items()}, user)
    return {"ok": True, "applied": apply, "changed": len(changes), "unchanged": unchanged,
            "unknown": unknown, "invalid": invalid, "changes": changes}
