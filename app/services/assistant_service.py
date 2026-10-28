"""
CloudPulse Assistant AI Assistant — a read-only, tool-using agent over everything CloudPulse knows.

The configured LLM (OpenAI-compatible, native tool calling) plans and calls tools:
  live Elasticsearch metrics & processes · server inventory & projects · capacity forecasts ·
  Entra ID (live Graph lookups + collected identity data) · Defender / Secure Score / Intune /
  Identity Protection snapshots · live Defender device drill-down & advanced hunting · Teams incidents.

Any tool returning a list registers a *dataset* (full rows kept server-side; the model sees a preview).
The model places datasets in its answer with [[table:<id>]] / [[chart:<id>|...]] markers, which the UI
renders as sortable / exportable tables and charts. Every tool is read-only.
"""
from __future__ import annotations
import asyncio
import json
import logging
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Callable, Optional

import httpx
from sqlalchemy import text

from app.database import AsyncSessionLocal
from app.services import graph_service as g
from app.services import inventory_service as inv
from app.services.llm_service import _get_llm_params
import app.config as cfg

log = logging.getLogger(__name__)
GST = timezone(timedelta(hours=4))
MAX_STEPS = 8
PREVIEW_ROWS = 12
TOOL_RESULT_CHARS = 7000
DATASET_ROW_CAP = 3000

# ─────────────────────────────────────────────────────────────────────────────
# Schema (chat history)
# ─────────────────────────────────────────────────────────────────────────────

_SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS cloudpulse_ai_chats (
        id          SERIAL PRIMARY KEY,
        username    VARCHAR(100) NOT NULL,
        title       VARCHAR(200),
        created_at  TIMESTAMPTZ DEFAULT NOW(),
        updated_at  TIMESTAMPTZ DEFAULT NOW()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS cloudpulse_ai_messages (
        id          SERIAL PRIMARY KEY,
        chat_id     INTEGER NOT NULL REFERENCES cloudpulse_ai_chats(id) ON DELETE CASCADE,
        role        VARCHAR(20) NOT NULL,
        content     TEXT,
        datasets    JSONB,
        steps       JSONB,
        created_at  TIMESTAMPTZ DEFAULT NOW()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_ai_chats_user ON cloudpulse_ai_chats(username, updated_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_ai_messages_chat ON cloudpulse_ai_messages(chat_id, id)",
]


async def ensure_schema() -> None:
    async with AsyncSessionLocal() as db:
        await db.execute(text("SELECT pg_advisory_xact_lock(86940040)"))
        for stmt in _SCHEMA:
            await db.execute(text(stmt))
        await db.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Datasets
# ─────────────────────────────────────────────────────────────────────────────

class Datasets:
    def __init__(self) -> None:
        self.items: dict[str, dict] = {}

    def add(self, title: str, rows: list[dict], note: str = "") -> dict:
        """Register rows; return what the model sees (id, size, columns, preview)."""
        ds_id = f"t{len(self.items) + 1}"
        rows = [{k: _plain(v) for k, v in r.items()} for r in rows]
        cols = list(dict.fromkeys(k for r in rows[:50] for k in r))
        self.items[ds_id] = {"id": ds_id, "title": title, "columns": cols, "rows": rows[:DATASET_ROW_CAP],
                             "total": len(rows), "note": note}
        return {"dataset_id": ds_id, "title": title, "total_rows": len(rows), "columns": cols,
                "preview": rows[:PREVIEW_ROWS], **({"note": note} if note else {})}


def _plain(v: Any) -> Any:
    if isinstance(v, datetime):
        return v.isoformat()
    if hasattr(v, "is_finite"):        # Decimal
        return float(v)
    if isinstance(v, (list, tuple)) and len(v) > 12:
        return list(v[:12]) + [f"+{len(v) - 12} more"]
    return v


def _contains(hay: Any, needle: Optional[str]) -> bool:
    return not needle or needle.lower() in str(hay or "").lower()


def _matcher(values: list, wanted: str) -> Callable[[Any], bool]:
    """Exact (case-insensitive) when some value equals `wanted` — so 'Production' never matches 'Non-Production' — else substring."""
    if not wanted:
        return lambda v: True
    w = wanted.strip().lower()
    if any(str(v or "").lower() == w for v in values):
        return lambda v: str(v or "").lower() == w
    return lambda v: w in str(v or "").lower()


# ─────────────────────────────────────────────────────────────────────────────
# Tools
# ─────────────────────────────────────────────────────────────────────────────

async def _latest_capacity() -> dict[str, dict]:
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(text("""
            SELECT DISTINCT ON (server_name) server_name, report_date, avg_cpu_pct, max_cpu_pct, avg_mem_pct,
                   avg_disk_pct, max_disk_pct, used_mem_gb, free_disk_gb
            FROM cloudpulse_capacity_daily ORDER BY server_name, report_date DESC
        """))).fetchall()
    return {inv.key_of(r.server_name): {k: _plain(v) for k, v in r._mapping.items()} for r in rows}


async def t_find_servers(ds: Datasets, query: str = "", project: str = "", environment: str = "", site: str = "",
                         os: str = "", min_cpu_pct: float = 0, min_mem_pct: float = 0, min_disk_pct: float = 0,
                         criticality: str = "") -> dict:
    servers = [s for s in await inv.list_servers() if s.get("monitored")]
    cap = await _latest_capacity()
    m_proj = _matcher([s["project_effective"] for s in servers], project)
    m_env = _matcher([s["environment_effective"] for s in servers], environment)
    m_site = _matcher([s.get("site") for s in servers], site)
    m_crit = _matcher([s.get("criticality") for s in servers], criticality)
    rows = []
    for s in servers:
        c = cap.get(s["server_key"], {})
        hay = " ".join(str(s.get(k) or "") for k in ("server_name", "ip_address", "application", "owner", "notes", "es_namespace"))
        if not _contains(hay, query) or not m_proj(s["project_effective"]) or not m_env(s["environment_effective"]) \
                or not m_site(s.get("site")) or not _contains(s.get("os_name"), os) or not m_crit(s.get("criticality")):
            continue
        if (c.get("avg_cpu_pct") or 0) < min_cpu_pct or (c.get("avg_mem_pct") or 0) < min_mem_pct or (c.get("max_disk_pct") or 0) < min_disk_pct:
            continue
        rows.append({"server": s["server_name"], "ip": s.get("ip_address"), "project": s["project_effective"],
                     "environment": s["environment_effective"], "site": s.get("site"), "os": s.get("os_name"),
                     "vcpu": s.get("vcpu"), "memory_gb": s.get("memory_gb"), "disk_gb": s.get("disk_gb"),
                     "cpu_avg_pct": c.get("avg_cpu_pct"), "mem_avg_pct": c.get("avg_mem_pct"), "worst_disk_pct": c.get("max_disk_pct"),
                     "application": s.get("application"), "owner": s.get("owner"), "criticality": s.get("criticality"),
                     "metrics_date": str(c.get("report_date") or "")})
    def group(key: str) -> dict:
        out: dict[str, dict] = {}
        for r in rows:
            g_ = out.setdefault(r[key] or "(none)", {"servers": 0, "vcpu": 0, "memory_gb": 0.0, "disk_gb": 0.0})
            g_["servers"] += 1
            g_["vcpu"] += r["vcpu"] or 0
            g_["memory_gb"] = round(g_["memory_gb"] + (r["memory_gb"] or 0), 1)
            g_["disk_gb"] = round(g_["disk_gb"] + (r["disk_gb"] or 0), 1)
        return dict(sorted(out.items(), key=lambda kv: -kv[1]["servers"]))

    summary = ds.add("Servers", rows, "CPU / memory / disk % are yesterday's daily averages")
    return {**summary,
            "totals": {"servers": len(rows), "vcpu": sum(r["vcpu"] or 0 for r in rows),
                       "memory_gb": round(sum(r["memory_gb"] or 0 for r in rows), 1), "disk_gb": round(sum(r["disk_gb"] or 0 for r in rows), 1)},
            "totals_by_project": group("project"), "totals_by_environment": group("environment"),
            "by_project_table": ds.add("Servers per project", [{"project": k, **v} for k, v in group("project").items()]),
            "by_environment_table": ds.add("Servers per environment", [{"environment": k, **v} for k, v in group("environment").items()])}


async def _resolve_server(name: str) -> Optional[dict]:
    k = inv.key_of(name)
    for s in await inv.list_servers():
        if s["server_key"] == k:
            return s
    cands = [s for s in await inv.list_servers() if k in s["server_key"]]
    return cands[0] if len(cands) == 1 else None


async def t_server_overview(ds: Datasets, server: str) -> dict:
    from app.services import es_service as es, capacity_forecast as cf, ad_service
    s = await _resolve_server(server)
    if not s:
        return {"error": f"No monitored server matches '{server}'. Use find_servers to search."}
    name = s["server_name"]
    live, fc = await asyncio.gather(es.get_live_server_snapshot(name, 15), cf.forecast("server", name, 90, 180))
    out: dict[str, Any] = {
        "server": name, "ip": s.get("ip_address"), "os": s.get("os_name"), "project": s["project_effective"],
        "environment": s["environment_effective"], "application": s.get("application"), "owner": s.get("owner"),
        "criticality": s.get("criticality"), "vcpu": s.get("vcpu"), "memory_gb": s.get("memory_gb"), "disk_gb": s.get("disk_gb"),
        "live_15min": {k: live.get(k) for k in ("cpu_pct", "cpu_max_pct", "mem_pct", "mem_used_gb", "mem_free_gb", "disk_pct", "last_seen", "severity")},
        "forecast_180d": {m: {"now": v.get("current"), "capacity": v.get("capacity"), "in_180d": (v.get("forecast") or [{}, {}, {}])[2].get("value"),
                              "direction": (v.get("forecast") or [{}, {}, {}])[2].get("direction"), "days_to_90pct": v.get("days_to_90")}
                          for m, v in fc.get("metrics", {}).items()},
    }
    if live.get("mounts"):
        out["volumes"] = ds.add(f"{name} — disk volumes (live)", live["mounts"])
    sec = await ad_service.load_section("sec_devices")
    dev = next((d for d in ((sec or {}).get("data") or {}).get("devices", []) if inv.key_of(d["name"]) == s["server_key"]), None)
    if dev:
        out["defender"] = {k: dev.get(k) for k in ("exposure", "sensor", "critical", "high", "exploitable", "missing_updates",
                                                   "months_behind", "oldest_missing", "av_mode", "av_sig_age", "cfg_failed", "last_seen")}
        out["defender"]["device_id"] = dev["id"]
    from app.services import teams_alert_service as tas
    active = [i for i in await tas.list_incidents(resolved=False)
              if any(inv.key_of(h or "") == s["server_key"] for h in [i.get("ig_host"), i.get("server_name")] + (i.get("hosts") or []))]
    out["teams_active_incidents"] = [{"type": i["metric_type"], "severity": i["severity"], "title": i.get("title"),
                                      "occurrences": i["occurrence_count"], "last": i["received_at"]} for i in active]
    return out


async def t_top_processes(ds: Datasets, server: str, sort_by: str = "cpu", top_n: int = 15) -> dict:
    from app.services import es_service as es
    s = await _resolve_server(server)
    name = s["server_name"] if s else server
    rows = await es.get_top_processes(name, "memory" if sort_by.lower().startswith("mem") else "cpu", min(int(top_n or 15), 50))
    return ds.add(f"{name} — top processes by {sort_by} (live, last few minutes)", rows) if rows else {"error": f"No process data for {name}."}


async def t_top_servers(ds: Datasets, metric: str = "cpu", top_n: int = 15, minutes: int = 60, project: str = "") -> dict:
    from app.services import es_service as es
    metric = {"mem": "memory", "ram": "memory"}.get(metric.lower(), metric.lower())
    rows = await es.get_top_servers(metric, 300 if project else min(int(top_n or 15), 100), min(int(minutes or 60), 1440))
    look = await inv.project_lookup()
    for r in rows:
        r["project"] = (look.get(inv.key_of(r.get("server", ""))) or {}).get("project", "Unassigned")
    if project:
        rows = [r for r in rows if _contains(r["project"], project)][:int(top_n or 15)]
    return ds.add(f"Top servers by {metric} — live, last {minutes} min" + (f" — {project}" if project else ""), rows)


async def t_capacity_forecast(ds: Datasets, scope: str = "fleet", name: str = "", horizon_days: int = 180) -> dict:
    from app.services import capacity_forecast as cf
    scope = scope if scope in ("fleet", "project", "server") else "fleet"
    if scope == "server":
        s = await _resolve_server(name)
        name = s["server_name"] if s else name
    f = await cf.forecast(scope, name or None, 90, horizon_days if horizon_days in (30, 90, 180, 365) else 180)
    rows = []
    for m, v in f["metrics"].items():
        r = {"resource": f"{v['label']} ({v['unit']})", "capacity": v.get("capacity"), "used_now": v.get("current"), "used_pct": v.get("current_pct"),
             "days_to_90pct": v.get("days_to_90"), "days_to_full": v.get("days_to_full")}
        for x in v.get("forecast", []):
            r[f"in_{x['days']}d"] = x["value"]
            r[f"change_{x['days']}d"] = x["delta"]
        rows.append(r)
    out = {"title": f["title"], "servers": f["servers"], "history_days": f["history_days"], "confidence": f["confidence"],
           "trend_available": f["trend_available"], "forecast": ds.add(f"Capacity forecast — {f['title']}", rows)}
    if f.get("history"):
        out["daily_history"] = ds.add(f"Daily used — {f['title']}", [{"date": h["date"], "cpu_vcpu": h["cpu"], "memory_gb": h["memory"], "disk_gb": h["disk"]} for h in f["history"]])
    if f.get("server_rows"):
        out["servers_under_pressure"] = ds.add(f"Servers by forecast pressure — {f['title']}", [
            {"server": r["server"], "project": r["project"], "cpu_now": r.get("cpu_now"), "cpu_forecast": r.get("cpu_fc"), "cpu_capacity": r.get("cpu_cap"),
             "mem_now_gb": r.get("memory_now"), "mem_forecast_gb": r.get("memory_fc"), "mem_capacity_gb": r.get("memory_cap"),
             "disk_now_gb": r.get("disk_now"), "disk_forecast_gb": r.get("disk_fc"), "disk_capacity_gb": r.get("disk_cap"),
             "peak_forecast_pct": r.get("pressure")} for r in f["server_rows"]])
    return out


async def t_project_summary(ds: Datasets, horizon_days: int = 180) -> dict:
    from app.services import capacity_forecast as cf
    p = await cf.projects_summary(90, horizon_days if horizon_days in (30, 90, 180, 365) else 180)
    rows = [{"project": r["project"], "servers": r["servers"], "environments": ", ".join(r.get("environments") or []),
             "vcpu_used": r.get("cpu_now"), "vcpu_total": r.get("cpu_cap"), "vcpu_forecast": r.get("cpu_fc"),
             "mem_used_gb": r.get("memory_now"), "mem_total_gb": r.get("memory_cap"), "mem_forecast_gb": r.get("memory_fc"),
             "disk_used_gb": r.get("disk_now"), "disk_total_gb": r.get("disk_cap"), "disk_forecast_gb": r.get("disk_fc")} for r in p["projects"]]
    return ds.add(f"Projects — used now vs {p['horizon']}-day forecast", rows)


async def t_capacity_history(ds: Datasets, server: str = "", project: str = "", days: int = 30) -> dict:
    days = max(1, min(int(days or 30), 365))
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(text("""
            SELECT server_name, report_date, avg_cpu_pct, max_cpu_pct, avg_mem_pct, max_disk_pct
            FROM cloudpulse_capacity_daily WHERE report_date >= CURRENT_DATE - CAST(:d AS INTEGER) ORDER BY report_date
        """), {"d": days})).fetchall()
    look = await inv.project_lookup()
    if server:
        s = await _resolve_server(server)
        k = s["server_key"] if s else inv.key_of(server)
        out = [{"date": str(r.report_date), "cpu_avg_pct": _plain(r.avg_cpu_pct), "cpu_max_pct": _plain(r.max_cpu_pct),
                "mem_avg_pct": _plain(r.avg_mem_pct), "worst_disk_pct": _plain(r.max_disk_pct)} for r in rows if inv.key_of(r.server_name) == k]
        return ds.add(f"Daily history — {server} ({days} days)", out)
    agg = defaultdict(lambda: defaultdict(list))
    for r in rows:
        p = (look.get(inv.key_of(r.server_name)) or {}).get("project", "Unassigned")
        if project and not _contains(p, project):
            continue
        for k, v in (("cpu", r.avg_cpu_pct), ("mem", r.avg_mem_pct), ("disk", r.max_disk_pct)):
            if v is not None and (k == "cpu" or float(v) > 0):    # 0% memory / disk means no data that day
                agg[str(r.report_date)][k].append(float(v))
    out = [{"date": d, "servers": len(v["cpu"]), "cpu_avg_pct": round(sum(v["cpu"]) / len(v["cpu"]), 1) if v["cpu"] else None,
            "mem_avg_pct": round(sum(v["mem"]) / len(v["mem"]), 1) if v["mem"] else None,
            "disk_avg_pct": round(sum(v["disk"]) / len(v["disk"]), 1) if v["disk"] else None} for d, v in sorted(agg.items())]
    return ds.add(f"Daily averages — {project or 'whole fleet'} ({days} days)", out)


async def t_entra_user(ds: Datasets, user: str) -> dict:
    u = user.strip()
    try:
        if "@" in u:
            # Filter rather than GET /users/{upn}: some tenants reject UPN keys ("Get By Key only supports UserId")
            safe = u.replace("'", "''")
            found = (await g.get("/users", {"$filter": f"userPrincipalName eq '{safe}' or mail eq '{safe}' or proxyAddresses/any(p:p eq 'smtp:{safe}')",
                                            "$select": "id,displayName,userPrincipalName,mail,accountEnabled,userType,department,jobTitle,createdDateTime,"
                                                       "onPremisesSyncEnabled,lastPasswordChangeDateTime,signInActivity,assignedLicenses,officeLocation",
                                            "$count": "true"})).get("value", [])
        else:
            safe = u.replace("'", "''")
            found = (await g.get("/users", {"$filter": f"startswith(displayName,'{safe}') or startswith(userPrincipalName,'{safe}') or startswith(mail,'{safe}')",
                                            "$select": "id,displayName,userPrincipalName,mail,accountEnabled,userType,department,jobTitle,createdDateTime,"
                                                       "onPremisesSyncEnabled,lastPasswordChangeDateTime,signInActivity,assignedLicenses,officeLocation",
                                            "$top": "10"})).get("value", [])
    except g.GraphError as e:
        return {"error": str(e)}
    if not found:
        return {"error": f"No Entra user matches '{user}'."}
    if len(found) > 1:
        return ds.add(f"Users matching '{user}'", [{"name": x.get("displayName"), "upn": x.get("userPrincipalName"),
                                                     "enabled": x.get("accountEnabled"), "department": x.get("department")} for x in found])
    x = found[0]
    methods, groups, regs = await asyncio.gather(
        g.get(f"/users/{x['id']}/authentication/methods"),
        g.get_all(f"/users/{x['id']}/memberOf", {"$select": "displayName,@odata.type", "$top": "100"}, max_items=300),
        g.get(f"/reports/authenticationMethods/userRegistrationDetails/{x['id']}"), return_exceptions=True)
    from app.services import ad_service
    lic = {s["sku_id"]: s["name"] for s in (((await ad_service.load_section("licences")) or {}).get("data") or {}).get("skus", [])}
    risk = next((r for r in ((((await ad_service.load_section("sec_risk")) or {}).get("data") or {}).get("risky_users", []))
                 if (r.get("upn") or "").lower() == (x.get("userPrincipalName") or "").lower()), None)
    sia = x.get("signInActivity") or {}
    out = {"name": x.get("displayName"), "upn": x.get("userPrincipalName"), "mail": x.get("mail"), "enabled": x.get("accountEnabled"),
           "type": x.get("userType"), "department": x.get("department"), "job_title": x.get("jobTitle"), "office": x.get("officeLocation"),
           "created": x.get("createdDateTime"), "synced_from_ad": bool(x.get("onPremisesSyncEnabled")), "password_last_changed": x.get("lastPasswordChangeDateTime"),
           "last_interactive_signin": sia.get("lastSignInDateTime"), "last_noninteractive_signin": sia.get("lastNonInteractiveSignInDateTime"),
           "licences": [lic.get(l["skuId"], l["skuId"]) for l in x.get("assignedLicenses") or []],
           "identity_protection_risk": risk or "not at risk"}
    if not isinstance(methods, Exception):
        out["mfa_methods"] = sorted({(m.get("@odata.type") or "").split(".")[-1].replace("AuthenticationMethod", "") for m in methods.get("value", [])} - {"password"})
    if not isinstance(regs, Exception):
        out["mfa_registered"] = regs.get("isMfaRegistered")
        out["is_admin"] = regs.get("isAdmin")
    if not isinstance(groups, Exception):
        roles = [m.get("displayName") for m in groups if "directoryRole" in (m.get("@odata.type") or "")]
        grps = [m.get("displayName") for m in groups if "group" in (m.get("@odata.type") or "").lower()]
        out["directory_roles"] = roles
        out["groups"] = ds.add(f"{x.get('displayName')} — group memberships", [{"group": n} for n in sorted(filter(None, grps))]) if grps else []
    return out


async def _snap(section: str) -> dict:
    from app.services import ad_service
    s = await ad_service.load_section(section)
    return (s or {}).get("data") or {}


IDENTITY_TOPICS = {
    "mfa_gaps": ("mfa", "mailbox_without_mfa", "Mailbox users without MFA"),
    "mfa_pending_registration": ("mfa", "pending_registration", "MFA enabled but not enrolled (will enrol at next sign-in)"),
    "mfa_unprotected": ("mfa", "unprotected", "MFA not enabled and not enrolled (password-only)"),
    "conditional_access_policies": ("mfa", "ca_policies", "Conditional Access policies"),
    "synced_without_mfa": ("mfa", "synced_without_mfa", "Synced users without MFA"),
    "admins_without_mfa": ("mfa", "admins_without_mfa", "Admins without MFA"),
    "stale_accounts": ("accounts", "stale", "Stale enabled accounts"),
    "never_signed_in": ("accounts", "never_signed_in", "Accounts that never signed in"),
    "disabled_licensed": ("accounts", "disabled_licensed", "Disabled accounts holding licences"),
    "guests": ("accounts", "guests", "Guest accounts"),
    "new_accounts": ("accounts", "new_7d", "Accounts created in the last 7 days"),
    "old_passwords": ("accounts", "pwd_over_365d", "Passwords older than 365 days"),
    "privileged": ("privileged", "assignments", "Directory role assignments"),
    "app_secrets": ("secrets", "attention", "App secrets / certificates needing action"),
    "app_secrets_upcoming": ("secrets", "upcoming", "App credentials expiring in 180 days"),
    "signin_failures_by_account": ("signins", "top_users", "Accounts with most failed sign-ins"),
    "signin_failures_recent": ("signins", "recent", "Recent failed sign-ins"),
    "licences": ("licences", "skus", "Licence utilisation"),
    "audit_important": ("audit", "important", "Important directory changes"),
    "role_changes": ("audit", "role_changes", "Role membership changes"),
    "ownerless_groups": ("groups", "ownerless", "Ownerless cloud groups"),
    "entra_devices_stale": ("devices", "stale", "Stale Entra-registered devices"),
    "domain_controllers": ("tenant", "dcs", "Domain controllers"),
}


async def t_identity_report(ds: Datasets, topic: str, contains: str = "", limit: int = 0) -> dict:
    if topic not in IDENTITY_TOPICS:
        return {"error": f"Unknown topic. Use one of: {', '.join(IDENTITY_TOPICS)}"}
    section, key, title = IDENTITY_TOPICS[topic]
    d = await _snap(section)
    rows = [r for r in d.get(key, []) if _contains(json.dumps(r, default=str), contains)]
    if limit:
        rows = rows[:int(limit)]
    return {**ds.add(title + (f" — matching '{contains}'" if contains else ""), rows), "section_summary": d.get("summary")}


SECURITY_TOPICS = ["incidents", "alerts", "vulnerabilities", "exploitable_cves", "missing_updates", "patch_status", "antivirus",
                   "secure_score", "secure_score_actions", "intune_noncompliant", "intune_unencrypted", "risky_users",
                   "risk_detections", "service_health", "message_center", "eos_software", "secure_config", "defender_devices"]


async def t_security_report(ds: Datasets, topic: str, project: str = "", platform: str = "", severity: str = "",
                            contains: str = "", limit: int = 0) -> dict:
    if topic not in SECURITY_TOPICS:
        return {"error": f"Unknown topic. Use one of: {', '.join(SECURITY_TOPICS)}"}

    projects = [p["project"] for p in await inv.projects()]
    m_proj = _matcher(projects, project)

    def keep(r: dict) -> bool:
        return ((not project or m_proj(r.get("project"))) and _contains(r.get("group") or r.get("platforms"), platform)
                and _contains(r.get("severity") or r.get("level"), severity) and _contains(json.dumps(r, default=str), contains))

    dev_cols = ("name", "group", "type", "project", "exposure", "critical", "exploitable", "missing_updates", "months_behind",
                "oldest_missing", "av_mode", "av_sig_age", "sensor", "last_seen")
    if topic in ("incidents", "alerts"):
        d = await _snap("sec_threats")
        rows = [r for r in d.get(topic, []) if r.get("status") != "resolved" and keep(r)]
        title, summary = f"Open Defender {topic}", d.get("summary")
    elif topic in ("risky_users", "risk_detections"):
        d = await _snap("sec_risk")
        rows = [r for r in d.get("risky_users" if topic == "risky_users" else "detections", []) if keep(r)]
        title, summary = topic.replace("_", " ").title(), d.get("summary")
    elif topic in ("service_health", "message_center"):
        d = await _snap("sec_service")
        rows = [r for r in (d.get("issues") if topic == "service_health" else d.get("messages")) or [] if keep(r)]
        title, summary = "Microsoft 365 " + topic.replace("_", " "), d.get("summary")
    elif topic in ("secure_score", "secure_score_actions"):
        d = await _snap("sec_score")
        rows = d.get("trend", []) if topic == "secure_score" else [a for a in d.get("actions", []) if a["status"] != "Completed" and keep(a)]
        for a in rows:
            a.pop("remediation", None)
        title, summary = "Secure Score " + ("trend" if topic == "secure_score" else "open improvement actions"), d.get("summary")
    elif topic in ("intune_noncompliant", "intune_unencrypted"):
        d = await _snap("sec_intune")
        rows = [r for r in d.get("devices", []) if (r["compliance"] == "noncompliant" if topic == "intune_noncompliant"
                else (r.get("os") or "").lower().startswith("windows") and r.get("encrypted") is False) and keep(r)]
        title, summary = topic.replace("_", " ").title(), d.get("summary")
    else:
        d = await _snap("sec_devices")
        summary = d.get("summary")
        devs = [r for r in d.get("devices", []) if keep(r)]
        if topic == "vulnerabilities":
            rows, title = [c for c in d.get("cves", []) if keep(c)], "High & critical CVEs"
        elif topic == "exploitable_cves":
            rows, title = [c for c in d.get("cves", []) if c.get("exploit") and keep(c)], "CVEs with a public exploit"
        elif topic == "missing_updates":
            rows = [{k: v for k, v in u.items() if k != "device_names"} | {"example_devices": (u.get("device_names") or [])[:8]}
                    for u in d.get("updates", []) if _contains(u.get("platforms"), platform) and _contains(json.dumps(u), contains)]
            title = "Missing security updates"
        elif topic == "eos_software":
            rows, title = [e for e in d.get("eos", []) if _contains(json.dumps(e), contains)], "End-of-support software"
        elif topic == "secure_config":
            rows, title = [c for c in d.get("config", []) if _contains(json.dumps(c), contains)], "Failing secure-configuration checks"
        elif topic == "antivirus":
            rows = [{k: r.get(k) for k in ("name", "group", "project", "av_mode", "av_sig_version", "av_sig_age", "av_sig_uptodate",
                                           "av_engine_uptodate", "av_platform_uptodate", "last_seen")} for r in devs if r["av_mode"] != "Not reported"]
            title = "Defender Antivirus status"
        elif topic == "patch_status":
            rows = [{k: r.get(k) for k in dev_cols} for r in sorted(devs, key=lambda r: -r["months_behind"])]
            title = "Patch status by device"
        else:
            rows, title = [{k: r.get(k) for k in dev_cols} for r in devs], "Defender devices"
    if limit:
        rows = rows[:int(limit)]
    suffix = " — ".join(filter(None, [project, platform, severity]))
    return {**ds.add(title + (f" — {suffix}" if suffix else ""), rows), "section_summary": summary}


async def t_defender_device(ds: Datasets, device: str) -> dict:
    from app.services import security_service as sec
    devs = (await _snap("sec_devices")).get("devices", [])
    k = inv.key_of(device)
    match = [d for d in devs if inv.key_of(d["name"]) == k] or [d for d in devs if k in d["name"].lower()]
    if not match:
        return {"error": f"No Defender device matches '{device}'."}
    d = match[0]
    x = await sec.device_detail(d["id"])
    return {"device": {k2: d.get(k2) for k2 in ("name", "platform", "type", "project", "exposure", "sensor", "critical", "exploitable",
                                                 "missing_updates", "months_behind", "av_mode", "av_sig_age", "cfg_failed", "last_seen")},
            "missing_updates": ds.add(f"{d['name']} — missing updates (live)", x["updates"]),
            "vulnerabilities": ds.add(f"{d['name']} — vulnerabilities (live)", x["vulns"]),
            "misconfigurations": ds.add(f"{d['name']} — failing secure configuration (live)", x["config"]),
            "alerts": ds.add(f"{d['name']} — alerts, 30 days (live)", x["alerts"])}


async def t_hunting_query(ds: Datasets, kql: str) -> dict:
    q = kql.strip().rstrip(";")
    if not re.search(r"\|\s*(take|limit|top|summarize)\b", q, re.I):
        q += "\n| take 500"
    try:
        rows = await g.hunt(q, timeout=120)
    except Exception as e:
        return {"error": f"Hunting query failed: {e}"}
    return ds.add("Advanced hunting result", rows[:2000], "Defender advanced hunting (live)")


async def t_teams_incidents(ds: Datasets, active: bool = True, project: str = "", server: str = "", category: str = "") -> dict:
    from app.services import teams_alert_service as tas
    rows = await tas.list_incidents(resolved=not active, limit=1000)
    look = await inv.project_lookup()
    out = []
    for r in rows:
        p = next(((look.get(inv.key_of(h or "")) or {}).get("project") for h in [r.get("ig_host"), r.get("server_name")] + (r.get("hosts") or [])
                  if (look.get(inv.key_of(h or "")) or {}).get("project") not in (None, "Unassigned")), r.get("project") or "")
        if not _contains(p, project) or not _contains(r.get("server_name"), server) or not _contains(r.get("metric_type"), category):
            continue
        out.append({"target": r.get("server_name"), "type": r.get("metric_type"), "severity": r.get("severity"), "project": p,
                    "title": r.get("title"), "occurrences": r.get("occurrence_count"), "first_seen": r.get("first_seen"),
                    "last_seen": r.get("received_at"), "jira": r.get("jira_key"), "cleared": r.get("resolved_at")})
    return ds.add(("Active" if active else "Cleared") + " Teams alert incidents", out)


async def t_posture_summary(ds: Datasets, area: str = "all") -> dict:
    from app.services import ad_service, security_service as sec
    snaps = await ad_service.load_snapshots(with_data=False)
    out = {"collected": {k: str(v.get("collected_at") or "")[:16] for k, v in snaps.items()}}
    if area in ("security", "all"):
        full = await ad_service.load_snapshots()
        items = await sec.findings({k: v for k, v in full.items() if k in sec.SECTIONS or k == "tenant"})
        out["security_score"] = ad_service.health_score(items)
        out["security_findings"] = [{"severity": f["severity"], "title": f["title"], "detail": f["detail"]} for f in items]
        out["security_summaries"] = {k: (snaps.get(k) or {}).get("data") for k in sec.SECTIONS}
    if area in ("identity", "all"):
        full = await ad_service.load_snapshots()
        items = await ad_service.findings(full)
        out["identity_score"] = ad_service.health_score(items)
        out["identity_findings"] = [{"severity": f["severity"], "title": f["title"], "detail": f["detail"]} for f in items]
        out["identity_summaries"] = {k: (snaps.get(k) or {}).get("data") for k in ("tenant", "accounts", "mfa", "privileged", "secrets", "signins", "licences")}
    return out


def _p(type_: str, desc: str, **extra) -> dict:
    return {"type": type_, "description": desc, **extra}


TOOLS: dict[str, tuple[Callable, str, dict, list, str]] = {
    # name: (fn, description, properties, required, progress label)
    "find_servers": (t_find_servers, "Search the Windows server inventory (241 servers) with IP, project, environment, vCPU, memory, disk, owner, and yesterday's average CPU/memory/disk %. Use for any inventory, 'list servers', 'which servers', or project questions.",
                     {"query": _p("string", "Free text matched against name, IP, application, owner, notes"), "project": _p("string", "Project name, e.g. Payments"),
                      "environment": _p("string", "Production / Non-Production / DR / Pre-Production"), "site": _p("string", "Site code e.g. HRC, KZN, AT3"),
                      "os": _p("string", "e.g. 2016, 2019, 2022"), "min_cpu_pct": _p("number", "Only servers with avg CPU ≥ this"),
                      "min_mem_pct": _p("number", "Only servers with avg memory ≥ this"), "min_disk_pct": _p("number", "Only servers with worst disk ≥ this"),
                      "criticality": _p("string", "Critical / High / Medium / Low")}, [], "🔎 Searching the server inventory"),
    "server_overview": (t_server_overview, "Everything about one server: inventory facts, LIVE CPU/memory/disk (last 15 min), disk volumes, 180-day forecast, Defender security status (vulnerabilities, missing patches, antivirus) and active Teams alert incidents.",
                        {"server": _p("string", "Server name (short or FQDN)")}, ["server"], "🖥️ Reading live server status"),
    "top_processes": (t_top_processes, "LIVE top processes on a server by CPU or memory (what is consuming resources right now).",
                      {"server": _p("string", "Server name"), "sort_by": _p("string", "cpu or memory", enum=["cpu", "memory"]), "top_n": _p("integer", "Default 15")},
                      ["server"], "⚡ Reading live processes"),
    "top_servers": (t_top_servers, "LIVE ranking of servers by CPU, memory or disk over the last N minutes, optionally for one project.",
                    {"metric": _p("string", "cpu / memory / disk", enum=["cpu", "memory", "disk"]), "top_n": _p("integer", "Default 15"),
                     "minutes": _p("integer", "Look-back window, default 60"), "project": _p("string", "Optional project filter")}, ["metric"], "📈 Ranking servers live"),
    "capacity_forecast": (t_capacity_forecast, "Capacity in absolute units (vCPU, memory GB, disk GB): used now, capacity, forecast at 30/90/180/365 days, days to 90% / full, for the fleet, a project or a server. Includes daily history and servers under most pressure.",
                          {"scope": _p("string", "fleet / project / server", enum=["fleet", "project", "server"]), "name": _p("string", "Project or server name"),
                           "horizon_days": _p("integer", "30, 90, 180 or 365 (default 180)")}, ["scope"], "🔮 Forecasting capacity"),
    "project_summary": (t_project_summary, "Every project with server count, environments, vCPU / memory GB / disk GB used vs total vs forecast.",
                        {"horizon_days": _p("integer", "Default 180")}, [], "🗂️ Summarising projects"),
    "capacity_history": (t_capacity_history, "Daily average CPU / memory / disk % history for a server, or averaged for a project or the whole fleet — use for trend charts.",
                         {"server": _p("string", "Server name (optional)"), "project": _p("string", "Project (optional)"), "days": _p("integer", "Default 30, max 365")},
                         [], "📊 Loading capacity history"),
    "entra_user": (t_entra_user, "LIVE Microsoft Entra ID lookup of one user: account status, department, sign-in activity, licences, MFA methods, admin roles, groups, Identity Protection risk.",
                   {"user": _p("string", "UPN, email or display name")}, ["user"], "🪪 Looking up the user in Entra ID"),
    "identity_report": (t_identity_report, "Identity lists from the latest Entra collection.",
                        {"topic": _p("string", "Which list", enum=list(IDENTITY_TOPICS)), "contains": _p("string", "Optional text filter"),
                         "limit": _p("integer", "Optional max rows")}, ["topic"], "👥 Querying identity data"),
    "security_report": (t_security_report, "Security lists from the latest Defender / Secure Score / Intune / Identity Protection / M365 health collection. Topics: "
                        "patch_status = per-device patch state (missing update count, months behind, oldest missing) — use for 'which servers are behind on patches'; "
                        "missing_updates = list of updates/KBs with how many devices miss each; vulnerabilities = high/critical CVEs; exploitable_cves = CVEs with public exploits; "
                        "defender_devices = device inventory with exposure, CVE counts, AV; antivirus = AV mode and signature age per device; secure_config = failing configuration checks; "
                        "eos_software = end-of-support software; incidents / alerts = open Defender incidents / alerts; risky_users / risk_detections = Identity Protection; "
                        "secure_score / secure_score_actions; intune_noncompliant / intune_unencrypted; service_health / message_center = Microsoft 365. "
                        "Device topics filter by project and platform (Windows Server, Windows client, Linux, macOS, Mobile).",
                        {"topic": _p("string", "Which list", enum=SECURITY_TOPICS), "project": _p("string", "Optional project"),
                         "platform": _p("string", "Optional platform group"), "severity": _p("string", "Optional severity e.g. high, critical"),
                         "contains": _p("string", "Optional text filter"), "limit": _p("integer", "Optional max rows")}, ["topic"], "🛡️ Querying security data"),
    "defender_device": (t_defender_device, "LIVE Defender drill-down for one device: missing updates (KBs), vulnerabilities (CVEs), failing secure configuration and alerts.",
                        {"device": _p("string", "Device / server name")}, ["device"], "🔬 Querying Defender live"),
    "hunting_query": (t_hunting_query, "Run a read-only Microsoft Defender advanced hunting KQL query (tables: DeviceInfo, DeviceTvmSoftwareVulnerabilities, DeviceTvmSoftwareInventory, DeviceTvmInfoGathering, DeviceTvmSecureConfigurationAssessment, AlertInfo, AlertEvidence, DeviceLogonEvents, DeviceProcessEvents, DeviceNetworkEvents, IdentityLogonEvents…). Use only when other tools cannot answer. Keep queries bounded with summarize/take.",
                      {"kql": _p("string", "KQL query")}, ["kql"], "🧭 Running a Defender hunting query"),
    "teams_incidents": (t_teams_incidents, "Alert incidents from the Teams monitoring channel (repeat alerts merged), active or cleared, filterable by project, server or type (cpu, memory, disk, availability, errors, response_time, gc, network).",
                        {"active": _p("boolean", "true = active (default), false = cleared"), "project": _p("string", "Optional project"),
                         "server": _p("string", "Optional server / target text"), "category": _p("string", "Optional alert type")}, [], "💬 Reading Teams alert incidents"),
    "posture_summary": (t_posture_summary, "Overall security and/or identity posture: health scores, all findings, and every collected summary. Start here for broad 'how are we doing' questions.",
                        {"area": _p("string", "security / identity / all", enum=["security", "identity", "all"])}, [], "🧭 Reading overall posture"),
}


def tool_specs() -> list[dict]:
    return [{"type": "function", "function": {"name": n, "description": d, "parameters": {"type": "object", "properties": props, "required": req}}}
            for n, (_, d, props, req, _) in TOOLS.items()]


# ─────────────────────────────────────────────────────────────────────────────
# Agent loop
# ─────────────────────────────────────────────────────────────────────────────

async def _system_prompt() -> str:
    projects = ", ".join(p["project"] for p in await inv.projects())
    now = datetime.now(GST).strftime("%A %d %B %Y %H:%M")
    org_name = await cfg.get("org.name", "your organisation")
    return f"""You are CloudPulse Assistant, the AI assistant inside CloudPulse — the Windows infrastructure & security operations platform of {org_name}.
Current time: {now} GST (Asia/Dubai). Users are infrastructure, security and identity engineers.

You can see: 241 monitored Windows servers (live metrics & processes from Elastic, daily capacity history, forecasts), the server inventory with projects ({projects}),
Microsoft Entra ID (users, MFA, admins, app secrets, sign-ins, licences, groups), Microsoft Defender XDR (incidents, alerts, devices, vulnerabilities, missing patches,
antivirus, secure configuration), Secure Score, Intune, Identity Protection, Microsoft 365 service health, and Teams alert incidents.

RULES
- Always get facts from tools; never invent servers, processes, numbers, users or dates. If a tool returns an error or no data, say so plainly.
- Earlier answers in this conversation contain NO raw data. For every new question — including follow-ups like "what about the first one?" —
  call the tools again (resolve "the first one" etc. from the conversation, then query it). Only answer without tools for greetings or
  general explanations that need no environment data.
- Call several tools in one step when they are independent. Use the most specific tool; hunting_query only as a last resort.
- You are read-only: you cannot change anything. When useful, recommend concrete next steps.
- Tools that return lists give a dataset_id with a preview; the user sees the FULL dataset only if you place it in your answer:
    [[table:t1]]                         full sortable, exportable table (optionally [[table:t1|cols=server,ip,vcpu]] to choose columns)
    [[chart:t2|type=bar|x=server|y=cpu_avg_pct|title=CPU by server]]   bar or line chart; y may list several numeric columns separated by commas;
                                         y=count counts rows per x value (e.g. servers per project)
  Prefer a table for any list over ~6 rows instead of writing rows yourself. Use charts for rankings and trends (line for dates).
  Only use the marker options shown (cols, type, x, y, title) with column names that exist in that dataset. Filter with tool arguments, not in markers.
- For counts and totals use the tools' total_rows / totals fields — never count preview rows (the preview is only the first rows).
- Answer in concise, well-structured Markdown: a one-line direct answer first, then key numbers (bold), then tables/charts, then brief recommendations.
- Mention data freshness when it matters (live vs. last collection). Use GST times. Keep units explicit (vCPU, GB, %)."""


async def _llm(messages: list[dict], tools: bool = True) -> dict:
    p = await _get_llm_params()
    body = {"model": p["model"], "messages": messages, "max_tokens": max(1500, p["max_tokens"]), "temperature": 0.2,
            "stream": False, "chat_template_kwargs": {"enable_thinking": False}}
    if tools:
        body.update({"tools": tool_specs(), "tool_choice": "auto"})
    async with httpx.AsyncClient(verify=p["ssl_verify"], timeout=httpx.Timeout(240.0, connect=30.0), trust_env=False) as c:
        r = await c.post(f"{p['base_url']}/chat/completions", json=body, headers={"Authorization": f"Bearer {p['api_key']}"})
        r.raise_for_status()
        return r.json()["choices"][0]["message"]


def _summarise_result(res: Any) -> str:
    if isinstance(res, dict):
        if res.get("error"):
            return "⚠️ " + str(res["error"])[:120]
        if "total_rows" in res:
            return f"{res['total_rows']} rows"
        n = sum(v.get("total_rows", 0) for v in res.values() if isinstance(v, dict) and "total_rows" in v)
        return f"{n} rows" if n else "done"
    return "done"


async def run(history: list[dict], user_text: str) -> AsyncIterator[dict]:
    """Yield progress events, then a final {"type": "answer"} event."""
    ds = Datasets()
    messages = [{"role": "system", "content": await _system_prompt()}] + history[-12:] + [{"role": "user", "content": user_text}]
    steps = []
    for step in range(MAX_STEPS):
        try:
            msg = await _llm(messages, tools=True)
        except Exception as e:
            yield {"type": "error", "error": f"AI model unavailable: {e}"}
            return
        calls = msg.get("tool_calls") or []
        if not calls and not steps:
            # Guardrail: an answer with no tool use is only acceptable when no environment data is needed
            check = messages + [{"role": "assistant", "content": msg.get("content") or ""},
                                {"role": "user", "content": "SYSTEM CHECK: you answered without calling any tool. If answering needs ANY data about "
                                 "servers, processes, metrics, capacity, projects, users, security or alerts, call the right tools now. Otherwise reply "
                                 "starting with NO_DATA_NEEDED followed by your answer."}]
            try:
                msg2 = await _llm(check, tools=True)
            except Exception:
                msg2 = {}
            if msg2.get("tool_calls"):
                msg, calls = msg2, msg2["tool_calls"]
            elif (msg2.get("content") or "").lstrip().startswith("NO_DATA_NEEDED"):
                msg = {"content": msg2["content"].lstrip()[len("NO_DATA_NEEDED"):].lstrip(" :\n")}
            else:
                msg = {"content": "I need to look that up but could not determine which data to query — please rephrase with the server, "
                                  "project or user name."}
        if not calls:
            content = msg.get("content") or "I could not produce an answer."
            yield {"type": "answer", "content": content, "datasets": list(ds.items.values()), "steps": steps}
            return
        messages.append({"role": "assistant", "content": msg.get("content") or "", "tool_calls": calls})
        for c in calls:
            name = c["function"]["name"]
            yield {"type": "step", "tool": name, "label": TOOLS.get(name, (None, "", {}, [], name))[4],
                   "args": c["function"].get("arguments")}

        async def exec_call(c: dict) -> tuple[dict, Any]:
            name = c["function"]["name"]
            try:
                args = json.loads(c["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            if name not in TOOLS:
                return c, {"error": f"Unknown tool {name}"}
            fn = TOOLS[name][0]
            try:
                t0 = time.monotonic()
                res = await asyncio.wait_for(fn(ds, **{k: v for k, v in args.items() if v not in (None, "")}), timeout=180)
                log.info("Assistant tool %s(%s) %.1fs", name, json.dumps(args)[:120], time.monotonic() - t0)
                return c, res
            except TypeError as e:
                return c, {"error": f"Bad arguments: {e}"}
            except Exception as e:
                log.warning("Assistant tool %s failed: %s", name, e)
                return c, {"error": str(e)[:300]}

        results = await asyncio.gather(*(exec_call(c) for c in calls))
        for c, res in results:
            body = json.dumps(res, default=str)
            if len(body) > TOOL_RESULT_CHARS:
                body = body[:TOOL_RESULT_CHARS] + '… [truncated — full data is in the datasets]'
            messages.append({"role": "tool", "tool_call_id": c["id"], "content": body})
            steps.append({"tool": c["function"]["name"], "args": c["function"].get("arguments"), "result": _summarise_result(res)})
            yield {"type": "step_done", "tool": c["function"]["name"], "summary": steps[-1]["result"]}
    # Out of steps: ask for a final answer without tools
    messages.append({"role": "user", "content": "Give your final answer now using the data gathered so far."})
    try:
        msg = await _llm(messages, tools=False)
        yield {"type": "answer", "content": msg.get("content") or "", "datasets": list(ds.items.values()), "steps": steps}
    except Exception as e:
        yield {"type": "error", "error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Chat storage
# ─────────────────────────────────────────────────────────────────────────────

async def list_chats(username: str) -> list[dict]:
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(text("""
            SELECT id, title, created_at, updated_at FROM cloudpulse_ai_chats WHERE username = :u ORDER BY updated_at DESC LIMIT 200
        """), {"u": username})).fetchall()
    return [dict(r._mapping) for r in rows]


async def get_chat(chat_id: int, username: str) -> Optional[dict]:
    async with AsyncSessionLocal() as db:
        chat = (await db.execute(text("SELECT id, title FROM cloudpulse_ai_chats WHERE id = :i AND username = :u"),
                                 {"i": chat_id, "u": username})).fetchone()
        if not chat:
            return None
        msgs = (await db.execute(text("""
            SELECT id, role, content, datasets, steps, created_at FROM cloudpulse_ai_messages WHERE chat_id = :i ORDER BY id
        """), {"i": chat_id})).fetchall()
    out = []
    for m in msgs:
        d = dict(m._mapping)
        for k in ("datasets", "steps"):
            if isinstance(d.get(k), str):
                d[k] = json.loads(d[k])
        out.append(d)
    return {"id": chat.id, "title": chat.title, "messages": out}


async def create_chat(username: str, title: str) -> int:
    async with AsyncSessionLocal() as db:
        cid = (await db.execute(text("INSERT INTO cloudpulse_ai_chats (username, title) VALUES (:u, :t) RETURNING id"),
                                {"u": username, "t": title[:200]})).scalar()
        await db.commit()
    return cid


async def add_message(chat_id: int, role: str, content: str, datasets: Optional[list] = None, steps: Optional[list] = None) -> None:
    async with AsyncSessionLocal() as db:
        await db.execute(text("""
            INSERT INTO cloudpulse_ai_messages (chat_id, role, content, datasets, steps)
            VALUES (:c, :r, :t, CAST(:d AS JSONB), CAST(:s AS JSONB))
        """), {"c": chat_id, "r": role, "t": content, "d": json.dumps(datasets or [], default=str), "s": json.dumps(steps or [], default=str)})
        await db.execute(text("UPDATE cloudpulse_ai_chats SET updated_at = NOW() WHERE id = :c"), {"c": chat_id})
        await db.commit()


async def history_for_llm(chat_id: int) -> list[dict]:
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(text("""
            SELECT role, content FROM cloudpulse_ai_messages WHERE chat_id = :c ORDER BY id DESC LIMIT 12
        """), {"c": chat_id})).fetchall()
    # Previous answers reference datasets that no longer exist for the model; strip the markers
    return [{"role": r.role, "content": re.sub(r"\[\[(table|chart):[^\]]*\]\]", "(table shown to user)", r.content or "")}
            for r in reversed(rows)]


async def delete_chat(chat_id: int, username: str) -> bool:
    async with AsyncSessionLocal() as db:
        res = await db.execute(text("DELETE FROM cloudpulse_ai_chats WHERE id = :i AND username = :u RETURNING id"),
                               {"i": chat_id, "u": username})
        ok = res.fetchone() is not None
        await db.commit()
    return ok
