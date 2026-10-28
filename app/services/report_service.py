"""
Report engine for Scheduled Reports.

Every report type builds the same document structure:
    {title, subtitle, category, generated_at, data_as_of, source,
     kpis: [{label, value, sub, tone}], highlights: [str],
     sections: [{title, note, kind: "table"|"bars", columns: [{key, label, kind}], rows, total, empty}]}

One renderer turns a document into a branded HTML report (inline styles, table layout) used
for the in-app viewer, print / PDF and email. Tables can be exported as CSV and are attached
to emails. Due schedules are executed by a scheduler tick guarded by a PostgreSQL lock.
"""
from __future__ import annotations
import asyncio
import csv
import html
import io
import json
import logging
import os
import re
import time
from datetime import date, datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Optional

from sqlalchemy import text

from app.database import AsyncSessionLocal
import app.config as cfg

log = logging.getLogger(__name__)
GST = timezone(timedelta(hours=4))
REPORTS_LOCK_ID = 86940020
LOGO_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "static", "brand", "org-logo.png")
EMAIL_ROW_LIMIT = 50

# ─────────────────────────────────────────────────────────────────────────────
# Catalogue
# ─────────────────────────────────────────────────────────────────────────────

REPORT_TYPES: dict[str, dict] = {
    "capacity_units":       {"label": "Capacity Forecast (vCPU / GB)", "group": "Capacity", "project_filter": True, "server_filter": True,
                             "desc": "Current vs forecast in vCPU, memory GB and disk GB with change and trend arrows — fleet, a project or a server."},
    "project_capacity":     {"label": "Project Capacity Summary", "group": "Capacity",
                             "desc": "Every project's servers, vCPU, memory and disk — used now vs 6-month forecast."},
    "fleet_summary":        {"label": "Fleet Capacity Summary", "group": "Capacity", "project_filter": True,
                             "desc": "Fleet-wide CPU / memory / disk averages, 12-month forecast and current hotspots."},
    "capacity_risk":        {"label": "Capacity Risk Forecast", "group": "Capacity", "project_filter": True,
                             "desc": "Servers forecast to cross 80% / 90% within 180 days, ranked by risk."},
    "server_detail":        {"label": "Server Detail", "group": "Capacity", "needs_server": True,
                             "desc": "Forecast, current utilisation and disk volumes for one server."},
    "jira_summary":         {"label": "Jira Ticket Summary", "group": "Operations",
                             "desc": "Tickets raised from CloudPulse by status and SR type."},
    "teams_incidents":      {"label": "Teams Alert Incidents", "group": "Operations", "project_filter": True,
                             "desc": "Active and recently cleared incidents from the Teams alert channel."},
    "sec_posture":          {"label": "Security Posture — Executive Summary", "group": "Security",
                             "desc": "Secure Score and trend, security findings, top improvement actions."},
    "sec_incidents":        {"label": "Defender Incidents", "group": "Security",
                             "desc": "Open Microsoft Defender XDR incidents by severity, ownership and affected assets."},
    "sec_patching":         {"label": "Patch Compliance", "group": "Security", "project_filter": True,
                             "desc": "Missing security updates by platform and device, months behind, top missing updates."},
    "sec_vulns":            {"label": "Vulnerability Exposure", "group": "Security", "project_filter": True,
                             "desc": "Exploitable and critical CVEs, and the devices most exposed."},
    "sec_av":               {"label": "Antivirus Health", "group": "Security", "project_filter": True,
                             "desc": "Defender Antivirus mode, outdated signatures / engine / platform per device."},
    "sec_intune":           {"label": "Intune Compliance", "group": "Security",
                             "desc": "Non-compliant, unencrypted and stale Intune-managed devices."},
    "sec_risky":            {"label": "Identity Risk", "group": "Security",
                             "desc": "Entra ID Protection risky users and risk detections."},
    "sec_service":          {"label": "Microsoft 365 Service Health & Changes", "group": "Security",
                             "desc": "Active service incidents / advisories and message-center items needing action."},
    "ad_executive":         {"label": "Identity Health — Executive Summary", "group": "Identity (Entra ID)",
                             "desc": "Identity health score, key metrics and every open finding."},
    "ad_disabled_licensed": {"label": "Disabled Accounts Holding Licences", "group": "Identity (Entra ID)",
                             "desc": "Disabled accounts that still consume paid licences — reclaim list."},
    "ad_inactive_accounts": {"label": "Inactive & Never-Used Accounts", "group": "Identity (Entra ID)",
                             "desc": "Enabled accounts with no sign-in beyond the stale threshold, and accounts never used."},
    "ad_devices":           {"label": "Device Inventory & Hygiene", "group": "Identity (Entra ID)",
                             "desc": "Device platforms and join types, stale and non-compliant devices."},
    "ad_mfa":               {"label": "MFA Status Report", "group": "Identity (Entra ID)",
                             "desc": "Per-user MFA state (Disabled / Enabled / Enforced), users and admins without MFA — mailbox users only."},
    "ad_mfa_not_enrolled":  {"label": "MFA Enabled — Not Enrolled", "group": "Identity (Entra ID)",
                             "desc": "Users with MFA enabled (system-preferred / per-user / policy) but no method enrolled — follow-up list for the service desk."},
    "ad_privileged":        {"label": "Privileged Access Review", "group": "Identity (Entra ID)",
                             "desc": "Directory role assignments, Global Admins and recent role changes."},
    "ad_app_secrets":       {"label": "App Secrets & Certificates Expiry", "group": "Identity (Entra ID)",
                             "desc": "App registration credentials expired or expiring soon."},
    "ad_guests":            {"label": "Guest Accounts Review", "group": "Identity (Entra ID)",
                             "desc": "External guest accounts with invitation state and last sign-in."},
    "ad_licences":          {"label": "Licence Utilisation", "group": "Identity (Entra ID)",
                             "desc": "Purchased vs assigned licences per SKU, unused and over-assigned seats."},
    "ad_signins":           {"label": "Failed Sign-in Analysis", "group": "Identity (Entra ID)",
                             "desc": "Failed sign-ins by account, IP, reason and country."},
}


def catalogue() -> list[dict]:
    return [{"id": k, **v} for k, v in REPORT_TYPES.items()]


# ─────────────────────────────────────────────────────────────────────────────
# Document helpers
# ─────────────────────────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(GST)


def col(key: str, label: str, kind: str = "text", **kw) -> dict:
    return {"key": key, "label": label, "kind": kind, **kw}


def kpi(label: str, value: Any, sub: str = "", tone: str = "neutral") -> dict:
    return {"label": label, "value": value, "sub": sub, "tone": tone}


def table(title: str, columns: list[dict], rows: list[dict], note: str = "", empty: str = "Nothing to report.",
          cap: int = 3000) -> dict:
    return {"title": title, "kind": "table", "note": note, "columns": columns, "rows": rows[:cap],
            "total": len(rows), "empty": empty}


def bars(title: str, items: list[dict], note: str = "", unit: str = "") -> dict:
    """items: [{name, count}] → horizontal bars."""
    return {"title": title, "kind": "bars", "note": note, "unit": unit,
            "rows": [{"label": i.get("name"), "value": i.get("count")} for i in items], "total": len(items)}


def doc(rtype: str, title: str, subtitle: str = "", kpis: list[dict] = None, sections: list[dict] = None,
        highlights: list[str] = None, data_as_of: Any = None, source: str = "") -> dict:
    return {
        "version": 2, "type": rtype, "title": title, "subtitle": subtitle,
        "category": REPORT_TYPES.get(rtype, {}).get("group", ""),
        "generated_at": _now().isoformat(),
        "data_as_of": data_as_of.isoformat() if isinstance(data_as_of, datetime) else data_as_of,
        "source": source, "kpis": kpis or [], "highlights": highlights or [], "sections": sections or [],
    }


def _tone(value: Optional[float], warn: float, crit: float, higher_is_bad: bool = True) -> str:
    if value is None:
        return "neutral"
    if higher_is_bad:
        return "crit" if value >= crit else "warn" if value >= warn else "ok"
    return "crit" if value <= crit else "warn" if value <= warn else "ok"


def _n(v: Any) -> str:
    return "—" if v is None else f"{v:,}" if isinstance(v, int) else f"{v:,.1f}" if isinstance(v, float) else str(v)


# ─────────────────────────────────────────────────────────────────────────────
# Builders — Capacity
# ─────────────────────────────────────────────────────────────────────────────

async def _latest_capacity(limit: int = 15) -> tuple[Optional[date], dict[str, list[dict]], list[dict]]:
    async with AsyncSessionLocal() as db:
        day = (await db.execute(text("SELECT MAX(report_date) FROM cloudpulse_capacity_daily"))).scalar()
        if not day:
            return None, {}, []
        rows = (await db.execute(text("""
            SELECT server_name, avg_cpu_pct, max_cpu_pct, avg_mem_pct, max_mem_pct, avg_disk_pct, max_disk_pct,
                   total_mem_gb, total_disk_gb, free_disk_gb, os_name, host_ip
            FROM cloudpulse_capacity_daily WHERE report_date = :d
        """), {"d": day})).fetchall()
    data = [{k: (float(v) if hasattr(v, "is_finite") else v) for k, v in r._mapping.items()} for r in rows]
    top = {m: sorted(data, key=lambda r: -(r.get(f"avg_{m}_pct") or 0))[:limit] for m in ("cpu", "mem", "disk")}
    return day, top, data


async def _with_projects(rows: list[dict], key: str, filters: dict) -> list[dict]:
    """Tag rows with their inventory project; keep only the requested project when filters['project'] is set."""
    from app.services import inventory_service as inv
    lookup = await inv.project_lookup()
    for r in rows:
        r["project"] = (lookup.get(inv.key_of(r.get(key) or "")) or {}).get("project", "Unassigned")
    want = (filters or {}).get("project")
    return [r for r in rows if r["project"] == want] if want else rows


async def build_fleet_summary(filters: dict) -> dict:
    from app.services import prediction_service as ps
    f = await ps.get_fleet_forecast(365, 90)
    risk = await ps.get_capacity_risk_report(180)
    day, top, data = await _latest_capacity(15)
    data = await _with_projects(data, "server_name", filters)
    top = {m_: sorted(data, key=lambda r: -(r.get(f"avg_{m_}_pct") or 0))[:15] for m_ in ("cpu", "mem", "disk")}
    m = f.get("metrics", {})
    names = {"cpu": "CPU", "memory": "Memory", "disk": "Disk"}

    def at(metric: str, d: int) -> Optional[float]:
        fc = m.get(metric, {}).get("forecast") or []
        return round(fc[d - 1], 1) if len(fc) >= d else None

    outlook = [{"metric": names[k], "current": v.get("current_value"), "trend": v.get("trend"),
                "slope": v.get("slope_per_day"), "d30": at(k, 30), "d90": at(k, 90), "d180": at(k, 180),
                "d365": at(k, 365), "to80": v.get("days_to_80"), "to90": v.get("days_to_90"),
                "r2": v.get("r_squared")} for k, v in m.items()]
    rc = risk.get("risk_counts", {})
    if filters.get("project"):
        scoped = await _with_projects(risk.get("servers_at_risk", []), "server", filters)
        rc = {lvl: sum(1 for x in scoped if x.get("risk_level") == lvl) for lvl in ("critical", "high", "medium", "low")}
    hot = sorted(data, key=lambda r: -max(r.get("max_cpu_pct") or 0, r.get("avg_mem_pct") or 0, r.get("max_disk_pct") or 0))[:25]
    highlights = []
    for o in outlook:
        if o["to90"] is not None:
            highlights.append(f"Fleet {o['metric']} is forecast to reach 90% in {o['to90']} days.")
    highlights.append(f"{rc.get('critical', 0)} critical and {rc.get('high', 0)} high capacity risks across the fleet (180-day horizon).")
    if hot:
        h = hot[0]
        highlights.append(f"Hottest server: {h['server_name']} — CPU peak {_n(h.get('max_cpu_pct'))}%, memory {_n(h.get('avg_mem_pct'))}%, worst disk {_n(h.get('max_disk_pct'))}%.")

    col_of = {"cpu": "avg_cpu_pct", "memory": "avg_mem_pct", "disk": "avg_disk_pct"}

    def mk(metric: str) -> dict:
        if filters.get("project"):   # averages over the project's servers (latest day)
            vals = [r.get(col_of[metric]) for r in data if r.get(col_of[metric]) is not None]
            avg = round(sum(vals) / len(vals), 1) if vals else None
            return kpi(f"Project avg {names[metric]}", f"{_n(avg)}%", f"{len(vals)} servers", _tone(avg, 70, 85))
        v = m.get(metric, {})
        return kpi(f"Fleet avg {names[metric]}", f"{_n(v.get('current_value'))}%", f"trend {v.get('trend', '—')}",
                   _tone(v.get("current_value"), 70, 85))

    srv_cols = [col("server_name", "Server", "mono"), col("project", "Project"), col("os_name", "OS"),
                col("avg_cpu_pct", "CPU avg", "pct", warn=80, crit=90), col("max_cpu_pct", "CPU peak", "pct", warn=80, crit=90),
                col("avg_mem_pct", "Memory", "pct", warn=85, crit=95), col("max_disk_pct", "Worst disk", "pct", warn=80, crit=90)]
    return doc("fleet_summary", "Fleet Capacity Summary" + (f" — {filters['project']}" if filters.get("project") else ""),
               f"{len(data)} Windows servers · daily averages for {day}" if day else "No capacity data",
               kpis=[kpi("Servers monitored", len(data)), mk("cpu"), mk("memory"), mk("disk"),
                     kpi("Critical risks", rc.get("critical", 0), "180-day horizon", "crit" if rc.get("critical") else "ok"),
                     kpi("High risks", rc.get("high", 0), "180-day horizon", "warn" if rc.get("high") else "ok")],
               highlights=highlights, data_as_of=str(day) if day else None, source="CloudPulse capacity database",
               sections=[
                   table("12-month forecast outlook", [
                       col("metric", "Metric"), col("current", "Current %", "num1"), col("trend", "Trend", "badge"),
                       col("slope", "Change / day", "num2"), col("d30", "In 30 d", "num1"), col("d90", "In 90 d", "num1"),
                       col("d180", "In 180 d", "num1"), col("d365", "In 365 d", "num1"),
                       col("to80", "Days to 80%", "num"), col("to90", "Days to 90%", "num"), col("r2", "Fit (R²)", "num2")],
                       outlook, note="Linear regression over up to 90 days of daily fleet averages."),
                   table("Hotspots — top 25 servers by worst metric", srv_cols, hot),
                   table("Top 15 by CPU", srv_cols, top.get("cpu", [])),
                   table("Top 15 by memory", srv_cols, top.get("mem", [])),
                   table("Top 15 by disk", srv_cols, top.get("disk", [])),
               ])


async def build_capacity_risk(filters: dict) -> dict:
    from app.services import prediction_service as ps
    r = await ps.get_capacity_risk_report(180)
    rows = await _with_projects(r.get("servers_at_risk", []), "server", filters)
    rc = {lvl: sum(1 for x in rows if x.get("risk_level") == lvl) for lvl in ("critical", "high", "medium", "low")}
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rows = sorted(rows, key=lambda x: (order.get(x.get("risk_level"), 9), x.get("days_to_90") if x.get("days_to_90") is not None else 9999))
    for x in rows:
        x["metric_label"] = {"cpu": "CPU", "memory": "Memory", "disk": "Disk"}.get(x.get("metric"), x.get("metric"))
    cols = [col("server", "Server", "mono"), col("project", "Project"), col("metric_label", "Metric"), col("current_pct", "Current", "pct", warn=80, crit=90),
            col("trend", "Trend", "badge"), col("days_to_80", "Days to 80%", "num"), col("days_to_90", "Days to 90%", "num"),
            col("slope_per_day", "Change / day", "num2"), col("r_squared", "Fit (R²)", "num2"), col("risk_level", "Risk", "badge")]
    urgent = [x for x in rows if x.get("risk_level") in ("critical", "high")]
    return doc("capacity_risk", "Capacity Risk Forecast" + (f" — {filters['project']}" if filters.get("project") else ""), "Servers forecast to cross 80% / 90% utilisation within 180 days",
               kpis=[kpi("Critical", rc.get("critical", 0), "already ≥ 90% or within 30 d", "crit" if rc.get("critical") else "ok"),
                     kpi("High", rc.get("high", 0), "≥ 90% within 90 d", "warn" if rc.get("high") else "ok"),
                     kpi("Medium", rc.get("medium", 0), "≥ 90% within 180 d"),
                     kpi("Low", rc.get("low", 0), "watch list"),
                     kpi("Servers assessed", len({x.get('server') for x in rows}))],
               highlights=[f"{x['server']} — {x['metric_label']} at {_n(x.get('current_pct'))}%, {x.get('trend')}, "
                           f"90% in {x.get('days_to_90') if x.get('days_to_90') is not None else 'n/a'} days" for x in urgent[:5]],
               source="CloudPulse capacity forecasts", data_as_of=r.get("generated_at"),
               sections=[table("Critical & high risk", cols, urgent, empty="No critical or high risks."),
                         table("Medium & low risk", cols, [x for x in rows if x.get("risk_level") not in ("critical", "high")])])


async def build_server_detail(filters: dict) -> dict:
    from app.services import prediction_service as ps
    srv = (filters or {}).get("server_name")
    if not srv:
        raise ValueError("Server Detail needs a server name")
    f = await ps.get_server_forecast(srv, 365, 90)
    from app.services import capacity_forecast as cf
    units_rows = _units_rows(await cf.forecast("server", srv, 90, 180))
    async with AsyncSessionLocal() as db:
        row = (await db.execute(text("""
            SELECT report_date, avg_cpu_pct, max_cpu_pct, avg_mem_pct, max_mem_pct, total_mem_gb, used_mem_gb,
                   avg_disk_pct, max_disk_pct, total_disk_gb, used_disk_gb, free_disk_gb, disk_details, os_name, host_ip
            FROM cloudpulse_capacity_daily WHERE server_name = :s ORDER BY report_date DESC LIMIT 1
        """), {"s": srv})).fetchone()
    cur = dict(row._mapping) if row else {}
    cur = {k: (float(v) if hasattr(v, "is_finite") else v) for k, v in cur.items()}
    disks = cur.get("disk_details") or []
    if isinstance(disks, str):
        disks = json.loads(disks)
    m = f.get("metrics", {})
    names = {"cpu": "CPU", "memory": "Memory", "disk": "Disk"}

    def at(metric: str, d: int):
        fc = m.get(metric, {}).get("forecast") or []
        return round(fc[d - 1], 1) if len(fc) >= d else None

    outlook = [{"metric": names[k], "current": v.get("current_value"), "trend": v.get("trend"),
                "slope": v.get("slope_per_day"), "d30": at(k, 30), "d90": at(k, 90), "d365": at(k, 365),
                "to80": v.get("days_to_80"), "to90": v.get("days_to_90"), "r2": v.get("r_squared")} for k, v in m.items()]
    return doc("server_detail", f"Server Detail — {srv}",
               " · ".join(filter(None, [cur.get("os_name"), cur.get("host_ip"), f"data for {cur.get('report_date')}" if cur else "no data"])),
               kpis=[kpi("CPU avg / peak", f"{_n(cur.get('avg_cpu_pct'))}% / {_n(cur.get('max_cpu_pct'))}%", "", _tone(cur.get("max_cpu_pct"), 80, 90)),
                     kpi("Memory", f"{_n(cur.get('avg_mem_pct'))}%", f"{_n(cur.get('used_mem_gb'))} of {_n(cur.get('total_mem_gb'))} GB", _tone(cur.get("avg_mem_pct"), 85, 95)),
                     kpi("Worst disk", f"{_n(cur.get('max_disk_pct'))}%", f"{_n(cur.get('free_disk_gb'))} GB free of {_n(cur.get('total_disk_gb'))} GB", _tone(cur.get("max_disk_pct"), 80, 90))],
               source="CloudPulse capacity database", data_as_of=str(cur.get("report_date")) if cur else None,
               sections=[
                   table("Forecast in vCPU / GB", [col("metric", "Resource"), col("capacity", "Capacity", "num1"),
                         col("current", "Used now", "num1"), col("current_pct", "Used %", "pct", warn=80, crit=90)]
                         + [col(f"d{h}", f"In {h} d", "fc") for h in (30, 90, 180, 365)]
                         + [col("days_to_90", "Days to 90%", "num")], units_rows),
                   table("Forecast (%)", [col("metric", "Metric"), col("current", "Current %", "num1"), col("trend", "Trend", "badge"),
                                      col("slope", "Change / day", "num2"), col("d30", "In 30 d", "num1"), col("d90", "In 90 d", "num1"),
                                      col("d365", "In 365 d", "num1"), col("to80", "Days to 80%", "num"), col("to90", "Days to 90%", "num"),
                                      col("r2", "Fit (R²)", "num2")], outlook),
                   table("Disk volumes", [col("mount", "Volume", "mono"), col("total_gb", "Size GB", "num1"), col("used_gb", "Used GB", "num1"),
                                          col("free_gb", "Free GB", "num1"), col("used_pct", "Used", "pct", warn=80, crit=90)], disks,
                         empty="No disk details recorded."),
               ])



# ─────────────────────────────────────────────────────────────────────────────
# Builders — Capacity in units (vCPU / GB) and projects
# ─────────────────────────────────────────────────────────────────────────────

_UNIT_NAMES = {"cpu": "CPU (vCPU)", "memory": "Memory (GB)", "disk": "Disk (GB)"}


def _units_rows(f: dict) -> list[dict]:
    rows = []
    for m, v in f["metrics"].items():
        row = {"metric": _UNIT_NAMES[m], "capacity": v.get("capacity"), "current": v.get("current"),
               "current_pct": v.get("current_pct"), "free": v.get("free"),
               "days_to_90": v.get("days_to_90"), "days_to_full": v.get("days_to_full")}
        for fc in v.get("forecast", []):
            k = f"d{fc['days']}"
            row.update({k: fc["value"], f"{k}_delta": fc["delta"], f"{k}_dir": fc["direction"], f"{k}_pct": fc["pct"]})
        rows.append(row)
    return rows


def _units_kpis(f: dict, horizon: int) -> list[dict]:
    out = [kpi("Servers", f.get("servers")),
           kpi("History used", f"{f.get('history_days', 0)} days", f"confidence: {f.get('confidence', 'low')}",
               "ok" if f.get("confidence") == "high" else "warn" if f.get("confidence") == "low" else "neutral")]
    for m, v in f["metrics"].items():
        fc = next((x for x in v.get("forecast", []) if x["days"] == horizon), None)
        arrow = {"up": "▲", "down": "▼"}.get(fc["direction"], "▶") if fc else ""
        sub = f"{v.get('current_pct') or 0:.0f}% used · {horizon} d: {fc['value']:,.0f} {arrow} {fc['delta']:+,.0f}" if fc else ""
        out.append(kpi(_UNIT_NAMES[m], f"{v.get('current', 0):,.0f} / {v.get('capacity', 0):,.0f}", sub,
                       _tone(fc["pct"] if fc else v.get("current_pct"), 80, 90)))
    return out


async def build_capacity_units(filters: dict) -> dict:
    from app.services import capacity_forecast as cf
    horizon = int(filters.get("horizon") or 180)
    if filters.get("server_name"):
        scope, name = "server", filters["server_name"]
    elif filters.get("project"):
        scope, name = "project", filters["project"]
    else:
        scope, name = "fleet", None
    f = await cf.forecast(scope, name, 90, horizon)
    hz_cols = [col(f"d{h}", f"In {h} d", "fc") for h in cf.HORIZONS]
    highlights = []
    if not f.get("trend_available"):
        highlights.append(f"Trends need at least {f.get('min_trend_days', 14)} days of history — forecasts are held at today's values until then.")
    for m, v in f["metrics"].items():
        fc = next((x for x in v.get("forecast", []) if x["days"] == horizon), None)
        if fc and fc["direction"] != "flat":
            highlights.append(f"{_UNIT_NAMES[m]}: {v['current']:,.1f} now → {fc['value']:,.1f} in {horizon} days "
                              f"({'▲' if fc['direction'] == 'up' else '▼'} {fc['delta']:+,.1f}, {fc['pct']:.0f}% of {v['capacity']:,.0f}).")
        if v.get("days_to_90") is not None and v["days_to_90"] <= 365:
            highlights.append(f"{_UNIT_NAMES[m]} reaches 90% of capacity in about {v['days_to_90']} days.")
    sections = [table(f"Forecast by horizon — {f['title']}",
                      [col("metric", "Resource"), col("capacity", "Capacity", "num1"), col("current", "Used now", "num1"),
                       col("current_pct", "Used %", "pct", warn=80, crit=90)] + hz_cols +
                      [col("days_to_90", "Days to 90%", "num"), col("days_to_full", "Days to full", "num")],
                      _units_rows(f), note="Usage is capped at installed capacity; ▲ / ▼ show the change from today."),
                table("Daily history (used)", [col("date", "Date", "date"), col("cpu", "CPU (vCPU)", "num1"),
                                               col("memory", "Memory (GB)", "num1"), col("disk", "Disk (GB)", "num1")],
                      list(reversed(f.get("history", [])))[:60])]
    if f.get("server_rows"):
        srv_cols = [col("server", "Server", "mono"), col("project", "Project"), col("environment", "Env"),
                    col("cpu", "CPU vCPU · now → forecast / cap", "nowfc", metric="cpu"),
                    col("memory", "Memory GB · now → forecast / cap", "nowfc", metric="memory"),
                    col("disk", "Disk GB · now → forecast / cap", "nowfc", metric="disk"),
                    col("pressure", "Peak forecast %", "pct", warn=80, crit=90)]
        sections.insert(1, table(f"Servers under most pressure in {horizon} days", srv_cols, f["server_rows"][:60],
                                 note="Ranked by the highest forecast utilisation across CPU, memory and disk."))
    return doc("capacity_units", "Capacity Forecast (vCPU / GB)",
               f"{f['title']} · {f.get('servers', 0)} servers · {horizon}-day outlook",
               kpis=_units_kpis(f, horizon), highlights=highlights, data_as_of=f.get("last_day"),
               source="CloudPulse capacity history + server inventory", sections=sections)


async def build_project_capacity(filters: dict) -> dict:
    from app.services import capacity_forecast as cf
    horizon = int(filters.get("horizon") or 180)
    p = await cf.projects_summary(90, horizon)
    rows = p["projects"]
    for r in rows:
        r["envs"] = ", ".join(r.get("environments") or [])
        r["pressure"] = max(r.get("cpu_pct_fc") or 0, r.get("memory_pct_fc") or 0, r.get("disk_pct_fc") or 0)
    tot = lambda k: sum(r.get(k) or 0 for r in rows)
    return doc("project_capacity", "Project Capacity Summary", f"Used now vs {horizon}-day forecast for every project",
               kpis=[kpi("Projects", len(rows)), kpi("Servers", tot("servers")),
                     kpi("vCPU", f"{tot('cpu_now'):,.0f} / {tot('cpu_cap'):,.0f}", "used / installed"),
                     kpi("Memory GB", f"{tot('memory_now'):,.0f} / {tot('memory_cap'):,.0f}", "used / installed"),
                     kpi("Disk GB", f"{tot('disk_now'):,.0f} / {tot('disk_cap'):,.0f}", "used / installed")],
               highlights=[f"{r['project']}: peak forecast {r['pressure']:.0f}% of capacity in {horizon} days." for r in
                           sorted(rows, key=lambda r: -r["pressure"])[:3] if r["pressure"] >= 70],
               source="CloudPulse capacity history + server inventory", sections=[
                   bars("Servers per project", [{"name": r["project"], "count": r["servers"]} for r in rows]),
                   table("Projects", [col("project", "Project"), col("servers", "Servers", "num"), col("envs", "Environments"),
                                      col("cpu", "CPU vCPU · now → forecast / cap", "nowfc", metric="cpu"),
                                      col("memory", "Memory GB · now → forecast / cap", "nowfc", metric="memory"),
                                      col("disk", "Disk GB · now → forecast / cap", "nowfc", metric="disk"),
                                      col("confidence", "Confidence", "badge")], rows,
                         note="Projects come from Admin → Server Inventory (pre-filled from the Elastic namespace)."),
               ])


# ─────────────────────────────────────────────────────────────────────────────
# Builders — Security (Defender, Secure Score, Identity Protection, Intune, service health)
# ─────────────────────────────────────────────────────────────────────────────

_SEC_SRC = "Microsoft Defender XDR / Entra ID / Intune via Microsoft Graph"


def _dev_filter(rows: list[dict], filters: dict) -> list[dict]:
    p = (filters or {}).get("project")
    return [r for r in rows if r.get("project") == p] if p else rows


def _suffix(filters: dict) -> str:
    return f" — {filters['project']}" if (filters or {}).get("project") else ""


async def build_sec_posture(filters: dict) -> dict:
    from app.services import ad_service, security_service as sec
    snaps = await ad_service.load_snapshots()
    items = await sec.findings({k: v for k, v in snaps.items() if k in sec.SECTIONS or k == "tenant"})
    sc, asof = await _snap("sec_score")
    d = {k: ((v.get("data") or {}).get("summary") or {}) for k, v in snaps.items()}
    s, th, rk, dv, it = sc.get("summary", {}), d.get("sec_threats", {}), d.get("sec_risk", {}), d.get("sec_devices", {}), d.get("sec_intune", {})
    score = ad_service.health_score(items)
    weekly = (sc.get("trend") or [])[::7]
    return doc("sec_posture", "Security Posture — Executive Summary", "Microsoft Secure Score, Defender, Entra ID Protection and Intune",
               kpis=[kpi("Security health", f"{score}/100", "Healthy" if score >= 85 else "Needs attention" if score >= 60 else "At risk", _tone(score, 85, 60, False)),
                     kpi("Secure Score", f"{s.get('pct', '—')}%", f"{s.get('current', 0):,.0f} / {s.get('max', 0):,.0f} · 30 d {s.get('change_30d', 0):+}", _tone(s.get("pct"), 70, 50, False)),
                     kpi("Open incidents", th.get("incidents_open"), f"{th.get('incidents_open_high', 0)} high · {th.get('incidents_unassigned', 0)} unassigned", "crit" if th.get("incidents_open_high") else "ok"),
                     kpi("Risky users", rk.get("at_risk"), f"{rk.get('high', 0)} high", "crit" if rk.get("high") else "warn" if rk.get("at_risk") else "ok"),
                     kpi("Exploitable devices", dv.get("with_exploitable"), f"{dv.get('exploitable_cves', 0)} CVEs", "warn" if dv.get("with_exploitable") else "ok"),
                     kpi("Servers behind on patches", dv.get("servers_behind_2m"), f"of {dv.get('windows_servers', 0)} Windows servers", "warn" if dv.get("servers_behind_2m") else "ok"),
                     kpi("AV signatures outdated", dv.get("av_sig_outdated"), "", "warn" if dv.get("av_sig_outdated") else "ok"),
                     kpi("Intune compliance", f"{it.get('compliance_pct', '—')}%", f"{it.get('noncompliant', 0)} non-compliant")],
               highlights=[f"{f['title']} — {f['detail']}" for f in items if f["severity"] == "critical"][:6],
               data_as_of=asof, source=_SEC_SRC, sections=[
                   table("Findings", [col("severity", "Severity", "badge"), col("title", "Finding"), col("detail", "Detail")], items, empty="No security findings."),
                   table("Top improvement actions", [col("title", "Action"), col("category", "Category"), col("service", "Service"),
                         col("gain", "Points available", "num1"), col("pct", "Achieved", "pct", warn=101, crit=102), col("cost", "Cost"), col("user_impact", "User impact")],
                         [a for a in sc.get("actions", []) if a["status"] != "Completed"][:20]),
                   table("Secure Score trend (weekly)", [col("date", "Date", "date"), col("score", "Score", "num1"), col("max", "Max", "num1"), col("pct", "Score %", "pct", warn=101, crit=102)],
                         list(reversed(weekly))),
               ])


async def build_sec_incidents(filters: dict) -> dict:
    t, asof = await _snap("sec_threats")
    s = t.get("summary", {})
    open_i = [i for i in t.get("incidents", []) if i["status"] != "resolved"]
    for i in open_i:
        i["devices_txt"], i["users_txt"] = ", ".join(i["devices"][:5]), ", ".join(i["users"][:5])
    cols = [col("id", "ID", "mono"), col("name", "Incident"), col("severity", "Severity", "badge"), col("status", "Status"), col("alerts", "Alerts", "num"),
            col("devices_txt", "Devices"), col("users_txt", "Users"), col("assigned", "Assigned to"), col("updated", "Updated", "datetime")]
    from collections import Counter
    return doc("sec_incidents", "Defender Incidents", "Open Microsoft Defender XDR incidents (updated in the last 30 days)",
               kpis=[kpi("Open incidents", s.get("incidents_open"), f"{s.get('incidents_30d', 0)} updated in 30 d", "warn" if s.get("incidents_open") else "ok"),
                     kpi("High severity", s.get("incidents_open_high"), "", "crit" if s.get("incidents_open_high") else "ok"),
                     kpi("Unassigned", s.get("incidents_unassigned"), "no owner", "warn" if s.get("incidents_unassigned") else "ok"),
                     kpi("Open alerts", f"{s.get('alerts_open', 0):,}{'+' if s.get('alerts_capped') else ''}", f"{s.get('alerts_open_high', 0):,} high"),
                     kpi("Devices in alerts", s.get("devices_in_alerts")), kpi("Users in alerts", s.get("users_in_alerts"))],
               data_as_of=asof, source=_SEC_SRC, sections=[
                   bars("Open incidents by severity", [{"name": k, "count": v} for k, v in Counter(i["severity"] for i in open_i).most_common()]),
                   bars("Open alerts by detection source", t.get("by_source", [])),
                   table("High-severity open incidents", cols, [i for i in open_i if i["severity"] == "high"], empty="No high-severity incidents open."),
                   table("All open incidents", cols, open_i),
               ])


_UPD_COLS = [col("name", "Update"), col("id", "KB / ID", "mono"), col("devices", "Devices", "num"), col("cves", "CVEs fixed", "num"),
             col("critical", "Critical", "num"), col("platforms_txt", "Platforms")]


async def build_sec_patching(filters: dict) -> dict:
    d, asof = await _snap("sec_devices")
    dv = _dev_filter(d.get("devices", []), filters)
    for r in dv:
        r["updates_txt"] = "; ".join(r.get("updates") or [])
    groups = {}
    for r in dv:
        g = groups.setdefault(r["group"], {"group": r["group"], "devices": 0, "up": 0, "missing": 0, "behind": 0, "critical": 0})
        g["devices"] += 1; g["up"] += 0 if r["missing_updates"] else 1; g["missing"] += 1 if r["missing_updates"] else 0
        g["behind"] += 1 if r["months_behind"] >= 2 else 0; g["critical"] += 1 if r["critical"] else 0
    for g in groups.values():
        g["pct"] = round(100 * g["up"] / g["devices"], 1) if g["devices"] else None
    ws = [r for r in dv if r["group"] == "Windows Server"]
    names = {r["name"] for r in dv}
    ups = [u for u in d.get("updates", []) if not filters.get("project") or set(u.get("device_names") or []) & names]
    for u in ups:
        u["platforms_txt"] = ", ".join(u.get("platforms") or [])
    dcols = [col("name", "Device", "mono"), col("group", "Platform"), col("project", "Project"), col("missing_updates", "Missing updates", "num"),
             col("months_behind", "Months behind", "num"), col("oldest_missing", "Oldest missing", "mono"), col("critical", "Critical CVEs", "num"),
             col("exploitable", "Exploitable", "num"), col("updates_txt", "Updates")]
    return doc("sec_patching", "Patch Compliance" + _suffix(filters), f"Latest Microsoft update month: {d.get('summary', {}).get('latest_update_month', '—')}",
               kpis=[kpi("Devices", len(dv)),
                     kpi("Windows servers fully patched", f"{sum(1 for r in ws if not r['missing_updates'])} / {len(ws)}", "",
                         _tone(100 * sum(1 for r in ws if not r['missing_updates']) / max(1, len(ws)), 90, 70, False)),
                     kpi("Windows servers 2+ months behind", sum(1 for r in ws if r["months_behind"] >= 2), "", "warn" if any(r["months_behind"] >= 2 for r in ws) else "ok"),
                     kpi("Devices missing updates", sum(1 for r in dv if r["missing_updates"]), "all platforms"),
                     kpi("Devices with critical CVEs", sum(1 for r in dv if r["critical"]), "", "crit" if any(r["critical"] for r in dv) else "ok")],
               data_as_of=asof, source=_SEC_SRC, sections=[
                   table("Patch status by platform", [col("group", "Platform"), col("devices", "Devices", "num"), col("pct", "Fully patched", "pct", warn=101, crit=102),
                         col("missing", "Missing updates", "num"), col("behind", "2+ months behind", "num"), col("critical", "With critical CVEs", "num")],
                         sorted(groups.values(), key=lambda g: -g["devices"])),
                   table("Windows servers behind on updates", dcols, sorted([r for r in ws if r["missing_updates"]], key=lambda r: -r["months_behind"]),
                         empty="All Windows servers are fully patched."),
                   table("Top missing updates", _UPD_COLS, ups[:40]),
                   table("All devices missing updates", dcols, sorted([r for r in dv if r["missing_updates"]], key=lambda r: (-r["months_behind"], -r["critical"]))),
               ])


async def build_sec_vulns(filters: dict) -> dict:
    d, asof = await _snap("sec_devices")
    dv = _dev_filter(d.get("devices", []), filters)
    cves = d.get("cves", [])
    for c in cves:
        c["software_txt"], c["fix_txt"] = ", ".join(c.get("software") or []), ", ".join(c.get("fix") or [])
    ccols = [col("cve", "CVE", "mono"), col("severity", "Severity", "badge"), col("cvss", "CVSS", "num1"), col("exploit", "Exploit", "bool"),
             col("devices", "Devices", "num"), col("software_txt", "Software"), col("fix_txt", "Fix"), col("published", "Published", "date")]
    return doc("sec_vulns", "Vulnerability Exposure" + _suffix(filters), "High and critical vulnerabilities from Defender Vulnerability Management",
               kpis=[kpi("Devices", len(dv)), kpi("With critical CVEs", sum(1 for r in dv if r["critical"]), "", "crit" if any(r["critical"] for r in dv) else "ok"),
                     kpi("With exploitable CVEs", sum(1 for r in dv if r["exploitable"]), "", "warn" if any(r["exploitable"] for r in dv) else "ok"),
                     kpi("Exploitable CVEs (tenant)", sum(1 for c in cves if c["exploit"])), kpi("Critical CVEs (tenant)", sum(1 for c in cves if c["severity"] == "Critical"))],
               data_as_of=asof, source=_SEC_SRC, sections=[
                   table("Most exposed devices", [col("name", "Device", "mono"), col("group", "Platform"), col("project", "Project"), col("exposure", "Exposure", "badge"),
                         col("critical", "Critical", "num"), col("high", "High", "num"), col("exploitable", "Exploitable", "num"), col("missing_updates", "Missing updates", "num")],
                         sorted([r for r in dv if r["critical"] or r["exploitable"]], key=lambda r: (-r["exploitable"], -r["critical"]))),
                   table("CVEs with a public exploit", ccols, [c for c in cves if c["exploit"]]),
                   table("Critical CVEs", ccols, [c for c in cves if c["severity"] == "Critical"]),
               ])


async def build_sec_av(filters: dict) -> dict:
    d, asof = await _snap("sec_devices")
    dv = [r for r in _dev_filter(d.get("devices", []), filters) if r["av_mode"] != "Not reported"]
    out = [r for r in dv if r["av_sig_uptodate"] is False or (r["av_sig_age"] or 0) > 3]
    inactive = [r for r in dv if r["av_mode"] not in ("Active", "EDR in block mode")]
    eng = [r for r in dv if r["av_engine_uptodate"] is False or r["av_platform_uptodate"] is False]
    cols = [col("name", "Device", "mono"), col("group", "Platform"), col("project", "Project"), col("av_mode", "AV mode", "badge"),
            col("av_sig_version", "Signature", "mono"), col("av_sig_age", "Signature age (d)", "num1"), col("av_sig_uptodate", "Sig. up to date", "bool"),
            col("av_engine_uptodate", "Engine up to date", "bool"), col("av_platform_uptodate", "Platform up to date", "bool"), col("last_seen", "Last seen", "datetime")]
    from collections import Counter
    return doc("sec_av", "Antivirus Health" + _suffix(filters), "Microsoft Defender Antivirus status per device",
               kpis=[kpi("Devices reporting AV", len(dv)), kpi("Signatures outdated", len(out), "", "warn" if out else "ok"),
                     kpi("Not in active mode", len(inactive), "passive / disabled", "warn" if inactive else "ok"),
                     kpi("Engine / platform outdated", len(eng), "", "warn" if eng else "ok")],
               data_as_of=asof, source=_SEC_SRC, sections=[
                   bars("AV mode", [{"name": k, "count": v} for k, v in Counter(r["av_mode"] for r in dv).most_common()]),
                   table("Outdated signatures", cols, sorted(out, key=lambda r: -(r["av_sig_age"] or 0)), empty="All signatures are current."),
                   table("Not in active mode", cols, inactive, empty="All devices run Defender in active mode."),
                   table("Engine or platform outdated", cols, eng, empty="All engines and platforms are current."),
               ])


async def build_sec_intune(filters: dict) -> dict:
    it, asof = await _snap("sec_intune")
    s, dv = it.get("summary", {}), it.get("devices", [])
    cols = [col("name", "Device", "mono"), col("os", "OS"), col("version", "Version", "mono"), col("compliance", "Compliance", "badge"),
            col("encrypted", "Encrypted", "bool"), col("user", "User", "mono"), col("owner", "Ownership"), col("sync_age", "Days since sync", "num")]
    return doc("sec_intune", "Intune Compliance", "Microsoft Intune managed devices",
               kpis=[kpi("Managed devices", s.get("devices")), kpi("Compliance", f"{s.get('compliance_pct', '—')}%", f"{s.get('compliant', 0)} compliant", _tone(s.get("compliance_pct"), 90, 70, False)),
                     kpi("Non-compliant", s.get("noncompliant"), "", "warn" if s.get("noncompliant") else "ok"),
                     kpi("Not encrypted (Windows)", s.get("not_encrypted"), "", "warn" if s.get("not_encrypted") else "ok"),
                     kpi("No sync 30+ days", s.get("stale_30d"))],
               data_as_of=asof, source=_SEC_SRC, sections=[
                   bars("Compliance state", it.get("by_compliance", [])),
                   table("Non-compliant devices", cols, [x for x in dv if x["compliance"] == "noncompliant"], empty="No non-compliant devices."),
                   table("Windows devices without encryption", cols, [x for x in dv if (x["os"] or "").lower().startswith("windows") and x["encrypted"] is False]),
                   table("Not synced for 30+ days", cols, sorted([x for x in dv if (x["sync_age"] or 0) > 30], key=lambda x: -(x["sync_age"] or 0))),
               ])


async def build_sec_risky(filters: dict) -> dict:
    r, asof = await _snap("sec_risk")
    s = r.get("summary", {})
    return doc("sec_risky", "Identity Risk", "Microsoft Entra ID Protection",
               kpis=[kpi("Users at risk", s.get("at_risk"), "", "warn" if s.get("at_risk") else "ok"), kpi("High risk", s.get("high"), "", "crit" if s.get("high") else "ok"),
                     kpi("Medium risk", s.get("medium")), kpi("Confirmed compromised", s.get("confirmed_compromised"), "", "crit" if s.get("confirmed_compromised") else "ok"),
                     kpi("Detections (30 d)", s.get("detections_30d"))],
               data_as_of=asof, source=_SEC_SRC, sections=[
                   table("Users at risk", [col("name", "User"), col("upn", "UPN", "mono"), col("level", "Risk", "badge"), col("state", "State"),
                                           col("detail", "Detail"), col("updated", "Updated", "datetime")], r.get("risky_users", [])),
                   bars("Detections by type", r.get("by_type", [])),
                   table("Risk detections (30 days)", [col("detected", "Detected", "datetime"), col("type", "Type"), col("level", "Risk", "badge"), col("upn", "User", "mono"),
                                                       col("ip", "IP", "mono"), col("country", "Country"), col("source", "Source")], r.get("detections", [])),
               ])


async def build_sec_service(filters: dict) -> dict:
    sv, asof = await _snap("sec_service")
    s = sv.get("summary", {})
    active = [i for i in sv.get("issues", []) if not i["resolved"]]
    return doc("sec_service", "Microsoft 365 Service Health & Changes", "Service status, active issues and message-center items needing action",
               kpis=[kpi("Services", s.get("services")), kpi("Degraded", s.get("degraded"), "", "warn" if s.get("degraded") else "ok"),
                     kpi("Active incidents", s.get("active_incidents"), "", "crit" if s.get("active_incidents") else "ok"),
                     kpi("Active advisories", s.get("active_advisories")), kpi("Action required", s.get("action_required"), "message center", "warn" if s.get("action_required") else "ok")],
               data_as_of=asof, source=_SEC_SRC, sections=[
                   table("Services not fully operational", [col("service", "Service"), col("status", "Status", "badge")],
                         [x for x in sv.get("services", []) if x["status"] != "serviceOperational"], empty="All services operational."),
                   table("Active issues", [col("id", "ID", "mono"), col("title", "Title"), col("service", "Service"), col("classification", "Type", "badge"),
                                           col("status", "Status"), col("updated", "Updated", "datetime")], active, empty="No active issues."),
                   table("Message center — action required", [col("id", "ID", "mono"), col("title", "Title"), col("services", "Services"),
                                                               col("act_by", "Act by", "date"), col("major", "Major change", "bool")],
                         sorted([m for m in sv.get("messages", []) if m["act_by"]], key=lambda m: m["act_by"] or "")),
               ])

# ─────────────────────────────────────────────────────────────────────────────
# Builders — Operations
# ─────────────────────────────────────────────────────────────────────────────

async def build_jira_summary(filters: dict) -> dict:
    days = int((filters or {}).get("days") or 30)
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(text("""
            SELECT ticket_key, summary, sr_type, status, created_by, effort_hours, created_at, ticket_url
            FROM cloudpulse_jira_tickets
            WHERE created_at >= NOW() - make_interval(days => CAST(:d AS INTEGER))
            ORDER BY created_at DESC
        """), {"d": days})).fetchall()
    t = [{k: (float(v) if hasattr(v, "is_finite") else v) for k, v in r._mapping.items()} for r in rows]
    from collections import Counter
    by_status, by_type = Counter(x["status"] or "Unknown" for x in t), Counter(x["sr_type"] or "Unknown" for x in t)
    open_n = sum(1 for x in t if (x["status"] or "").lower() not in ("resolved", "closed", "done"))
    return doc("jira_summary", "Jira Ticket Summary", f"Tickets raised from CloudPulse in the last {days} days",
               kpis=[kpi("Tickets", len(t)), kpi("Open / in progress", open_n, "", "warn" if open_n else "ok"),
                     kpi("Resolved", len(t) - open_n, "", "ok"),
                     kpi("Effort logged", f"{sum(x['effort_hours'] or 0 for x in t):,.1f} h")],
               source="CloudPulse Jira log", sections=[
                   bars("By status", [{"name": k, "count": v} for k, v in by_status.most_common()]),
                   bars("By service request type", [{"name": k, "count": v} for k, v in by_type.most_common(12)]),
                   table("Tickets", [col("ticket_key", "Ticket", "mono"), col("summary", "Summary"), col("sr_type", "SR type"),
                                     col("status", "Status", "badge"), col("effort_hours", "Effort h", "num1"),
                                     col("created_by", "Raised by"), col("created_at", "Created", "datetime")], t,
                         empty="No tickets in this period.")])


async def build_teams_incidents(filters: dict) -> dict:
    from app.services import teams_alert_service as tas
    from app.services import inventory_service as inv
    lookup = await inv.project_lookup()

    def proj(r: dict) -> Optional[str]:
        for h in [r.get("ig_host")] + (r.get("hosts") or []) + [r.get("server_name")]:
            p = (lookup.get(inv.key_of(h or "")) or {}).get("project")
            if p and p != "Unassigned":
                return p
        return r.get("project") or None

    active = await tas.list_incidents(resolved=False)
    resolved = await tas.list_incidents(resolved=True, limit=500)
    for r in active + resolved:
        r["inv_project"] = proj(r)
    if filters.get("project"):
        active = [r for r in active if r["inv_project"] == filters["project"]]
        resolved = [r for r in resolved if r["inv_project"] == filters["project"]]
    week_ago = _now() - timedelta(days=7)
    recent = [r for r in resolved if r.get("resolved_at") and r["resolved_at"] >= week_ago]
    label = {"response_time": "Response time", "gc": "GC", "cpu": "CPU", "memory": "Memory", "disk": "Disk",
             "availability": "Availability", "errors": "Errors", "network": "Network", "other": "Other"}

    def flat(r: dict) -> dict:
        return {"target": r.get("server_name"), "type": label.get(r.get("metric_type"), r.get("metric_type")),
                "severity": r.get("severity"), "project": r.get("inv_project") or r.get("project"), "title": r.get("title"),
                "count": r.get("occurrence_count"), "first": r.get("first_seen"), "last": r.get("received_at"),
                "cleared": r.get("resolved_at"), "cleared_by": r.get("resolved_by"), "jira": r.get("jira_key")}

    from collections import Counter
    cols = [col("target", "Target", "mono"), col("type", "Type"), col("severity", "Severity", "badge"), col("project", "Project"),
            col("title", "Alert"), col("count", "Occurrences", "num"), col("first", "First seen", "datetime"),
            col("last", "Last seen", "datetime"), col("jira", "Jira", "mono")]
    return doc("teams_incidents", "Teams Alert Incidents" + (f" — {filters['project']}" if filters.get("project") else ""), "Incidents from the Teams monitoring channel (repeat alerts merged)",
               kpis=[kpi("Active incidents", len(active), f"{sum(r['occurrence_count'] for r in active)} occurrences",
                         "crit" if any(r.get("severity") == "critical" for r in active) else "warn" if active else "ok"),
                     kpi("Critical", sum(1 for r in active if r.get("severity") == "critical"), "", "crit" if any(r.get("severity") == "critical" for r in active) else "ok"),
                     kpi("Cleared (7 days)", len(recent), "", "ok"),
                     kpi("Ticketed", sum(1 for r in active + recent if r.get("jira_key")))],
               source="CloudPulse Teams Alerts", sections=[
                   bars("Active incidents by type", [{"name": k, "count": v} for k, v in Counter(label.get(r.get("metric_type"), r.get("metric_type")) for r in active).most_common()]),
                   table("Active incidents", cols, [flat(r) for r in active], empty="No active incidents."),
                   table("Cleared in the last 7 days", cols[:6] + [col("cleared", "Cleared", "datetime"), col("cleared_by", "Cleared by")],
                         [flat(r) for r in recent], empty="Nothing cleared in the last 7 days."),
               ])


# ─────────────────────────────────────────────────────────────────────────────
# Builders — Identity (from AD health snapshots)
# ─────────────────────────────────────────────────────────────────────────────

async def _snap(section: str) -> tuple[dict, Optional[datetime]]:
    from app.services import ad_service
    s = await ad_service.load_section(section)
    if not s or not s.get("data"):
        raise ValueError(f"Identity data for '{section}' has not been collected yet — open AD / Entra Health and click Collect now.")
    return s["data"], s.get("collected_at")


_USER_COLS = [col("name", "Name"), col("upn", "User principal name", "mono"), col("title", "Job title"), col("dept", "Department"),
              col("company", "Company"), col("licence_names", "Licences", "list"), col("created", "Created", "date"),
              col("last_signin", "Last sign-in", "date"), col("inactive_days", "Inactive (days)", "num"), col("synced", "Source", "source")]
# disabled accounts: what licences they hold and how many are paid
_DISABLED_COLS = [col("name", "Name"), col("upn", "User principal name", "mono"), col("title", "Job title"), col("dept", "Department"),
                  col("company", "Company"), col("licence_names", "Licences", "list"), col("paid_licence_count", "Paid licences", "num"),
                  col("usage_location", "Usage location"), col("created", "Created", "date"), col("last_signin", "Last sign-in", "date"),
                  col("inactive_days", "Inactive (days)", "num"), col("synced", "Source", "source")]
_SRC = "Microsoft Entra ID via Microsoft Graph"


async def build_ad_executive(filters: dict) -> dict:
    from app.services import ad_service
    snaps = await ad_service.load_snapshots()
    if not snaps:
        raise ValueError("Identity data has not been collected yet.")
    items = await ad_service.findings(snaps)
    score = ad_service.health_score(items)
    sm = {k: ((v.get("data") or {}).get("summary") or {}) for k, v in snaps.items()}
    a, m, p, sec, si, lic, dv = (sm.get(k, {}) for k in ("accounts", "mfa", "privileged", "secrets", "signins", "licences", "devices"))
    asof = max((v["collected_at"] for v in snaps.values() if v.get("collected_at")), default=None)
    area = {"tenant": "Sync & DCs", "secrets": "App secrets", "privileged": "Privileged access", "mfa": "MFA",
            "accounts": "Accounts", "signins": "Sign-ins", "audit": "Audit", "licences": "Licences", "devices": "Devices & groups"}
    return doc("ad_executive", "Identity Health — Executive Summary", sm.get("tenant", {}).get("tenant_name", ""),
               kpis=[kpi("Health score", f"{score}/100", "Healthy" if score >= 85 else "Needs attention" if score >= 60 else "At risk",
                         _tone(score, 85, 60, higher_is_bad=False)),
                     kpi("MFA coverage", f"{m.get('mfa_pct', '—')}%", f"{m.get('admins_without_mfa', 0)} admins without MFA",
                         "crit" if m.get("admins_without_mfa") else _tone(m.get("mfa_pct"), 95, 80, False)),
                     kpi("Global admins", p.get("global_admins", "—"), f"{p.get('privileged_principals', 0)} privileged principals"),
                     kpi("Secrets needing action", (sec.get("critical") or 0) + (sec.get("warning") or 0) + (sec.get("expired_unreplaced") or 0),
                         f"this app: {round(sec['this_app_days_left'])} d left" if sec.get("this_app_days_left") is not None else "",
                         "crit" if sec.get("critical") or sec.get("expired_unreplaced") else "ok"),
                     kpi("Stale accounts", a.get("stale", "—"), f"of {a.get('enabled', 0):,} enabled", "warn" if a.get("stale") else "ok"),
                     kpi("Failed sign-ins", si.get("failures", "—"), f"last {si.get('window_hours', 24)} h"),
                     kpi("Unused paid licences", lic.get("paid_unused", "—"), f"{lic.get('on_disabled_users', 0)} on disabled users"),
                     kpi("Stale devices", dv.get("stale", "—"), f"of {dv.get('total', 0):,}")],
               highlights=[f"{f['title']} — {f['detail']}" for f in items if f["severity"] == "critical"][:6],
               data_as_of=asof, source=_SRC, sections=[
                   table("Findings", [col("severity", "Severity", "badge"), col("area", "Area"), col("title", "Finding"), col("detail", "Detail")],
                         [{"severity": f["severity"], "area": area.get(f["section"], f["section"]), "title": f["title"], "detail": f["detail"]} for f in items],
                         empty="No findings — identity posture is clean."),
               ])


async def build_ad_disabled_licensed(filters: dict) -> dict:
    acc, asof = await _snap("accounts")
    lic, _ = await _snap("licences")
    rows = acc.get("disabled_licensed", [])
    skus = [s for s in lic.get("skus", []) if s.get("disabled_users")]
    seats = sum(s["disabled_users"] for s in skus if not s.get("free"))
    return doc("ad_disabled_licensed", "Disabled Accounts Holding Licences", "Licences that can be reclaimed from disabled accounts",
               kpis=[kpi("Disabled accounts with licences", len(rows), "", "warn" if rows else "ok"),
                     kpi("Paid seats to reclaim", seats, "across SKUs", "warn" if seats else "ok"),
                     kpi("SKUs affected", len(skus))],
               highlights=[f"{s['name']}: {s['disabled_users']} seat(s) on disabled accounts" for s in sorted(skus, key=lambda s: -s["disabled_users"])[:5]],
               data_as_of=asof, source=_SRC, sections=[
                   bars("Licences held by disabled accounts", acc.get("disabled_by_licence", [])[:15]),
                   bars("Disabled licensed accounts by department", _count_by(rows, "dept", 12)),
                   table("Licences held by disabled accounts, per SKU", [col("name", "Licence"), col("part", "SKU", "mono"),
                         col("disabled_users", "On disabled accounts", "num"), col("available", "Free seats", "num"), col("free", "Free / trial", "bool")],
                         sorted(skus, key=lambda s: -s["disabled_users"])),
                   table("Disabled accounts", _DISABLED_COLS, sorted(rows, key=lambda r: (-(r.get("paid_licence_count") or 0), r.get("name") or "")),
                         empty="No disabled accounts hold licences."),
               ])


async def build_ad_inactive_accounts(filters: dict) -> dict:
    acc, asof = await _snap("accounts")
    s = acc.get("summary", {})
    stale, never = acc.get("stale", []), acc.get("never_signed_in", [])
    return doc("ad_inactive_accounts", "Inactive & Never-Used Accounts",
               f"Enabled accounts with no sign-in for more than {s.get('stale_days', 90)} days",
               kpis=[kpi("Enabled accounts", s.get("enabled")),
                     kpi(f"Inactive > {s.get('stale_days', 90)} d", len(stale), f"{100 * len(stale) / max(1, s.get('enabled') or 1):.1f}% of enabled", "warn" if stale else "ok"),
                     kpi("Never signed in", len(never), "enabled accounts", "warn" if never else "ok"),
                     kpi("Synced from AD", sum(1 for r in stale if r.get("synced")), "of the inactive accounts"),
                     kpi("Licensed & inactive", sum(1 for r in stale if r.get("licence_count")), "reclaim candidates", "warn")],
               data_as_of=asof, source=_SRC, sections=[
                   bars("Inactive accounts by department", _count_by(stale, "dept", 12)),
                   bars("Paid licences on inactive accounts", acc.get("stale_by_licence", [])[:15]),
                   table(f"Inactive accounts (no sign-in > {s.get('stale_days', 90)} days)",
                         _USER_COLS + [col("pwd_age_days", "Password age (days)", "num")], stale),
                   table("Accounts that never signed in", _USER_COLS, never),
               ])


def _count_by(rows: list[dict], key: str, n: int) -> list[dict]:
    from collections import Counter
    return [{"name": k, "count": v} for k, v in Counter((r.get(key) or "(none)") for r in rows).most_common(n)]


async def build_ad_devices(filters: dict) -> dict:
    d, asof = await _snap("devices")
    gr, _ = await _snap("groups")
    s, g = d.get("summary", {}), gr.get("summary", {})
    dcols = [col("name", "Device", "mono"), col("owner", "Owner", "mono"), col("os", "Platform"), col("version", "Version", "mono"),
             col("manufacturer", "Manufacturer"), col("model", "Model"), col("trust", "Join type"),
             col("managed", "Managed", "bool"), col("compliant", "Compliant", "bool"), col("registered", "Registered", "date"),
             col("last_signin", "Last activity", "date"), col("inactive_days", "Inactive (days)", "num")]
    return doc("ad_devices", "Device Inventory & Hygiene", "Entra ID registered, joined and hybrid-joined devices",
               kpis=[kpi("Devices", s.get("total")), kpi("Hybrid joined", s.get("hybrid_joined")),
                     kpi("Managed", s.get("managed")),
                     kpi("Compliant", s.get("compliant"), f"{s.get('non_compliant', 0)} non-compliant", "warn" if s.get("non_compliant") else "ok"),
                     kpi(f"Stale > {s.get('stale_days', 90)} d", s.get("stale"), "enabled devices", "warn" if s.get("stale") else "ok"),
                     kpi("Ownerless groups", g.get("ownerless"), "cloud groups", "warn" if g.get("ownerless") else "ok")],
               data_as_of=asof, source=_SRC, sections=[
                   bars("Devices by platform", d.get("by_os", [])),
                   bars("Devices by join type", d.get("by_trust", [])),
                   table("Windows builds", [col("name", "Build", "mono"), col("count", "Devices", "num")], d.get("windows_versions", [])),
                   table("Stale devices", dcols, d.get("stale", [])),
                   table("Non-compliant devices", dcols, d.get("non_compliant", [])),
               ])


async def build_ad_mfa(filters: dict) -> dict:
    """Preferred basis: legacy per-user MFA state (Disabled / Enabled / Enforced); registration as fallback."""
    d, asof = await _snap("mfa")
    s = d.get("summary", {})
    ucols = [col("name", "Name"), col("upn", "User principal name", "mono"), col("admin", "Admin", "bool"),
             col("title", "Job title"), col("dept", "Department"), col("company", "Company"), col("per_user", "Per-user MFA", "badge"), col("registered", "Method registered", "bool"),
             col("methods", "Methods", "list"), col("last_signin", "Last sign-in", "date"), col("synced", "Source", "source")]
    excl = s.get("excluded_no_mailbox", 0)
    scope = "Enabled member accounts with a mailbox, plus all admins"
    cat_sections = []
    if s.get("requirement_known"):
        ccols = [col("name", "Name"), col("upn", "User principal name", "mono"), col("title", "Job title"), col("dept", "Department"),
                 col("company", "Company"), col("admin", "Admin", "bool"), col("required_by", "MFA enabled by"),
                 col("last_signin", "Last sign-in", "date"), col("inactive_days", "Inactive (days)", "num"), col("synced", "Source", "source")]
        cat_sections = [
            table("MFA not enabled and not enrolled", ccols, d.get("unprotected", []),
                  note="No system-preferred MFA, per-user MFA, Conditional Access or security default applies — password-only sign-in.",
                  empty="Every user has MFA enabled or enrolled."),
            table("MFA enabled, not enrolled", ccols, d.get("pending_registration", []),
                  note="MFA is enabled for these users but no method is enrolled — they will be asked to register at next sign-in. Long-inactive ones are offboarding candidates."),
            table("Conditional Access policies", [col("name", "Policy"), col("state", "State", "badge"), col("requires_mfa", "Requires MFA", "bool"),
                  col("strength", "Auth strength"), col("scope", "Users in scope"), col("excludes", "Excluded"), col("apps", "Apps"),
                  col("conditions", "Conditions"), col("covers", "Users covered", "num")], d.get("ca_policies", [])),
        ]
    if s.get("per_user_available"):
        n = s.get("users") or 0
        kpis = [kpi("Users in scope", n, "mailbox users + admins"),
                kpi("MFA coverage", f"{s.get('mfa_pct', '—')}%", "per-user Enabled or Enforced", _tone(s.get("mfa_pct"), 95, 80, False)),
                kpi("Disabled (no MFA)", s.get("per_user_disabled"), "per-user state", "crit" if s.get("per_user_disabled") else "ok"),
                kpi("Enabled", s.get("per_user_enabled"), "activated, not yet enforced", "warn" if s.get("per_user_enabled") else "neutral"),
                kpi("Enforced", s.get("per_user_enforced"), "MFA required at sign-in", "ok"),
                kpi("Enforced, not registered", s.get("enforced_not_registered"), "will register at next sign-in",
                    "warn" if s.get("enforced_not_registered") else "ok"),
                kpi("Admins without MFA", s.get("admins_without_mfa"), f"of {s.get('admins', 0)} admins", "crit" if s.get("admins_without_mfa") else "ok"),
                kpi("Excluded (no mailbox)", excl, "service / resource accounts")]
        sections = [
            table("Users with per-user MFA Disabled", ucols, d.get("per_user_disabled", []), empty="No users have per-user MFA disabled."),
            table("Enforced but no method registered yet", ucols, d.get("enforced_not_registered", []),
                  note="Per-user MFA is Enforced; these users will be required to register at their next sign-in.",
                  empty="Every enforced user has registered a method."),
            table("Per-user MFA Enabled (activated, not enforced)", ucols, d.get("per_user_enabled", []),
                  note="Enabled users are prompted to register; MFA is enforced once they complete registration."),
            table("Administrators without MFA", ucols, d.get("admins_without_mfa", []), empty="Every administrator has MFA."),
        ]
        basis = "Basis: per-user MFA state (Disabled / Enabled / Enforced) from Microsoft Entra ID."
    else:
        kpis = [kpi("Users in scope", s.get("users"), "mailbox users + admins"),
                kpi("MFA registered", f"{s.get('registered_pct', s.get('mfa_pct', '—'))}%", "registration report", _tone(s.get("mfa_pct"), 95, 80, False)),
                kpi("Without MFA (mailbox)", s.get("mailbox_without_mfa"), "MFA not enabled, no method", "warn"),
                kpi("Without MFA (synced)", s.get("synced_without_mfa"), "MFA not enabled, no method", "warn"),
                kpi("Admins without MFA", s.get("admins_without_mfa"), f"of {s.get('admins', 0)} admins", "crit" if s.get("admins_without_mfa") else "ok"),
                kpi("Excluded (no mailbox)", excl, "service / resource accounts")]
        sections = [
            table("Mailbox users without MFA", ucols, d.get("mailbox_without_mfa", []), empty="Every mailbox user has MFA registered."),
            table("Administrators without MFA", ucols, d.get("admins_without_mfa", []), empty="Every administrator has MFA registered."),
            table("Synced (on-prem) users without MFA", ucols, d.get("synced_without_mfa", []),
                  note="Accounts synced from on-prem AD (including service accounts without a mailbox) with MFA not enabled and no method registered. Users with MFA enabled but not enrolled are reported separately."),
        ]
        basis = ("Basis: MFA method registration. Per-user MFA state (Disabled / Enabled / Enforced) is the preferred basis — "
                 "it needs the Microsoft Graph application permission Policy.Read.All.")
    if s.get("requirement_known"):
        kpis = [kpi("Protected", s.get("protected"), "MFA method registered", "ok"),
                kpi("MFA enabled, not enrolled", s.get("pending_registration"), f"enrol at next sign-in · {s.get('pending_inactive_90d', 0)} inactive 90+ d", "warn" if s.get("pending_registration") else "ok"),
                kpi("MFA not enabled, not enrolled", s.get("unprotected"), "password-only", "crit" if s.get("unprotected") else "ok")] + kpis
        sections = cat_sections + sections
    return doc("ad_mfa", "MFA Status Report", scope, kpis=kpis,
               highlights=[basis] + ([f"{excl} enabled accounts without a mailbox are excluded as likely on-prem service accounts; admins are always included."] if excl else []),
               data_as_of=asof, source=_SRC,
               sections=[bars("Registered methods", d.get("methods", []))] + sections)


async def build_ad_mfa_not_enrolled(filters: dict) -> dict:
    d, asof = await _snap("mfa")
    s = d.get("summary", {})
    rows = d.get("pending_registration", [])
    active = [r for r in rows if (r.get("inactive_days") if r.get("inactive_days") is not None else 9999) <= 30]
    idle = [r for r in rows if (r.get("inactive_days") if r.get("inactive_days") is not None else 9999) > 90]
    from collections import Counter
    cols = [col("name", "Name"), col("upn", "User principal name", "mono"), col("title", "Job title"), col("dept", "Department"),
            col("company", "Company"), col("office", "Office"), col("admin", "Admin", "bool"),
            col("required_by", "MFA enabled by"), col("created", "Created", "date"), col("last_signin", "Last sign-in", "date"),
            col("inactive_days", "Inactive (days)", "num"), col("synced", "Source", "source")]
    return doc("ad_mfa_not_enrolled", "MFA Enabled — Not Enrolled",
               "Users with MFA enabled but no authentication method enrolled — they will be asked to enrol at next sign-in",
               kpis=[kpi("MFA enabled, not enrolled", len(rows), f"of {s.get('users', 0)} users in scope", "warn" if rows else "ok"),
                     kpi("Signed in last 30 days", len(active), "contact to enrol now", "warn" if active else "ok"),
                     kpi("Inactive 90+ days", len(idle), "review / offboarding candidates", "warn" if idle else "ok"),
                     kpi("MFA not enabled, not enrolled", s.get("unprotected"), "password-only", "crit" if s.get("unprotected") else "ok"),
                     kpi("Protected", s.get("protected"), "method enrolled", "ok")],
               highlights=[f"{len(active)} of these users signed in within the last 30 days — they are actively using a password-only session and should enrol now."] if active else [],
               data_as_of=asof, source=_SRC, sections=[
                   bars("By department", [{"name": k, "count": v} for k, v in Counter(r.get("dept") or "(none)" for r in rows).most_common(12)]),
                   table("Signed in within 30 days — enrol now", cols, sorted(active, key=lambda r: r.get("inactive_days") or 0)),
                   table("All users — MFA enabled, not enrolled", cols, sorted(rows, key=lambda r: (r.get("inactive_days") is None, r.get("inactive_days") or 0))),
                   table("Inactive 90+ days", cols, idle, note="Long-inactive accounts with no MFA enrolled — consider disabling."),
               ])


async def build_ad_privileged(filters: dict) -> dict:
    d, asof = await _snap("privileged")
    try:
        au, _ = await _snap("audit")
    except ValueError:
        au = {}
    try:
        mfa, _ = await _snap("mfa")
    except ValueError:
        mfa = {}
    mfa_by_id = {r["id"]: r for r in mfa.get("admins", []) + mfa.get("pending_registration", []) + mfa.get("unprotected", [])}
    for a in d.get("assignments", []):
        m = mfa_by_id.get(a.get("id"))
        a["mfa_methods"] = (m or {}).get("methods") if m else None
        a["mfa_registered"] = (m or {}).get("registered") if m else None
    s = d.get("summary", {})
    return doc("ad_privileged", "Privileged Access Review", "Active (permanent) directory role assignments",
               kpis=[kpi("Global admins", s.get("global_admins"), "target 2–5", "warn" if (s.get("global_admins") or 0) > 5 or (s.get("global_admins") or 0) < 2 else "ok"),
                     kpi("Privileged principals", s.get("privileged_principals"), f"{s.get('privileged_assignments', 0)} assignments"),
                     kpi("Roles in use", s.get("roles_in_use")),
                     kpi("Synced admins", s.get("synced_privileged"), "should be cloud-only", "warn" if s.get("synced_privileged") else "ok"),
                     kpi("Inactive privileged", s.get("stale_privileged"), "", "warn" if s.get("stale_privileged") else "ok"),
                     kpi("Role changes", (au.get("summary") or {}).get("role_changes", "—"), f"last {(au.get('summary') or {}).get('window_days', 7)} days")],
               data_as_of=asof, source=_SRC, sections=[
                   table("Role assignments", [col("role", "Role"), col("name", "Principal"), col("upn", "UPN / App ID", "mono"), col("kind", "Type"),
                                              col("title", "Job title"), col("dept", "Department"),
                                              col("enabled", "Enabled", "bool"), col("mfa_registered", "MFA enrolled", "bool"),
                                              col("mfa_methods", "MFA methods", "list"), col("pwd_age_days", "Password age (days)", "num"),
                                              col("last_signin", "Last sign-in", "date"),
                                              col("inactive_days", "Inactive (days)", "num"), col("synced", "Source", "source")], d.get("assignments", [])),
                   table("Roles", [col("role", "Role"), col("privileged", "Highly privileged", "bool"), col("members", "Members", "num")],
                         [r for r in d.get("roles", []) if r.get("members")]),
                   table("Recent role membership changes", _AUDIT_COLS, au.get("role_changes", []), empty="No role changes in the audit window."),
               ])


_AUDIT_COLS = [col("time", "Time", "datetime"), col("activity", "Activity"), col("by", "Initiated by", "mono"),
               col("target", "Target"), col("result", "Result", "badge")]


async def build_ad_app_secrets(filters: dict) -> dict:
    d, asof = await _snap("secrets")
    s = d.get("summary", {})
    ccols = [col("app", "Application"), col("kind", "Type"), col("name", "Credential"), col("end", "Expires", "date"),
             col("days_left", "Days left", "num"), col("status", "Status", "badge"), col("app_has_valid", "Other valid credential", "bool")]
    own = d.get("this_app", [])
    return doc("ad_app_secrets", "App Secrets & Certificates Expiry", "App registration credentials expired or expiring",
               kpis=[kpi("Expired, no replacement", s.get("expired_unreplaced"), "apps likely broken", "crit" if s.get("expired_unreplaced") else "ok"),
                     kpi(f"Expiring ≤ {s.get('crit_days', 7)} d", s.get("critical"), "renew now", "crit" if s.get("critical") else "ok"),
                     kpi(f"Expiring ≤ {s.get('warn_days', 30)} d", s.get("warning"), "plan renewal", "warn" if s.get("warning") else "ok"),
                     kpi("App registrations", s.get("apps"), f"{s.get('credentials', 0)} credentials"),
                     kpi("CloudPulse app", f"{round(s['this_app_days_left'])} d" if s.get("this_app_days_left") is not None else "—",
                         "until its secret expires", _tone(s.get("this_app_days_left"), s.get("warn_days", 30), s.get("crit_days", 7), False))],
               highlights=[f"CloudPulse's own secret '{o['name']}' expires {o['end'][:10]} ({round(o['days_left'])} days)." for o in own],
               data_as_of=asof, source=_SRC, sections=[
                   table("Needs action", ccols, d.get("attention", []), empty="No credentials need action."),
                   table("Expiring in the next 180 days", ccols, d.get("upcoming", [])),
               ])


async def build_ad_guests(filters: dict) -> dict:
    d, asof = await _snap("accounts")
    g = d.get("guests", [])
    for r in g:
        r["domain"] = ((r.get("mail") or (r.get("upn") or "").split("#EXT#")[0].replace("_", "@")).rsplit("@", 1)[-1] or "").lower() or None
    stale_days = d.get("summary", {}).get("stale_days", 90)
    inactive = [r for r in g if r.get("inactive_days") is None or r["inactive_days"] > stale_days]
    return doc("ad_guests", "Guest Accounts Review", "External (B2B) guest accounts",
               kpis=[kpi("Guest accounts", len(g)),
                     kpi(f"Inactive > {stale_days} d or never", len(inactive), "removal candidates", "warn" if inactive else "ok"),
                     kpi("Pending invitations", sum(1 for r in g if r.get("guest_state") == "PendingAcceptance"))],
               data_as_of=asof, source=_SRC, sections=[
                   bars("Guests by home domain", _count_by(g, "domain", 12)),
                   table("Guest accounts", [col("name", "Name"), col("mail", "Email", "mono"), col("domain", "Home domain"),
                                            col("company", "Company"), col("guest_state", "Invitation"),
                                            col("enabled", "Enabled", "bool"), col("licence_names", "Licences", "list"), col("created", "Invited", "date"),
                                            col("last_signin", "Last sign-in", "date"), col("inactive_days", "Inactive (days)", "num")], g),
               ])


async def build_ad_licences(filters: dict) -> dict:
    d, asof = await _snap("licences")
    s = d.get("summary", {})
    skus = d.get("skus", [])
    return doc("ad_licences", "Licence Utilisation", "Purchased vs assigned seats per subscription",
               kpis=[kpi("Paid SKUs", s.get("paid_skus")), kpi("Purchased seats", s.get("paid_enabled")),
                     kpi("Assigned", s.get("paid_consumed"), f"{100 * (s.get('paid_consumed') or 0) / max(1, s.get('paid_enabled') or 1):.1f}% used"),
                     kpi("Unused seats", s.get("paid_unused")),
                     kpi("Near capacity", s.get("near_capacity"), "SKUs", "warn" if s.get("near_capacity") else "ok"),
                     kpi("Over-assigned", s.get("over_assigned"), "SKUs", "crit" if s.get("over_assigned") else "ok"),
                     kpi("On disabled users", s.get("on_disabled_users"), "seats to reclaim", "warn" if s.get("on_disabled_users") else "ok")],
               data_as_of=asof, source=_SRC, sections=[
                   table("Paid subscriptions", _LIC_COLS, [x for x in skus if not x.get("free")]),
                   table("Free & trial subscriptions", _LIC_COLS, [x for x in skus if x.get("free")]),
               ])


_LIC_COLS = [col("name", "Licence"), col("part", "SKU", "mono"), col("enabled", "Purchased", "num"), col("consumed", "Assigned", "num"),
             col("available", "Available", "num"), col("pct", "Utilisation", "pct", warn=90, crit=98),
             col("disabled_users", "On disabled users", "num"), col("status", "Status", "badge")]


async def build_ad_signins(filters: dict) -> dict:
    d, asof = await _snap("signins")
    s = d.get("summary", {})
    return doc("ad_signins", "Failed Sign-in Analysis", f"Genuine sign-in failures in the last {s.get('window_hours', 24)} hours (MFA / session prompts excluded)",
               kpis=[kpi("Failures", s.get("failures")), kpi("Accounts affected", s.get("users_affected")),
                     kpi("Source IPs", s.get("ips")), kpi("Risky", s.get("risky"), "medium / high", "warn" if s.get("risky") else "ok"),
                     kpi(f"Outside {s.get('home_country', 'AE')}", s.get("foreign")), kpi("Legacy auth", s.get("legacy_auth"))],
               data_as_of=asof, source=_SRC, sections=[
                   bars("Failure reasons", d.get("reasons", [])[:10]),
                   bars("Countries", d.get("countries", [])[:10]),
                   table("Accounts with the most failures", [col("upn", "Account", "mono"), col("name", "Name"), col("count", "Failures", "num"),
                         col("top_reason", "Main reason"), col("countries", "Countries", "list"), col("ips", "IPs", "num"),
                         col("last", "Last failure", "datetime")], d.get("top_users", [])),
                   table("Source IPs", [col("ip", "IP address", "mono"), col("country", "Country"), col("count", "Failures", "num"),
                                        col("users", "Accounts", "num")], d.get("top_ips", [])),
               ])


BUILDERS: dict[str, Callable[[dict], Awaitable[dict]]] = {
    "capacity_units": build_capacity_units, "project_capacity": build_project_capacity,
    "fleet_summary": build_fleet_summary, "capacity_risk": build_capacity_risk, "server_detail": build_server_detail,
    "jira_summary": build_jira_summary, "teams_incidents": build_teams_incidents,
    "sec_posture": build_sec_posture, "sec_incidents": build_sec_incidents, "sec_patching": build_sec_patching,
    "sec_vulns": build_sec_vulns, "sec_av": build_sec_av, "sec_intune": build_sec_intune, "sec_risky": build_sec_risky,
    "sec_service": build_sec_service,
    "ad_executive": build_ad_executive, "ad_disabled_licensed": build_ad_disabled_licensed,
    "ad_inactive_accounts": build_ad_inactive_accounts, "ad_devices": build_ad_devices, "ad_mfa": build_ad_mfa,
    "ad_mfa_not_enrolled": build_ad_mfa_not_enrolled,
    "ad_privileged": build_ad_privileged, "ad_app_secrets": build_ad_app_secrets, "ad_guests": build_ad_guests,
    "ad_licences": build_ad_licences, "ad_signins": build_ad_signins,
}


async def generate(rtype: str, filters: Optional[dict] = None) -> dict:
    if rtype not in BUILDERS:
        raise ValueError(f"Unknown report type '{rtype}'")
    return await BUILDERS[rtype](filters or {})


def row_count(d: dict) -> int:
    return sum(s.get("total", 0) for s in d.get("sections", []) if s.get("kind") == "table")


# ─────────────────────────────────────────────────────────────────────────────
# Rendering
# ─────────────────────────────────────────────────────────────────────────────

INK, AQUA, AQUA_DK, MUTED, LINE, ZEBRA = "#062329", "#2FD3C5", "#0E8C82", "#5B6B70", "#E3E8EA", "#F6F9F9"
TONES = {  # text, background
    "crit": ("#B42318", "#FEECEB"), "warn": ("#9A5B00", "#FFF4DE"), "ok": ("#18794E", "#E7F6EE"),
    "info": ("#1E5FA8", "#E8F1FB"), "neutral": (INK, "#FFFFFF"),
}
_BADGE_TONE = {
    "critical": "crit", "expired": "crit", "high": "crit", "error": "crit", "failure": "crit", "rising": "warn",
    "warning": "warn", "medium": "warn", "in progress": "warn", "open": "warn",
    "ok": "ok", "low": "ok", "success": "ok", "resolved": "ok", "closed": "ok", "done": "ok", "enabled": "ok",
    "falling": "ok", "stable": "info", "info": "info",
}
_FONT = "Segoe UI, Roboto, Helvetica, Arial, sans-serif"
_MONO = "Consolas, 'Cascadia Mono', Menlo, monospace"
E = html.escape


def _fmt_dt(v: Any, with_time: bool) -> str:
    if not v:
        return "—"
    try:
        d = v if isinstance(v, datetime) else datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        if isinstance(d, datetime) and d.tzinfo:
            d = d.astimezone(GST)
        return d.strftime("%d %b %Y %H:%M") if with_time and isinstance(d, datetime) else d.strftime("%d %b %Y")
    except Exception:
        return E(str(v)[:19])


def _badge(text_: str, tone: str) -> str:
    fg, bg = TONES.get(tone, TONES["neutral"])
    return (f'<span style="display:inline-block;padding:2px 9px;border-radius:10px;font-size:11px;font-weight:700;'
            f'letter-spacing:.3px;color:{fg};background:{bg};white-space:nowrap">{E(text_)}</span>')


_ARROW = {"up": ("▲", "#C2410C"), "down": ("▼", "#18794E"), "flat": ("▶", "#8A989C")}


def _arrow(direction: Optional[str], delta: Optional[float], unit: str = "") -> str:
    sym, colr = _ARROW.get(direction or "flat", _ARROW["flat"])
    d = "" if delta is None else f" {'+' if delta > 0 else ''}{delta:,.1f}{(' ' + unit) if unit else ''}"
    return f'<span style="color:{colr};font-weight:700;white-space:nowrap">{sym}{E(d)}</span>'


def _cell(v: Any, c: dict, r: Optional[dict] = None) -> tuple[str, str]:
    """Return (html, align)."""
    k = c.get("kind", "text")
    r = r or {}
    if k == "fc":                       # forecast value with change from now
        key = c["key"]
        if v is None:
            return '<span class="ig-d">—</span>', "right"
        pct = r.get(f"{key}_pct")
        return (f'<div style="font:600 13px {_MONO};white-space:nowrap">{v:,.1f}</div>'
                f'<div style="font-size:11px">{_arrow(r.get(f"{key}_dir"), r.get(f"{key}_delta"))}'
                + (f'<span style="color:{MUTED}"> · {pct:.0f}%</span>' if pct is not None else "") + '</div>'), "right"
    if k == "nowfc":                    # metric prefix m: m_now → m_fc of m_cap
        m = c["metric"]
        now, fc, cap = r.get(f"{m}_now"), r.get(f"{m}_fc"), r.get(f"{m}_cap")
        if now is None:
            return '<span class="ig-d">—</span>', "right"
        pf = r.get(f"{m}_pct_fc")
        tone = TONES["crit" if (pf or 0) >= 90 else "warn" if (pf or 0) >= 80 else "ok"][0]
        return (f'<div style="font:600 12.5px {_MONO};white-space:nowrap">{now:,.1f} → <span style="color:{tone}">{fc:,.1f}</span>'
                f'<span style="color:{MUTED};font-weight:400"> / {cap:,.0f}</span></div>'
                f'<div style="font-size:11px">{_arrow(r.get(f"{m}_dir"), r.get(f"{m}_delta"))}'
                + (f'<span style="color:{MUTED}"> · {pf:.0f}% of capacity</span>' if pf is not None else "") + '</div>'), "right"
    if k == "unit":
        if v is None:
            return '<span class="ig-d">—</span>', "right"
        return f'{v:,.1f} <span style="color:{MUTED}">{E(c.get("unit", ""))}</span>', "right"
    if v is None or v == "" or v == []:
        return '<span class="ig-d">—</span>', "right" if k.startswith("num") or k in ("pct",) else "left"
    if k == "num":
        return (f"{v:,}" if isinstance(v, int) else f"{v:,.0f}" if isinstance(v, float) else E(str(v))), "right"
    if k in ("num1", "num2"):
        try:
            return f"{float(v):,.{k[-1]}f}", "right"
        except (TypeError, ValueError):
            return E(str(v)), "right"
    if k == "pct":
        try:
            p = float(v)
        except (TypeError, ValueError):
            return E(str(v)), "right"
        tone = "crit" if p >= c.get("crit", 90) else "warn" if p >= c.get("warn", 80) else "ok"
        fg = TONES[tone][0]
        w = max(2, min(100, round(p)))
        return (f'<table role="presentation" class="ig-p" cellpadding="0" cellspacing="0"><tr>'
                f'<td class="ig-pv" style="color:{fg}">{p:.1f}%</td>'
                f'<td><div class="ig-pt"><div class="ig-pf" style="width:{w}%;background:{fg}"></div></div></td></tr></table>'), "right"
    if k == "date":
        return _fmt_dt(v, False), "left"
    if k == "datetime":
        return _fmt_dt(v, True), "left"
    if k == "badge":
        return _badge(str(v).upper(), _BADGE_TONE.get(str(v).lower(), "neutral")), "left"
    if k == "bool":
        return ('<span style="color:#18794E;font-weight:700">Yes</span>' if v is True
                else '<span style="color:#9AA7AB">No</span>' if v is False else E(str(v))), "center"
    if k == "source":
        return ("AD sync" if v else "Cloud"), "left"
    if k == "list":
        return ", ".join(E(str(x)) for x in (v if isinstance(v, list) else [v])), "left"
    if k == "mono":
        return f'<span class="ig-m">{E(str(v))}</span>', "left"
    return E(str(v)), "left"


def _kpi_grid(kpis: list[dict]) -> str:
    if not kpis:
        return ""
    per_row = 4 if len(kpis) in (4, 7, 8) else 3 if len(kpis) in (3, 5, 6, 9) else 4
    out = []
    for i in range(0, len(kpis), per_row):
        cells = []
        for k in kpis[i:i + per_row]:
            fg, bg = TONES.get(k.get("tone", "neutral"), TONES["neutral"])
            bar = TONES.get(k.get("tone"), (LINE,))[0] if k.get("tone") not in (None, "neutral") else AQUA
            v = k.get("value")
            v = f"{v:,}" if isinstance(v, int) else E(str(v if v is not None else "—"))
            cells.append(
                f'<td width="{100 // per_row}%" style="padding:6px;vertical-align:top">'
                f'<div style="border:1px solid {LINE};border-top:3px solid {bar};border-radius:8px;padding:12px 14px;background:{bg if k.get("tone") not in (None, "neutral", "ok") else "#FFFFFF"}">'
                f'<div style="font:600 10.5px {_FONT};letter-spacing:.6px;text-transform:uppercase;color:{MUTED}">{E(k["label"])}</div>'
                f'<div style="font:700 24px {_FONT};color:{fg if k.get("tone") in ("crit", "warn") else INK};margin-top:4px;line-height:1.15">{v}</div>'
                f'<div style="font:12px {_FONT};color:{MUTED};margin-top:3px;min-height:15px">{E(k.get("sub") or "")}</div>'
                f'</div></td>')
        cells += ['<td style="padding:6px"></td>'] * (per_row - len(kpis[i:i + per_row]))
        out.append("<tr>" + "".join(cells) + "</tr>")
    return f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;margin:4px -6px 8px">{"".join(out)}</table>'


def _section(s: dict, idx: int, row_limit: Optional[int], web: bool) -> str:
    head = (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:26px 0 8px"><tr>'
            f'<td style="border-left:4px solid {AQUA};padding:2px 0 2px 10px">'
            f'<div style="font:700 15px {_FONT};color:{INK}">{E(s["title"])}'
            f'<span style="font:600 12px {_FONT};color:{MUTED};margin-left:8px">{s.get("total", 0):,} item{"s" if s.get("total", 0) != 1 else ""}</span></div>'
            + (f'<div style="font:12px {_FONT};color:{MUTED};margin-top:2px">{E(s["note"])}</div>' if s.get("note") else "")
            + '</td>'
            + (f'<td align="right" class="noprint"><button onclick="dlCsv({idx})" style="font:600 11px {_FONT};color:{AQUA_DK};background:#fff;'
               f'border:1px solid {AQUA};border-radius:6px;padding:4px 10px;cursor:pointer">⬇ CSV</button></td>' if web and s["kind"] == "table" and s.get("rows") else "")
            + '</tr></table>')
    rows = s.get("rows") or []
    if not rows:
        return head + f'<div style="font:13px {_FONT};color:{MUTED};padding:12px 14px;border:1px dashed {LINE};border-radius:8px">{E(s.get("empty") or "Nothing to report.")}</div>'

    if s["kind"] == "bars":
        mx = max((r.get("value") or 0) for r in rows) or 1
        body = "".join(
            f'<tr><td style="padding:5px 12px 5px 0;font:13px {_FONT};color:{INK};width:38%;white-space:nowrap;overflow:hidden">{E(str(r["label"]))}</td>'
            f'<td style="padding:5px 0"><div style="height:12px;width:{max(1, round(100 * (r.get("value") or 0) / mx))}%;background:{AQUA_DK};border-radius:0 4px 4px 0"></div></td>'
            f'<td style="padding:5px 0 5px 10px;font:600 12px {_MONO};color:{INK};text-align:right;width:70px">{(r.get("value") or 0):,}</td></tr>'
            for r in rows)
        return head + f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">{body}</table>'

    cols = s["columns"]
    shown = rows if not row_limit else rows[:row_limit]
    th = "".join(
        f'<th class="ig-th" style="text-align:{"right" if c.get("kind", "").startswith("num") or c.get("kind") in ("pct", "fc", "nowfc", "unit") else "center" if c.get("kind") == "bool" else "left"}">'
        f'{E(c["label"])}</th>' for c in cols)
    trs = []
    for i, r in enumerate(shown):
        tds = []
        for c in cols:
            h, align = _cell(r.get(c["key"]), c, r)
            tds.append(f'<td class="ig-td{" ig-r" if align == "right" else " ig-c" if align == "center" else ""}">{h}</td>')
        trs.append(f'<tr{" class=ig-z" if i % 2 else ""}>{"".join(tds)}</tr>')
    more = ""
    if row_limit and len(rows) > row_limit:
        more = (f'<div style="font:12px {_FONT};color:{MUTED};padding:8px 2px">Showing the first {row_limit} of {len(rows):,} rows — '
                f'the full list is attached as <b>{E(_csv_name(s, idx))}</b>.</div>')
    return (head + f'<table class="ig-t" width="100%" cellpadding="0" cellspacing="0">'
            f'<thead><tr>{th}</tr></thead><tbody>{"".join(trs)}</tbody></table>' + more)


def _csv_name(s: dict, idx: int) -> str:
    return f"{idx + 1:02d}-" + re.sub(r"[^a-z0-9]+", "-", s["title"].lower()).strip("-")[:50] + ".csv"


_BASE_CSS = (
    "<style>"
    f".ig-t{{border-collapse:collapse;border:1px solid {LINE};width:100%}}"
    f".ig-th{{padding:9px 10px;background:{INK};color:#FFFFFF;font:600 11px {_FONT};letter-spacing:.4px;"
    "text-transform:uppercase;white-space:nowrap}"
    f".ig-td{{padding:8px 10px;border-bottom:1px solid {LINE};font:13px {_FONT};color:{INK};text-align:left;vertical-align:top}}"
    ".ig-r{text-align:right}.ig-c{text-align:center}"
    f".ig-z td{{background:{ZEBRA}}}"
    f".ig-m{{font-family:{_MONO};font-size:12px}}.ig-d{{color:#9AA7AB}}"
    ".ig-p{border-collapse:collapse;margin-left:auto}.ig-p td{padding:0}"
    f".ig-pv{{padding:0 8px 0 0!important;font:600 12px {_MONO};text-align:right;white-space:nowrap}}"
    ".ig-pt{width:70px;height:6px;background:#E9EEF0;border-radius:3px}.ig-pf{height:6px;border-radius:3px}"
    "</style>"
)


def render_html(d: dict, mode: str = "web", logo_src: str = "/static/brand/org-logo.png",
                report_id: Optional[int] = None) -> str:
    """mode: 'web' (viewer with toolbar + CSV buttons) or 'email' (inline-only, row-limited)."""
    web = mode == "web"
    if d.get("version") != 2:   # legacy run stored raw data
        return (f'<html><body style="font:13px {_FONT};padding:24px"><h2>{E(str(d.get("type", "Report")))}</h2>'
                f'<pre style="white-space:pre-wrap">{E(json.dumps(d, indent=2, default=str))}</pre></body></html>')
    row_limit = None if web else EMAIL_ROW_LIMIT
    gen = _fmt_dt(d.get("generated_at"), True)
    asof = _fmt_dt(d.get("data_as_of"), "T" in str(d.get("data_as_of") or "") or " " in str(d.get("data_as_of") or ""))
    highlights = "".join(f'<li style="margin:3px 0">{E(h)}</li>' for h in d.get("highlights") or [])
    sections = "".join(_section(s, i, row_limit, web) for i, s in enumerate(d.get("sections") or []))
    meta = " &nbsp;·&nbsp; ".join(filter(None, [
        f"Generated {gen} GST", f"Data as of {asof}" if d.get("data_as_of") else "", E(d.get("source") or ""),
        f"Report #{report_id}" if report_id else ""]))

    toolbar = script = print_css = ""
    if web:
        toolbar = (f'<div class="noprint" style="position:sticky;top:0;z-index:5;background:{INK};padding:10px 20px;display:flex;gap:10px;align-items:center">'
                   f'<span style="font:600 13px {_FONT};color:#fff;flex:1">CloudPulse Platform · {E(d["title"])}</span>'
                   f'<button onclick="window.print()" style="font:600 12px {_FONT};background:{AQUA};color:{INK};border:0;border-radius:6px;padding:7px 14px;cursor:pointer">🖨 Print / Save as PDF</button>'
                   f'</div>')
        script = ("<script>const __DOC=" + json.dumps(d, default=str).replace("</", "<\\/") + ";"
                  "function dlCsv(i){const s=__DOC.sections[i];const q=v=>'\"'+String(v==null?'':Array.isArray(v)?v.join('; '):v).replace(/\"/g,'\"\"')+'\"';"
                  "const csv=[s.columns.map(c=>q(c.label)).join(','),...s.rows.map(r=>s.columns.map(c=>q(r[c.key])).join(','))].join('\\n');"
                  "const a=document.createElement('a');a.href=URL.createObjectURL(new Blob(['\\ufeff'+csv],{type:'text/csv'}));"
                  "a.download=(__DOC.title+'-'+s.title).replace(/[^a-z0-9]+/gi,'-').toLowerCase()+'.csv';a.click();}</script>")
        print_css = ("<style>@media print{.noprint{display:none!important}body{background:#fff!important}"
                     ".sheet{box-shadow:none!important;margin:0!important;max-width:none!important}"
                     "thead{display:table-header-group}tr{page-break-inside:avoid}}@page{size:A4 landscape;margin:12mm}</style>")

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{E(d['title'])}</title>{_BASE_CSS}{print_css}</head>
<body style="margin:0;padding:0;background:#EEF2F3;-webkit-text-size-adjust:100%">{toolbar}
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#EEF2F3"><tr><td align="center" style="padding:24px 12px">
<table role="presentation" class="sheet" width="100%" cellpadding="0" cellspacing="0" style="max-width:1040px;background:#FFFFFF;border-radius:10px;box-shadow:0 2px 14px rgba(6,35,41,.08);overflow:hidden">
<tr><td style="height:6px;background:linear-gradient(90deg,{INK},{AQUA_DK},{AQUA});background-color:{AQUA_DK}"></td></tr>
<tr><td style="padding:22px 32px 14px">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
    <td style="vertical-align:middle"><img src="{logo_src}" alt="Organisation logo" height="34" style="height:34px;display:block;border:0"></td>
    <td align="right" style="vertical-align:middle;font:600 11px {_FONT};letter-spacing:1.2px;text-transform:uppercase;color:{AQUA_DK}">
      CloudPulse Platform<br><span style="color:{MUTED};letter-spacing:.4px;text-transform:none;font-weight:400">{E(d.get('category') or 'Report')}</span></td>
  </tr></table>
</td></tr>
<tr><td style="padding:4px 32px 0">
  <div style="font:700 24px {_FONT};color:{INK};line-height:1.25">{E(d['title'])}</div>
  {f'<div style="font:14px {_FONT};color:{MUTED};margin-top:4px">{E(d["subtitle"])}</div>' if d.get('subtitle') else ''}
  <div style="font:12px {_FONT};color:{MUTED};margin-top:10px;padding-bottom:14px;border-bottom:1px solid {LINE}">{meta}</div>
</td></tr>
<tr><td style="padding:14px 32px 4px">{_kpi_grid(d.get('kpis') or [])}</td></tr>
{f'''<tr><td style="padding:4px 32px 0"><div style="background:#F1FBFA;border:1px solid #BFEDE8;border-radius:8px;padding:12px 16px">
  <div style="font:700 11px {_FONT};letter-spacing:.8px;text-transform:uppercase;color:{AQUA_DK};margin-bottom:4px">Key points</div>
  <ul style="margin:0;padding-left:18px;font:13px {_FONT};color:{INK};line-height:1.5">{highlights}</ul></div></td></tr>''' if highlights else ''}
<tr><td style="padding:0 32px 26px">{sections}</td></tr>
<tr><td style="padding:14px 32px;background:{ZEBRA};border-top:1px solid {LINE};font:11.5px {_FONT};color:{MUTED}">
  Confidential — for internal use only. Generated automatically by CloudPulse Platform.
</td></tr>
</table></td></tr></table>{script}</body></html>"""


def csv_bytes(s: dict) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([c["label"] for c in s["columns"]])
    for r in s.get("rows") or []:
        w.writerow(["; ".join(map(str, v)) if isinstance(v, list) else ("" if v is None else v)
                    for v in (r.get(c["key"]) for c in s["columns"])])
    return ("\ufeff" + buf.getvalue()).encode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Running, storing, emailing
# ─────────────────────────────────────────────────────────────────────────────

async def ensure_columns() -> None:
    async with AsyncSessionLocal() as db:
        await db.execute(text("ALTER TABLE cloudpulse_report_history ADD COLUMN IF NOT EXISTS email_status TEXT"))
        await db.execute(text("ALTER TABLE cloudpulse_report_history ADD COLUMN IF NOT EXISTS recipients TEXT"))
        await db.commit()


def _recipients(raw: Optional[str]) -> list[str]:
    return [r.strip() for r in re.split(r"[,;\s]+", raw or "") if "@" in r]


async def email_report(d: dict, recipients: list[str], report_id: Optional[int]) -> str:
    from app.services import mail_service
    if not recipients:
        return "not sent (no recipients)"
    logo = open(LOGO_PATH, "rb").read() if os.path.exists(LOGO_PATH) else None
    body = render_html(d, "email", logo_src="cid:org-logo" if logo else "", report_id=report_id)
    attachments = [(_csv_name(s, i), csv_bytes(s)) for i, s in enumerate(d.get("sections") or [])
                   if s["kind"] == "table" and s.get("rows")]
    subject = f"Windows Ops · {d['title']} · {datetime.now(GST):%d %b %Y}"
    r = await mail_service.send_report_email(recipients, subject, body,
                                             inline_images={"org-logo": logo} if logo else None,
                                             attachments=attachments)
    return f"sent to {len(recipients)}" if r.get("ok") else f"failed: {r.get('error')}"


async def run_and_store(rtype: str, filters: dict, name: str, schedule_id: Optional[int],
                        recipients: Optional[str], send: bool = True) -> dict:
    await ensure_columns()
    t0 = time.monotonic()
    d, status, err = {}, "success", None
    try:
        d = await generate(rtype, filters)
    except Exception as e:
        log.warning("Report %s (%s) failed: %s", name, rtype, e)
        status, err = "error", str(e)[:500]
    duration = round(time.monotonic() - t0, 2)
    async with AsyncSessionLocal() as db:
        rid = (await db.execute(text("""
            INSERT INTO cloudpulse_report_history
                (schedule_id, schedule_name, report_type, status, duration_seconds, row_count,
                 error_message, report_data, filters, recipients)
            VALUES (:sid, :name, :rtype, :status, :dur, :rows, :err, CAST(:data AS JSONB), CAST(:filt AS JSONB), :rcpt)
            RETURNING id
        """), {"sid": schedule_id, "name": name, "rtype": rtype, "status": status, "dur": duration,
               "rows": row_count(d), "err": err, "data": json.dumps(d, default=str),
               "filt": json.dumps(filters or {}), "rcpt": recipients or ""})).scalar()
        if schedule_id:
            await db.execute(text("UPDATE cloudpulse_scheduled_reports SET last_run_at = NOW() WHERE id = :id"), {"id": schedule_id})
        await db.commit()
    email_status = None
    if status == "success" and send:
        email_status = await email_report(d, _recipients(recipients), rid)
        async with AsyncSessionLocal() as db:
            await db.execute(text("UPDATE cloudpulse_report_history SET email_status = :e WHERE id = :id"),
                             {"e": email_status, "id": rid})
            await db.commit()
    return {"ok": status == "success", "id": rid, "status": status, "error": err, "duration_seconds": duration,
            "row_count": row_count(d), "email_status": email_status}


async def run_due() -> int:
    """Execute every enabled schedule whose next_run_at has passed, then roll next_run_at forward."""
    from app.routers.scheduled_reports_router import _ensure_tables, _next_run
    await _ensure_tables()
    async with AsyncSessionLocal() as db:
        due = (await db.execute(text("""
            SELECT id, name, report_type, filters, recipients, frequency, hour, minute, day_of_week, day_of_month
            FROM cloudpulse_scheduled_reports
            WHERE enabled = TRUE AND next_run_at IS NOT NULL AND next_run_at <= NOW()
            ORDER BY next_run_at
        """))).fetchall()
    for s in due:
        filters = s.filters if isinstance(s.filters, dict) else json.loads(s.filters or "{}")
        log.info("Running scheduled report #%d %s (%s)", s.id, s.name, s.report_type)
        res = await run_and_store(s.report_type, filters, s.name, s.id, s.recipients)
        log.info("Scheduled report #%d → %s, email: %s", s.id, res["status"], res["email_status"])
        nxt = _next_run(s.frequency, s.hour, s.minute, s.day_of_week, s.day_of_month)
        async with AsyncSessionLocal() as db:
            await db.execute(text("UPDATE cloudpulse_scheduled_reports SET next_run_at = :n WHERE id = :id"),
                             {"n": nxt, "id": s.id})
            await db.commit()
    return len(due)


async def scheduled_tick() -> None:
    from app.services import teams_alert_service as tas
    await tas._run_locked(REPORTS_LOCK_ID, "reports_due", run_due)
