"""
Capacity forecasting in absolute units — vCPU, memory GB, disk GB — for the fleet,
a project or a single server.

  vCPU used  = server vCPU (inventory) × daily average CPU %
  Memory GB  = used_mem_gb   (capacity is total_mem_gb)
  Disk GB    = used_disk_gb  (capacity is total_disk_gb)

Daily totals are regressed linearly (same maths as the % forecasts). Forecasts are capped
at physical capacity — usage cannot exceed what exists — and "days to 90% / full" says
when the trend gets there. Confidence reflects how much history the trend is based on.
"""
from __future__ import annotations
from collections import defaultdict
from datetime import date, timedelta
from typing import Any, Optional

from sqlalchemy import text

from app.database import AsyncSessionLocal
from app.services import inventory_service as inv
from app.services.prediction_service import _linear_regression

HORIZONS = [30, 90, 180, 365]
METRICS = {
    "cpu":    {"label": "CPU",    "unit": "vCPU"},
    "memory": {"label": "Memory", "unit": "GB"},
    "disk":   {"label": "Disk",   "unit": "GB"},
}


def _confidence(days: int, r2: float) -> str:
    if days < 14:
        return "low"
    if days < 45 or r2 < 0.3:
        return "medium"
    return "high"


def _direction(delta: float, capacity: float, current: float = 0.0) -> str:
    """▲ / ▼ when the change is at least 2% of today's value (or 0.2% of capacity), else ▶."""
    eps = max(0.02 * (current or 0), 0.002 * (capacity or 0), 0.05)
    return "up" if delta > eps else "down" if delta < -eps else "flat"


async def _load(lookback_days: int) -> tuple[list[dict], dict[str, dict]]:
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(text("""
            SELECT server_name, report_date, avg_cpu_pct, total_mem_gb, used_mem_gb, total_disk_gb, used_disk_gb
            FROM infraguardian_capacity_daily
            WHERE report_date >= CURRENT_DATE - CAST(:d AS INTEGER)
            ORDER BY report_date
        """), {"d": lookback_days})).fetchall()
    servers = {s["server_key"]: s for s in await inv.list_servers()}
    out = []
    for r in rows:
        s = servers.get(inv.key_of(r.server_name), {})
        vcpu = s.get("vcpu")
        out.append({
            "server": r.server_name, "key": inv.key_of(r.server_name), "day": r.report_date,
            "project": s.get("project_effective", "Unassigned"), "environment": s.get("environment_effective", ""),
            "cpu_cap": float(vcpu) if vcpu else None,
            "cpu": float(vcpu) * float(r.avg_cpu_pct or 0) / 100 if vcpu else None,
            "memory_cap": float(r.total_mem_gb or 0) or None, "memory": float(r.used_mem_gb or 0),
            "disk_cap": float(r.total_disk_gb or 0) or None, "disk": float(r.used_disk_gb or 0),
        })
    return out, servers


MIN_TREND_DAYS = 14   # below this a linear trend is noise — forecasts stay flat at today's value


def _server_model(rs: list[dict], metric: str) -> Optional[dict]:
    """Per-server linear model for one metric: current, capacity, slope (0 when history is too short)."""
    pts = [(r["day"], r[metric]) for r in rs if r[metric] is not None and r[f"{metric}_cap"]]
    if not pts:
        return None
    cap = rs[-1][f"{metric}_cap"] or 0.0
    d0 = pts[0][0]
    x = [float((d - d0).days) for d, _ in pts]
    y = [v for _, v in pts]
    trend_ok = len(set(x)) >= MIN_TREND_DAYS
    slope, _, r2 = _linear_regression(x, y) if trend_ok else (0.0, 0.0, 0.0)
    return {"cap": cap, "current": y[-1], "slope": slope, "r2": r2, "days": len(set(x)), "trend_ok": trend_ok}


def _project(model: dict, h: int) -> float:
    return max(0.0, min(model["current"] + model["slope"] * h, model["cap"])) if model["cap"] else max(0.0, model["current"])


def _days_to(current: float, slope: float, cap: float, frac: float) -> Optional[int]:
    if not cap:
        return None
    target = frac * cap
    if current >= target:
        return 0
    if slope <= 0:
        return None
    d = (target - current) / slope
    return int(d) + 1 if d <= 3650 else None


def _summarise(rows: list[dict]) -> dict:
    """Aggregate = sum of per-server models (each capped at its own capacity)."""
    if not rows:
        return {"servers": 0, "history_days": 0, "first_day": None, "last_day": None, "confidence": "low",
                "trend_available": False, "min_trend_days": MIN_TREND_DAYS,
                "metrics": {m: {**METRICS[m], "capacity": 0, "current": 0, "forecast": []} for m in METRICS}, "history": []}
    last_day = max(r["day"] for r in rows)
    by_server: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_server[r["key"]].append(r)
    live = {k: rs for k, rs in by_server.items() if rs[-1]["day"] == last_day}   # servers still reporting
    days = sorted({r["day"] for r in rows})
    metrics, r2s, trend_any = {}, [], False
    for m in METRICS:
        models = [md for rs in live.values() if (md := _server_model(rs, m))]
        cap = sum(md["cap"] for md in models)
        cur = sum(md["current"] for md in models)
        slope = sum(md["slope"] for md in models)
        trend_any = trend_any or any(md["trend_ok"] for md in models)
        r2s += [md["r2"] for md in models if md["trend_ok"]]
        fc = []
        for h in HORIZONS:
            val = sum(_project(md, h) for md in models)
            delta = val - cur
            fc.append({"days": h, "value": round(val, 1), "pct": round(100 * val / cap, 1) if cap else None,
                       "delta": round(delta, 1), "delta_pct": round(100 * delta / cur, 1) if cur else None,
                       "direction": _direction(delta, cap, cur),
                       "capped": any(md["cap"] and md["current"] + md["slope"] * h > md["cap"] for md in models)})
        metrics[m] = {**METRICS[m], "capacity": round(cap, 1), "current": round(cur, 1),
                      "current_pct": round(100 * cur / cap, 1) if cap else None, "free": round(max(0.0, cap - cur), 1),
                      "slope_per_day": round(slope, 3), "trend": _direction(slope * 30, cap, cur),
                      "days_to_90": _days_to(cur, slope, cap, 0.9), "days_to_full": _days_to(cur, slope, cap, 1.0),
                      "servers_over_90": sum(1 for md in models if md["cap"] and md["current"] >= 0.9 * md["cap"]),
                      "forecast": fc}
    # Display history: daily totals over servers still reporting
    hist = defaultdict(lambda: defaultdict(float))
    for k, rs in live.items():
        for r in rs:
            for m in METRICS:
                if r[m] is not None and r[f"{m}_cap"]:
                    hist[r["day"]][m] += r[m]
    avg_r2 = sum(r2s) / len(r2s) if r2s else 0.0
    return {
        "servers": len(live), "history_days": len(days), "first_day": str(days[0]), "last_day": str(days[-1]),
        "confidence": _confidence(len(days), avg_r2) if trend_any else "low",
        "trend_available": trend_any, "min_trend_days": MIN_TREND_DAYS, "metrics": metrics,
        "history": [{"date": str(d), **{m: round(hist[d][m], 1) for m in METRICS}} for d in sorted(hist)],
    }


def _server_rows(rows: list[dict], horizon: int) -> list[dict]:
    by_server: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_server[r["key"]].append(r)
    hi = HORIZONS.index(horizon) if horizon in HORIZONS else 2
    out = []
    for key, rs in by_server.items():
        s = _summarise(rs)
        last = rs[-1]
        row: dict[str, Any] = {"server": last["server"], "project": last["project"], "environment": last["environment"],
                               "history_days": s["history_days"]}
        pressure = 0.0
        for m, v in s["metrics"].items():
            if not v.get("forecast"):
                continue
            f = v["forecast"][hi]
            row.update({f"{m}_cap": v["capacity"], f"{m}_now": v["current"], f"{m}_pct": v["current_pct"],
                        f"{m}_fc": f["value"], f"{m}_delta": f["delta"], f"{m}_dir": f["direction"],
                        f"{m}_pct_fc": f["pct"], f"{m}_days_to_90": v["days_to_90"]})
            pressure = max(pressure, f["pct"] or 0)
        row["pressure"] = round(pressure, 1)      # highest forecast utilisation across metrics
        out.append(row)
    return sorted(out, key=lambda r: -r["pressure"])


async def forecast(scope: str = "fleet", name: Optional[str] = None, lookback_days: int = 90,
                   horizon: int = 180) -> dict:
    """scope: fleet | project | server."""
    rows, _ = await _load(lookback_days)
    if scope == "project":
        rows = [r for r in rows if r["project"] == name]
    elif scope == "server":
        k = inv.key_of(name or "")
        rows = [r for r in rows if r["key"] == k]
    title = {"fleet": "Whole fleet", "project": f"Project: {name}", "server": name}.get(scope, scope)
    result = {"scope": scope, "name": name, "title": title, "lookback_days": lookback_days,
              "horizons": HORIZONS, "horizon": horizon, **_summarise(rows)}
    if scope != "server":
        result["server_rows"] = _server_rows(rows, horizon)
    return result


async def projects_summary(lookback_days: int = 90, horizon: int = 180) -> dict:
    rows, servers = await _load(lookback_days)
    by_project: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_project[r["project"]].append(r)
    hi = HORIZONS.index(horizon) if horizon in HORIZONS else 2
    envs = defaultdict(set)
    for s in servers.values():
        if s.get("environment_effective"):
            envs[s["project_effective"]].add(s["environment_effective"])
    out = []
    for p, rs in by_project.items():
        s = _summarise(rs)
        row = {"project": p, "servers": s["servers"], "environments": sorted(envs.get(p, [])),
               "history_days": s["history_days"], "confidence": s["confidence"]}
        for m, v in s["metrics"].items():
            f = v["forecast"][hi]
            row.update({f"{m}_cap": v["capacity"], f"{m}_now": v["current"], f"{m}_pct": v["current_pct"],
                        f"{m}_fc": f["value"], f"{m}_pct_fc": f["pct"], f"{m}_delta": f["delta"],
                        f"{m}_dir": f["direction"], f"{m}_days_to_90": v["days_to_90"]})
        out.append(row)
    out.sort(key=lambda r: (r["project"] == "Unassigned", -r["servers"]))
    return {"horizon": horizon, "horizons": HORIZONS, "lookback_days": lookback_days, "projects": out}
