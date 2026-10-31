"""
AI Capacity Prediction Service
Uses linear regression on historical daily data to forecast capacity trends.
Supports per-server and fleet-wide predictions with confidence intervals.
All timestamps in GST (UTC+4).
"""
from __future__ import annotations
import math
from datetime import date, datetime, timedelta, timezone
from typing import Optional
from sqlalchemy import text
from app.database import AsyncSessionLocal

# GST = UTC+4
GST = timezone(timedelta(hours=4))


def _now_gst() -> datetime:
    return datetime.now(GST)


def _gst_date() -> date:
    return _now_gst().date()


# ── Linear Regression ─────────────────────────────────────────────────────────

def _linear_regression(x: list[float], y: list[float]) -> tuple[float, float, float]:
    """
    Returns (slope, intercept, r_squared).
    x = numeric day indices (0, 1, 2, …), y = metric values (0–100 or GB).
    """
    n = len(x)
    if n < 2:
        return 0.0, y[0] if y else 0.0, 0.0

    sx = sum(x); sy = sum(y)
    sxx = sum(xi**2 for xi in x)
    sxy = sum(xi*yi for xi, yi in zip(x, y))

    denom = n * sxx - sx**2
    if abs(denom) < 1e-9:
        return 0.0, sy / n, 0.0

    slope = (n * sxy - sx * sy) / denom
    intercept = (sy - slope * sx) / n

    # R²
    y_mean = sy / n
    ss_tot = sum((yi - y_mean)**2 for yi in y)
    ss_res = sum((yi - (slope*xi + intercept))**2 for xi, yi in zip(x, y))
    r2 = 1.0 - (ss_res / ss_tot) if ss_tot > 1e-9 else 1.0

    return slope, intercept, r2


def _confidence_band(x: list[float], y: list[float], slope: float, intercept: float,
                     forecast_x: list[float], z: float = 1.645) -> tuple[list[float], list[float]]:
    """
    Returns (lower_bound, upper_bound) for forecast_x.
    z=1.645 → 90% confidence interval.
    """
    n = len(x)
    if n < 3:
        flat = [0.0]*len(forecast_x)
        return flat, flat

    # Residual standard error
    residuals = [(yi - (slope*xi + intercept))**2 for xi, yi in zip(x, y)]
    mse = sum(residuals) / (n - 2) if n > 2 else sum(residuals)
    se = math.sqrt(mse)

    x_mean = sum(x) / n
    sxx = sum((xi - x_mean)**2 for xi in x)

    lower, upper = [], []
    for fx in forecast_x:
        leverage = math.sqrt(1/n + (fx - x_mean)**2 / (sxx if sxx > 0 else 1))
        margin = z * se * leverage
        predicted = slope * fx + intercept
        lower.append(max(0.0, predicted - margin))
        upper.append(min(100.0, predicted + margin))
    return lower, upper


def _days_to_threshold(slope: float, intercept: float, current_day: int, threshold: float) -> Optional[int]:
    """Days from current_day until predicted value >= threshold. None if never."""
    if slope <= 0:
        return None
    days = (threshold - intercept) / slope - current_day
    if days < 0:
        return 0   # already past threshold
    if days > 730:
        return None
    return int(math.ceil(days))


# ── Fleet Prediction ───────────────────────────────────────────────────────────

async def get_fleet_forecast(forecast_days: int = 365, lookback_days: int = 90) -> dict:
    """
    Fleet-wide average CPU/memory/disk forecast.
    Returns historical series + forecasted series + confidence bands.
    """
    async with AsyncSessionLocal() as db:
        rows = await db.execute(text("""
            SELECT report_date,
                   ROUND(AVG(avg_cpu_pct)::numeric,  1) AS avg_cpu,
                   ROUND(AVG(avg_mem_pct)::numeric,  1) AS avg_mem,
                   ROUND(AVG(avg_disk_pct)::numeric, 1) AS avg_disk,
                   COUNT(*) AS server_count
            FROM infraguardian_capacity_daily
            WHERE report_date >= CURRENT_DATE - CAST(:days AS INTEGER)
            GROUP BY report_date
            ORDER BY report_date
        """), {"days": lookback_days})
        history = rows.fetchall()

    if not history:
        return {"ok": False, "error": "No historical data available"}

    dates = [str(r[0]) for r in history]
    cpu_v  = [float(r[1] or 0) for r in history]
    mem_v  = [float(r[2] or 0) for r in history]
    disk_v = [float(r[3] or 0) for r in history]
    x = list(range(len(dates)))

    # Forecast x indices
    last_date = history[-1][0]
    fc_x = list(range(len(x), len(x) + forecast_days))
    fc_dates = [(last_date + timedelta(days=i+1)).isoformat() for i in range(forecast_days)]

    result = {"lookback_days": lookback_days, "forecast_days": forecast_days,
              "history_dates": dates, "forecast_dates": fc_dates,
              "generated_at": _now_gst().isoformat(), "metrics": {}}

    for metric, values in [("cpu", cpu_v), ("memory", mem_v), ("disk", disk_v)]:
        slope, intercept, r2 = _linear_regression(x, values)
        fc_values = [min(100.0, max(0.0, slope*fx + intercept)) for fx in fc_x]
        lo, hi = _confidence_band(x, values, slope, intercept, fc_x)

        current_idx = x[-1]
        result["metrics"][metric] = {
            "historical":     values,
            "forecast":       [round(v, 1) for v in fc_values],
            "confidence_low": [round(v, 1) for v in lo],
            "confidence_high":[round(v, 1) for v in hi],
            "slope_per_day":  round(slope, 4),
            "r_squared":      round(r2, 3),
            "current_value":  values[-1],
            "days_to_80":     _days_to_threshold(slope, intercept, current_idx, 80),
            "days_to_90":     _days_to_threshold(slope, intercept, current_idx, 90),
            "trend":          "rising" if slope > 0.05 else "falling" if slope < -0.05 else "stable",
        }

    return result


async def get_server_forecast(server_name: str, forecast_days: int = 365, lookback_days: int = 90) -> dict:
    """Per-server capacity forecast."""
    async with AsyncSessionLocal() as db:
        rows = await db.execute(text("""
            SELECT report_date, avg_cpu_pct, avg_mem_pct, avg_disk_pct,
                   total_disk_gb, used_disk_gb, total_mem_gb, used_mem_gb
            FROM infraguardian_capacity_daily
            WHERE server_name = :srv
              AND report_date >= CURRENT_DATE - CAST(:days AS INTEGER)
            ORDER BY report_date
        """), {"srv": server_name, "days": lookback_days})
        history = rows.fetchall()

    if not history:
        return {"ok": False, "error": f"No data found for {server_name}"}

    dates  = [str(r[0]) for r in history]
    cpu_v  = [float(r[1] or 0) for r in history]
    mem_v  = [float(r[2] or 0) for r in history]
    disk_v = [float(r[3] or 0) for r in history]
    disk_gb_total = float(history[-1][4] or 0)
    mem_gb_total  = float(history[-1][6] or 0)
    x = list(range(len(dates)))

    last_date = history[-1][0]
    fc_x     = list(range(len(x), len(x) + forecast_days))
    fc_dates = [(last_date + timedelta(days=i+1)).isoformat() for i in range(forecast_days)]

    result = {"server": server_name, "lookback_days": lookback_days, "forecast_days": forecast_days,
              "history_dates": dates, "forecast_dates": fc_dates,
              "disk_gb_total": disk_gb_total, "mem_gb_total": mem_gb_total,
              "generated_at": _now_gst().isoformat(), "metrics": {}}

    for metric, values in [("cpu", cpu_v), ("memory", mem_v), ("disk", disk_v)]:
        slope, intercept, r2 = _linear_regression(x, values)
        fc_values = [min(100.0, max(0.0, slope*fx + intercept)) for fx in fc_x]
        lo, hi = _confidence_band(x, values, slope, intercept, fc_x)
        current_idx = x[-1]
        result["metrics"][metric] = {
            "historical":     values,
            "forecast":       [round(v, 1) for v in fc_values],
            "confidence_low": [round(v, 1) for v in lo],
            "confidence_high":[round(v, 1) for v in hi],
            "slope_per_day":  round(slope, 4),
            "r_squared":      round(r2, 3),
            "current_value":  values[-1],
            "days_to_80":     _days_to_threshold(slope, intercept, current_idx, 80),
            "days_to_90":     _days_to_threshold(slope, intercept, current_idx, 90),
            "trend":          "rising" if slope > 0.05 else "falling" if slope < -0.05 else "stable",
        }

    return result


async def get_capacity_risk_report(horizon_days: int = 180) -> dict:
    """
    Returns servers projected to breach 80% or 90% thresholds within horizon_days.
    Sorted by risk severity.
    """
    async with AsyncSessionLocal() as db:
        # Get distinct servers with enough history
        servers = await db.execute(text("""
            SELECT DISTINCT server_name
            FROM infraguardian_capacity_daily
            WHERE report_date >= CURRENT_DATE - 30
        """))
        server_names = [r[0] for r in servers.fetchall()]

    at_risk = []
    for srv in server_names:
        try:
            forecast = await get_server_forecast(srv, horizon_days, lookback_days=60)
            if not forecast.get("metrics"):
                continue
            for metric in ("cpu", "memory", "disk"):
                m = forecast["metrics"].get(metric, {})
                d80 = m.get("days_to_80")
                d90 = m.get("days_to_90")
                if d80 is not None or d90 is not None:
                    at_risk.append({
                        "server":       srv,
                        "metric":       metric,
                        "current_pct":  m.get("current_value", 0),
                        "trend":        m.get("trend"),
                        "days_to_80":   d80,
                        "days_to_90":   d90,
                        "slope_per_day": m.get("slope_per_day"),
                        "r_squared":    m.get("r_squared"),
                        "risk_level":   "critical" if (d90 is not None and d90 <= 30) else
                                       "high"     if (d90 is not None and d90 <= 90) else
                                       "medium"   if (d80 is not None and d80 <= 60) else "low",
                    })
        except Exception:
            continue

    # Sort: critical first, then by days_to_90 ascending
    at_risk.sort(key=lambda r: (
        {"critical":0,"high":1,"medium":2,"low":3}.get(r["risk_level"],4),
        r.get("days_to_90") or r.get("days_to_80") or 999
    ))

    return {
        "horizon_days": horizon_days,
        "servers_at_risk": at_risk,
        "risk_counts": {
            "critical": sum(1 for r in at_risk if r["risk_level"] == "critical"),
            "high":     sum(1 for r in at_risk if r["risk_level"] == "high"),
            "medium":   sum(1 for r in at_risk if r["risk_level"] == "medium"),
            "low":      sum(1 for r in at_risk if r["risk_level"] == "low"),
        },
        "generated_at": _now_gst().isoformat(),
    }


async def get_fleet_servers() -> list[str]:
    """
    Return all server names that have capacity data.
    Primary source: infraguardian_capacity_daily (DB).
    Fallback: live Elasticsearch aggregation when DB is empty.
    """
    async with AsyncSessionLocal() as db:
        rows = await db.execute(text("""
            SELECT DISTINCT server_name
            FROM infraguardian_capacity_daily
            WHERE report_date >= CURRENT_DATE - 90
            ORDER BY server_name
        """))
        servers = [r[0] for r in rows.fetchall()]

    if servers:
        return servers

    # DB is empty (first deployment, daily job hasn't run yet).
    # Fall back to live ES to populate the dropdown.
    try:
        from app.services.es_service import list_windows_servers
        return await list_windows_servers(limit=200)
    except Exception:
        return []


async def generate_fleet_narrative(forecast: dict) -> str:
    """Use LLM to generate a natural-language capacity summary from the forecast data."""
    from app.services.llm_service import chat_completion
    metrics = forecast.get("metrics", {})
    cpu_m  = metrics.get("cpu", {})
    mem_m  = metrics.get("memory", {})
    disk_m = metrics.get("disk", {})
    horizon = forecast.get("forecast_days", 365)
    horizon_label = f"{horizon//365} year" if horizon >= 365 else f"{horizon} days"

    context = f"""Fleet capacity forecast summary for the next {horizon_label}:
- CPU: currently {cpu_m.get('current_value',0):.1f}%, trend={cpu_m.get('trend')}, days to 80%={cpu_m.get('days_to_80','N/A')}, days to 90%={cpu_m.get('days_to_90','N/A')}
- Memory: currently {mem_m.get('current_value',0):.1f}%, trend={mem_m.get('trend')}, days to 80%={mem_m.get('days_to_80','N/A')}, days to 90%={mem_m.get('days_to_90','N/A')}
- Disk: currently {disk_m.get('current_value',0):.1f}%, trend={disk_m.get('trend')}, days to 80%={disk_m.get('days_to_80','N/A')}, days to 90%={disk_m.get('days_to_90','N/A')}"""

    system = """You are an expert infrastructure capacity analyst.
Write a concise 3-4 sentence executive summary of the fleet capacity forecast.
Be specific with numbers and timeframes. Use natural, professional language.
Flag any urgent concerns. End with a clear recommendation."""
    try:
        return await chat_completion(system, context)
    except Exception:
        return "Capacity forecast generated. Review the charts for detailed trend analysis."
