"""
Reports router — reads from infraguardian_capacity_daily and hourly tables.
All data is historical; no live ES calls here.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from app.auth import get_current_user
from app.database import AsyncSessionLocal

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/fleet-trend")
async def fleet_trend(
    days: int = Query(14, ge=1, le=90),
    _: dict = Depends(get_current_user),
):
    """Daily fleet-wide average CPU / memory / disk over the last N days."""
    try:
        async with AsyncSessionLocal() as db:
            rows = await db.execute(text("""
                SELECT report_date,
                       ROUND(AVG(avg_cpu_pct)::numeric,  1) AS avg_cpu,
                       ROUND(AVG(avg_mem_pct)::numeric,  1) AS avg_mem,
                       ROUND(AVG(avg_disk_pct)::numeric, 1) AS avg_disk,
                       ROUND(SUM(total_mem_gb)::numeric,  1) AS fleet_total_mem_gb,
                       ROUND(SUM(used_mem_gb)::numeric,   1) AS fleet_used_mem_gb,
                       ROUND(SUM(total_disk_gb)::numeric, 1) AS fleet_total_disk_gb,
                       ROUND(SUM(used_disk_gb)::numeric,  1) AS fleet_used_disk_gb,
                       COUNT(*) AS server_count
                FROM infraguardian_capacity_daily
                WHERE report_date >= CURRENT_DATE - CAST(:days AS INTEGER)
                GROUP BY report_date
                ORDER BY report_date
            """), {"days": days})
            cols = ["date", "avg_cpu", "avg_mem", "avg_disk",
                    "fleet_total_mem_gb", "fleet_used_mem_gb",
                    "fleet_total_disk_gb", "fleet_used_disk_gb", "server_count"]
            data = [dict(zip(cols, r)) for r in rows.fetchall()]
            for d in data:
                d["date"] = str(d["date"])
        return {"days": days, "trend": data}
    except Exception as e:
        return {"days": days, "trend": [], "error": str(e)}


@router.get("/server/{server_name}")
async def server_report(
    server_name: str,
    days: int = Query(30, ge=1, le=365),
    _: dict = Depends(get_current_user),
):
    """Per-server daily history with GB data for trend / growth analysis."""
    try:
        async with AsyncSessionLocal() as db:
            rows = await db.execute(text("""
                SELECT report_date,
                       COALESCE(avg_cpu_pct,  0) AS avg_cpu,
                       COALESCE(avg_mem_pct,  0) AS avg_mem,
                       COALESCE(avg_disk_pct, 0) AS avg_disk,
                       COALESCE(total_mem_gb,  0) AS total_mem_gb,
                       COALESCE(used_mem_gb,   0) AS used_mem_gb,
                       COALESCE(free_mem_gb,   0) AS free_mem_gb,
                       COALESCE(total_disk_gb, 0) AS total_disk_gb,
                       COALESCE(used_disk_gb,  0) AS used_disk_gb,
                       COALESCE(free_disk_gb,  0) AS free_disk_gb,
                       disk_details, os_name, host_ip
                FROM infraguardian_capacity_daily
                WHERE server_name = :srv
                  AND report_date >= CURRENT_DATE - CAST(:days AS INTEGER)
                ORDER BY report_date
            """), {"srv": server_name, "days": days})
            cols = ["date", "avg_cpu", "avg_mem", "avg_disk",
                    "total_mem_gb", "used_mem_gb", "free_mem_gb",
                    "total_disk_gb", "used_disk_gb", "free_disk_gb",
                    "disk_details", "os_name", "host_ip"]
            history = []
            for r in rows.fetchall():
                row = dict(zip(cols, r))
                row["date"] = str(row["date"])
                # Compute free if not stored
                if not row["free_mem_gb"] and row["total_mem_gb"] and row["used_mem_gb"]:
                    row["free_mem_gb"] = round(row["total_mem_gb"] - row["used_mem_gb"], 1)
                if not row["free_disk_gb"] and row["total_disk_gb"] and row["used_disk_gb"]:
                    row["free_disk_gb"] = round(row["total_disk_gb"] - row["used_disk_gb"], 1)
                history.append(row)

        # Simple linear growth projection (avg daily delta × 30 days)
        growth = {}
        if len(history) >= 3:
            first, last = history[0], history[-1]
            n = len(history) - 1
            for col in ("avg_cpu", "avg_mem", "avg_disk", "used_mem_gb", "used_disk_gb"):
                try:
                    delta_per_day = ((last.get(col) or 0) - (first.get(col) or 0)) / n
                    growth[col] = {
                        "daily_delta": round(delta_per_day, 2),
                        "projected_30d": round((last.get(col) or 0) + delta_per_day * 30, 2),
                    }
                except Exception:
                    pass

        return {"server": server_name, "days": days, "history": history, "growth_projection": growth}
    except Exception as e:
        return {"server": server_name, "days": days, "history": [], "growth_projection": {}, "error": str(e)}


@router.get("/top-consumers")
async def top_consumers(
    days: int = Query(7, ge=1, le=30),
    metric: str = Query("avg_cpu_pct"),
    limit: int = Query(20, ge=1, le=100),
    _: dict = Depends(get_current_user),
):
    """Top N servers by average metric over the last N days (from daily DB)."""
    allowed = {"avg_cpu_pct", "avg_mem_pct", "avg_disk_pct",
               "used_mem_gb", "used_disk_gb"}
    if metric not in allowed:
        metric = "avg_cpu_pct"
    try:
        async with AsyncSessionLocal() as db:
            rows = await db.execute(text(f"""
                SELECT server_name,
                       COALESCE(MAX(os_name), '') AS os_name,
                       ROUND(AVG(COALESCE(avg_cpu_pct,  0))::numeric, 1) AS avg_cpu,
                       ROUND(AVG(COALESCE(avg_mem_pct,  0))::numeric, 1) AS avg_mem,
                       ROUND(AVG(COALESCE(avg_disk_pct, 0))::numeric, 1) AS avg_disk,
                       ROUND(AVG(COALESCE(used_mem_gb,  0))::numeric, 1) AS avg_used_mem_gb,
                       ROUND(AVG(COALESCE(used_disk_gb, 0))::numeric, 1) AS avg_used_disk_gb,
                       COUNT(*) AS days_seen
                FROM infraguardian_capacity_daily
                WHERE report_date >= CURRENT_DATE - CAST(:days AS INTEGER)
                GROUP BY server_name
                ORDER BY AVG(COALESCE({metric}, 0)) DESC NULLS LAST
                LIMIT :limit
            """), {"days": days, "limit": limit})
            cols = ["server", "os_name", "avg_cpu", "avg_mem", "avg_disk",
                    "avg_used_mem_gb", "avg_used_disk_gb", "days_seen"]
            return {"days": days, "metric": metric, "servers": [dict(zip(cols, r)) for r in rows.fetchall()]}
    except Exception as e:
        return {"days": days, "metric": metric, "servers": [], "error": str(e)}


@router.get("/hourly/{server_name}")
async def server_hourly(
    server_name: str,
    hours: int = Query(24, ge=1, le=48),
    _: dict = Depends(get_current_user),
):
    """Hourly snapshots for one server (up to 48h of intraday data)."""
    try:
        async with AsyncSessionLocal() as db:
            rows = await db.execute(text("""
                SELECT collected_at,
                       COALESCE(cpu_pct,0) AS cpu_pct,
                       COALESCE(mem_pct,0) AS mem_pct,
                       COALESCE(total_mem_gb,0) AS total_mem_gb,
                       COALESCE(used_mem_gb,0) AS used_mem_gb,
                       COALESCE(disk_pct,0) AS disk_pct,
                       COALESCE(total_disk_gb,0) AS total_disk_gb,
                       COALESCE(used_disk_gb,0) AS used_disk_gb
                FROM infraguardian_capacity_hourly
                WHERE server_name = :srv
                  AND collected_at >= NOW() - make_interval(hours => CAST(:hours AS INTEGER))
                ORDER BY collected_at
            """), {"srv": server_name, "hours": hours})
            cols = ["ts", "cpu_pct", "mem_pct", "total_mem_gb", "used_mem_gb",
                    "disk_pct", "total_disk_gb", "used_disk_gb"]
            data = []
            for r in rows.fetchall():
                row = dict(zip(cols, r))
                row["ts"] = row["ts"].isoformat() if row["ts"] else None
                data.append(row)
        return {"server": server_name, "hours": hours, "snapshots": data}
    except Exception as e:
        return {"server": server_name, "hours": hours, "snapshots": [], "error": str(e)}


@router.get("/summary-stats")
async def summary_stats(_: dict = Depends(get_current_user)):
    """Quick stats for the dashboard header cards."""
    async with AsyncSessionLocal() as db:
        row = await db.execute(text("""
            SELECT
                COUNT(DISTINCT server_name) AS total_servers,
                ROUND(AVG(avg_cpu_pct)::numeric,  1) AS fleet_avg_cpu,
                ROUND(AVG(avg_mem_pct)::numeric,  1) AS fleet_avg_mem,
                ROUND(AVG(avg_disk_pct)::numeric, 1) AS fleet_avg_disk,
                COUNT(*) FILTER (WHERE avg_cpu_pct  >= 90) AS cpu_critical,
                COUNT(*) FILTER (WHERE avg_mem_pct  >= 90) AS mem_critical,
                COUNT(*) FILTER (WHERE avg_disk_pct >= 90) AS disk_critical
            FROM infraguardian_capacity_daily
            WHERE report_date = (SELECT MAX(report_date) FROM infraguardian_capacity_daily)
        """))
        r = row.fetchone()
        if r:
            return {
                "total_servers":  r[0],
                "fleet_avg_cpu":  r[1],
                "fleet_avg_mem":  r[2],
                "fleet_avg_disk": r[3],
                "cpu_critical":   r[4],
                "mem_critical":   r[5],
                "disk_critical":  r[6],
            }
        return {}
