"""Capacity dashboard routes — ES read-only, no writes to ES."""
from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text

from app.auth import get_current_user
from app.database import AsyncSessionLocal
from app.services import es_service

router = APIRouter(prefix="/api/capacity", tags=["capacity"])


@router.get("/dashboard")
async def dashboard(
    minutes: int = Query(60, ge=5, le=1440),
    _: dict = Depends(get_current_user),
):
    """Top 20 by CPU, top 20 by memory, top 20 by disk — live from ES."""
    import asyncio
    cpu, mem, disk, fleet = await asyncio.gather(
        es_service.get_top_servers("cpu",    20, minutes),
        es_service.get_top_servers("memory", 20, minutes),
        es_service.get_top_servers("disk",   20, minutes),
        es_service.get_fleet_summary(minutes),
    )
    return {"cpu": cpu, "memory": mem, "disk": disk,
            "fleet": fleet, "window_minutes": minutes}


@router.get("/top20/{metric}")
async def top20(
    metric: str,
    minutes: int = Query(60, ge=5, le=1440),
    _: dict = Depends(get_current_user),
):
    """Top 20 Windows Servers for a specific metric (cpu|memory|disk) — live ES."""
    if metric not in ("cpu", "memory", "disk"):
        raise HTTPException(status_code=400, detail="metric must be cpu, memory, or disk")
    results = await es_service.get_top_servers(metric, 20, minutes)
    return {"metric": metric, "window_minutes": minutes, "servers": results}


@router.get("/servers")
async def list_servers(
    q: str = Query("", max_length=100),
    limit: int = Query(20, ge=1, le=100),
    _: dict = Depends(get_current_user),
):
    return await es_service.list_windows_servers(q, limit)


@router.get("/server/{server_name}")
async def server_detail(
    server_name: str,
    hours: int = Query(4, ge=1, le=72),
    _: dict = Depends(get_current_user),
):
    data = await es_service.get_server_detail(server_name, hours)
    if not data:
        raise HTTPException(status_code=404, detail="Server not found or no data")
    return data


@router.get("/history/{server_name}")
async def server_history(
    server_name: str,
    days: int = Query(30, ge=1, le=365),
    _: dict = Depends(get_current_user),
):
    """Historical daily averages from Postgres."""
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                text("""
                    SELECT report_date, avg_cpu_pct, avg_mem_pct, avg_disk_pct,
                           disk_details, host_ip, os_name
                    FROM infraguardian_capacity_daily
                    WHERE server_name = :name
                      AND report_date >= CURRENT_DATE - CAST(:days AS INTEGER)
                    ORDER BY report_date DESC
                """),
                {"name": server_name, "days": days},
            )
            cols = ["report_date", "avg_cpu_pct", "avg_mem_pct", "avg_disk_pct",
                    "disk_details", "host_ip", "os_name"]
            rows = []
            for r in result.fetchall():
                row = dict(zip(cols, r))
                row["report_date"] = str(row["report_date"])
                rows.append(row)
        return {"server": server_name, "days": days, "history": rows}
    except Exception as e:
        return {"server": server_name, "days": days, "history": [], "error": str(e)}


@router.get("/summary")
async def capacity_summary(
    days: int = Query(7, ge=1, le=90),
    _: dict = Depends(get_current_user),
):
    """Fleet-wide daily averages for trend charts."""
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                text("""
                    SELECT report_date,
                           ROUND(AVG(avg_cpu_pct)::numeric, 1)  AS avg_cpu,
                           ROUND(AVG(avg_mem_pct)::numeric, 1)  AS avg_memory,
                           ROUND(AVG(avg_disk_pct)::numeric, 1) AS avg_disk,
                           COUNT(*)                               AS server_count
                    FROM infraguardian_capacity_daily
                    WHERE report_date >= CURRENT_DATE - CAST(:days AS INTEGER)
                    GROUP BY report_date
                    ORDER BY report_date
                """),
                {"days": days},
            )
            cols = ["report_date", "avg_cpu", "avg_memory", "avg_disk", "server_count"]
            return [dict(zip(cols, r)) for r in result.fetchall()]
    except Exception:
        return []


@router.get("/live/{server_name}")
async def server_live_snapshot(
    server_name: str,
    minutes: int = Query(5, ge=1, le=15),
    _: dict = Depends(get_current_user),
):
    """
    Live snapshot: current CPU%, memory%, disk% + per-mount detail.
    minutes: 1 | 5 | 10 | 15  — lookback window.
    """
    try:
        data = await es_service.get_live_server_snapshot(server_name, minutes=minutes)
        return data
    except Exception as e:
        return {"server": server_name, "error": str(e), "cpu_pct": 0, "mem_pct": 0, "disk_pct": 0}


@router.get("/processes/{server_name}")
async def server_top_processes(
    server_name: str,
    sort_by: str = Query("cpu", pattern="^(cpu|memory)$"),
    top_n: int = Query(10, ge=1, le=20),
    _: dict = Depends(get_current_user),
):
    """
    Top N processes for a server sorted by CPU or memory.
    sort_by: 'cpu' | 'memory'
    Used by alert agents and the server detail panel.
    """
    try:
        procs = await es_service.get_top_processes(server_name, sort_by=sort_by, top_n=top_n)
        return {"server": server_name, "sort_by": sort_by, "processes": procs}
    except Exception as e:
        return {"server": server_name, "sort_by": sort_by, "processes": [], "error": str(e)}


@router.post("/aggregate")
async def trigger_aggregation(
    report_date: Optional[str] = None,
    admin: dict = Depends(get_current_user),
):
    """Manually trigger daily capacity aggregation (admin action)."""
    from datetime import date
    d = date.fromisoformat(report_date) if report_date else date.today()
    count = await es_service.aggregate_daily_capacity(d)
    return {"ok": True, "report_date": str(d), "servers_saved": count}
