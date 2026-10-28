"""
AI Capacity Prediction API
Endpoints for fleet/server forecasts, risk assessment, and narrative summaries.
All timestamps returned in GST (UTC+4).
"""
from __future__ import annotations
from datetime import date, timedelta
from fastapi import APIRouter, Depends, Query
from app.auth import get_current_user
from app.services import prediction_service

router = APIRouter(prefix="/api/predict", tags=["prediction"])


@router.get("/fleet")
async def fleet_forecast(
    days: int = Query(365, ge=30, le=730, description="Forecast horizon in days (30-730)"),
    lookback: int = Query(90, ge=14, le=365, description="Historical lookback in days"),
    _: dict = Depends(get_current_user),
):
    """
    Fleet-wide AI capacity forecast for CPU, memory, and disk.
    Returns historical series + forecast + 90% confidence bands.
    """
    try:
        return await prediction_service.get_fleet_forecast(
            forecast_days=days, lookback_days=lookback
        )
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.get("/fleet/narrative")
async def fleet_narrative(
    days: int = Query(365, ge=30, le=730),
    lookback: int = Query(90, ge=14, le=365),
    _: dict = Depends(get_current_user),
):
    """LLM-generated executive narrative for fleet forecast."""
    try:
        forecast = await prediction_service.get_fleet_forecast(
            forecast_days=days, lookback_days=lookback
        )
        narrative = await prediction_service.generate_fleet_narrative(forecast)
        return {"narrative": narrative, "forecast_days": days}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.get("/server/{server_name}")
async def server_forecast(
    server_name: str,
    days: int = Query(365, ge=30, le=730),
    lookback: int = Query(90, ge=14, le=365),
    _: dict = Depends(get_current_user),
):
    """Per-server capacity forecast with confidence intervals."""
    try:
        return await prediction_service.get_server_forecast(
            server_name=server_name, forecast_days=days, lookback_days=lookback
        )
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.get("/risk")
async def capacity_risk(
    horizon: int = Query(180, ge=30, le=730, description="Risk horizon in days"),
    _: dict = Depends(get_current_user),
):
    """
    Servers projected to breach 80% or 90% thresholds within the horizon.
    Severity: critical (≤30d to 90%), high (≤90d), medium (≤60d to 80%), low.
    """
    try:
        return await prediction_service.get_capacity_risk_report(horizon_days=horizon)
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.get("/servers")
async def list_servers(_: dict = Depends(get_current_user)):
    """All server names that have capacity data."""
    try:
        from sqlalchemy import text
        from app.database import AsyncSessionLocal

        # Check if DB has any historical rows
        async with AsyncSessionLocal() as db:
            chk = await db.execute(text(
                "SELECT COUNT(*) FROM cloudpulse_capacity_daily WHERE report_date >= CURRENT_DATE - 90"
            ))
            db_count = chk.scalar() or 0

        servers = await prediction_service.get_fleet_servers()
        source = "db" if db_count > 0 else "es"
        return {"servers": servers, "count": len(servers), "source": source}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.post("/seed")
async def seed_capacity(_: dict = Depends(get_current_user),
                        days_back: int = Query(1, ge=1, le=7, description="How many days back to seed")):
    """
    Manually trigger capacity aggregation for recent days.
    Useful on first deployment to populate historical data without waiting for 01:00 cron.
    """
    try:
        from app.services.es_service import aggregate_daily_capacity
        results = []
        for i in range(days_back, 0, -1):
            target = str(date.today() - timedelta(days=i))
            count = await aggregate_daily_capacity(target)
            results.append({"date": target, "servers_seeded": count})
        total = sum(r["servers_seeded"] for r in results)
        return {"ok": True, "seeded": results, "total_rows": total}
    except Exception as e:
        return {"ok": False, "error": str(e)}
