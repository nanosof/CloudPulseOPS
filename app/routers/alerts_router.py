"""Capacity alerts — list, acknowledge, LLM analysis."""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from typing import Optional

from app.auth import get_current_user, require_admin
from app.database import AsyncSessionLocal
from app.services import llm_service

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


class AcknowledgeRequest(BaseModel):
    alert_id: int
    note: Optional[str] = None


@router.get("")
async def list_alerts(
    limit: int = Query(50, le=200),
    unacked_only: bool = False,
    _: dict = Depends(get_current_user),
):
    async with AsyncSessionLocal() as db:
        where = "WHERE acknowledged_at IS NULL" if unacked_only else ""
        result = await db.execute(
            text(f"""
                SELECT id, server_name, metric, value, severity, details,
                       acknowledged_at, acknowledged_by, jira_ticket_key, created_at
                FROM cloudpulse_alerts
                {where}
                ORDER BY created_at DESC
                LIMIT :limit
            """),
            {"limit": limit},
        )
        cols = ["id", "server_name", "metric", "value", "severity", "details",
                "acknowledged_at", "acknowledged_by", "jira_ticket_key", "created_at"]
        return [dict(zip(cols, r)) for r in result.fetchall()]


@router.post("/acknowledge")
async def acknowledge(body: AcknowledgeRequest, user: dict = Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        await db.execute(
            text("""
                UPDATE cloudpulse_alerts
                SET acknowledged_at = NOW(), acknowledged_by = :u
                WHERE id = :id
            """),
            {"u": user["username"], "id": body.alert_id},
        )
        await db.commit()
    return {"ok": True}


@router.post("/analyze/{alert_id}")
async def analyze_alert(alert_id: int, user: dict = Depends(get_current_user)):
    """Call the LLM to analyze the alert and return remediation advice."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text("SELECT server_name, metric, value, details FROM cloudpulse_alerts WHERE id = :id"),
            {"id": alert_id},
        )
        row = result.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")
        server, metric, value, details = row

    analysis = await llm_service.analyze_capacity_alert(
        server=server,
        metric=metric,
        value=float(value) if value else 0.0,
        context={"details": details or {}},
    )

    # Store LLM response in alert row
    async with AsyncSessionLocal() as db:
        await db.execute(
            text("UPDATE cloudpulse_alerts SET details = :d WHERE id = :id"),
            {"d": str(details or {}) + f"\n\nAI Analysis: {analysis}", "id": alert_id},
        )
        await db.commit()

    return analysis


@router.post("/create")
async def create_alert(
    server_name: str,
    metric: str,
    value: float,
    severity: str = "warning",
    details: Optional[dict] = None,
    user: dict = Depends(get_current_user),
):
    """Manually create an alert (also called internally by scheduler)."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text("""
                INSERT INTO cloudpulse_alerts (server_name, metric, value, severity, details)
                VALUES (:server, :metric, :value, :severity, :details)
                RETURNING id
            """),
            {
                "server":   server_name,
                "metric":   metric,
                "value":    value,
                "severity": severity,
                "details":  str(details or {}),
            },
        )
        alert_id = result.scalar()
        await db.commit()
    return {"ok": True, "id": alert_id}
