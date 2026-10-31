"""Teams Alerts routes — alerts read from a Teams chat, enriched with CloudPulse data and LLM analysis."""
from __future__ import annotations
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text

from app.auth import get_current_user
from app.database import AsyncSessionLocal
from app.routers.jira_router import _resolve_jira_username
from app.services import jira_service, llm_service, teams_service
from app.services import teams_alert_service as tas
import app.config as cfg

router = APIRouter(prefix="/api/teams", tags=["teams"])


class TeamsTicketRequest(BaseModel):
    summary: str
    description: str
    sr_type_id: str
    subsidiary_id: Optional[str] = ""
    effort_hours: Optional[float] = 1.0


@router.get("/status")
async def teams_status(_: dict = Depends(get_current_user)):
    status = await teams_service.auth_status()
    try:
        await teams_service._get_token()
        status["token_ok"] = True
    except Exception as e:
        status["token_ok"] = False
        status["error"] = str(e)
    return status


@router.get("/alerts")
async def list_alerts(
    resolved_limit: int = Query(2000, ge=0, le=10000),
    _: dict = Depends(get_current_user),
):
    """
    Incidents (repeat alerts of the same type on the same host merged together):
    every active incident plus the most recently resolved ones.
    """
    from app.services import inventory_service as inv
    active = await tas.list_incidents(resolved=False)
    resolved = await tas.list_incidents(resolved=True, limit=resolved_limit)
    lookup = await inv.project_lookup()
    for r in active + resolved:   # project from Admin → Server Inventory, when the alert maps to a known server
        hosts = [r.get("ig_host")] + (r.get("hosts") or []) + [r.get("server_name")]
        r["inv_project"] = next((p for h in hosts if (p := (lookup.get(inv.key_of(h or "")) or {}).get("project"))
                                 and p != "Unassigned"), None)
    return {"active": active, "resolved": resolved}


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: int, _: dict = Depends(get_current_user)):
    alert = await tas.get_alert(alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return alert


@router.post("/alerts/{alert_id}/reanalyze")
async def reanalyze_alert(alert_id: int, _: dict = Depends(get_current_user)):
    alert = await tas.get_alert(alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return await tas.reanalyze(alert)


@router.post("/alerts/{alert_id}/resolve")
async def set_resolved(alert_id: int, resolved: bool = True, _: dict = Depends(get_current_user)):
    if not await tas.get_alert(alert_id):
        raise HTTPException(404, "Alert not found")
    await tas.mark_resolved(alert_id, resolved)
    return {"ok": True}


@router.post("/alerts/{alert_id}/draft")
async def jira_draft(alert_id: int, _: dict = Depends(get_current_user)):
    """Generate a pre-filled Jira ticket draft for an alert using the LLM."""
    alert = await tas.get_alert(alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    draft = await tas.generate_jira_draft(alert)
    draft["alert_id"] = alert_id
    return draft


@router.post("/alerts/{alert_id}/ticket")
async def create_ticket(alert_id: int, body: TeamsTicketRequest, user: dict = Depends(get_current_user)):
    """Create a Jira ticket, log it alongside other CloudPulse tickets and link it to the alert."""
    alert = await tas.get_alert(alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")

    result = await jira_service.create_ticket(
        summary=body.summary,
        description=body.description,
        sr_type_id=body.sr_type_id,
        subsidiary_id=body.subsidiary_id,
        effort_hours=body.effort_hours,
        assignee=await _resolve_jira_username(user),
    )

    if result.get("ok"):
        await tas.set_jira(alert_id, result["key"], result["url"])
        proj_key = await cfg.get("jira.project_key", "SD")
        async with AsyncSessionLocal() as db:
            await db.execute(
                text("""
                    INSERT INTO infraguardian_jira_tickets
                        (ticket_key, ticket_url, project_key, summary, sr_type,
                         subsidiary_id, effort_hours, created_by, status, raw_input)
                    VALUES
                        (:key, :url, :proj, :summary, :sr_type,
                         :sub, :effort, :created_by, 'In Progress', :raw)
                """),
                {
                    "key":        result["key"],
                    "url":        result["url"],
                    "proj":       proj_key,
                    "summary":    body.summary,
                    "sr_type":    llm_service.SR_TYPES.get(body.sr_type_id, body.sr_type_id),
                    "sub":        body.subsidiary_id,
                    "effort":     body.effort_hours,
                    "created_by": user["username"],
                    "raw":        f"Teams alert #{alert_id}: {alert.get('server_name')}",
                },
            )
            await db.commit()

    return result


@router.post("/poll")
async def manual_poll(_: dict = Depends(get_current_user)):
    stored = await tas.poll_once()
    if stored is None:
        return {"ok": True, "stored": 0, "busy": True}
    return {"ok": True, "stored": stored}


@router.post("/resolve-check")
async def manual_resolve_check(_: dict = Depends(get_current_user)):
    resolved = await tas.check_and_resolve_active_alerts()
    if resolved is None:
        return {"ok": True, "resolved": 0, "busy": True}
    return {"ok": True, "resolved": resolved}
