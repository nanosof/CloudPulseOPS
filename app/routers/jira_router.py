"""Jira ticket creator routes — streaming draft generation + ticket creation."""
from __future__ import annotations
import json
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import text
from typing import Optional

from app.auth import get_current_user
from app.database import AsyncSessionLocal
from app.services import llm_service, jira_service
from app.scheduler import scheduler
import app.config as cfg

router = APIRouter(prefix="/api/jira", tags=["jira"])


def _derive_jira_username(user: dict) -> str:
    """Derive Jira DC username from signed-in user's email (email prefix, Title-cased)."""
    email = user.get("email") or ""
    if email and "@" in email:
        raw_prefix = email.split("@")[0]
        return ".".join(p.capitalize() for p in raw_prefix.split("."))
    return user.get("username", "")


async def _resolve_jira_username(user: dict) -> str:
    """
    Resolve the correct Jira DC username for the current user.

    Primary: email-derived (works when email = Firstname.Lastname@domain).
    Fallback: configured jira.username (when email maps to a single-word like 'admin').
    This ensures stats and ticket listing work even when the CloudPulse account
    has a generic email (e.g. admin@example.com) instead of the Jira-matching one.
    """
    derived = _derive_jira_username(user)
    # If derived looks like a single word (no dot) it won't match a Jira DC username
    # → fall back to the configured jira.username (Title-cased)
    if "." not in derived:
        configured = await cfg.get("jira.username", "")
        if configured:
            return ".".join(p.capitalize() for p in configured.split("."))
    return derived


class DraftRequest(BaseModel):
    summary: str   # brief one-line summary typed by the user; the full description is drafted from it


class CreateTicketRequest(BaseModel):
    summary: str
    description: str
    sr_type_id: str            # customfield_32404 option ID (numeric string)
    subsidiary_id: Optional[str] = None   # customfield_36200 option ID
    effort_hours: Optional[float] = None
    resolution_note: Optional[str] = None   # confirmed resolution summary


class ResolveRequest(BaseModel):
    ticket_key: str
    resolution_note: str


class ScheduleResolveRequest(BaseModel):
    ticket_key: str
    resolution_note: str
    delay_minutes: float   # effort_hours × 60


@router.post("/draft/stream")
async def stream_draft(body: DraftRequest, user: dict = Depends(get_current_user)):
    """
    Streams NDJSON events for LLM ticket draft generation:
    classifying → generating → draft_ready (or error)
    """
    async def event_generator():
        async for chunk in llm_service.generate_jira_draft(body.summary):
            yield chunk

    return StreamingResponse(event_generator(), media_type="application/x-ndjson")


@router.post("/ticket")
async def create_ticket(body: CreateTicketRequest, user: dict = Depends(get_current_user)):
    """Create ticket in Jira DC and log to DB. Assignee derived from signed-in user's email."""
    jira_user = await _resolve_jira_username(user)

    result = await jira_service.create_ticket(
        summary=body.summary,
        description=body.description,
        sr_type_id=body.sr_type_id,
        subsidiary_id=body.subsidiary_id,
        effort_hours=body.effort_hours,
        assignee=jira_user,
    )

    if result.get("ok"):
        sr_type_name = llm_service.SR_TYPES.get(body.sr_type_id, body.sr_type_id)
        proj_key = await cfg.get("jira.project_key", "SD")
        async with AsyncSessionLocal() as db:
            await db.execute(
                text("""
                    INSERT INTO infraguardian_jira_tickets
                        (ticket_key, ticket_url, project_key, summary, sr_type,
                         subsidiary_id, effort_hours, created_by, status)
                    VALUES
                        (:key, :url, :proj, :summary, :sr_type,
                         :sub, :effort, :created_by, 'In Progress')
                """),
                {
                    "key":        result["key"],
                    "url":        result["url"],
                    "proj":       proj_key,
                    "summary":    body.summary,
                    "sr_type":    sr_type_name,
                    "sub":        body.subsidiary_id,
                    "effort":     body.effort_hours,
                    "created_by": user["username"],
                },
            )
            await db.commit()

    return result


@router.post("/schedule-resolve")
async def schedule_resolve(body: ScheduleResolveRequest, user: dict = Depends(get_current_user)):
    """Schedule auto-resolve for a ticket after delay_minutes."""
    ticket_key    = body.ticket_key
    resolution    = body.resolution_note
    delay_minutes = max(1.0, body.delay_minutes)   # at least 1 minute

    fire_at = datetime.now(timezone.utc) + timedelta(minutes=delay_minutes)

    async def _do_resolve():
        result = await jira_service.resolve_ticket(ticket_key, resolution)
        if result.get("ok"):
            async with AsyncSessionLocal() as db:
                await db.execute(
                    text("UPDATE infraguardian_jira_tickets SET status = 'Resolved', scheduled_resolve_at = NULL WHERE ticket_key = :k"),
                    {"k": ticket_key},
                )
                await db.commit()

    try:
        from apscheduler.triggers.date import DateTrigger
        scheduler.add_job(
            _do_resolve,
            DateTrigger(run_date=fire_at),
            id=f"resolve_{ticket_key}",
            replace_existing=True,
        )
        # Save scheduled time + resolution note to DB (for countdown and restart recovery)
        async with AsyncSessionLocal() as db:
            await db.execute(
                text("""UPDATE infraguardian_jira_tickets
                        SET scheduled_resolve_at = :t,
                            resolution_note = :note
                        WHERE ticket_key = :k"""),
                {"t": fire_at, "k": ticket_key, "note": resolution},
            )
            await db.commit()
        return {
            "ok": True,
            "ticket_key": ticket_key,
            "scheduled_at": fire_at.isoformat() + "Z",
            "delay_minutes": delay_minutes,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.get("/tickets")
async def list_tickets(
    filter: str = "mine",   # all | ytd | mtd | mine
    limit: int = 200,
    user: dict = Depends(get_current_user),
):
    """
    Return tickets newest-first for the current user.
    Merges Jira API (assigned-to-me) with local DB (created via CloudPulse).
    DB record takes priority when ticket_key matches (has scheduled_resolve_at countdown etc.)
    filter: all (90d) | ytd | mtd | mine (all-time assigned to me)
    """
    jira_user = await _resolve_jira_username(user)
    try:
        # ── 1. DB tickets ────────────────────────────────────────────────────────
        db_filter = ""
        db_params: dict = {"limit": limit}
        if filter == "ytd":
            db_filter = "AND created_at >= date_trunc('year', NOW())"
        elif filter == "mtd":
            db_filter = "AND created_at >= date_trunc('month', NOW())"
        # "mine" and "all": no date restriction on DB (it's the user's own created tickets)

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                text(f"""
                    SELECT ticket_key, ticket_url, project_key, summary, sr_type,
                           subsidiary_id, effort_hours, created_by, created_at, status,
                           scheduled_resolve_at
                    FROM infraguardian_jira_tickets
                    WHERE 1=1 {db_filter}
                    ORDER BY created_at DESC
                    LIMIT :limit
                """),
                db_params,
            )
            cols = ["ticket_key", "ticket_url", "project_key", "summary", "sr_type",
                    "subsidiary_id", "effort_hours", "created_by", "created_at", "status",
                    "scheduled_resolve_at"]
            db_tickets: dict[str, dict] = {}
            for r in result.fetchall():
                row = dict(zip(cols, r))
                row["created_at"] = row["created_at"].isoformat() if row.get("created_at") else None
                row["scheduled_resolve_at"] = row["scheduled_resolve_at"].isoformat() if row.get("scheduled_resolve_at") else None
                row["source"] = "db"
                db_tickets[row["ticket_key"]] = row

        # ── 2. Jira API tickets assigned to me ───────────────────────────────────
        jira_tickets = await jira_service.get_user_tickets(jira_user, filter=filter, limit=limit)

        # ── 3. Merge: DB record wins when same key (has richer data + countdown) ─
        merged: dict[str, dict] = {}
        for jt in jira_tickets:
            key = jt.get("ticket_key") or ""
            if key:
                merged[key] = jt                        # start with Jira data
        for key, dbt in db_tickets.items():
            if key:
                merged[key] = dbt                       # DB overwrites (has scheduled_resolve_at etc.)
                # Bring Jira status into DB record when DB still shows 'In Progress'
                # but Jira already moved it forward (e.g. Resolved outside CloudPulse)
                if key in {jt.get("ticket_key") for jt in jira_tickets}:
                    jira_status = next((jt["status"] for jt in jira_tickets if jt.get("ticket_key") == key), None)
                    if jira_status and dbt.get("status") != jira_status:
                        merged[key] = {**dbt, "status": jira_status}

        tickets = sorted(merged.values(), key=lambda t: t.get("created_at") or "", reverse=True)
        return {"tickets": tickets, "filter": filter, "count": len(tickets)}
    except Exception as e:
        return {"tickets": [], "filter": filter, "count": 0, "error": str(e)}


@router.get("/stats")
async def ticket_stats(user: dict = Depends(get_current_user)):
    """MTD, YTD, open, in-progress ticket counts for the current user (Jira or DB fallback)."""
    jira_user = await _resolve_jira_username(user)
    ig_user   = user.get("username", jira_user)
    try:
        stats = await jira_service.get_user_stats(jira_user)
        # If DB fallback, pass ig_username for correct filtering
        if stats.get("source") == "db":
            stats2 = await jira_service.get_user_stats_from_db(ig_user)
            stats2["jira_username"] = jira_user
            stats2["note"] = stats.get("note", "counts from local DB")
            return stats2
        return stats
    except Exception as e:
        return {"ytd": 0, "mtd": 0, "open": 0, "in_progress": 0, "error": str(e)}


@router.post("/seed-test")
async def seed_test_tickets(user: dict = Depends(get_current_user)):
    """
    Seed the DB with 20 realistic mock tickets for testing/demo.
    Safe to call multiple times — uses ON CONFLICT DO UPDATE.
    """
    jira_user = await _resolve_jira_username(user)
    ig_user   = user.get("username", jira_user)

    mock = jira_service._generate_mock_tickets(jira_user, ig_user)

    from datetime import datetime as _dt
    async with AsyncSessionLocal() as db:
        for t in mock:
            # Parse created_at string to datetime for asyncpg
            ca = t["created_at"]
            if isinstance(ca, str):
                ca = _dt.fromisoformat(ca)
            await db.execute(
                text("""
                    INSERT INTO infraguardian_jira_tickets
                        (ticket_key, ticket_url, project_key, summary, sr_type,
                         effort_hours, created_by, created_at, status)
                    VALUES
                        (:key, :url, :proj, :summary, :sr_type,
                         :effort, :created_by, :created_at, :status)
                    ON CONFLICT (ticket_key) DO UPDATE SET
                        status  = EXCLUDED.status,
                        summary = EXCLUDED.summary
                """),
                {
                    "key":        t["ticket_key"],
                    "url":        t["ticket_url"],
                    "proj":       t["project_key"],
                    "summary":    t["summary"],
                    "sr_type":    t["sr_type"],
                    "effort":     t["effort_hours"],
                    "created_by": t["created_by"],
                    "created_at": ca,
                    "status":     t["status"],
                },
            )
        await db.commit()

    return {"ok": True, "seeded": len(mock), "jira_username": jira_user, "ig_username": ig_user}


@router.get("/ticket/{key}")
async def get_ticket(key: str, user: dict = Depends(get_current_user)):
    return await jira_service.get_ticket(key)


@router.post("/ticket/resolve")
async def resolve_ticket(body: ResolveRequest, user: dict = Depends(get_current_user)):
    result = await jira_service.resolve_ticket(body.ticket_key, body.resolution_note)
    if result.get("ok"):
        async with AsyncSessionLocal() as db:
            await db.execute(
                text("UPDATE infraguardian_jira_tickets SET status = 'Resolved' WHERE ticket_key = :k"),
                {"k": body.ticket_key},
            )
            await db.commit()
    return result


@router.get("/subsidiaries")
async def get_subsidiaries(_: dict = Depends(get_current_user)):
    return [{"id": k, "name": v} for k, v in llm_service.SUBSIDIARIES.items()]


@router.get("/sr-types")
async def get_sr_types(_: dict = Depends(get_current_user)):
    return [{"id": k, "name": v} for k, v in llm_service.SR_TYPES.items()]
