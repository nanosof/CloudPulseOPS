"""
Scheduled Reports API
CRUD for report schedules + report history.
All timestamps in GST (UTC+4).
"""
from __future__ import annotations
import json
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel
from sqlalchemy import text

from app.auth import get_current_user
from app.database import AsyncSessionLocal

router = APIRouter(prefix="/api/reports/scheduled", tags=["scheduled_reports"])

GST = timezone(timedelta(hours=4))


def _now_gst() -> datetime:
    return datetime.now(GST)


# ── Request / Response models ──────────────────────────────────────────────────

class CreateScheduleRequest(BaseModel):
    name: str
    report_type: str          # see report_service.REPORT_TYPES
    frequency: str            # daily | weekly | monthly
    day_of_week: Optional[int] = 1   # 1-7, Mon=1, for weekly
    day_of_month: Optional[int] = 1  # 1-28, for monthly
    hour: int = 8             # 0-23 GST hour
    minute: int = 0
    recipients: str = ""      # comma-separated emails (stored as text)
    filters: Optional[dict] = None   # e.g. {"servers": [...], "metric": "disk"}
    enabled: bool = True


class UpdateScheduleRequest(BaseModel):
    name: Optional[str] = None
    frequency: Optional[str] = None
    day_of_week: Optional[int] = None
    day_of_month: Optional[int] = None
    hour: Optional[int] = None
    minute: Optional[int] = None
    recipients: Optional[str] = None
    filters: Optional[dict] = None
    enabled: Optional[bool] = None


# ── DB schema helpers ──────────────────────────────────────────────────────────

async def _ensure_tables():
    async with AsyncSessionLocal() as db:
        await db.execute(text("""
            CREATE TABLE IF NOT EXISTS infraguardian_scheduled_reports (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                report_type TEXT NOT NULL,
                frequency TEXT NOT NULL,
                day_of_week INT,
                day_of_month INT,
                hour INT DEFAULT 8,
                minute INT DEFAULT 0,
                recipients TEXT DEFAULT '',
                filters JSONB,
                enabled BOOLEAN DEFAULT TRUE,
                created_by TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW(),
                last_run_at TIMESTAMPTZ,
                next_run_at TIMESTAMPTZ
            )
        """))
        await db.execute(text("""
            CREATE TABLE IF NOT EXISTS infraguardian_report_history (
                id SERIAL PRIMARY KEY,
                schedule_id INT REFERENCES infraguardian_scheduled_reports(id),
                schedule_name TEXT,
                report_type TEXT,
                status TEXT DEFAULT 'pending',
                generated_at TIMESTAMPTZ DEFAULT NOW(),
                duration_seconds FLOAT,
                row_count INT,
                error_message TEXT,
                report_data JSONB,
                filters JSONB
            )
        """))
        await db.commit()


def _next_run(freq: str, hour: int, minute: int,
              day_of_week: Optional[int], day_of_month: Optional[int]) -> datetime:
    """Calculate the next GST run time for a schedule."""
    now = _now_gst()
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if freq == "daily":
        if target <= now:
            target += timedelta(days=1)
    elif freq == "weekly":
        dow = day_of_week or 1   # 1=Mon
        # Python weekday: Mon=0
        py_dow = dow - 1
        days_ahead = (py_dow - now.weekday()) % 7
        if days_ahead == 0 and target <= now:
            days_ahead = 7
        target = (now + timedelta(days=days_ahead)).replace(
            hour=hour, minute=minute, second=0, microsecond=0)
    elif freq == "monthly":
        dom = day_of_month or 1
        # try this month, then next
        candidate = now.replace(day=min(dom, 28), hour=hour, minute=minute, second=0, microsecond=0)
        if candidate <= now:
            # advance to next month
            if now.month == 12:
                candidate = candidate.replace(year=now.year + 1, month=1)
            else:
                candidate = candidate.replace(month=now.month + 1)
        target = candidate
    return target


# ── CRUD Endpoints ─────────────────────────────────────────────────────────────

@router.get("/")
async def list_schedules(
    enabled_only: bool = Query(False),
    user: dict = Depends(get_current_user),
):
    await _ensure_tables()
    async with AsyncSessionLocal() as db:
        q = "SELECT * FROM infraguardian_scheduled_reports"
        if enabled_only:
            q += " WHERE enabled = TRUE"
        q += " ORDER BY created_at DESC"
        rows = await db.execute(text(q))
        cols = rows.keys()
        schedules = []
        for r in rows.fetchall():
            row = dict(zip(cols, r))
            for k in ("created_at", "updated_at", "last_run_at", "next_run_at"):
                if row.get(k):
                    row[k] = row[k].isoformat()
            if row.get("filters") and isinstance(row["filters"], str):
                row["filters"] = json.loads(row["filters"])
            schedules.append(row)
    return {"schedules": schedules}


@router.post("/")
async def create_schedule(body: CreateScheduleRequest, user: dict = Depends(get_current_user)):
    from app.services import report_service
    if body.report_type not in report_service.REPORT_TYPES:
        raise HTTPException(400, f"Unknown report type '{body.report_type}'")
    await _ensure_tables()
    next_run = _next_run(body.frequency, body.hour, body.minute,
                         body.day_of_week, body.day_of_month)
    async with AsyncSessionLocal() as db:
        result = await db.execute(text("""
            INSERT INTO infraguardian_scheduled_reports
                (name, report_type, frequency, day_of_week, day_of_month,
                 hour, minute, recipients, filters, enabled, created_by, next_run_at)
            VALUES
                (:name, :rtype, :freq, :dow, :dom,
                 :hour, :min, :recip, CAST(:filters AS JSONB), :enabled, :by, :next)
            RETURNING id
        """), {
            "name": body.name, "rtype": body.report_type, "freq": body.frequency,
            "dow": body.day_of_week, "dom": body.day_of_month,
            "hour": body.hour, "min": body.minute,
            "recip": body.recipients,
            "filters": json.dumps(body.filters or {}),
            "enabled": body.enabled, "by": user["username"],
            "next": next_run,
        })
        new_id = result.scalar()
        await db.commit()
    return {"ok": True, "id": new_id, "next_run_at": next_run.isoformat()}


@router.put("/{schedule_id}")
async def update_schedule(schedule_id: int, body: UpdateScheduleRequest,
                          user: dict = Depends(get_current_user)):
    await _ensure_tables()
    sets = []
    params: dict = {"id": schedule_id}
    for field, col in [("name", "name"), ("frequency", "frequency"),
                       ("day_of_week", "day_of_week"), ("day_of_month", "day_of_month"),
                       ("hour", "hour"), ("minute", "minute"),
                       ("recipients", "recipients"), ("enabled", "enabled")]:
        val = getattr(body, field)
        if val is not None:
            sets.append(f"{col} = :{field}")
            params[field] = val
    if body.filters is not None:
        sets.append("filters = CAST(:filters AS JSONB)")
        params["filters"] = json.dumps(body.filters)
    sets.append("updated_at = NOW()")
    if not sets:
        return {"ok": True, "message": "Nothing to update"}
    async with AsyncSessionLocal() as db:
        await db.execute(
            text(f"UPDATE infraguardian_scheduled_reports SET {', '.join(sets)} WHERE id = :id"),
            params,
        )
        # Timing may have changed — recompute the next run
        row = (await db.execute(text("""
            SELECT frequency, hour, minute, day_of_week, day_of_month FROM infraguardian_scheduled_reports WHERE id = :id
        """), {"id": schedule_id})).fetchone()
        if row:
            await db.execute(text("UPDATE infraguardian_scheduled_reports SET next_run_at = :n WHERE id = :id"),
                             {"n": _next_run(*row), "id": schedule_id})
        await db.commit()
    return {"ok": True}


@router.delete("/{schedule_id}")
async def delete_schedule(schedule_id: int, user: dict = Depends(get_current_user)):
    await _ensure_tables()
    async with AsyncSessionLocal() as db:
        # Keep past reports in history; just detach them from the deleted schedule
        await db.execute(
            text("UPDATE infraguardian_report_history SET schedule_id = NULL WHERE schedule_id = :id"),
            {"id": schedule_id},
        )
        await db.execute(
            text("DELETE FROM infraguardian_scheduled_reports WHERE id = :id"),
            {"id": schedule_id},
        )
        await db.commit()
    return {"ok": True}


class GenerateRequest(BaseModel):
    report_type: str
    filters: Optional[dict] = None
    recipients: Optional[str] = ""


@router.get("/types")
async def report_types(_: dict = Depends(get_current_user)):
    """Report catalogue, grouped by category."""
    from app.services import report_service
    return {"types": report_service.catalogue()}


@router.post("/generate")
async def generate_now(body: GenerateRequest, user: dict = Depends(get_current_user)):
    """Ad-hoc report: generate now, store in history, optionally email recipients."""
    from app.services import report_service
    if body.report_type not in report_service.REPORT_TYPES:
        raise HTTPException(400, f"Unknown report type '{body.report_type}'")
    await _ensure_tables()
    label = report_service.REPORT_TYPES[body.report_type]["label"]
    return await report_service.run_and_store(body.report_type, body.filters or {}, f"Ad-hoc · {label}",
                                              None, body.recipients or "", send=bool(body.recipients))


@router.post("/{schedule_id}/run")
async def run_schedule_now(schedule_id: int, email: bool = Query(True), user: dict = Depends(get_current_user)):
    """Run a schedule immediately: store in history and (by default) email its recipients."""
    from app.services import report_service
    await _ensure_tables()
    async with AsyncSessionLocal() as db:
        row = (await db.execute(text("""
            SELECT id, name, report_type, filters, recipients FROM infraguardian_scheduled_reports WHERE id = :id
        """), {"id": schedule_id})).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Schedule not found")
    filters = row.filters if isinstance(row.filters, dict) else json.loads(row.filters or "{}")
    return await report_service.run_and_store(row.report_type, filters, row.name, row.id, row.recipients, send=email)


@router.get("/history")
async def report_history(
    limit: int = Query(50, ge=1, le=500),
    report_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    _: dict = Depends(get_current_user),
):
    """Search and filter report run history."""
    from app.services import report_service
    await _ensure_tables()
    await report_service.ensure_columns()
    conditions = []
    params: dict = {"limit": limit}
    if report_type:
        conditions.append("report_type = :report_type")
        params["report_type"] = report_type
    if status:
        conditions.append("status = :status")
        params["status"] = status
    if search:
        conditions.append("schedule_name ILIKE :search")
        params["search"] = f"%{search}%"
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    async with AsyncSessionLocal() as db:
        rows = await db.execute(text(f"""
            SELECT id, schedule_id, schedule_name, report_type, status, generated_at, duration_seconds,
                   row_count, error_message, email_status, recipients
            FROM infraguardian_report_history
            {where}
            ORDER BY generated_at DESC
            LIMIT :limit
        """), params)
        history = []
        for r in rows.fetchall():
            row = dict(r._mapping)
            if row.get("generated_at"):
                row["generated_at"] = row["generated_at"].isoformat()
            history.append(row)
    return {"history": history}


@router.get("/history/{report_id}/data")
async def get_report_data(report_id: int, _: dict = Depends(get_current_user)):
    """Fetch the stored report document for a historical run."""
    await _ensure_tables()
    async with AsyncSessionLocal() as db:
        r = (await db.execute(
            text("SELECT report_data, report_type, generated_at FROM infraguardian_report_history WHERE id = :id"),
            {"id": report_id},
        )).fetchone()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    data, rtype, gen_at = r
    return {"report_type": rtype, "generated_at": gen_at.isoformat() if gen_at else None, "data": data}


@router.get("/history/{report_id}/html")
async def get_report_html(report_id: int, _: dict = Depends(get_current_user)):
    """Rendered, branded report for the in-app viewer (print / save as PDF from there)."""
    from app.services import report_service
    await _ensure_tables()
    async with AsyncSessionLocal() as db:
        r = (await db.execute(
            text("SELECT report_data, report_type, status, error_message FROM infraguardian_report_history WHERE id = :id"),
            {"id": report_id},
        )).fetchone()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    data = r.report_data if isinstance(r.report_data, dict) else json.loads(r.report_data or "{}")
    if r.status != "success":
        data = report_service.doc(r.report_type, "Report failed", r.error_message or "", sections=[])
    return {"html": report_service.render_html(data or {"type": r.report_type}, "web", report_id=report_id)}
