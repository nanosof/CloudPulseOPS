"""
CloudPulse — FastAPI application entry point.
"""
from __future__ import annotations
import logging
from contextlib import asynccontextmanager
from datetime import date

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from apscheduler.triggers.cron import CronTrigger

from app.database import AsyncSessionLocal, engine
from app.routers import auth_router, capacity_router, settings_router, jira_router, alerts_router
from app.routers import agent, reports_router, users_router, prediction_router, scheduled_reports_router
from app.routers import teams_router, ad_router, inventory_router, security_router, assistant_router
from app.scheduler import scheduler
import app.config as cfg

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s — %(message)s")
log = logging.getLogger("cloudpulse")


async def _hourly_collect_job():
    """Scheduled: collect current ES metrics for all servers → hourly temp table."""
    log.info("Running hourly capacity snapshot collection…")
    try:
        from app.services.es_service import collect_hourly_snapshot
        count = await collect_hourly_snapshot()
        log.info(f"Hourly snapshot done — {count} servers collected")
        try:
            from app.services.inventory_service import refresh as _refresh_inventory
            await _refresh_inventory()
        except Exception as e:
            log.warning(f"Inventory refresh failed (non-fatal): {e}")
        # Check thresholds on fresh data
        await _check_capacity_thresholds()
    except Exception as e:
        log.exception(f"Hourly collection failed: {e}")


async def _daily_aggregate_job():
    """Scheduled: aggregate yesterday's hourly snapshots into the daily table."""
    log.info("Running daily capacity aggregation…")
    try:
        from app.services.es_service import aggregate_daily_capacity
        from datetime import timedelta
        yesterday = date.today() - timedelta(days=1)
        count = await aggregate_daily_capacity(yesterday)
        log.info(f"Daily aggregation done — {count} servers saved for {yesterday}")
    except Exception as e:
        log.exception(f"Daily aggregation failed: {e}")


async def _check_capacity_thresholds():
    """Read top servers and create DB alerts for critical/warning ones."""
    from app.services.es_service import get_top_servers
    from sqlalchemy import text

    cpu_threshold  = await cfg.get_float("capacity.cpu_warning_pct",  80.0)
    mem_threshold  = await cfg.get_float("capacity.mem_warning_pct",  85.0)
    disk_threshold = await cfg.get_float("capacity.disk_warning_pct", 85.0)

    checks = [
        ("cpu",    cpu_threshold),
        ("memory", mem_threshold),
        ("disk",   disk_threshold),
    ]

    for metric, threshold in checks:
        servers = await get_top_servers(metric, 20, 60)
        for s in servers:
            val = s.get("value", 0.0)
            if val >= threshold:
                severity = "critical" if val >= 90.0 else "warning"
                async with AsyncSessionLocal() as db:
                    # Only create if no unacknowledged alert for this server+metric in last hour
                    existing = await db.execute(
                        text("""
                            SELECT id FROM infraguardian_alerts
                            WHERE server_name = :srv AND metric = :m
                              AND acknowledged_at IS NULL
                              AND created_at > NOW() - INTERVAL '1 hour'
                        """),
                        {"srv": s["server_name"], "m": metric},
                    )
                    if not existing.fetchone():
                        await db.execute(
                            text("""
                                INSERT INTO infraguardian_alerts
                                    (server_name, metric, value, severity)
                                VALUES (:srv, :m, :v, :sev)
                            """),
                            {"srv": s["server_name"], "m": metric, "v": val, "sev": severity},
                        )
                        await db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    log.info("CloudPulse starting…")

    # Warm up config cache
    try:
        await cfg.load_all()
        log.info("Config cache loaded")
    except Exception as e:
        log.warning(f"Config cache warm-up failed (DB may not be ready): {e}")

    # Schedule hourly ES collection (runs at :05 past every hour)
    scheduler.add_job(
        _hourly_collect_job,
        CronTrigger(minute=5),
        id="hourly_collect",
        replace_existing=True,
    )

    # Schedule daily aggregation at 01:00
    agg_hour = await cfg.get_int("capacity.agg_hour", 1)
    scheduler.add_job(
        _daily_aggregate_job,
        CronTrigger(hour=agg_hour, minute=0),
        id="daily_aggregate",
        replace_existing=True,
    )
    # ── Teams Alerts: schema + DB-driven scheduler tick ─────────────────────
    try:
        from apscheduler.triggers.interval import IntervalTrigger
        from app.services import teams_alert_service as _tas
        try:
            await _tas.ensure_schema()
        except Exception as e:
            log.warning(f"Teams Alerts schema check non-fatal: {e}")
        scheduler.add_job(
            _tas.scheduled_tick,
            IntervalTrigger(seconds=_tas.TICK_SECONDS),
            id="teams_tick",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        log.info("Teams Alerts: scheduler tick every %ss (intervals read from teams.* settings)", _tas.TICK_SECONDS)
    except Exception as e:
        log.warning(f"Teams Alerts setup non-fatal: {e}")

    # ── AD / Entra health: schema + DB-driven collection tick ───────────────
    try:
        from apscheduler.triggers.interval import IntervalTrigger
        from app.services import ad_service as _ad
        try:
            await _ad.ensure_schema()
            from app.services import security_service as _sec
            await _sec.ensure_settings()
            from app.services import assistant_service as _ai
            await _ai.ensure_schema()
        except Exception as e:
            log.warning(f"AD health schema check non-fatal: {e}")
        scheduler.add_job(
            _ad.scheduled_tick,
            IntervalTrigger(seconds=60),
            id="ad_tick",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        log.info("AD health: collection tick every 60s (interval read from ad.refresh_minutes)")
    except Exception as e:
        log.warning(f"AD health setup non-fatal: {e}")

    # ── Server inventory: schema + first fill (refreshed after each hourly collection) ──
    try:
        from sqlalchemy import text
        from app.services import inventory_service as _inv
        await _inv.ensure_schema()
        async with AsyncSessionLocal() as db:
            empty = not (await db.execute(text("SELECT 1 FROM infraguardian_server_inventory LIMIT 1"))).fetchone()
        if empty:
            await _inv.refresh()
    except Exception as e:
        log.warning(f"Server inventory setup non-fatal: {e}")

    # ── Scheduled reports: run due schedules and email them ─────────────────
    try:
        from apscheduler.triggers.interval import IntervalTrigger
        from app.services import report_service as _rs
        scheduler.add_job(
            _rs.scheduled_tick,
            IntervalTrigger(seconds=60),
            id="reports_tick",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        log.info("Scheduled reports: due-schedule check every 60s")
    except Exception as e:
        log.warning(f"Scheduled reports setup non-fatal: {e}")

    scheduler.start()
    log.info(f"Scheduler started — hourly collect at :05, daily aggregation at {agg_hour:02d}:00")

    # ── Initial capacity seed (first-deploy bootstrap) ──────────────────────
    # If capacity_daily is empty, run yesterday's aggregation immediately so
    # the AI Prediction server dropdown is populated without waiting 24+ hours.
    try:
        from sqlalchemy import text
        async with AsyncSessionLocal() as db:
            result = await db.execute(text("SELECT COUNT(*) FROM infraguardian_capacity_daily"))
            row_count = result.scalar() or 0
        if row_count == 0:
            log.info("capacity_daily is empty — running initial seed for yesterday…")
            from app.services.es_service import aggregate_daily_capacity
            from datetime import timedelta
            yesterday = date.today() - timedelta(days=1)
            seeded = await aggregate_daily_capacity(str(yesterday))
            log.info(f"Initial seed complete — {seeded} servers seeded for {yesterday}")
    except Exception as e:
        log.warning(f"Initial capacity seed failed (non-fatal): {e}")

    # ── DB migration: add missing columns if not present ────────────────────
    try:
        from sqlalchemy import text
        async with AsyncSessionLocal() as db:
            await db.execute(text("""
                ALTER TABLE infraguardian_jira_tickets
                ADD COLUMN IF NOT EXISTS resolution_note TEXT
            """))
            await db.execute(text("""
                ALTER TABLE infraguardian_jira_tickets
                ADD COLUMN IF NOT EXISTS scheduled_resolve_at TIMESTAMPTZ
            """))
            await db.commit()
        log.info("Jira tickets schema: resolution_note + scheduled_resolve_at columns ensured")
    except Exception as e:
        log.warning(f"Jira schema migration non-fatal: {e}")

    # ── Re-register pending scheduled-resolve jobs (survive restart) ─────────
    # APScheduler is in-memory; any pending auto-resolve jobs are lost on restart.
    # Re-read tickets with future scheduled_resolve_at and re-schedule them.
    try:
        from sqlalchemy import text
        from apscheduler.triggers.date import DateTrigger
        from app.services import jira_service as _js

        async with AsyncSessionLocal() as db:
            pending = await db.execute(text("""
                SELECT ticket_key, resolution_note, scheduled_resolve_at
                FROM infraguardian_jira_tickets
                WHERE scheduled_resolve_at > NOW()
                  AND status NOT IN ('Resolved', 'Closed')
            """))
            pending_rows = pending.fetchall()

        revived = 0
        for ticket_key, resolution_note, fire_at in pending_rows:
            note = resolution_note or "Auto-resolved by CloudPulse"

            async def _make_resolve(key=ticket_key, res=note):
                result = await _js.resolve_ticket(key, res)
                if result.get("ok"):
                    async with AsyncSessionLocal() as db2:
                        await db2.execute(
                            text("UPDATE infraguardian_jira_tickets SET status='Resolved', scheduled_resolve_at=NULL WHERE ticket_key=:k"),
                            {"k": key},
                        )
                        await db2.commit()

            scheduler.add_job(
                _make_resolve,
                DateTrigger(run_date=fire_at),
                id=f"resolve_{ticket_key}",
                replace_existing=True,
            )
            revived += 1

        if revived:
            log.info(f"Re-registered {revived} pending auto-resolve job(s) after restart")
    except Exception as e:
        log.warning(f"Pending job re-registration non-fatal: {e}")

    yield

    # Shutdown
    scheduler.shutdown(wait=False)
    await engine.dispose()
    log.info("CloudPulse shut down")


app = FastAPI(
    title="CloudPulse Platform",
    description="Windows Infrastructure AI Operations Platform",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# CORS — tighten in production if needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routers
app.include_router(auth_router.router)
app.include_router(capacity_router.router)
app.include_router(settings_router.router)
app.include_router(jira_router.router)
app.include_router(alerts_router.router)
app.include_router(agent.router)
app.include_router(reports_router.router)
app.include_router(users_router.router)
app.include_router(prediction_router.router)
app.include_router(scheduled_reports_router.router)
app.include_router(teams_router.router)
app.include_router(ad_router.router)
app.include_router(security_router.router)
app.include_router(assistant_router.router)
app.include_router(inventory_router.router)
app.include_router(inventory_router.forecast_router)

# Static files (login.html, app.html, assets)
import os
static_dir = os.path.join(os.path.dirname(__file__), "..", "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "cloudpulse"}


# Serve SPA pages
@app.get("/login", include_in_schema=False)
@app.get("/login.html", include_in_schema=False)
async def login_page():
    return FileResponse(os.path.join(static_dir, "login.html"))


@app.get("/{full_path:path}", include_in_schema=False)
async def catch_all(full_path: str, request: Request):
    """Serve app.html for all non-API routes (SPA catch-all)."""
    if full_path.startswith("api/") or full_path.startswith("static/"):
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    return FileResponse(os.path.join(static_dir, "app.html"))
