"""AD / Entra ID health routes — snapshots collected from Microsoft Graph + DC metrics."""
from __future__ import annotations
import asyncio

from fastapi import APIRouter, Depends, HTTPException

from app.auth import get_current_user
from app.services import ad_service

router = APIRouter(prefix="/api/ad", tags=["ad"])

_background: set = set()   # keep refresh tasks referenced until they finish


@router.get("/overview")
async def overview(_: dict = Depends(get_current_user)):
    """Summaries of every section, KPI trends, prioritised findings and the health score."""
    snaps = await ad_service.load_snapshots()
    items = await ad_service.findings(snaps)
    return {
        "running":   await ad_service.is_running(),
        "last_run":  await ad_service.last_run(),
        "sections":  {name: {"ok": s["ok"], "error": s["error"], "duration_ms": s["duration_ms"],
                             "collected_at": s["collected_at"], "attempted_at": s["attempted_at"],
                             "summary": (s["data"] or {}).get("summary")}
                      for name, s in snaps.items()},
        "kpis":      await ad_service.kpi_trends(30),
        "findings":  items,
        "score":     ad_service.health_score(items),
        "counts":    {sev: sum(1 for f in items if f["severity"] == sev) for sev in ("critical", "warning", "info")},
    }


@router.get("/section/{name}")
async def section(name: str, _: dict = Depends(get_current_user)):
    if name not in ad_service.SECTIONS:
        raise HTTPException(404, "Unknown section")
    snap = await ad_service.load_section(name)
    if not snap:
        raise HTTPException(404, "Not collected yet")
    return snap


@router.post("/refresh")
async def refresh(_: dict = Depends(get_current_user)):
    """Start a full collection in the background (no-op if one is already running)."""
    if await ad_service.is_running():
        return {"ok": True, "started": False, "running": True}
    task = asyncio.create_task(ad_service.run_now())
    _background.add(task)
    task.add_done_callback(_background.discard)
    return {"ok": True, "started": True}


@router.get("/status")
async def status(_: dict = Depends(get_current_user)):
    return {"running": await ad_service.is_running(), "last_run": await ad_service.last_run()}
