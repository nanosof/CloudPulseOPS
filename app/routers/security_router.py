"""Security posture, threats, devices and patching — snapshots from Microsoft Graph / Defender."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth import get_current_user
from app.services import ad_service, security_service

router = APIRouter(prefix="/api/security", tags=["security"])


@router.get("/overview")
async def overview(_: dict = Depends(get_current_user)):
    snaps = await ad_service.load_snapshots()
    sec = {k: v for k, v in snaps.items() if k in security_service.SECTIONS or k == "tenant"}
    items = await security_service.findings(sec)
    return {
        "running": await ad_service.is_running(),
        "last_run": await ad_service.last_run(),
        "sections": {k: {"ok": v["ok"], "error": v["error"], "collected_at": v["collected_at"],
                         "summary": (v["data"] or {}).get("summary")} for k, v in sec.items()},
        "kpis": await ad_service.kpi_trends(30),
        "findings": items,
        "score": ad_service.health_score(items),
        "counts": {s: sum(1 for f in items if f["severity"] == s) for s in ("critical", "warning", "info")},
    }


@router.get("/section/{name}")
async def section(name: str, _: dict = Depends(get_current_user)):
    if name not in ad_service.SECTIONS:
        raise HTTPException(404, "Unknown section")
    snap = await ad_service.load_section(name)
    if not snap:
        raise HTTPException(404, "Not collected yet")
    return snap


@router.get("/device/{device_id}")
async def device(device_id: str, _: dict = Depends(get_current_user)):
    """Live drill-down: vulnerabilities, missing updates, misconfigurations and alerts for one Defender device."""
    try:
        return await security_service.device_detail(device_id)
    except Exception as e:
        raise HTTPException(502, f"Defender query failed: {e}")


@router.get("/lockouts")
async def lockouts(
    hours: int = Query(24, ge=1, le=720),
    username: str = Query(""),
    _: dict = Depends(get_current_user),
):
    """Account lockout events (4740) and failed logon summary (4625) from Elasticsearch."""
    from app.services import es_service as es
    return await es.get_lockout_events(hours=hours, username=username)
