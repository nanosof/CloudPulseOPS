"""Settings management — read/write all config from infraguardian_settings."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth import require_admin
import app.config as cfg

router = APIRouter(prefix="/api/settings", tags=["settings"])

SECRET_MASK = "***"


class SettingUpdate(BaseModel):
    value: str


class BulkUpdate(BaseModel):
    settings: dict[str, str]


def _mask(row: dict) -> dict:
    if row.get("is_secret") and row.get("value") and row["value"] != "":
        row["value"] = SECRET_MASK
    return row


@router.get("")
async def get_all_settings(admin: dict = Depends(require_admin)):
    all_settings = await cfg.get_all()
    return [_mask(s) for s in all_settings]


@router.get("/{category}")
async def get_category(category: str, admin: dict = Depends(require_admin)):
    rows = await cfg.get_all_by_category(category)
    return [_mask(r) for r in rows]


@router.put("/{key:path}")
async def update_setting(
    key: str,
    body: SettingUpdate,
    admin: dict = Depends(require_admin),
):
    # Don't overwrite secrets with the mask placeholder
    if body.value == SECRET_MASK:
        return {"ok": True, "skipped": True}
    await cfg.set_value(key, body.value)
    return {"ok": True}


@router.post("/bulk")
async def bulk_update(body: BulkUpdate, admin: dict = Depends(require_admin)):
    # Fetch current settings so we can protect existing secret values
    current = {s["key"]: s for s in await cfg.get_all()}
    skipped = 0
    updated = 0
    for key, value in body.settings.items():
        # Never overwrite with the mask placeholder
        if value == SECRET_MASK:
            skipped += 1
            continue
        # Skip empty string for secret fields that already have a value stored
        cur = current.get(key, {})
        if value == "" and cur.get("is_secret") and cur.get("value"):
            skipped += 1
            continue
        await cfg.set_value(key, value)
        updated += 1
    return {"ok": True, "updated": updated, "skipped": skipped}


# ─── Connection testers ──────────────────────────────────────────────────────

@router.post("/test/elasticsearch")
async def test_es(admin: dict = Depends(require_admin)):
    from app.services.es_service import test_connection
    return await test_connection()


@router.post("/test/llm")
async def test_llm(admin: dict = Depends(require_admin)):
    try:
        from app.services.llm_service import chat_completion
        result = await chat_completion(
            "You are a test assistant.",
            "Reply with exactly: OK"
        )
        return {"ok": True, "response": result[:100]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.post("/test/jira")
async def test_jira(admin: dict = Depends(require_admin)):
    from app.services.jira_service import test_connection
    return await test_connection()


@router.post("/reload-cache")
async def reload_cache(admin: dict = Depends(require_admin)):
    """Force-reload all settings from DB into memory cache.
    Use this after updating settings directly via psql — no container restart needed."""
    await cfg.invalidate_cache()
    await cfg.load_all()
    return {"ok": True, "message": "Settings cache reloaded from database"}


@router.post("/test/mail")
async def test_mail(admin: dict = Depends(require_admin)):
    try:
        from app.services.mail_service import send_alert_email
        to = await cfg.get("mail.from", "")
        result = await send_alert_email(
            to,
            "CloudPulse — Mail Test",
            "<html><body style='font-family:Arial'>Mail connection test from CloudPulse. ✅</body></html>"
        )
        return result
    except Exception as e:
        return {"ok": False, "error": str(e)}
