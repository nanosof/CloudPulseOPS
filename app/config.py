"""
Runtime configuration manager.
All settings stored in PostgreSQL infraguardian_settings table.
Provides in-memory cache with invalidation.
"""
from __future__ import annotations
import asyncio
from typing import Any, Dict, Optional
from sqlalchemy import text
from app.database import AsyncSessionLocal

_cache: Dict[str, str] = {}
_loaded = False
_lock = asyncio.Lock()


async def _load_all():
    global _cache, _loaded
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text("SELECT key, value FROM infraguardian_settings")
        )
        rows = result.fetchall()
        _cache = {r[0]: r[1] or "" for r in rows}
        _loaded = True


async def get(key: str, default: str = "") -> str:
    global _loaded
    if not _loaded:
        async with _lock:
            if not _loaded:
                await _load_all()
    return _cache.get(key, default)


async def get_int(key: str, default: int = 0) -> int:
    v = await get(key, str(default))
    try:
        return int(v)
    except (ValueError, TypeError):
        return default


async def get_float(key: str, default: float = 0.0) -> float:
    v = await get(key, str(default))
    try:
        return float(v)
    except (ValueError, TypeError):
        return default


async def get_bool(key: str, default: bool = False) -> bool:
    v = await get(key, str(default))
    return v.lower() in ("true", "1", "yes", "on")


async def set_value(key: str, value: str, updated_by: str = "system"):
    global _cache
    async with AsyncSessionLocal() as db:
        await db.execute(
            text("""
                UPDATE infraguardian_settings
                SET value = :val, updated_at = NOW(), updated_by = :by
                WHERE key = :key
            """),
            {"val": value, "key": key, "by": updated_by}
        )
        await db.commit()
    _cache[key] = value


async def get_all_by_category(category: str) -> list[dict]:
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text("""
                SELECT key, value, description, is_secret
                FROM infraguardian_settings
                WHERE category = :cat
                ORDER BY key
            """),
            {"cat": category}
        )
        rows = result.fetchall()
        return [
            {
                "key": r[0],
                "value": "***" if r[3] and r[1] else (r[1] or ""),
                "description": r[2],
                "is_secret": r[3],
            }
            for r in rows
        ]


async def get_all() -> list[dict]:
    """Return all settings (for admin settings page)."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text("""
                SELECT key, value, category, description, is_secret
                FROM infraguardian_settings
                ORDER BY category, key
            """)
        )
        return [
            {
                "key":         r[0],
                "value":       r[1] or "",
                "category":    r[2],
                "description": r[3],
                "is_secret":   r[4],
            }
            for r in result.fetchall()
        ]


async def load_all():
    """Public wrapper for cache warm-up on startup."""
    await _load_all()


async def invalidate_cache():
    global _loaded
    _loaded = False
