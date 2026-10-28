"""
Shared APScheduler instance.
Import from here to avoid circular dependencies between main.py and routers.
"""
from apscheduler.schedulers.asyncio import AsyncIOScheduler

scheduler = AsyncIOScheduler()
