"""
Agent-to-Agent API  (prefix: /api/v1/agent)
============================================
Lets a separate monitoring AI agent (n8n, Zabbix webhook, etc.) query
CloudPulse for real-time CPU / memory / disk / process data for a
specific server and receive a structured JSON payload it can act on.

Authentication
--------------
Every request must carry the header  X-CloudPulse-Key: <token>
(X-InfraGuardian-Key is still accepted for older integrations.)
The token is stored (plain-text for now, bcrypt-upgradeable later) in
the infraguardian_settings row with key = 'agent.api_key'.
An empty key in the DB means the feature is disabled entirely.

Optional IP allowlist
---------------------
Setting 'agent.allowed_ips' (comma-separated) restricts callers by
source IP.  Leave empty to allow any IP.

Endpoints
---------
GET  /api/v1/agent/server/{server_name}
     Real-time metrics for one server.
     Query params:
       metrics  comma-separated subset of: cpu,memory,disk,process
                (default: all four)
       minutes  look-back window in minutes (default 60, max 480)

GET  /api/v1/agent/fleet
     Fleet-level summary (top 10 by worst metric).
     Query params:
       minutes  look-back window (default 60)

POST /api/v1/agent/query
     Batch: request metrics for several servers in one call.
     Body: {"servers": ["SRV-001","SRV-002"], "metrics": ["cpu","disk"], "minutes": 60}
"""

from __future__ import annotations

import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.services.es_service import (
    get_server_detail,
    get_top_servers,
)

router = APIRouter(prefix="/api/v1/agent", tags=["agent"])


# ─────────────────────────────────────────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────────────────────────────────────────

async def _get_setting(db: AsyncSession, key: str, default: str = "") -> str:
    row = await db.execute(
        text("SELECT value FROM infraguardian_settings WHERE key = :k"),
        {"k": key},
    )
    result = row.fetchone()
    return (result[0] or "").strip() if result else default


async def _verify_agent_key(
    request: Request,
    x_cloudpulse_key: Optional[str] = Header(None, alias="X-CloudPulse-Key"),
    x_infraguardian_key: Optional[str] = Header(None, alias="X-InfraGuardian-Key"),  # older integrations
    db: AsyncSession = Depends(get_db),
) -> None:
    """Dependency: validates API key and (optionally) caller IP."""

    # ── Load settings ─────────────────────────────────────────────────────
    stored_key = await _get_setting(db, "agent.api_key")
    if not stored_key:
        raise HTTPException(
            status_code=503,
            detail="Agent API is not enabled — set agent.api_key in CloudPulse settings.",
        )

    key = x_cloudpulse_key or x_infraguardian_key
    if not key or key != stored_key:
        raise HTTPException(status_code=401, detail="Invalid or missing X-CloudPulse-Key.")

    # ── Optional IP allowlist ──────────────────────────────────────────────
    allowed_ips_raw = await _get_setting(db, "agent.allowed_ips")
    if allowed_ips_raw:
        allowed = {ip.strip() for ip in allowed_ips_raw.split(",") if ip.strip()}
        caller_ip = request.client.host if request.client else ""
        if caller_ip not in allowed:
            raise HTTPException(
                status_code=403,
                detail=f"Caller IP {caller_ip!r} is not in the allowed list.",
            )


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic models
# ─────────────────────────────────────────────────────────────────────────────

class BatchQueryRequest(BaseModel):
    servers: list[str]
    metrics: list[str] = ["cpu", "memory", "disk", "process"]
    minutes: int = 60


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_VALID_METRICS = {"cpu", "memory", "disk", "process"}
_MAX_MINUTES   = 480  # 8 hours max look-back


def _parse_metrics(raw: str | None) -> list[str]:
    if not raw:
        return list(_VALID_METRICS)
    parsed = [m.strip().lower() for m in raw.split(",")]
    return [m for m in parsed if m in _VALID_METRICS] or list(_VALID_METRICS)


def _clamp_minutes(minutes: int) -> int:
    return max(5, min(minutes, _MAX_MINUTES))


async def _last_capacity_snapshot(db: AsyncSession, server_name: str) -> dict[str, Any]:
    """Return the most recent daily capacity row for this server (if any)."""
    row = await db.execute(
        text("""
            SELECT report_date, avg_cpu_pct, max_cpu_pct,
                   avg_mem_pct, total_mem_gb, used_mem_gb, free_mem_gb,
                   avg_disk_pct, total_disk_gb, used_disk_gb, free_disk_gb,
                   disk_details
            FROM infraguardian_capacity_daily
            WHERE server_name = :srv
            ORDER BY report_date DESC
            LIMIT 1
        """),
        {"srv": server_name},
    )
    r = row.fetchone()
    if not r:
        return {}
    return {
        "report_date":   str(r[0]),
        "avg_cpu_pct":   r[1],
        "max_cpu_pct":   r[2],
        "avg_mem_pct":   r[3],
        "total_mem_gb":  r[4],
        "used_mem_gb":   r[5],
        "free_mem_gb":   r[6],
        "avg_disk_pct":  r[7],
        "total_disk_gb": r[8],
        "used_disk_gb":  r[9],
        "free_disk_gb":  r[10],
        "disk_details":  r[11],
    }


async def _capacity_thresholds(db: AsyncSession) -> dict[str, float]:
    rows = await db.execute(
        text("""
            SELECT key, value FROM infraguardian_settings
            WHERE key IN (
                'capacity.cpu_warn', 'capacity.cpu_crit',
                'capacity.mem_warn', 'capacity.disk_warn', 'capacity.disk_crit'
            )
        """)
    )
    result = {}
    for key, val in rows.fetchall():
        try:
            result[key.split(".", 1)[1]] = float(val)
        except (TypeError, ValueError):
            pass
    return result


def _severity(value: float, warn: float, crit: float) -> str:
    if value >= crit:
        return "critical"
    if value >= warn:
        return "warning"
    return "ok"


async def _build_server_payload(
    server_name: str,
    metrics: list[str],
    minutes: int,
    db: AsyncSession,
) -> dict[str, Any]:
    """Fetch real-time ES data + DB snapshot for one server and return payload."""
    t0 = time.monotonic()

    # Real-time from Elasticsearch
    # get_server_detail uses hours; convert minutes → hours (min 1h window)
    detail = await get_server_detail(server_name, hours=max(1, minutes // 60))

    # Historical snapshot from DB
    snapshot = await _last_capacity_snapshot(db, server_name)

    # Thresholds
    thresh = await _capacity_thresholds(db)
    cpu_warn  = thresh.get("cpu_warn",  80)
    cpu_crit  = thresh.get("cpu_crit",  90)
    mem_warn  = thresh.get("mem_warn",  85)
    disk_warn = thresh.get("disk_warn", 80)
    disk_crit = thresh.get("disk_crit", 90)

    # get_server_detail returns: info, cpu, memory, disks, processes
    info  = detail.get("info",      {})
    cpu_d = detail.get("cpu",       {})
    mem_d = detail.get("memory",    {})
    disks = detail.get("disks",     [])
    procs = detail.get("processes", [])

    payload: dict[str, Any] = {
        "server": server_name,
        "query_window_minutes": minutes,
        "elapsed_ms": None,  # filled below
        "os_name":  info.get("os_name"),
        "host_ip":  info.get("ip"),
        "realtime": {},
        "capacity_snapshot": snapshot,
        "alerts": [],
    }

    rt = payload["realtime"]

    if "cpu" in metrics:
        # cpu_d: {trend:[], avg:float, max:float}  (values already 0-100)
        val = cpu_d.get("avg", 0) or 0
        sev = _severity(val, cpu_warn, cpu_crit)
        rt["cpu"] = {
            "avg_pct":  val,
            "max_pct":  cpu_d.get("max"),
            "severity": sev,
        }
        if sev != "ok":
            payload["alerts"].append({
                "metric": "cpu", "severity": sev,
                "value": val, "threshold": cpu_crit if sev == "critical" else cpu_warn,
                "message": f"CPU {val:.1f}% is {sev} on {server_name}",
            })

    if "memory" in metrics:
        # mem_d: {trend:[], avg:float, max:float, total_gb:float, free_gb:float}
        val      = mem_d.get("avg", 0) or 0
        total_gb = mem_d.get("total_gb", 0) or 0
        free_gb  = mem_d.get("free_gb",  0) or 0
        used_gb  = round(total_gb - free_gb, 1)
        sev = _severity(val, mem_warn, mem_warn + 10)
        rt["memory"] = {
            "used_pct":  val,
            "total_gb":  total_gb,
            "used_gb":   used_gb,
            "free_gb":   free_gb,
            "severity":  sev,
        }
        if sev != "ok":
            payload["alerts"].append({
                "metric": "memory", "severity": sev,
                "value": val, "threshold": mem_warn,
                "message": f"Memory {val:.1f}% used on {server_name}",
            })

    if "disk" in metrics:
        # disks: [{mount, used_pct, total_gb, free_gb, severity}, ...]
        disk_alerts = []
        rt["disk"] = []
        for d in disks:
            val      = d.get("used_pct", 0) or 0
            total_gb = d.get("total_gb", 0) or 0
            free_gb  = d.get("free_gb",  0) or 0
            used_gb  = round(total_gb - free_gb, 1)
            sev = _severity(val, disk_warn, disk_crit)
            rt["disk"].append({
                "mount":    d.get("mount"),
                "used_pct": val,
                "total_gb": total_gb,
                "used_gb":  used_gb,
                "free_gb":  free_gb,
                "severity": sev,
            })
            if sev != "ok":
                disk_alerts.append({
                    "metric": f"disk:{d.get('mount', '?')}",
                    "severity": sev,
                    "value": val, "threshold": disk_crit if sev == "critical" else disk_warn,
                    "message": f"Disk {d.get('mount','?')} {val:.1f}% used on {server_name}",
                })
        payload["alerts"].extend(disk_alerts)

    if "process" in metrics:
        # procs: [{name, cpu_pct, mem_mb}, ...]
        rt["process"] = procs

    payload["elapsed_ms"] = round((time.monotonic() - t0) * 1000, 1)

    # Overall severity (highest of all alerts)
    all_severities = [a["severity"] for a in payload["alerts"]]
    payload["overall_severity"] = (
        "critical" if "critical" in all_severities else
        "warning"  if "warning"  in all_severities else
        "ok"
    )

    return payload


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/server/{server_name}",
    summary="Real-time metrics for one server",
    dependencies=[Depends(_verify_agent_key)],
)
async def agent_server(
    server_name: str,
    metrics: Optional[str] = Query(
        None,
        description="Comma-separated: cpu,memory,disk,process (default: all)",
    ),
    minutes: int = Query(60, ge=5, le=_MAX_MINUTES, description="Look-back window"),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """
    Called by a monitoring AI agent when it receives an alert for *server_name*.
    Returns real-time ES data + last daily capacity snapshot + severity assessment.
    """
    parsed_metrics = _parse_metrics(metrics)
    minutes = _clamp_minutes(minutes)
    return await _build_server_payload(server_name, parsed_metrics, minutes, db)


@router.get(
    "/fleet",
    summary="Fleet-level summary (top servers by metric)",
    dependencies=[Depends(_verify_agent_key)],
)
async def agent_fleet(
    minutes: int = Query(60, ge=5, le=_MAX_MINUTES),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """
    Returns top-10 servers for each metric so an external agent can
    identify the hottest servers fleet-wide without iterating per-server.
    """
    minutes = _clamp_minutes(minutes)
    t0 = time.monotonic()

    import asyncio as _asyncio
    cpu_top, mem_top, disk_top, thresh = await _asyncio.gather(
        get_top_servers(metric="cpu",    top_n=10, minutes=minutes),
        get_top_servers(metric="memory", top_n=10, minutes=minutes),
        get_top_servers(metric="disk",   top_n=10, minutes=minutes),
        _capacity_thresholds(db),
    )

    return {
        "query_window_minutes": minutes,
        "elapsed_ms": round((time.monotonic() - t0) * 1000, 1),
        "top_cpu":    cpu_top,
        "top_memory": mem_top,
        "top_disk":   disk_top,
        "thresholds": thresh,
    }


@router.post(
    "/query",
    summary="Batch query: metrics for multiple servers",
    dependencies=[Depends(_verify_agent_key)],
)
async def agent_batch_query(
    body: BatchQueryRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """
    Allows an agent to ask about several servers in one HTTP call.
    Returns a list of server payloads in the same order as *body.servers*.

    Example body:
        {
            "servers": ["WINSERVER-01", "WINSERVER-02"],
            "metrics": ["cpu", "disk"],
            "minutes": 30
        }
    """
    if len(body.servers) > 20:
        raise HTTPException(
            status_code=400,
            detail="Batch limit is 20 servers per request.",
        )

    metrics  = [m for m in body.metrics if m in _VALID_METRICS] or list(_VALID_METRICS)
    minutes  = _clamp_minutes(body.minutes)
    t0       = time.monotonic()

    import asyncio as _aio
    results = await _aio.gather(
        *[_build_server_payload(srv, metrics, minutes, db) for srv in body.servers],
        return_exceptions=True,
    )

    servers_out = []
    for srv, res in zip(body.servers, results):
        if isinstance(res, Exception):
            servers_out.append({"server": srv, "error": str(res)})
        else:
            servers_out.append(res)

    return {
        "query_window_minutes": minutes,
        "metrics_requested": metrics,
        "elapsed_ms": round((time.monotonic() - t0) * 1000, 1),
        "servers": servers_out,
    }


@router.get(
    "/health",
    summary="Agent API health check (no auth required)",
    include_in_schema=True,
)
async def agent_health() -> dict[str, str]:
    """Public endpoint so a monitoring agent can verify the API is reachable."""
    return {"status": "ok", "service": "CloudPulse Agent API v1"}
