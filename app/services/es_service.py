"""
Elasticsearch service — read-only capacity data for Windows Server hosts.

Targets Elastic Agent 8.x data streams:
  metrics-system.cpu-*          → CPU metrics
  metrics-system.memory-*       → Memory metrics
  metrics-system.filesystem-*   → Disk / filesystem metrics
  metrics-system.process-*      → Per-process metrics

Windows Server filter: host.os.name.keyword wildcard "Windows Server*"
This captures 2016/2019/2022/2025 in all editions (Standard, Datacenter)
and excludes Windows 10/11 desktops.
"""
from __future__ import annotations
import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import httpx
import app.config as cfg

# ─────────────────────────────────────────────────────────────────
# Index patterns for Elastic Agent data streams
#
# This environment uses custom namespaces that end with "_windows",
# e.g.:  metrics-system.cpu-at3_vsn_windows-*
#         metrics-system.cpu-hrc_sc_prod_windows-*
#         metrics-system.cpu-kzn_emt_vsn_nprod_windows-*
#
# Using "*windows*" in the pattern targets ONLY Windows data streams
# and inherently excludes Linux/other OS namespaces — no OS field
# filter needed. Server vs desktop distinction is handled by the
# fact that only Windows Server hosts have Elastic Agent deployed.
# ─────────────────────────────────────────────────────────────────
_IDX_CPU  = "metrics-system.cpu-*windows*"
_IDX_MEM  = "metrics-system.memory-*windows*"
_IDX_DISK = "metrics-system.filesystem-*windows*"
_IDX_PROC = "metrics-system.process-*windows*"

# Filter to Windows Server editions only (2016/2019/2022/2025, all editions).
# host.os.name is a keyword field in ECS — wildcard works directly on it.
# This excludes Windows 10/11 desktops that share the *windows* namespaces.
_SERVER_FILTER = {"wildcard": {"host.os.name": "Windows Server*"}}

# Disk-specific exclusions — must be added as must_not in every disk query.
# UDF (Universal Disk Format) drives are optical drives / mounted ISOs.
# They are always read-only and report 100% used with no free space.
# Excluding them prevents false CRITICAL alerts on every server that has a
# mounted ISO or DVD drive.
_DISK_MUST_NOT = [
    {"term": {"system.filesystem.type": "udf"}},   # optical / ISO mounts
    {"term": {"system.filesystem.type": "cdfs"}},  # CD-ROM filesystem (rare but possible)
]


def _es_headers(username: str, password: str) -> dict:
    import base64
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}", "Content-Type": "application/json"}


async def _get_conn() -> tuple[str, dict, bool]:
    url      = await cfg.get("es.url", "")
    username = await cfg.get("es.username", "")
    password = await cfg.get("es.password", "")
    ssl_v    = await cfg.get_bool("es.ssl_verify", False)
    return url.rstrip("/"), _es_headers(username, password), ssl_v


async def _post(path: str, body: dict) -> dict:
    """
    POST to ES. Always passes:
      ignore_unavailable=true        — skip shards/indices that are offline
      allow_partial_search_results=true — return what we have if some shards fail
    """
    url, headers, ssl_verify = await _get_conn()
    params = "ignore_unavailable=true&allow_partial_search_results=true"
    sep = "&" if "?" in path else "?"
    full = f"{url}{path}{sep}{params}"
    async with httpx.AsyncClient(verify=ssl_verify, timeout=30) as client:
        resp = await client.post(full, json=body, headers=headers)
        resp.raise_for_status()
        return resp.json()


def _field(src: dict, dotpath: str, default=None):
    """
    Get a value from an ES _source dict that may store fields as either:
      • nested objects:  {"host": {"os": {"name": "..."}}}
      • flat dot-keys:   {"host.os.name": "..."}
    Falls back to default if not found.
    """
    if dotpath in src:
        return src[dotpath]
    parts = dotpath.split(".")
    val = src
    for p in parts:
        if not isinstance(val, dict):
            return default
        val = val.get(p)
        if val is None:
            return default
    return val if val is not None else default


def _severity(val: float) -> str:
    if val >= 90: return "critical"
    if val >= 80: return "warning"
    return "ok"


# ─────────────────────────────────────────────────────────────────
# Top N servers by metric (dashboard overview)
# ─────────────────────────────────────────────────────────────────

async def get_top_servers(metric: str = "cpu", top_n: int = 20, minutes: int = 60) -> List[Dict]:
    """
    Returns top N Windows Server hosts sorted by metric (cpu | memory | disk).
    Uses bucket aggregations — read-only, no writes.
    """
    # Per-metric: index pattern and ES field
    # system.cpu.total.norm.pct  → already normalised 0–1 (×100 = %)
    # system.memory.actual.used.pct → 0–1
    # system.filesystem.used.pct    → 0–1
    metric_cfg = {
        "cpu":    {"index": _IDX_CPU,  "field": "system.cpu.total.norm.pct"},
        "memory": {"index": _IDX_MEM,  "field": "system.memory.actual.used.pct"},
        "disk":   {"index": _IDX_DISK, "field": "system.filesystem.used.pct"},
    }
    mc = metric_cfg.get(metric, metric_cfg["cpu"])

    # Disk queries additionally exclude UDF/optical mounts (always show 100% used)
    must_not = _DISK_MUST_NOT if metric == "disk" else []

    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}},
                    _SERVER_FILTER,
                ],
                **({"must_not": must_not} if must_not else {}),
            }
        },
        "aggs": {
            "by_host": {
                "terms": {
                    "field": "host.name",
                    "size":  500,
                    "order": {"avg_val": "desc"}
                },
                "aggs": {
                    "avg_val": {"avg": {"field": mc["field"]}},
                    "max_val": {"max": {"field": mc["field"]}},
                    "top_hit": {
                        "top_hits": {
                            "size": 1,
                            "_source": ["host.name", "host.os.name", "host.ip"],
                            "sort": [{"@timestamp": "desc"}]
                        }
                    }
                }
            }
        }
    }

    try:
        resp = await _post(f"/{mc['index']}/_search", body)
    except Exception as e:
        return [{"error": str(e)}]

    results = []
    for bucket in resp.get("aggregations", {}).get("by_host", {}).get("buckets", [])[:top_n]:
        src = (bucket.get("top_hit", {}).get("hits", {}).get("hits") or [{}])[0].get("_source", {})
        avg = (bucket.get("avg_val", {}).get("value") or 0)
        mx  = (bucket.get("max_val", {}).get("value") or 0)
        avg_pct = round(avg * 100, 1)
        max_pct = round(mx  * 100, 1)

        ips = _field(src, "host.ip", "")
        results.append({
            "server":   bucket["key"],
            "os_name":  _field(src, "host.os.name", "Windows Server"),
            "ip":       (ips[0] if isinstance(ips, list) and ips else str(ips)) if ips else "",
            "avg":      avg_pct,
            "max":      max_pct,
            "severity": _severity(avg_pct),
        })

    return results


# ─────────────────────────────────────────────────────────────────
# Per-server detail: CPU trend, Memory trend, Disk mounts, Processes
# ─────────────────────────────────────────────────────────────────

async def get_server_detail(server_name: str, hours: int = 24) -> Dict:
    host_filter = {"term": {"host.name": server_name}}

    async def _cpu_trend():
        body = {
            "size": 0,
            "query": {"bool": {"filter": [
                {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                host_filter,
                _SERVER_FILTER,
            ]}},
            "aggs": {
                "over_time": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "15m",
                        "min_doc_count": 1
                    },
                    "aggs": {
                        "avg_cpu": {"avg": {"field": "system.cpu.total.norm.pct"}},
                        "max_cpu": {"max": {"field": "system.cpu.total.norm.pct"}},
                    }
                },
                "overall_avg": {"avg": {"field": "system.cpu.total.norm.pct"}},
                "overall_max": {"max": {"field": "system.cpu.total.norm.pct"}},
            }
        }
        r = await _post(f"/{_IDX_CPU}/_search", body)
        agg = r.get("aggregations", {})
        return {
            "trend": [
                {
                    "time": b["key_as_string"],
                    "avg":  round((b.get("avg_cpu", {}).get("value") or 0) * 100, 1),
                    "max":  round((b.get("max_cpu", {}).get("value") or 0) * 100, 1),
                }
                for b in agg.get("over_time", {}).get("buckets", [])
            ],
            "avg": round((agg.get("overall_avg", {}).get("value") or 0) * 100, 1),
            "max": round((agg.get("overall_max", {}).get("value") or 0) * 100, 1),
        }

    async def _mem_trend():
        body = {
            "size": 0,
            "query": {"bool": {"filter": [
                {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                host_filter,
                _SERVER_FILTER,
            ]}},
            "aggs": {
                "over_time": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "15m",
                        "min_doc_count": 1
                    },
                    "aggs": {
                        "used_pct": {"avg": {"field": "system.memory.actual.used.pct"}},
                    }
                },
                "overall_avg":  {"avg": {"field": "system.memory.actual.used.pct"}},
                "overall_max":  {"max": {"field": "system.memory.actual.used.pct"}},
                "total_bytes":  {"max": {"field": "system.memory.total"}},
                "free_bytes":   {"avg": {"field": "system.memory.actual.free"}},
            }
        }
        r = await _post(f"/{_IDX_MEM}/_search", body)
        agg = r.get("aggregations", {})
        return {
            "trend": [
                {
                    "time":     b["key_as_string"],
                    "used_pct": round((b.get("used_pct", {}).get("value") or 0) * 100, 1),
                }
                for b in agg.get("over_time", {}).get("buckets", [])
            ],
            "avg":      round((agg.get("overall_avg", {}).get("value") or 0) * 100, 1),
            "max":      round((agg.get("overall_max", {}).get("value") or 0) * 100, 1),
            "total_gb": round((agg.get("total_bytes", {}).get("value") or 0) / (1024**3), 1),
            "free_gb":  round((agg.get("free_bytes",  {}).get("value") or 0) / (1024**3), 1),
        }

    async def _disk_detail():
        body = {
            "size": 0,
            "query": {"bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": "now-30m"}}},
                    host_filter,
                    _SERVER_FILTER,
                ],
                "must_not": _DISK_MUST_NOT,
            }},
            "aggs": {
                "by_mount": {
                    "terms": {
                        "field": "system.filesystem.mount_point",
                        "size":  20
                    },
                    "aggs": {
                        "used_pct": {"avg": {"field": "system.filesystem.used.pct"}},
                        "total":    {"max": {"field": "system.filesystem.total"}},
                        "free":     {"avg": {"field": "system.filesystem.free"}},
                    }
                }
            }
        }
        r = await _post(f"/{_IDX_DISK}/_search", body)
        mounts = []
        for b in r.get("aggregations", {}).get("by_mount", {}).get("buckets", []):
            used_pct = (b.get("used_pct", {}).get("value") or 0) * 100
            mounts.append({
                "mount":    b["key"],
                "used_pct": round(used_pct, 1),
                "total_gb": round((b.get("total", {}).get("value") or 0) / (1024**3), 1),
                "free_gb":  round((b.get("free",  {}).get("value") or 0) / (1024**3), 1),
                "severity": _severity(used_pct),
            })
        return sorted(mounts, key=lambda x: -x["used_pct"])

    async def _top_processes():
        body = {
            "size": 0,
            "query": {"bool": {"filter": [
                {"range": {"@timestamp": {"gte": "now-5m"}}},
                host_filter,
                _SERVER_FILTER,
            ]}},
            "aggs": {
                "by_proc": {
                    "terms": {
                        "field": "process.name",
                        "size":  8,
                        "order": {"avg_cpu": "desc"}
                    },
                    "aggs": {
                        "avg_cpu": {"avg": {"field": "system.process.cpu.total.pct"}},
                        "avg_mem": {"avg": {"field": "system.process.memory.rss.bytes"}},
                    }
                }
            }
        }
        r = await _post(f"/{_IDX_PROC}/_search", body)
        procs = []
        for b in r.get("aggregations", {}).get("by_proc", {}).get("buckets", []):
            cpu_pct = round((b.get("avg_cpu", {}).get("value") or 0) * 100, 2)
            mem_mb  = round((b.get("avg_mem", {}).get("value") or 0) / (1024**2), 1)
            procs.append({
                "name":    b["key"],
                "cpu_pct": cpu_pct,
                "mem_mb":  mem_mb,
            })
        return sorted(procs, key=lambda x: -x["cpu_pct"])[:8]

    async def _host_info():
        body = {
            "size": 1,
            "query": {"bool": {"filter": [
                host_filter,
                _SERVER_FILTER,
            ]}},
            "sort": [{"@timestamp": "desc"}],
            "_source": [
                "host.name", "host.os.name", "host.os.version",
                "host.os.build", "host.os.kernel", "host.ip",
                "host.hostname", "host.architecture", "@timestamp"
            ],
        }
        r = await _post(f"/{_IDX_CPU}/_search", body)
        hits = r.get("hits", {}).get("hits", [])
        if hits:
            src = hits[0]["_source"]
            ips = _field(src, "host.ip", "")
            return {
                "name":         _field(src, "host.name", server_name),
                "os_name":      _field(src, "host.os.name", "Windows Server"),
                "os_version":   _field(src, "host.os.version", ""),
                "os_build":     _field(src, "host.os.build", ""),
                "os_kernel":    _field(src, "host.os.kernel", ""),
                "architecture": _field(src, "host.architecture", "x86_64"),
                "ip": (ips[0] if isinstance(ips, list) and ips else str(ips)) if ips else "",
                "last_seen": hits[0].get("_source", {}).get("@timestamp", ""),
            }
        return {"name": server_name}

    # Run all queries concurrently
    cpu, mem, disks, procs, info = await asyncio.gather(
        _cpu_trend(), _mem_trend(), _disk_detail(), _top_processes(), _host_info(),
        return_exceptions=True
    )

    def safe(r, default):
        return default if isinstance(r, Exception) else r

    return {
        "server":    server_name,
        "info":      safe(info,  {"name": server_name}),
        "cpu":       safe(cpu,   {"trend": [], "avg": 0, "max": 0}),
        "memory":    safe(mem,   {"trend": [], "avg": 0, "max": 0, "total_gb": 0, "free_gb": 0}),
        "disks":     safe(disks, []),
        "processes": safe(procs, []),
    }


# ─────────────────────────────────────────────────────────────────
# List all Windows Server hosts (search autocomplete)
# ─────────────────────────────────────────────────────────────────

async def list_windows_servers(query: str = "", limit: int = 50) -> List[str]:
    filters: list = [
        {"range": {"@timestamp": {"gte": "now-2h"}}},
        _SERVER_FILTER,
    ]
    if query:
        filters.append({"wildcard": {"host.name": f"*{query.lower()}*"}})

    body = {
        "size": 0,
        "query": {"bool": {"filter": filters}},
        "aggs": {
            "servers": {"terms": {"field": "host.name", "size": limit}}
        }
    }
    try:
        resp = await _post(f"/{_IDX_CPU}/_search", body)
        return [b["key"] for b in resp.get("aggregations", {}).get("servers", {}).get("buckets", [])]
    except Exception:
        return []


# ─────────────────────────────────────────────────────────────────
# Dashboard fleet summary (total server count, severity counts)
# ─────────────────────────────────────────────────────────────────

async def get_fleet_summary(minutes: int = 60) -> Dict:
    """
    Returns total Windows Server count (from inventory DB) and severity bands
    (from Elasticsearch live CPU data).

    Total comes from the inventory table so the count is stable even when servers
    temporarily stop reporting to Elasticsearch.  Only rows with monitored=TRUE
    and os_name ILIKE 'Windows Server%' are counted — workstations, desktops,
    and decommissioned hosts are excluded.
    """
    from sqlalchemy import text
    from app.database import AsyncSessionLocal

    # ── Stable total: inventory DB, Windows Server OS only ───────────
    try:
        async with AsyncSessionLocal() as db:
            row = (await db.execute(text(
                "SELECT COUNT(*) FROM infraguardian_server_inventory "
                "WHERE monitored = TRUE AND os_name ILIKE 'Windows Server%'"
            ))).fetchone()
            db_total = int(row[0]) if row else 0
    except Exception:
        db_total = 0

    # ── Severity bands: live ES CPU data ────────────────────────────
    async def _severity_bands(window_minutes: int):
        body = {
            "size": 0,
            "query": {"bool": {"filter": [
                {"range": {"@timestamp": {"gte": f"now-{window_minutes}m"}}},
                _SERVER_FILTER,
            ]}},
            "aggs": {
                "by_host": {
                    "terms": {"field": "host.name", "size": 500},
                    "aggs": {
                        "avg_cpu": {"avg": {"field": "system.cpu.total.norm.pct"}},
                    }
                }
            }
        }
        r = await _post(f"/{_IDX_CPU}/_search", body)
        critical = warning = ok = 0
        for b in r.get("aggregations", {}).get("by_host", {}).get("buckets", []):
            pct = (b.get("avg_cpu", {}).get("value") or 0) * 100
            sev = _severity(pct)
            if sev == "critical":   critical += 1
            elif sev == "warning":  warning  += 1
            else:                   ok       += 1
        return critical, warning, ok

    # ── Reporting counts per freshness window ────────────────────────
    # Each returns how many unique Windows Server hosts sent CPU data
    # within that window — shows agent health across the fleet.
    async def _count_reporting(window_minutes: int) -> int:
        body = {
            "size": 0,
            "query": {"bool": {"filter": [
                {"range": {"@timestamp": {"gte": f"now-{window_minutes}m"}}},
                _SERVER_FILTER,
            ]}},
            "aggs": {
                "unique_hosts": {"cardinality": {"field": "host.name"}}
            }
        }
        r = await _post(f"/{_IDX_CPU}/_search", body)
        return int(r.get("aggregations", {}).get("unique_hosts", {}).get("value", 0))

    try:
        # Run severity bands + all four freshness counts in parallel
        results = await asyncio.gather(
            _severity_bands(minutes),
            _count_reporting(1),
            _count_reporting(5),
            _count_reporting(10),
            _count_reporting(15),
            return_exceptions=True,
        )
        bands_result, r1, r5, r10, r15 = results

        def _safe_int(v):
            return int(v) if isinstance(v, int) else 0

        reporting = {
            "1m":  _safe_int(r1),
            "5m":  _safe_int(r5),
            "10m": _safe_int(r10),
            "15m": _safe_int(r15),
        }

        if isinstance(bands_result, Exception):
            raise bands_result
        critical, warning, ok = bands_result

        # If no servers are actively reporting in the requested window, widen to 24h
        if (critical + warning + ok) == 0 and minutes < 1440:
            critical, warning, ok = await _severity_bands(1440)
            return {"total": db_total, "critical": critical, "warning": warning, "ok": ok,
                    "window_minutes": minutes, "window_fallback": True, "reporting": reporting}
        return {"total": db_total, "critical": critical, "warning": warning, "ok": ok,
                "window_minutes": minutes, "reporting": reporting}
    except Exception as e:
        return {"total": db_total, "critical": 0, "warning": 0, "ok": 0, "error": str(e)}


# ─────────────────────────────────────────────────────────────────
# Daily capacity aggregation (APScheduler — stores averages to DB)
# ─────────────────────────────────────────────────────────────────

async def aggregate_daily_capacity(report_date: str | None = None) -> int:
    """
    Computes day-average CPU / memory / disk for every Windows Server
    and upserts one row per server into infraguardian_capacity_daily.
    Returns the number of servers saved.
    """
    from sqlalchemy import text
    from app.database import AsyncSessionLocal
    import json

    if not report_date:
        report_date = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    report_date = str(report_date)[:10]
    report_day = datetime.strptime(report_date, "%Y-%m-%d").date()   # asyncpg needs a date, not a string

    day_filter = {
        "range": {
            "@timestamp": {
                "gte": f"{report_date}T00:00:00Z",
                "lte": f"{report_date}T23:59:59Z",
            }
        }
    }

    # ── CPU ──────────────────────────────────────────────────────
    cpu_body = {
        "size": 0,
        "query": {"bool": {"filter": [day_filter, _SERVER_FILTER]}},
        "aggs": {
            "by_host": {
                "terms": {"field": "host.name", "size": 500},
                "aggs": {
                    "avg_cpu": {"avg": {"field": "system.cpu.total.norm.pct"}},
                    "max_cpu": {"max": {"field": "system.cpu.total.norm.pct"}},
                    "os_hit":  {
                        "top_hits": {
                            "size": 1,
                            "_source": ["host.os.name", "host.ip"],
                            "sort": [{"@timestamp": "desc"}]
                        }
                    },
                }
            }
        }
    }

    # ── Memory ───────────────────────────────────────────────────
    mem_body = {
        "size": 0,
        "query": {"bool": {"filter": [day_filter, _SERVER_FILTER]}},
        "aggs": {
            "by_host": {
                "terms": {"field": "host.name", "size": 500},
                "aggs": {
                    "avg_mem":   {"avg": {"field": "system.memory.actual.used.pct"}},
                    "max_mem":   {"max": {"field": "system.memory.actual.used.pct"}},
                    "total_mem": {"avg": {"field": "system.memory.total"}},
                    "free_mem":  {"avg": {"field": "system.memory.actual.free"}},
                }
            }
        }
    }

    # ── Disk ─────────────────────────────────────────────────────
    # Exclude UDF/optical drives — they are always 100% used (read-only media)
    # and would corrupt the daily capacity averages and alerts.
    disk_body = {
        "size": 0,
        "query": {"bool": {
            "filter":   [day_filter, _SERVER_FILTER],
            "must_not": _DISK_MUST_NOT,
        }},
        "aggs": {
            "by_host": {
                "terms": {"field": "host.name", "size": 500},
                "aggs": {
                    "max_disk": {"max": {"field": "system.filesystem.used.pct"}},
                    "avg_disk": {"avg": {"field": "system.filesystem.used.pct"}},
                    "by_mount": {
                        "terms": {
                            "field": "system.filesystem.mount_point",
                            "size": 20
                        },
                        "aggs": {
                            "avg_used_pct": {"avg": {"field": "system.filesystem.used.pct"}},
                            "total_bytes":  {"max": {"field": "system.filesystem.total"}},
                            "free_bytes":   {"avg": {"field": "system.filesystem.free"}},
                        }
                    }
                }
            }
        }
    }

    try:
        cpu_r, mem_r, disk_r = await asyncio.gather(
            _post(f"/{_IDX_CPU}/_search",  cpu_body),
            _post(f"/{_IDX_MEM}/_search",  mem_body),
            _post(f"/{_IDX_DISK}/_search", disk_body),
            return_exceptions=True
        )
    except Exception as e:
        return 0

    def _buckets(r):
        if isinstance(r, Exception):
            return []
        return r.get("aggregations", {}).get("by_host", {}).get("buckets", [])

    cpu_map  = {b["key"]: b for b in _buckets(cpu_r)}
    mem_map  = {b["key"]: b for b in _buckets(mem_r)}
    disk_map = {b["key"]: b for b in _buckets(disk_r)}

    saved = 0
    async with AsyncSessionLocal() as db:
        for server, cpu_b in cpu_map.items():
            src = (cpu_b.get("os_hit", {}).get("hits", {}).get("hits") or [{}])[0].get("_source", {})
            ips     = _field(src, "host.ip", "")
            ip      = (ips[0] if isinstance(ips, list) and ips else str(ips)) if ips else ""
            os_name = _field(src, "host.os.name", "Windows Server")

            avg_cpu = round((cpu_b.get("avg_cpu", {}).get("value") or 0) * 100, 2)
            max_cpu = round((cpu_b.get("max_cpu", {}).get("value") or 0) * 100, 2)

            # ── Memory GB values ─────────────────────────────────
            mem_b        = mem_map.get(server, {})
            avg_mem      = round((mem_b.get("avg_mem", {}).get("value") or 0) * 100, 2)
            max_mem      = round((mem_b.get("max_mem", {}).get("value") or 0) * 100, 2)
            total_mem_b  = mem_b.get("total_mem", {}).get("value") or 0
            free_mem_b   = mem_b.get("free_mem",  {}).get("value") or 0
            used_mem_b   = max(total_mem_b - free_mem_b, 0)
            total_mem_gb = round(total_mem_b / (1024**3), 2)
            used_mem_gb  = round(used_mem_b  / (1024**3), 2)
            free_mem_gb  = round(free_mem_b  / (1024**3), 2)

            # ── Disk GB values (per mount, then summed) ───────────
            disk_b   = disk_map.get(server, {})
            avg_disk = round((disk_b.get("avg_disk", {}).get("value") or 0) * 100, 2)
            max_disk = round((disk_b.get("max_disk", {}).get("value") or 0) * 100, 2)

            disk_details    = []
            total_disk_bytes = 0
            used_disk_bytes  = 0
            free_disk_bytes  = 0

            for mb in disk_b.get("by_mount", {}).get("buckets", []):
                mount_total_b = mb.get("total_bytes", {}).get("value") or 0
                mount_free_b  = mb.get("free_bytes",  {}).get("value") or 0
                mount_used_b  = max(mount_total_b - mount_free_b, 0)
                mount_pct     = round((mb.get("avg_used_pct", {}).get("value") or 0) * 100, 2)
                total_disk_bytes += mount_total_b
                used_disk_bytes  += mount_used_b
                free_disk_bytes  += mount_free_b
                disk_details.append({
                    "mount":    mb["key"],
                    "used_pct": mount_pct,
                    "total_gb": round(mount_total_b / (1024**3), 1),
                    "used_gb":  round(mount_used_b  / (1024**3), 1),
                    "free_gb":  round(mount_free_b  / (1024**3), 1),
                })

            total_disk_gb = round(total_disk_bytes / (1024**3), 2)
            used_disk_gb  = round(used_disk_bytes  / (1024**3), 2)
            free_disk_gb  = round(free_disk_bytes  / (1024**3), 2)

            await db.execute(text("""
                INSERT INTO infraguardian_capacity_daily
                    (server_name, report_date,
                     avg_cpu_pct, max_cpu_pct,
                     avg_mem_pct, max_mem_pct, total_mem_gb, used_mem_gb, free_mem_gb,
                     avg_disk_pct, max_disk_pct, total_disk_gb, used_disk_gb, free_disk_gb,
                     disk_details, os_name, host_ip)
                VALUES (:srv, :dt,
                        :avg_cpu, :max_cpu,
                        :avg_mem, :max_mem, :total_mem, :used_mem, :free_mem,
                        :avg_disk, :max_disk, :total_disk, :used_disk, :free_disk,
                        :disk_json, :os, :ip)
                ON CONFLICT (server_name, report_date) DO UPDATE SET
                    avg_cpu_pct   = EXCLUDED.avg_cpu_pct,
                    max_cpu_pct   = EXCLUDED.max_cpu_pct,
                    avg_mem_pct   = EXCLUDED.avg_mem_pct,
                    max_mem_pct   = EXCLUDED.max_mem_pct,
                    total_mem_gb  = EXCLUDED.total_mem_gb,
                    used_mem_gb   = EXCLUDED.used_mem_gb,
                    free_mem_gb   = EXCLUDED.free_mem_gb,
                    avg_disk_pct  = EXCLUDED.avg_disk_pct,
                    max_disk_pct  = EXCLUDED.max_disk_pct,
                    total_disk_gb = EXCLUDED.total_disk_gb,
                    used_disk_gb  = EXCLUDED.used_disk_gb,
                    free_disk_gb  = EXCLUDED.free_disk_gb,
                    disk_details  = EXCLUDED.disk_details,
                    os_name       = EXCLUDED.os_name,
                    host_ip       = EXCLUDED.host_ip
            """), {
                "srv": server, "dt": report_day,
                "avg_cpu": avg_cpu, "max_cpu": max_cpu,
                "avg_mem": avg_mem, "max_mem": max_mem,
                "total_mem": total_mem_gb, "used_mem": used_mem_gb, "free_mem": free_mem_gb,
                "avg_disk": avg_disk, "max_disk": max_disk,
                "total_disk": total_disk_gb, "used_disk": used_disk_gb, "free_disk": free_disk_gb,
                "disk_json": json.dumps(disk_details),
                "os": os_name, "ip": ip,
            })
            saved += 1
        await db.commit()

    return saved


# ─────────────────────────────────────────────────────────────────
# Connection test (index-level only — no cluster privileges needed)
# ─────────────────────────────────────────────────────────────────

# Correct index for Windows Security event logs (Elastic Agent data stream)
_IDX_SEC = ".ds-logs-system.security-*,logs-system.security*,winlogbeat-*"

def _user_filter(username: str) -> dict:
    """Match username across all 4 fields used by different Elastic Agent versions."""
    safe = username.replace("*", "").replace("?", "")
    return {"bool": {"should": [
        {"term":     {"winlog.event_data.TargetUserName": safe}},
        {"term":     {"user.target.name": safe}},
        {"term":     {"related.user": safe}},
        {"term":     {"winlog.event_data.SubjectUserName": safe}},
    ], "minimum_should_match": 1}}


def _extract_caller(lockouts: list, failures: list) -> tuple[str, str]:
    """
    5-layer CallerComputerName extraction (mirrors n8n Correlate AD Events node).
    Returns (machine_name, source_description).
    """
    import re as _re

    def clean(v: str) -> str:
        v = (v or "").replace("\\\\", "").replace("\\", "").strip()
        return "" if v in ("-", "") else v

    def from_message(msg: str) -> str:
        if not msg:
            return ""
        m = _re.search(r"Caller\s+Computer\s+Name:\s*\\{0,2}([^\n\r\s]+)", msg, _re.I)
        return clean(m.group(1)) if m and m.group(1) else ""

    # Layer 1 – TargetDomainName on 4740 (Elastic/Filebeat mapping: CallerComputerName → TargetDomainName)
    for h in lockouts:
        eid = str((h.get("winlog") or {}).get("event_id", ""))
        if eid == "4740":
            v = clean((h.get("winlog") or {}).get("event_data", {}).get("TargetDomainName", ""))
            # only accept if it looks like a machine name (not a plain domain like EMARATECH)
            if v and ("." in v or "-" in v or len(v) > 8):
                return v, "TargetDomainName (Event 4740 — Caller Computer Name)"

    # Layer 2 – parse from message text ("Caller Computer Name:\tXXX")
    for h in lockouts:
        v = from_message(h.get("message", ""))
        if v:
            return v, "CallerComputerName (parsed from message)"

    # Layer 3 – explicit CallerComputerName field (some older Elastic versions)
    for h in lockouts:
        v = clean((h.get("winlog") or {}).get("event_data", {}).get("CallerComputerName", ""))
        if v:
            return v, "CallerComputerName (Event 4740)"

    # Layer 4 – WorkstationName on 4625
    for h in failures:
        v = clean((h.get("winlog") or {}).get("event_data", {}).get("WorkstationName", ""))
        if v:
            return v, "WorkstationName (Event 4625)"

    # Layer 5 – SubjectComputerName / source.domain / host.hostname
    for h in lockouts:
        v = clean((h.get("winlog") or {}).get("event_data", {}).get("SubjectComputerName", ""))
        if v:
            return v, "SubjectComputerName (Event 4740)"
    for h in lockouts + failures:
        v = clean(h.get("source", {}).get("domain", "") or (h.get("host") or {}).get("hostname", ""))
        if v:
            return v, "source.domain / host.hostname"

    return "", "Not found in any field"


def _burst_analysis(timestamps: list[str]) -> list[dict]:
    """Group consecutive timestamps within 5-min windows into bursts."""
    from datetime import datetime as _dt, timezone as _tz
    ts = sorted(t for t in timestamps if t)
    if not ts:
        return []
    bursts, burst = [], [ts[0]]
    for i in range(1, len(ts)):
        try:
            diff = (_dt.fromisoformat(ts[i].replace("Z", "+00:00")) -
                    _dt.fromisoformat(ts[i - 1].replace("Z", "+00:00"))).total_seconds()
        except Exception:
            diff = 999
        if diff < 300:
            burst.append(ts[i])
        else:
            bursts.append(burst)
            burst = [ts[i]]
    bursts.append(burst)
    return [{"start": b[0], "end": b[-1], "count": len(b)} for b in bursts]


async def get_lockout_events(hours: float = 24, username: str = "") -> Dict:
    """Overview: recent lockout events + per-account / DC / source summaries."""
    hours = max(0.1, min(float(hours), 720))
    window = f"now-{hours}h"

    short_u = username.split("@")[0].strip() if username else ""
    base_filter: list = [{"range": {"@timestamp": {"gte": window}}}]
    if short_u:
        base_filter.append(_user_filter(short_u))

    # event.code is keyword (string "4740") — reliable across all Elastic Agent versions.
    # winlog.event_id is long in EA 8.x — use integers. Both in should for max compat.
    _event_filter = {"bool": {"should": [
        {"terms": {"event.code":    ["4740", "4625", "4771"]}},
        {"terms": {"winlog.event_id": [4740, 4625, 4771]}},
    ], "minimum_should_match": 1}}

    events_body = {
        "size": 500,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": base_filter + [_event_filter]}},
        "_source": ["@timestamp", "event.code", "event.action", "winlog.event_id",
                    "winlog.event_data.TargetUserName", "winlog.event_data.TargetDomainName",
                    "winlog.event_data.CallerComputerName", "winlog.event_data.WorkstationName",
                    "winlog.event_data.SubjectMachineName", "winlog.event_data.LogonType",
                    "winlog.computer_name", "user.target.name", "related.user",
                    "host.hostname", "message"],
    }
    aggs_body = {
        "size": 0,
        "query": {"bool": {"filter": base_filter + [_event_filter]}},
        "aggs": {
            "by_user":  {"terms": {"field": "winlog.event_data.TargetUserName.keyword", "size": 30,
                                   "order": {"_count": "desc"}}},
            "by_dc":    {"terms": {"field": "winlog.computer_name.keyword", "size": 10}},
            "by_event": {"terms": {"field": "event.code", "size": 5}},
            "timeline": {"date_histogram": {"field": "@timestamp",
                                            "calendar_interval": "1h" if hours <= 72 else "1d",
                                            "min_doc_count": 1}},
        },
    }

    try:
        er, ar = await asyncio.gather(
            _post(f"/{_IDX_SEC}/_search?ignore_unavailable=true", events_body),
            _post(f"/{_IDX_SEC}/_search?ignore_unavailable=true", aggs_body),
        )
    except Exception as e:
        return {"error": str(e), "events": [], "by_account": [], "by_source_machine": [],
                "by_dc": [], "total_lockout_events": 0, "failed_logons_total": 0}

    hits = (er.get("hits") or {}).get("hits", [])
    aggs = ar.get("aggregations") or {}

    def _parse_hit(h: dict) -> dict:
        s = h.get("_source", {})
        wl = s.get("winlog") or {}
        ed = wl.get("event_data") or {}
        # event.code (keyword) is more reliable than winlog.event_id (long)
        eid = str((s.get("event") or {}).get("code") or wl.get("event_id", ""))
        acct = (ed.get("TargetUserName") or (s.get("user") or {}).get("target", {}).get("name")
                or (s.get("related") or {}).get("user", [""])[0] if isinstance(
                    (s.get("related") or {}).get("user"), list) else ed.get("TargetUserName") or "")
        # For 4740: TargetDomainName = Caller Computer Name (Elastic/Filebeat field mapping)
        if eid == "4740":
            caller = ed.get("TargetDomainName", "").replace("\\\\", "").strip("-").strip()
            if not caller or ("." not in caller and "-" not in caller and len(caller) <= 8):
                # fall back to message parse
                import re as _re2
                msg = s.get("message", "")
                m2 = _re2.search(r"Caller\s+Computer\s+Name:\s*\\{0,2}([^\n\r\t\s]+)", msg, _re2.I)
                caller = m2.group(1).strip() if m2 and m2.group(1) else caller
        else:
            caller = (ed.get("CallerComputerName") or ed.get("WorkstationName") or
                      ed.get("SubjectMachineName") or "").replace("\\\\", "").strip("-").strip()
        return {
            "timestamp": s.get("@timestamp", ""),
            "event_id": eid,
            "event_type": {"4740": "Lockout", "4625": "Failed Logon", "4771": "Kerberos Failure"}.get(eid, eid),
            "account": acct,
            "caller_machine": caller,
            "logon_type": ed.get("LogonType", ""),
            "domain_controller": wl.get("computer_name", "") or (s.get("host") or {}).get("hostname", ""),
        }

    from collections import Counter as _Counter
    events = [_parse_hit(h) for h in hits]
    lockouts = [e for e in events if e["event_id"] == "4740"]
    failures = [e for e in events if e["event_id"] == "4625"]

    by_acct = _Counter(e["account"] for e in lockouts if e["account"])
    unique_accounts = [{"account": k, "lockouts": v, "last_seen": next(
        (e["timestamp"] for e in lockouts if e["account"] == k), "")}
        for k, v in by_acct.most_common(30)]

    # Build source-machine summary from parsed events (TargetDomainName for 4740)
    by_src = _Counter(e["caller_machine"] for e in lockouts if e.get("caller_machine"))
    source_machines = [{"machine": k, "lockouts": v} for k, v in by_src.most_common(20)]

    return {
        "window_hours": hours,
        "total_lockout_events": len(lockouts),
        "unique_accounts_locked": len(by_acct),
        "failed_logons_total": len(failures),
        "kerberos_failures": len([e for e in events if e["event_id"] == "4771"]),
        "events": events[:200],
        "by_account": unique_accounts,
        "by_source_machine": source_machines,
        "by_dc": [{"dc": b["key"], "count": b["doc_count"]}
                  for b in (aggs.get("by_dc") or {}).get("buckets", [])],
        "failed_logon_timeline": [{"time": b["key_as_string"], "count": b["doc_count"]}
                                   for b in (aggs.get("timeline") or {}).get("buckets", [])],
    }


async def get_user_lockout_triage(username: str, hours: float = 24) -> Dict:
    """
    Full triage for one user: ES lockout/failure/Kerberos events + Azure AD sign-in correlation.
    Mirrors the n8n Account Lockout Agent workflow logic.
    """
    hours = max(1, min(int(hours), 168))
    window = f"now-{hours}h"
    short_user = username.split("@")[0] if "@" in username else username

    es_body = {
        "size": 50,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": window}}}],
            "must": [
                _user_filter(short_user),
                {"bool": {"should": [
                    {"terms": {"event.code":      ["4740", "4625", "4771"]}},
                    {"terms": {"winlog.event_id": [4740, 4625, 4771]}},
                    {"terms": {"event.action": ["locked-out-user-account",
                                                "logon-failed",
                                                "kerberos-pre-authentication-failed"]}},
                ], "minimum_should_match": 1}},
            ],
        }},
        "_source": ["@timestamp", "event.code", "event.action", "winlog.event_id",
                    "winlog.event_data.TargetUserName", "winlog.event_data.TargetDomainName",
                    "winlog.event_data.CallerComputerName", "winlog.event_data.WorkstationName",
                    "winlog.event_data.SubjectComputerName", "winlog.event_data.SubjectMachineName",
                    "winlog.event_data.SubjectUserName", "winlog.event_data.LogonType",
                    "winlog.event_data.LogonProcessName", "winlog.event_data.AuthenticationPackageName",
                    "winlog.event_data.IpAddress", "winlog.computer_name",
                    "user.target.name", "related.user", "source.domain", "source.ip",
                    "host.hostname", "message"],
    }

    # Run ES + Azure sign-in query in parallel
    async def _azure_signins() -> list:
        try:
            from app.services import graph_service as g
            from datetime import datetime, timezone, timedelta
            since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
            upn = username if "@" in username else None
            if not upn:
                return []
            params = {
                "$filter": f"userPrincipalName eq '{upn}' and createdDateTime ge {since}",
                "$top": "50",
                "$orderby": "createdDateTime desc",
                "$select": ("createdDateTime,userDisplayName,userPrincipalName,appDisplayName,"
                            "ipAddress,location,status,deviceDetail,clientAppUsed,"
                            "conditionalAccessStatus,riskLevelDuringSignIn,riskState,"
                            "riskDetail,resourceDisplayName,isInteractive,authenticationRequirement"),
            }
            data = await g.get("/auditLogs/signIns", params)
            return data.get("value", [])
        except Exception:
            return []

    try:
        es_r, azure_signins = await asyncio.gather(
            _post(f"/{_IDX_SEC}/_search?ignore_unavailable=true", es_body),
            _azure_signins(),
        )
    except Exception as e:
        return {"error": str(e)}

    all_hits = (es_r.get("hits") or {}).get("hits", [])
    sources = [h.get("_source", {}) for h in all_hits]

    def eid(s: dict) -> str:
        return str((s.get("winlog") or {}).get("event_id", ""))

    lockout_src = [s for s in sources if eid(s) == "4740" or
                   (s.get("event") or {}).get("action") == "locked-out-user-account"]
    failure_src = [s for s in sources if eid(s) == "4625" or
                   (s.get("event") or {}).get("action") == "logon-failed"]
    kerb_src    = [s for s in sources if eid(s) == "4771" or
                   (s.get("event") or {}).get("action") == "kerberos-pre-authentication-failed"]

    # Extract username
    ad_username = short_user
    for s in lockout_src + failure_src:
        wl = s.get("winlog") or {}
        ed = wl.get("event_data") or {}
        u = (ed.get("TargetUserName") or (s.get("user") or {}).get("target", {}).get("name", "") or "")
        if u and u not in ("-", ""):
            ad_username = u
            break

    # CallerComputerName (5-layer)
    def _wl_ed(s: dict) -> dict:
        return (s.get("winlog") or {}).get("event_data") or {}

    caller_machine, caller_source = _extract_caller(
        [{"winlog": s.get("winlog", {}), "message": s.get("message", "")} for s in lockout_src],
        [{"winlog": s.get("winlog", {})} for s in failure_src],
    )
    is_kerberos = not caller_machine and len(lockout_src) > 0

    # Domain controllers
    all_dcs = list(dict.fromkeys(
        (s.get("winlog") or {}).get("computer_name", "") or (s.get("host") or {}).get("hostname", "")
        for s in sources if (s.get("winlog") or {}).get("computer_name") or (s.get("host") or {}).get("hostname")
    ))

    # IPs from AD events
    ad_ips = list(dict.fromkeys(
        ip for s in failure_src + lockout_src
        for ip in [_wl_ed(s).get("IpAddress", ""), (s.get("source") or {}).get("ip", "")]
        if ip and ip not in ("-", "::1", "127.0.0.1", "")
    ))

    # Logon type summary
    from collections import Counter as _Counter
    lt_counts = _Counter(
        _wl_ed(s).get("LogonType", "") for s in failure_src + lockout_src
        if _wl_ed(s).get("LogonType")
    )
    logon_type_map = {
        "2": "Interactive (console/keyboard)", "3": "Network (shares/VPN/IIS)",
        "4": "Batch (scheduled task)", "5": "Service (Windows service)",
        "7": "Unlock (workstation unlock)", "8": "NetworkCleartext (legacy web/IIS)",
        "9": "NewCredentials (runas/impersonation)", "10": "RemoteInteractive (RDP)",
        "11": "CachedInteractive (offline cached logon)",
    }
    logon_type_summary = [
        {"type": lt, "description": logon_type_map.get(str(lt), f"Type {lt}"), "count": cnt}
        for lt, cnt in lt_counts.most_common()
    ]

    # Auth packages
    auth_packages = list(dict.fromkeys(
        _wl_ed(s).get("AuthenticationPackageName", "") for s in failure_src
        if _wl_ed(s).get("AuthenticationPackageName")
    ))
    logon_processes = list(dict.fromkeys(
        _wl_ed(s).get("LogonProcessName", "") for s in failure_src
        if _wl_ed(s).get("LogonProcessName")
    ))

    # Lockout burst analysis
    lockout_ts = [s.get("@timestamp", "") for s in lockout_src if s.get("@timestamp")]
    bursts = _burst_analysis(lockout_ts)

    # Build event rows for display
    def _row(s: dict) -> dict:
        wl = s.get("winlog") or {}
        ed = wl.get("event_data") or {}
        eid_v = str((s.get("event") or {}).get("code") or wl.get("event_id", ""))
        if eid_v == "4740":
            caller = ed.get("TargetDomainName", "").replace("\\\\", "").strip("-").strip()
            if not caller or ("." not in caller and "-" not in caller and len(caller) <= 8):
                import re as _re3
                msg = s.get("message", "")
                m3 = _re3.search(r"Caller\s+Computer\s+Name:\s*\\{0,2}([^\n\r\t\s]+)", msg, _re3.I)
                caller = m3.group(1).strip() if m3 and m3.group(1) else caller
        else:
            caller = (ed.get("CallerComputerName") or ed.get("WorkstationName") or
                      ed.get("SubjectMachineName") or "").replace("\\\\", "").strip("-").strip()
        return {
            "timestamp": s.get("@timestamp", ""),
            "event_id": eid_v,
            "event_type": {"4740": "Lockout", "4625": "Failed Logon", "4771": "Kerberos Failure"}.get(eid_v, eid_v),
            "caller_machine": caller or caller_machine,
            "logon_type": ed.get("LogonType", ""),
            "ip": ed.get("IpAddress", "") or (s.get("source") or {}).get("ip", ""),
            "domain_controller": wl.get("computer_name", "") or (s.get("host") or {}).get("hostname", ""),
            "auth_package": ed.get("AuthenticationPackageName", ""),
        }

    # Azure sign-in analysis
    ERROR_MAP = {
        50126: "Invalid username or password",
        50053: "Account locked (IDS lock)",
        50055: "Password expired",
        50057: "Account disabled",
        53000: "Conditional Access / MFA required",
        53003: "Blocked by Conditional Access policy",
    }
    az_failures = [s for s in azure_signins if (s.get("status") or {}).get("errorCode", 0) != 0]
    az_successes = [s for s in azure_signins if (s.get("status") or {}).get("errorCode", 0) == 0]
    az_err_counts = _Counter(
        ERROR_MAP.get((s.get("status") or {}).get("errorCode"), f"Error {(s.get('status') or {}).get('errorCode')}")
        for s in az_failures
    )
    az_apps_failed  = list(dict.fromkeys(s.get("appDisplayName", "") for s in az_failures if s.get("appDisplayName")))
    az_apps_success = list(dict.fromkeys(s.get("appDisplayName", "") for s in az_successes if s.get("appDisplayName")))
    az_ips = list(dict.fromkeys(s.get("ipAddress", "") for s in azure_signins if s.get("ipAddress")))
    az_locs = list(dict.fromkeys(
        (s.get("location") or {}).get("countryOrRegion", "") for s in azure_signins
        if (s.get("location") or {}).get("countryOrRegion")
    ))
    az_clients = list(dict.fromkeys(s.get("clientAppUsed", "") for s in azure_signins if s.get("clientAppUsed")))
    mfa_failures = sum(1 for s in az_failures if s.get("authenticationRequirement") == "multiFactorAuthentication")

    severity = "low"
    total_events = len(lockout_src) + len(failure_src)
    if len(lockout_src) >= 10 or total_events >= 50:
        severity = "critical"
    elif len(lockout_src) >= 5 or total_events >= 20:
        severity = "high"
    elif len(lockout_src) >= 2 or total_events >= 10:
        severity = "medium"

    return {
        "username": ad_username,
        "window_hours": hours,
        "severity": severity,
        "is_kerberos": is_kerberos,
        "caller_machine": caller_machine,
        "caller_machine_source": caller_source,
        "all_ips": list(dict.fromkeys(ad_ips + az_ips)),
        "ad_ips": ad_ips,
        "domain_controllers": all_dcs[:10],
        "auth_packages": auth_packages,
        "logon_processes": logon_processes,
        "lockout_count": len(lockout_src),
        "failed_logon_count": len(failure_src),
        "kerberos_failure_count": len(kerb_src),
        "logon_type_summary": logon_type_summary,
        "lockout_bursts": bursts,
        "events": [_row(s) for s in sources],
        "azure": {
            "total": len(azure_signins),
            "successes": len(az_successes),
            "failures": len(az_failures),
            "mfa_failures": mfa_failures,
            "failed_apps": az_apps_failed,
            "successful_apps": az_apps_success,
            "source_ips": az_ips,
            "locations": az_locs,
            "client_apps": az_clients,
            "error_summary": [{"reason": k, "count": v} for k, v in az_err_counts.most_common()],
            "sign_ins": [
                {"time": s.get("createdDateTime", ""),
                 "app": s.get("appDisplayName", ""),
                 "status": "✅ Success" if (s.get("status") or {}).get("errorCode", 0) == 0 else "❌ Failed",
                 "error": ERROR_MAP.get((s.get("status") or {}).get("errorCode"), ""),
                 "ip": s.get("ipAddress", ""),
                 "location": f"{(s.get('location') or {}).get('city', '')} {(s.get('location') or {}).get('countryOrRegion', '')}".strip(),
                 "client": s.get("clientAppUsed", ""),
                 "device": (s.get("deviceDetail") or {}).get("displayName", ""),
                 "risk": s.get("riskLevelDuringSignIn", ""),
                 "mfa": s.get("authenticationRequirement", "")}
                for s in azure_signins[:50]
            ],
        },
    }


async def test_connection() -> dict:
    """
    Verify ES connectivity using a GET _count (no body, no cluster privileges needed).
    GET avoids any request-body parsing issues on restricted ES roles.
    """
    if not (await cfg.get("es.url", "")):
        return {"ok": False, "error": "ES URL not configured"}
    try:
        url, headers, ssl_verify = await _get_conn()
        import httpx as _httpx
        async with _httpx.AsyncClient(verify=ssl_verify, timeout=15) as client:
            resp = await client.get(
                f"{url}/{_IDX_CPU}/_count?ignore_unavailable=true",
                headers=headers,
            )
            resp.raise_for_status()
            count = resp.json().get("count", 0)
        return {
            "ok":    True,
            "index": _IDX_CPU,
            "windows_server_docs": count,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ─────────────────────────────────────────────────────────────────
# Hourly snapshot collection
# Collects current metrics for ALL Windows Servers and stores them
# in infraguardian_capacity_hourly.  Runs every hour via APScheduler.
# The daily aggregation reads this table instead of hitting ES.
# ─────────────────────────────────────────────────────────────────

async def collect_hourly_snapshot() -> int:
    """
    Collect a one-hour look-back snapshot for every Windows Server and
    persist to infraguardian_capacity_hourly.  Returns # rows inserted.
    """
    from datetime import datetime, timezone
    from sqlalchemy import text
    from app.database import AsyncSessionLocal

    # ── Aggregate CPU per host ────────────────────────────────────
    cpu_body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": "now-70m"}}},
            _SERVER_FILTER,
        ]}},
        "aggs": {
            "by_host": {
                "terms": {"field": "host.name", "size": 500},
                "aggs": {
                    "avg_cpu": {"avg": {"field": "system.cpu.total.norm.pct"}},
                    "top_hit": {"top_hits": {"size": 1, "sort": [{"@timestamp": "desc"}],
                                            "_source": ["host.os.name", "host.ip"]}},
                }
            }
        }
    }

    # ── Aggregate Memory per host ─────────────────────────────────
    mem_body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": "now-70m"}}},
            _SERVER_FILTER,
        ]}},
        "aggs": {
            "by_host": {
                "terms": {"field": "host.name", "size": 500},
                "aggs": {
                    "avg_mem":   {"avg": {"field": "system.memory.actual.used.pct"}},
                    "total_mem": {"avg": {"field": "system.memory.total"}},
                    "free_mem":  {"avg": {"field": "system.memory.actual.free"}},
                }
            }
        }
    }

    # ── Aggregate Disk per host (UDF excluded) ────────────────────
    disk_body = {
        "size": 0,
        "query": {"bool": {
            "filter":   [{"range": {"@timestamp": {"gte": "now-70m"}}}, _SERVER_FILTER],
            "must_not": _DISK_MUST_NOT,
        }},
        "aggs": {
            "by_host": {
                "terms": {"field": "host.name", "size": 500},
                "aggs": {
                    "avg_disk": {"avg": {"field": "system.filesystem.used.pct"}},
                    "max_disk": {"max": {"field": "system.filesystem.used.pct"}},
                    "by_mount": {
                        "terms": {"field": "system.filesystem.mount_point", "size": 20},
                        "aggs": {
                            "avg_used_pct": {"avg": {"field": "system.filesystem.used.pct"}},
                            "total_bytes":  {"max": {"field": "system.filesystem.total"}},
                            "free_bytes":   {"avg": {"field": "system.filesystem.free"}},
                        }
                    }
                }
            }
        }
    }

    try:
        cpu_r, mem_r, disk_r = await asyncio.gather(
            _post(f"/{_IDX_CPU}/_search",  cpu_body),
            _post(f"/{_IDX_MEM}/_search",  mem_body),
            _post(f"/{_IDX_DISK}/_search", disk_body),
            return_exceptions=True,
        )
    except Exception:
        return 0

    def _bkts(r, key="by_host"):
        if isinstance(r, Exception): return []
        return r.get("aggregations", {}).get(key, {}).get("buckets", [])

    # Build lookup maps: server_name → bucket data
    cpu_map  = {b["key"]: b for b in _bkts(cpu_r)}
    mem_map  = {b["key"]: b for b in _bkts(mem_r)}
    disk_map = {b["key"]: b for b in _bkts(disk_r)}

    all_servers = set(cpu_map) | set(mem_map) | set(disk_map)
    if not all_servers:
        return 0

    now = datetime.now(timezone.utc)
    saved = 0

    async with AsyncSessionLocal() as db:
        for server in sorted(all_servers):
            cpu_b  = cpu_map.get(server, {})
            mem_b  = mem_map.get(server, {})
            disk_b = disk_map.get(server, {})

            # Meta
            src      = (cpu_b.get("top_hit", {}).get("hits", {}).get("hits") or [{}])[0].get("_source", {})
            os_name  = _field(src, "host.os.name", "Windows Server")
            ips      = _field(src, "host.ip", "")
            ip       = (ips[0] if isinstance(ips, list) and ips else str(ips)) if ips else ""

            # CPU
            cpu_pct = round((cpu_b.get("avg_cpu", {}).get("value") or 0) * 100, 2)

            # Memory GB
            total_mem_b = mem_b.get("total_mem", {}).get("value") or 0
            free_mem_b  = mem_b.get("free_mem",  {}).get("value") or 0
            used_mem_b  = max(total_mem_b - free_mem_b, 0)
            mem_pct     = round((mem_b.get("avg_mem", {}).get("value") or 0) * 100, 2)
            total_mem_gb = round(total_mem_b / (1024**3), 2)
            used_mem_gb  = round(used_mem_b  / (1024**3), 2)
            free_mem_gb  = round(free_mem_b  / (1024**3), 2)

            # Disk
            disk_pct   = round((disk_b.get("avg_disk", {}).get("value") or 0) * 100, 2)
            mounts     = []
            total_disk = 0.0; used_disk = 0.0; free_disk = 0.0
            for mb in disk_b.get("by_mount", {}).get("buckets", []):
                t = mb.get("total_bytes", {}).get("value") or 0
                f = mb.get("free_bytes",  {}).get("value") or 0
                u = max(t - f, 0)
                total_disk += t; used_disk += u; free_disk += f
                mounts.append({
                    "mount":    mb["key"],
                    "used_pct": round((mb.get("avg_used_pct", {}).get("value") or 0) * 100, 2),
                    "total_gb": round(t / (1024**3), 1),
                    "used_gb":  round(u / (1024**3), 1),
                    "free_gb":  round(f / (1024**3), 1),
                })
            total_disk_gb = round(total_disk / (1024**3), 2)
            used_disk_gb  = round(used_disk  / (1024**3), 2)
            free_disk_gb  = round(free_disk  / (1024**3), 2)

            await db.execute(text("""
                INSERT INTO infraguardian_capacity_hourly
                    (server_name, collected_at,
                     cpu_pct,
                     mem_pct, total_mem_gb, used_mem_gb, free_mem_gb,
                     disk_pct, total_disk_gb, used_disk_gb, free_disk_gb,
                     disk_details, os_name, host_ip)
                VALUES
                    (:srv, :ts,
                     :cpu,
                     :mem, :tmg, :umg, :fmg,
                     :disk, :tdg, :udg, :fdg,
                     :djson, :os, :ip)
            """), {
                "srv": server, "ts": now,
                "cpu": cpu_pct,
                "mem": mem_pct, "tmg": total_mem_gb, "umg": used_mem_gb, "fmg": free_mem_gb,
                "disk": disk_pct, "tdg": total_disk_gb, "udg": used_disk_gb, "fdg": free_disk_gb,
                "djson": json.dumps(mounts), "os": os_name, "ip": ip,
            })
            saved += 1

        # Prune rows older than 48 hours (keep table small)
        await db.execute(text("""
            DELETE FROM infraguardian_capacity_hourly
            WHERE collected_at < NOW() - INTERVAL '48 hours'
        """))
        await db.commit()

    return saved


# ─────────────────────────────────────────────────────────────────
# Live single-server snapshot (current values + top-10 processes)
# ─────────────────────────────────────────────────────────────────

async def get_live_server_snapshot(server_name: str, minutes: int = 5) -> Dict:
    """
    Return current CPU %, memory %, disk % and last-seen timestamp
    for a single Windows Server host.
    minutes: 1 | 5 | 10 | 15 — lookback window.
    """
    # Clamp to allowed values
    minutes = minutes if minutes in (1, 5, 10, 15) else 5
    host_filter = {"term": {"host.name": server_name}}

    async def _live_cpu():
        body = {
            "size": 0,
            "query": {"bool": {"filter": [
                {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}},
                host_filter, _SERVER_FILTER,
            ]}},
            "aggs": {
                "avg_cpu": {"avg": {"field": "system.cpu.total.norm.pct"}},
                "max_cpu": {"max": {"field": "system.cpu.total.norm.pct"}},
                "last_ts": {"max": {"field": "@timestamp"}},
            }
        }
        r = await _post(f"/{_IDX_CPU}/_search", body)
        agg = r.get("aggregations", {})
        return {
            "cpu_pct":     round((agg.get("avg_cpu", {}).get("value") or 0) * 100, 1),
            "cpu_max_pct": round((agg.get("max_cpu", {}).get("value") or 0) * 100, 1),
            "last_seen":   agg.get("last_ts", {}).get("value_as_string", ""),
        }

    async def _live_mem():
        body = {
            "size": 0,
            "query": {"bool": {"filter": [
                {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}},
                host_filter, _SERVER_FILTER,
            ]}},
            "aggs": {
                "avg_mem":     {"avg": {"field": "system.memory.actual.used.pct"}},
                "total_bytes": {"max": {"field": "system.memory.total"}},
                "free_bytes":  {"avg": {"field": "system.memory.actual.free"}},
            }
        }
        r = await _post(f"/{_IDX_MEM}/_search", body)
        agg = r.get("aggregations", {})
        return {
            "mem_pct":    round((agg.get("avg_mem", {}).get("value") or 0) * 100, 1),
            "total_gb":   round((agg.get("total_bytes", {}).get("value") or 0) / (1024**3), 1),
            "free_gb":    round((agg.get("free_bytes",  {}).get("value") or 0) / (1024**3), 1),
        }

    async def _live_disk():
        body = {
            "size": 0,
            "query": {"bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{max(minutes, 5)}m"}}},
                    host_filter, _SERVER_FILTER,
                ],
                "must_not": _DISK_MUST_NOT,
            }},
            "aggs": {
                "by_mount": {
                    "terms": {"field": "system.filesystem.mount_point", "size": 20},
                    "aggs": {
                        "used_pct": {"avg": {"field": "system.filesystem.used.pct"}},
                        "total":    {"max": {"field": "system.filesystem.total"}},
                        "free":     {"avg": {"field": "system.filesystem.free"}},
                    }
                }
            }
        }
        r = await _post(f"/{_IDX_DISK}/_search", body)
        mounts = []
        for b in r.get("aggregations", {}).get("by_mount", {}).get("buckets", []):
            used_pct = (b.get("used_pct", {}).get("value") or 0) * 100
            mounts.append({
                "mount":    b["key"],
                "used_pct": round(used_pct, 1),
                "total_gb": round((b.get("total", {}).get("value") or 0) / (1024**3), 1),
                "free_gb":  round((b.get("free",  {}).get("value") or 0) / (1024**3), 1),
                "severity": _severity(used_pct),
            })
        mounts_sorted = sorted(mounts, key=lambda x: -x["used_pct"])
        # Overall disk: worst mount
        overall = mounts_sorted[0]["used_pct"] if mounts_sorted else 0.0
        return {"disk_pct": overall, "mounts": mounts_sorted}

    cpu, mem, disk = await asyncio.gather(
        _live_cpu(), _live_mem(), _live_disk(), return_exceptions=True
    )

    def safe(r, default):
        return default if isinstance(r, Exception) else r

    cpu_d  = safe(cpu,  {"cpu_pct": 0, "cpu_max_pct": 0, "last_seen": ""})
    mem_d  = safe(mem,  {"mem_pct": 0, "total_gb": 0, "free_gb": 0})
    disk_d = safe(disk, {"disk_pct": 0, "mounts": []})

    used_gb = round(mem_d["total_gb"] - mem_d["free_gb"], 1)
    return {
        "server":       server_name,
        "window_minutes": minutes,
        "cpu_pct":      cpu_d["cpu_pct"],
        "cpu_max_pct":  cpu_d["cpu_max_pct"],
        "mem_pct":      mem_d["mem_pct"],
        "mem_total_gb": mem_d["total_gb"],
        "mem_used_gb":  used_gb,
        "mem_free_gb":  mem_d["free_gb"],
        "disk_pct":     disk_d["disk_pct"],
        "mounts":       disk_d["mounts"],
        "last_seen":    cpu_d["last_seen"],
        "severity": {
            "cpu":  _severity(cpu_d["cpu_pct"]),
            "mem":  _severity(mem_d["mem_pct"]),
            "disk": _severity(disk_d["disk_pct"]),
        }
    }


async def get_top_processes(server_name: str, sort_by: str = "cpu", top_n: int = 10) -> List[Dict]:
    """
    Return top N processes for a server sorted by CPU or memory.
    sort_by: 'cpu' | 'memory'
    Queries the last 5 minutes of process metrics.
    """
    host_filter = {"term": {"host.name": server_name}}
    order_field = "avg_cpu" if sort_by == "cpu" else "avg_mem"

    body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": "now-5m"}}},
            host_filter,
            _SERVER_FILTER,
        ]}},
        "aggs": {
            "by_proc": {
                "terms": {
                    "field": "process.name",
                    "size":  top_n * 2,  # over-fetch, then sort client-side
                    "order": {order_field: "desc"}
                },
                "aggs": {
                    "avg_cpu": {"avg": {"field": "system.process.cpu.total.pct"}},
                    "avg_mem": {"avg": {"field": "system.process.memory.rss.bytes"}},
                    "max_cpu": {"max": {"field": "system.process.cpu.total.pct"}},
                }
            }
        }
    }
    r = await _post(f"/{_IDX_PROC}/_search", body)
    procs = []
    for b in r.get("aggregations", {}).get("by_proc", {}).get("buckets", []):
        cpu_pct = round((b.get("avg_cpu", {}).get("value") or 0) * 100, 2)
        max_pct = round((b.get("max_cpu", {}).get("value") or 0) * 100, 2)
        mem_mb  = round((b.get("avg_mem", {}).get("value") or 0) / (1024**2), 1)
        procs.append({
            "name":    b["key"],
            "cpu_pct": cpu_pct,
            "cpu_max_pct": max_pct,
            "mem_mb":  mem_mb,
            "doc_count": b.get("doc_count", 0),
        })

    # Re-sort client-side for accuracy (aggregation order is approximate)
    if sort_by == "memory":
        procs.sort(key=lambda x: -x["mem_mb"])
    else:
        procs.sort(key=lambda x: -x["cpu_pct"])

    return procs[:top_n]
