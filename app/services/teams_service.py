"""
Microsoft Teams chat poller via Microsoft Graph API.

Uses client_credentials (app-only) flow with Chat.Read.All Application permission.
Credentials come from the same Azure App Registration as Entra SSO
(entra.tenant_id / entra.client_id / entra.client_secret).
"""
from __future__ import annotations
import logging
import re
import time
from typing import Optional

import httpx
import app.config as cfg

log = logging.getLogger(__name__)
GRAPH = "https://graph.microsoft.com/v1.0"

# Token cache keyed by (tenant, client) so a settings change forces a new grant
_cache: dict = {"key": None, "access_token": None, "expires_at": 0.0}


async def _credentials() -> tuple[str, str, str]:
    return (
        await cfg.get("entra.tenant_id", ""),
        await cfg.get("entra.client_id", ""),
        await cfg.get("entra.client_secret", ""),
    )


async def _get_token() -> str:
    tenant, client_id, secret = await _credentials()
    key = (tenant, client_id)
    if _cache["key"] == key and _cache["access_token"] and time.time() < _cache["expires_at"]:
        return _cache["access_token"]
    if not (tenant and client_id and secret):
        raise RuntimeError("Entra tenant_id / client_id / client_secret not configured")

    data = {
        "grant_type":    "client_credentials",
        "client_id":     client_id,
        "client_secret": secret,
        "scope":         "https://graph.microsoft.com/.default",
    }
    url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.post(url, data=data)
        if resp.status_code != 200:
            err = resp.json() if "application/json" in resp.headers.get("content-type", "") else resp.text
            raise RuntimeError(f"Token request failed ({resp.status_code}): {err}")
        body = resp.json()
        if "error" in body:
            raise RuntimeError(f"Token error: {body['error']} — {body.get('error_description', '')}")
    _cache["key"]          = key
    _cache["access_token"] = body["access_token"]
    _cache["expires_at"]   = time.time() + int(body.get("expires_in", 3600)) - 60
    log.info("Teams app token acquired (expires in %ss)", body.get("expires_in", 3600))
    return _cache["access_token"]


async def auth_status() -> dict:
    _, _, secret = await _credentials()
    has_token = bool(_cache["access_token"])
    return {
        "auth_flow":                "client_credentials",
        "enabled":                  await cfg.get_bool("teams.enabled", True),
        "has_client_secret":        bool(secret),
        "has_token":                has_token,
        "token_expires_in_seconds": max(0, int(_cache["expires_at"] - time.time())) if has_token else 0,
        "chat_id":                  await cfg.get("teams.chat_id", ""),
        "poll_interval":            await cfg.get_int("teams.poll_interval", 60),
    }


# ── Message fetching ───────────────────────────────────────────────────────────

async def fetch_messages() -> list[dict]:
    """Return the 50 most recent messages from the configured Teams chat (newest first)."""
    chat_id = await cfg.get("teams.chat_id", "")
    if not chat_id:
        log.warning("teams.chat_id not configured — skipping poll")
        return []
    token   = await _get_token()
    headers = {"Authorization": f"Bearer {token}"}
    params  = {"$top": 50, "$orderby": "createdDateTime desc"}

    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.get(f"{GRAPH}/chats/{chat_id}/messages", headers=headers, params=params)
        if resp.status_code == 403:
            body = resp.json()
            log.error("Graph 403 — verify Chat.Read.All Application permission has admin consent. Error: %s",
                      body.get("error", {}).get("message", resp.text[:200]))
            return []
        if resp.status_code == 404:
            log.error("Teams chat not found — verify teams.chat_id: %s", chat_id)
            return []
        resp.raise_for_status()
        return resp.json().get("value", [])


def extract_message_text(msg: dict) -> str:
    body    = msg.get("body", {}) or {}
    content = body.get("content", "") or ""
    if body.get("contentType", "text") == "html":
        content = re.sub(r"<[^>]+>", " ", content)
        content = re.sub(r"\s+", " ", content).strip()
    return content


def get_sender(msg: dict) -> str:
    try:
        return msg["from"]["user"]["displayName"]
    except (KeyError, TypeError):
        return "unknown"


# ── Alert classification ───────────────────────────────────────────────────────

# Alert categories. cpu / memory / disk on a host can be verified (and auto-cleared)
# against CloudPulse metrics; the rest clear via Dynatrace RESOLVED status or manually.
METRIC_CATEGORIES = ("cpu", "memory", "disk")

# Whole-word patterns (plural allowed), so "ram" doesn't match "Program" and "down" doesn't match "slowdown"
_CATEGORY_PATTERNS: dict[str, str] = {
    "availability":  r"outage|unavailable|unreachable|not responding|down|offline|availability|connectivity|crash(?:ed)?|restart(?:ed)?|stopped",
    "errors":        r"failure rate|failures?|errors?|exceptions?|5\d\d|failed",
    "response_time": r"response times?|user action duration|slow(?:down|ness)?|latency|duration degradation",
    "gc":            r"garbage[- ]collection|gc",
    "network":       r"network|interface utili[sz]ation|bandwidth|packet loss|switch",
    "cpu":           r"cpu|processor",
    "disk":          r"disks?|storage|drives?|volumes?|free space|partition",
    "memory":        r"memory|mem|ram|heap|pagefile|out of memory",
}
_CATEGORY_RES = {k: re.compile(rf"\b(?:{p})s?\b", re.I) for k, p in _CATEGORY_PATTERNS.items()}

# Dynatrace problem severity → category, when the title gives no clue
_DT_SEVERITY_CATEGORY = {
    "AVAILABILITY": "availability",
    "ERROR":        "errors",
    "PERFORMANCE":  "response_time",
}


def classify(text: str, dt_severity: str = "") -> str:
    """Category whose keyword appears first in text (titles lead with the main symptom)."""
    best, best_pos = None, len(text) + 1
    for category, rx in _CATEGORY_RES.items():
        m = rx.search(text)
        if m and m.start() < best_pos:
            best, best_pos = category, m.start()
    return best or _DT_SEVERITY_CATEGORY.get(dt_severity.upper(), "other")


_ALERT_WORDS = re.compile(
    r"\b(?:alert|alarm|critical|warning|exceeded|threshold|problem|issue|failure|error|anomaly|"
    r"spike|overload|saturation|degradation|outage|down|unavailable|high|usage)\b",
    re.I,
)


def is_alert_message(text: str) -> bool:
    return bool(_ALERT_WORDS.search(text))


# ── Structured AIOps / Dynatrace notification parser ───────────────────────────
#
#   🚨 [ALERT] Isolated Operational Event: <Project> - <Title> Status: ... ID: AIBI_123
#   📊 Alert Metadata Summary: ... Hit 1 - Event ID: P-123 | Timestamp: ... | Source: dynatrace |
#   Status: OPEN | Severity: PERFORMANCE | Impacted Entity: <entity> | Host(s): h1, h2 | ...

_HEAD_RE   = re.compile(r"\[(?P<tag>[A-Z]+)\]\s*(?P<kind>[^:\[\]]{3,60}):\s*(?P<project>.+?)\s+-\s+(?P<title>.+?)\s+Status:", re.S)
_REF_RE    = re.compile(r"\bID:\s*(AIB[A-Z]?_\d+)")
_HIT_SPLIT = re.compile(r"\bHit \d+\s*-\s*")
_TITLE_HOST_RE = re.compile(r"\b(?:on|for)\s+([A-Za-z0-9][\w-]*(?:\.[\w-]+)*)\s*$")

# Hit statuses meaning the event is over (Dynatrace: RESOLVED/CLOSED; Elastic: recovered/ok)
CLEARED_STATUSES = ("RESOLVED", "CLOSED", "RECOVERED", "OK")


def _field(segment: str, name: str) -> str:
    m = re.search(rf"{name}:\s*(.*?)\s*(?:\||🔗|🤖|$)", segment)
    return m.group(1).strip() if m else ""


def parse_alert(text: str) -> Optional[dict]:
    """Parse a structured AIOps alert. Returns None for messages in any other format."""
    head = _HEAD_RE.search(text)
    if not head:
        return None
    title   = head.group("title").strip()
    project = head.group("project").strip()

    hits = []
    for seg in _HIT_SPLIT.split(text)[1:]:
        hosts = [h.strip() for h in _field(seg, r"Host\(s\)").split(",") if h.strip()]
        hits.append({
            "id":       _field(seg, "Event ID"),
            "status":   _field(seg, "Status").upper(),
            "severity": _field(seg, "Severity").upper(),
            "entity":   _field(seg, "Impacted Entity"),
            "hosts":    hosts,
        })

    open_hits = [h for h in hits if h["status"] not in CLEARED_STATUSES] or hits
    hosts: list[str] = []
    for h in open_hits:
        hosts += [x for x in h["hosts"] if x.lower() not in {y.lower() for y in hosts}]
    entity      = next((h["entity"] for h in open_hits if h["entity"]), "")
    dt_severity = next((h["severity"] for h in open_hits if h["severity"]), "")
    tag         = head.group("tag").upper()
    category    = classify(title, dt_severity)

    # Elastic-sourced alerts carry no Host(s) field — the host ends the title ("… on HOST")
    if not hosts and category in METRIC_CATEGORIES:
        m = _TITLE_HOST_RE.search(title)
        if m:
            hosts = [m.group(1)]

    return {
        "tag":        tag,
        "project":    "" if project.lower() == "unknown" else project,
        "title":      title,
        "alert_ref":  (_REF_RE.search(text) or [None, ""])[1],
        "hits":       [{"id": h["id"], "status": h["status"]} for h in hits if h["id"]],
        "all_resolved": bool(hits) and all(h["status"] in CLEARED_STATUSES for h in hits),
        "entity":     entity,
        "hosts":      hosts,
        "category":   category,
        "severity":   "critical" if tag == "CRITICAL" or re.search(r"\bcritical\b", title, re.I) else "warning",
    }


# ── Server name extraction (regex fallback when the LLM can't find one) ────────

_SERVER_PATTERNS = [
    r"[Ss]erver[:\s]+([A-Za-z0-9][\w\-\.]{2,})",
    r"[Hh]ost(?:name)?[:\s]+([A-Za-z0-9][\w\-\.]{2,})",
    r"[Nn]ode[:\s]+([A-Za-z0-9][\w\-\.]{2,})",
    r"\bon\s+([A-Za-z][A-Za-z0-9\-]{3,})\b",
    r"\bfor\s+([A-Za-z][A-Za-z0-9\-]{3,})\b",
    r"\b([A-Z]{2,}[A-Z0-9\-]{2,})\b",
]


def extract_server_name(text: str) -> Optional[str]:
    for pattern in _SERVER_PATTERNS:
        match = re.search(pattern, text)
        if match:
            candidate = match.group(1).strip(".,;:")
            if candidate.upper() not in ("OK", "CPU", "RAM", "MB", "GB", "TB", "SLA", "API"):
                return candidate
    return None
