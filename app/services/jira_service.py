"""
Jira Data Center REST API service.
Field IDs and workflow transitions match the service desk project configuration.
"""
from __future__ import annotations
import base64
from typing import Optional
import httpx
import app.config as cfg

# ── Hardcoded workflow constants ───────────────────────────────────────────────
_PROJECT_ID       = "12702"
_ISSUETYPE_ID     = "11301"
_IN_PROGRESS_TID  = "131"   # transition → In Progress
_RESOLVE_TID      = "21"    # transition → Resolved

# Fixed custom field values
_CF_14503  = [{"key": "SD-217"}]               # always required
_CF_13657  = {"id": "20707"}
_CF_13204  = {"id": "14612"}
_CF_13210  = {"id": "13518"}

# Resolve-time fixed values
_CF_14600  = [{"key": "SD-194"}]
_CF_15305  = [{"key": "SD-1884"}]
_CF_14509  = {"id": "23807"}
# ──────────────────────────────────────────────────────────────────────────────


async def _get_client() -> tuple[httpx.AsyncClient, str, dict]:
    base_url = await cfg.get("jira.base_url", "")
    username = await cfg.get("jira.username", "")
    token    = await cfg.get("jira.api_token", "")
    creds    = base64.b64encode(f"{username}:{token}".encode()).decode()
    headers  = {
        "Authorization": f"Basic {creds}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    client = httpx.AsyncClient(verify=False, timeout=30)
    return client, base_url.rstrip("/"), headers


async def test_connection() -> dict:
    _, base, headers = await _get_client()
    if not base:
        return {"ok": False, "error": "Jira URL not configured"}
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        try:
            r = await client.get(f"{base}/rest/api/2/myself", headers=headers)
            if r.status_code == 200:
                data = r.json()
                return {"ok": True, "user": data.get("displayName"), "email": data.get("emailAddress")}
            return {"ok": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}


async def create_ticket(
    summary: str,
    description: str,
    sr_type_id: str,
    subsidiary_id: Optional[str] = None,
    effort_hours: Optional[float] = None,
    assignee: Optional[str] = None,
) -> dict:
    """
    Create a Jira issue matching the n8n workflow exactly.
    - Project and issuetype are hardcoded IDs.
    - After creation: assign to the signed-in user (email prefix), else jira.default_assignee.
    - Transition to In Progress.
    """
    _, base, headers = await _get_client()
    if not base:
        return {"ok": False, "error": "Jira not configured"}

    fields: dict = {
        "project":           {"id": _PROJECT_ID},
        "summary":           summary,
        "description":       description,
        "issuetype":         {"id": _ISSUETYPE_ID},
        # Always-required fields
        "customfield_14503": _CF_14503,
        "customfield_13657": _CF_13657,
        "customfield_13204": _CF_13204,
        "customfield_13210": _CF_13210,
    }

    # SR Type
    if sr_type_id:
        fields["customfield_32404"] = {"id": sr_type_id}

    # Subsidiary
    if subsidiary_id:
        fields["customfield_36200"] = {"id": subsidiary_id}

    # Effort hours (numeric field, not timetracking)
    fields["customfield_32700"] = float(effort_hours) if effort_hours else 0.5

    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        try:
            r = await client.post(
                f"{base}/rest/api/2/issue",
                json={"fields": fields},
                headers=headers,
            )
            if r.status_code not in (200, 201):
                return {"ok": False, "error": f"HTTP {r.status_code}: {r.text[:500]}"}

            data = r.json()
            ticket_key = data.get("key")
            ticket_url = f"{base}/browse/{ticket_key}"

            # Assign to the signed-in user (email prefix), else the configured default assignee
            jira_user = assignee or await cfg.get("jira.default_assignee", "")
            if jira_user:
                await _assign_ticket(client, base, headers, ticket_key, jira_user)

            # Transition to In Progress (hardcoded id 131)
            await _transition(client, base, headers, ticket_key, _IN_PROGRESS_TID)

            return {"ok": True, "key": ticket_key, "url": ticket_url, "id": data.get("id")}

        except Exception as e:
            return {"ok": False, "error": str(e)}


async def _assign_ticket(client, base, headers, ticket_key, jira_username: str):
    """Assign ticket to the given Jira username."""
    try:
        await client.put(
            f"{base}/rest/api/2/issue/{ticket_key}/assignee",
            json={"name": jira_username},
            headers=headers,
        )
    except Exception:
        pass


async def _transition(client, base, headers, ticket_key, transition_id: str):
    """Apply a hardcoded transition ID."""
    try:
        await client.post(
            f"{base}/rest/api/2/issue/{ticket_key}/transitions",
            json={"transition": {"id": transition_id}},
            headers=headers,
        )
    except Exception:
        pass


async def _transition_with_fields(client, base, headers, ticket_key, transition_id: str, update_fields: dict):
    """Apply a transition with additional field updates (for resolve)."""
    try:
        await client.post(
            f"{base}/rest/api/2/issue/{ticket_key}/transitions",
            json={"transition": {"id": transition_id}, "fields": update_fields},
            headers=headers,
        )
    except Exception:
        pass


async def resolve_ticket(ticket_key: str, resolution_note: str) -> dict:
    """
    Resolve a Jira ticket matching n8n workflow:
    - Transition id 21
    - Required fields: customfield_14600, 15305, 14608, 14509
    - Add comment with resolution note
    """
    _, base, headers = await _get_client()
    if not base:
        return {"ok": False, "error": "Jira not configured"}

    update_fields = {
        "customfield_14600": _CF_14600,
        "customfield_15305": _CF_15305,
        "customfield_14608": resolution_note,
        "customfield_14509": _CF_14509,
    }

    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        try:
            # Resolve transition with fields
            r = await client.post(
                f"{base}/rest/api/2/issue/{ticket_key}/transitions",
                json={"transition": {"id": _RESOLVE_TID}, "fields": update_fields},
                headers=headers,
            )
            if r.status_code not in (200, 201, 204):
                return {"ok": False, "error": f"Transition HTTP {r.status_code}: {r.text[:300]}"}

            # Add comment with resolution note
            await client.post(
                f"{base}/rest/api/2/issue/{ticket_key}/comment",
                json={"body": resolution_note},
                headers=headers,
            )

            return {"ok": True, "key": ticket_key}

        except Exception as e:
            return {"ok": False, "error": str(e)}


async def get_ticket(ticket_key: str) -> dict:
    _, base, headers = await _get_client()
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        try:
            r = await client.get(f"{base}/rest/api/2/issue/{ticket_key}", headers=headers)
            r.raise_for_status()
            data = r.json()
            fields = data.get("fields", {})
            return {
                "ok":      True,
                "key":     data.get("key"),
                "summary": fields.get("summary"),
                "status":  fields.get("status", {}).get("name"),
                "assignee":fields.get("assignee", {}).get("displayName") if fields.get("assignee") else None,
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}


def _generate_mock_tickets(jira_username: str, ig_username: str) -> list[dict]:
    """Generate 20 realistic test tickets for development / demo use."""
    from datetime import datetime, timedelta
    now = datetime.utcnow()

    rows = [
        # (key, summary, sr_type, status, days_ago, effort_h)
        ("SD-2451", "High CPU on VD-WIN-09 causing application slowdown",        "Incident",       "In Progress", 2,  2.0),
        ("SD-2448", "Exchange Server mailbox quota exceeded for 3 users",          "Incident",       "In Progress", 4,  1.5),
        ("SD-2445", "Deploy Windows security patches - October 2026",              "Change Request", "In Progress", 5,  4.0),
        ("SD-2440", "New user account setup for IT department",                    "Service Request","Open",        7,  0.5),
        ("SD-2435", "VPN configuration update for remote workers",                 "Service Request","Open",        9,  1.0),
        ("SD-2430", "Backup verification failed on FILE-SERVER-02",                "Incident",       "Open",        10, 2.0),
        ("SD-2425", "Memory leak in IIS application pool causing restarts",        "Incident",       "Resolved",    12, 3.0),
        ("SD-2420", "RDP connection timeout for finance department",               "Incident",       "Resolved",    14, 1.0),
        ("SD-2415", "Antivirus definition update deployment",                      "Change Request", "Resolved",    16, 2.0),
        ("SD-2410", "Disk space alert on DC-01 - C drive at 92%",                 "Incident",       "Resolved",    18, 1.5),
        ("SD-2405", "Group Policy update for software restriction policies",        "Change Request", "Resolved",    20, 2.5),
        ("SD-2400", "Printer driver update for accounts team",                     "Service Request","Resolved",    22, 0.5),
        ("SD-2380", "SSL certificate renewal for internal web portal",             "Change Request", "Resolved",    35, 2.0),
        ("SD-2360", "Network switch firmware upgrade - Core Layer",                "Change Request", "Resolved",    45, 4.0),
        ("SD-2340", "Windows Server 2019 license compliance audit",                "Service Request","Resolved",    55, 3.0),
        ("SD-2320", "Hyper-V VM snapshot cleanup and storage reclaim",             "Service Request","Resolved",    68, 2.5),
        ("SD-2290", "Active Directory password policy enforcement update",          "Change Request", "Resolved",    95, 2.0),
        ("SD-2270", "SIEM log integration for new server group",                   "Service Request","Resolved",   115, 5.0),
        ("SD-2250", "Server room UPS replacement coordination",                    "Change Request", "Resolved",   140, 3.0),
        ("SD-2230", "Migrate legacy file share to DFS namespace",                  "Service Request","Resolved",   175, 6.0),
    ]

    result = []
    for key, summary, sr_type, status, days_ago, effort in rows:
        created = now - timedelta(days=days_ago)
        result.append({
            "ticket_key":           key,
            "ticket_url":           f"#mock/browse/{key}",
            "project_key":          "SD",
            "summary":              summary,
            "sr_type":              sr_type,
            "status":               status,
            "created_by":           ig_username,
            "created_at":           created.isoformat(),
            "scheduled_resolve_at": None,
            "effort_hours":         effort,
            "subsidiary_id":        None,
            "source":               "mock",
        })
    return result


async def get_user_stats_from_db(ig_username: str) -> dict:
    """Compute ticket stats from the local DB — fallback when Jira is not configured."""
    from sqlalchemy import text
    from app.database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        ytd  = (await db.execute(text(
            "SELECT COUNT(*) FROM cloudpulse_jira_tickets WHERE created_at >= date_trunc('year', NOW()) AND created_by = :u"),
            {"u": ig_username})).scalar() or 0
        mtd  = (await db.execute(text(
            "SELECT COUNT(*) FROM cloudpulse_jira_tickets WHERE created_at >= date_trunc('month', NOW()) AND created_by = :u"),
            {"u": ig_username})).scalar() or 0
        open_c = (await db.execute(text(
            "SELECT COUNT(*) FROM cloudpulse_jira_tickets WHERE status NOT IN ('Resolved','Closed','Done') AND created_by = :u"),
            {"u": ig_username})).scalar() or 0
        inp  = (await db.execute(text(
            "SELECT COUNT(*) FROM cloudpulse_jira_tickets WHERE status = 'In Progress' AND created_by = :u"),
            {"u": ig_username})).scalar() or 0
    return {"ytd": ytd, "mtd": mtd, "open": open_c, "in_progress": inp, "source": "db"}


async def get_my_tickets_ytd() -> list:
    """YTD tickets assigned to current user."""
    _, base, headers = await _get_client()
    if not base:
        return []
    jql = 'assignee = currentUser() AND created >= "2026-01-01" ORDER BY created DESC'
    return await _search_tickets(base, headers, jql)


async def get_my_tickets_mtd() -> list:
    """MTD tickets assigned to current user."""
    _, base, headers = await _get_client()
    if not base:
        return []
    from datetime import date
    first_of_month = date.today().replace(day=1).isoformat()
    jql = f'assignee = currentUser() AND created >= "{first_of_month}" ORDER BY created DESC'
    return await _search_tickets(base, headers, jql)


async def _search_tickets(base: str, headers: dict, jql: str, limit: int = 200) -> list:
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        try:
            r = await client.post(
                f"{base}/rest/api/2/search",
                json={"jql": jql, "maxResults": limit,
                      "fields": ["summary", "status", "issuetype", "created", "assignee",
                                 "customfield_32404", "customfield_36200"]},
                headers=headers,
            )
            r.raise_for_status()
            issues = r.json().get("issues", [])
            result = []
            for issue in issues:
                f = issue.get("fields", {})
                result.append({
                    "key":       issue.get("key"),
                    "summary":   f.get("summary"),
                    "status":    f.get("status", {}).get("name"),
                    "issuetype": f.get("issuetype", {}).get("name"),
                    "created":   f.get("created"),
                    "assignee":  (f.get("assignee") or {}).get("displayName"),
                })
            return result
        except Exception:
            return []


async def get_user_tickets(jira_username: str, filter: str = "mine", limit: int = 200) -> list:
    """
    Fetch tickets assigned to jira_username directly from Jira.
    filter: all (last 90d) | ytd | mtd | mine (all time)
    Returns list of dicts in the same shape as cloudpulse_jira_tickets DB rows.
    """
    _, base, headers = await _get_client()
    if not base:
        return []

    assignee_clause = f'assignee = "{jira_username}"'
    if filter == "ytd":
        date_clause = "AND created >= startOfYear()"
    elif filter == "mtd":
        date_clause = "AND created >= startOfMonth()"
    elif filter == "mine":
        date_clause = ""          # all time — show everything assigned to me
    else:                         # "all" — cap at last 90 days to avoid huge result set
        date_clause = "AND created >= -90d"

    jql = f'{assignee_clause} {date_clause} ORDER BY created DESC'
    raw = await _search_tickets(base, headers, jql, limit=limit)

    result = []
    for t in raw:
        key = t.get("key") or ""
        result.append({
            "ticket_key":           key,
            "ticket_url":           f"{base}/browse/{key}" if key else None,
            "project_key":          key.split("-")[0] if "-" in key else None,
            "summary":              t.get("summary"),
            "sr_type":              t.get("issuetype"),
            "status":               t.get("status"),
            "created_by":           jira_username,
            "created_at":           t.get("created"),
            "scheduled_resolve_at": None,
            "effort_hours":         None,
            "subsidiary_id":        None,
            "source":               "jira",
        })
    return result


async def get_user_stats(jira_username: str) -> dict:
    """MTD, YTD, open, in-progress ticket counts for a Jira user (parallel queries)."""
    import asyncio

    _, base, headers = await _get_client()
    if not base:
        # Fall back to DB counts (works with seeded/created tickets)
        stats = await get_user_stats_from_db(jira_username)
        stats["jira_username"] = jira_username
        stats["note"] = "Jira not configured — counts from local DB"
        return stats

    queries = {
        "ytd":         f'assignee = "{jira_username}" AND created >= startOfYear()',
        "mtd":         f'assignee = "{jira_username}" AND created >= startOfMonth()',
        # Use statusCategory to catch any "open" status name (To Do, Open, New, etc.)
        "open":        f'assignee = "{jira_username}" AND statusCategory = "To Do"',
        "in_progress": f'assignee = "{jira_username}" AND statusCategory = "In Progress"',
    }

    errors: list[str] = []

    async def _count(key: str, jql: str) -> int:
        try:
            async with httpx.AsyncClient(verify=False, timeout=15) as client:
                r = await client.post(
                    f"{base}/rest/api/2/search",
                    json={"jql": jql, "maxResults": 0},
                    headers=headers,
                )
                if r.status_code == 200:
                    return r.json().get("total", 0)
                errors.append(f"{key}: HTTP {r.status_code} — {r.text[:120]}")
                return 0
        except Exception as e:
            errors.append(f"{key}: {e}")
            return 0

    results = await asyncio.gather(*[_count(k, jql) for k, jql in queries.items()])
    out = dict(zip(queries.keys(), results))
    out["jira_username"] = jira_username
    if errors:
        out["error"] = "; ".join(errors)
    return out
