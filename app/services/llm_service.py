"""
LLM service — any OpenAI-compatible chat completions endpoint.
"""
from __future__ import annotations
import json
from typing import AsyncIterator

import httpx
import app.config as cfg


def _make_client(ssl_verify: bool) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        verify=ssl_verify,
        timeout=httpx.Timeout(120.0, connect=30.0),
        trust_env=False,
    )


async def _get_llm_params() -> dict:
    return {
        "base_url":   await cfg.get("llm.base_url"),
        "model":      await cfg.get("llm.model", "qwen/qwen3.5-122b-a10b"),
        "api_key":    await cfg.get("llm.api_key", "nokey"),
        "ssl_verify": await cfg.get_bool("llm.ssl_verify", False),
        "max_tokens": await cfg.get_int("llm.max_tokens", 4096),
        "temperature":await cfg.get_float("llm.temperature", 0.4),
    }


async def chat_completion(system: str, user: str) -> str:
    """Single-shot completion. Returns full text."""
    p = await _get_llm_params()
    payload = {
        "model": p["model"],
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
        "max_tokens":  p["max_tokens"],
        "temperature": p["temperature"],
        "stream": False,
        "chat_template_kwargs": {"enable_thinking": False},
    }
    headers = {
        "Authorization": f"Bearer {p['api_key']}",
        "Content-Type": "application/json",
    }
    async with _make_client(p["ssl_verify"]) as client:
        resp = await client.post(
            f"{p['base_url']}/chat/completions",
            json=payload,
            headers=headers,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


async def stream_completion(system: str, user: str) -> AsyncIterator[str]:
    """Streaming completion — yields text chunks."""
    p = await _get_llm_params()
    payload = {
        "model": p["model"],
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
        "max_tokens":  p["max_tokens"],
        "temperature": p["temperature"],
        "stream": True,
        "chat_template_kwargs": {"enable_thinking": False},
    }
    headers = {
        "Authorization": f"Bearer {p['api_key']}",
        "Content-Type": "application/json",
    }
    async with _make_client(p["ssl_verify"]) as client:
        async with client.stream(
            "POST",
            f"{p['base_url']}/chat/completions",
            json=payload,
            headers=headers,
        ) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if line.startswith("data: "):
                    chunk = line[6:]
                    if chunk.strip() == "[DONE]":
                        break
                    try:
                        delta = json.loads(chunk)["choices"][0]["delta"].get("content", "")
                        if delta:
                            yield delta
                    except Exception:
                        continue


# ─────────────────────────────────────────────────────────────────
# Capacity alert analysis
# ─────────────────────────────────────────────────────────────────

async def analyze_capacity_alert(server: str, metric: str, value: float, context: dict) -> dict:
    """Analyze a capacity alert and return structured recommendations."""
    system = """You are CloudPulse, an enterprise Windows infrastructure AI assistant.
Analyze capacity alerts and provide actionable, concise remediation advice.
Always respond in valid JSON with keys: summary, root_causes, immediate_actions, long_term_actions, estimated_resolution_hours."""

    user = f"""Server: {server}
Alert: {metric} at {value:.1f}%
Context: {json.dumps(context, indent=2)}

Analyze this Windows infrastructure capacity issue and provide structured remediation advice."""

    try:
        text = await chat_completion(system, user)
        # Extract JSON from response
        start = text.find("{")
        end   = text.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(text[start:end])
    except Exception as e:
        pass
    return {
        "summary": f"{metric} critical on {server} at {value:.1f}%",
        "root_causes": ["High resource utilization detected"],
        "immediate_actions": ["Investigate top processes", "Check recent deployments"],
        "long_term_actions": ["Review capacity planning", "Consider scaling"],
        "estimated_resolution_hours": 2,
    }


# ─────────────────────────────────────────────────────────────────
# Jira ticket generation pipeline
# ─────────────────────────────────────────────────────────────────

SUBSIDIARIES = {
    "43502": "emaratech Group",
    "43503": "emaratech G",
    "43504": "emaratech Solutions",
    "43505": "noqodi",
    "43506": "Cybranytech",
    "43507": "Emirates Real Estate Solutions",
    "43508": "emaratech Egypt",
    "43509": "Zajel",
    "43481": "Others",
}

# Key = Jira customfield_32404 option ID, Value = display name
SR_TYPES: dict[str, str] = {
    "38124": "IT Helpdesk",
    "38125": "Back-up & Restore",
    "38126": "Dashboards & Reporting",
    "43697": "Database Patching - Prod",
    "43698": "Database Patching - Non-Prod",
    "43699": "Database BAU & Health check - Prod",
    "43700": "Database BAU & Health check - Non-Prod",
    "43701": "Goldengate Administration",
    "43702": "Oracle cloud Administration",
    "43703": "Database Audit (PCI DSS / PWC / FAA)",
    "43704": "Vender engagement/meetings",
    "43705": "User Access Reviews",
    "43706": "GDRFA audits (DESC, FAD)",
    "43707": "GDRFA project support: Data-Lake/Internal/Others",
    "43708": "Database Pen/vulnerability/ Other Tests",
    "43709": "Database Automation tasks",
    "43710": "Database Backup and Restoration",
    "43711": "Windows Server Operations (BAU & Health Checks)",
    "43712": "Patching & Maintenance – Prod",
    "43713": "Patching & Maintenance – Non-Prod",
    "43714": "VDI / Remote Access Support",
    "43715": "Windows / AD Access & Privileged Access (PAM)",
    "43716": "Security Vulnerability Remediation",
    "43717": "Audit Evidence Collection & Compliance Support",
    "43718": "On Call Production Alert & Response",
    "43719": "Logging & SIEM Onboarding / Support",
    "43720": "Application Deployment & Configuration - Lower environment",
    "43721": "Integration Connectivity & Access",
    "43722": "DR / PROD Connectivity & Failover Support",
    "43723": "Environment Provisioning & Maintenance",
    "43724": "Performance Testing Support",
    "43725": "DNS Provisioning",
    "43726": "File Server / EFS / Sharepoint Access",
    "43727": "New Mailbox / SMTP Configuration",
    "43728": "Vendor Discussion",
    "43729": "SOC Notification & Response",
    "43730": "Password Reset & Unblock Access",
    "43731": "EDR & Antivirus Tuning & Support",
    "43732": "Software Installation",
    "43733": "Group Policy Enforcement",
    "43734": "Email Whitelisting & Moderation",
    "43874": "Middleware - Patching/upgrade/migration- Prod",
    "43875": "Middleware - Patching/upgrade/migration - Non-prod",
    "43876": "Middleware - BAU Support - Prod",
    "43877": "Middleware - BAU Support- Non-Prod",
    "43878": "Middleware - Project meeting",
    "43879": "Middleware - Application Onboarding",
    "43880": "Middleware - Automation",
    "43881": "Middleware - Performance tuning",
    "43882": "Middleware - Vendor engagement",
    "43474": "Monitoring & Observability",
    "43475": "Centralized Log Management",
    "43476": "Operational & Business Dashboards",
    "43979": "Assets Transfer",
    "44400": "Unix - BAU & Health Check",
}


async def generate_jira_draft(summary: str) -> AsyncIterator[str]:
    """
    Streaming pipeline. Yields NDJSON events:
      {"stage": "classifying"|"generating"|"draft_ready"|"error", "data": {...}}

    Input: one-line or short summary from the UI.
    Output draft: subsidiary_id, subsidiary_name, sr_type_id, sr_type_name,
                  description (humanized paragraphs), priority, effort_hours.
    """
    import json as _json

    system = f"""You are a senior IT Service Management engineer at emaratech Group (UAE).
Your job is to turn a brief issue summary into a complete, professional Jira Service Request.

SUBSIDIARY OPTIONS — pick the most relevant numeric ID:
{_json.dumps(SUBSIDIARIES, indent=2)}

SR TYPE OPTIONS — pick the numeric ID that best matches the work:
{_json.dumps(SR_TYPES, indent=2)}

RULES:
- Default subsidiary is "emaratech G" (43503) unless the summary names another entity.
- For Windows server / infrastructure work choose IDs 43711–43734 range first.
- Write the description as a fluent, professional engineer would write it — NOT bullet points, NOT robotic.
- Description structure (flowing paragraphs, no headers):
    1. What is happening / what was observed.
    2. Business or operational impact.
    3. Environment details (servers, systems, users affected).
    4. Any investigation or steps already taken.
    5. What outcome is expected from this ticket.
- Keep the description concise but complete — typically 150–250 words.
- Effort hours: realistic estimate for the sr_type chosen.
- resolution_notes: 4 to 6 concise, humanized bullet points describing what was done to resolve this issue.
  Write them as an engineer documenting their actual work — specific, natural, past tense.
  Examples: "Cleared disk space by removing stale IIS logs older than 30 days from C:\\inetpub\\logs",
  "Restarted the SQL Server Agent service after confirming no active jobs were running".
  Each note should be 1–2 sentences, standalone, and read like real fieldwork notes.

Respond ONLY with valid JSON — no markdown fences, no explanation:
{{
  "summary": "<concise ticket title, max 80 chars, action-verb style e.g. 'Upgrade SCCM to version 2509 on primary site server'>",
  "subsidiary_id": "<numeric string ID from subsidiaries>",
  "subsidiary_name": "<matching name>",
  "sr_type_id": "<numeric string ID from SR types>",
  "sr_type_name": "<matching name>",
  "description": "<professional multi-paragraph description>",
  "effort_hours": <number>,
  "resolution_notes": ["<note 1>", "<note 2>", "<note 3>", "<note 4>", "<note 5>"]
}}"""

    yield _json.dumps({"stage": "classifying", "data": {"message": "Analysing issue and selecting SR type…"}}) + "\n"
    await asyncio.sleep(0.05)
    yield _json.dumps({"stage": "generating", "data": {"message": "Drafting professional description and resolution notes…"}}) + "\n"

    try:
        full_text = await chat_completion(system, summary)
        start = full_text.find("{")
        end   = full_text.rfind("}") + 1
        if start >= 0 and end > start:
            draft = _json.loads(full_text[start:end])
        else:
            raise ValueError("LLM did not return valid JSON")
        # Ensure resolution_notes is a list
        if "resolution_notes" not in draft or not isinstance(draft["resolution_notes"], list):
            draft["resolution_notes"] = []
    except Exception as e:
        yield _json.dumps({"stage": "error", "data": {"message": str(e)}}) + "\n"
        return

    yield _json.dumps({"stage": "draft_ready", "data": draft}) + "\n"


import asyncio
