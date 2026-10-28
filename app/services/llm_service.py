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

# Jira customfield option IDs for subsidiary/business unit.
# Replace these with the option IDs from your Jira instance
# (Admin → Custom fields → find the subsidiary field → view options).
SUBSIDIARIES: dict[str, str] = {
    # "10001": "Head Office",
    # "10002": "Regional Office",
    # "10003": "Others",
}

# Jira SR type option IDs — replace with option IDs from your Jira instance.
# These map to the SR type custom field on your service request issue type.
SR_TYPES: dict[str, str] = {
    # Common types for infrastructure teams — add your own IDs from Jira:
    # "10100": "IT Helpdesk",
    # "10101": "Back-up & Restore",
    # "10102": "Windows Server Operations",
    # "10103": "Patching & Maintenance",
    # "10104": "Security Vulnerability Remediation",
    # "10105": "On Call Production Alert & Response",
    # "10106": "Monitoring & Observability",
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

    import app.config as _cfg
    org_name = await _cfg.get("org.name", "Your Organisation")

    system = f"""You are a senior IT Service Management engineer at {org_name}.
Your job is to turn a brief issue summary into a complete, professional Jira Service Request.

SUBSIDIARY OPTIONS — pick the most relevant numeric ID:
{_json.dumps(SUBSIDIARIES, indent=2)}

SR TYPE OPTIONS — pick the numeric ID that best matches the work:
{_json.dumps(SR_TYPES, indent=2)}

RULES:
- Pick the subsidiary that best matches the context, or the first one listed as the default.
- For Windows server / infrastructure work choose the most relevant SR type first.
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
