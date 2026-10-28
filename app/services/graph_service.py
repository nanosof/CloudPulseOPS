"""
Microsoft Graph read helpers (app-only, client_credentials).
Reuses the Entra app token from teams_service; adds paging and throttling retry.
"""
from __future__ import annotations
import asyncio
import logging
from typing import Any, Optional

import httpx

from app.services import teams_service

log = logging.getLogger(__name__)
GRAPH      = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"


class GraphError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(f"Graph {status}: {message}")
        self.status = status


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(verify=False, timeout=httpx.Timeout(90.0, connect=20.0))


async def _request(client: httpx.AsyncClient, url: str, params: Optional[dict] = None) -> dict:
    for attempt in range(4):
        token = await teams_service._get_token()
        resp = await client.get(url, params=params, headers={
            "Authorization":    f"Bearer {token}",
            "ConsistencyLevel": "eventual",
        })
        if resp.status_code in (429, 503, 504) and attempt < 3:
            wait = int(resp.headers.get("Retry-After", "0") or 0) or 2 ** (attempt + 1)
            log.info("Graph throttled (%s) on %s — retrying in %ss", resp.status_code, url.split("?")[0], wait)
            await asyncio.sleep(min(wait, 30))
            continue
        if resp.status_code != 200:
            try:
                msg = resp.json().get("error", {}).get("message", resp.text[:200])
            except Exception:
                msg = resp.text[:200]
            raise GraphError(resp.status_code, msg)
        return resp.json()
    raise GraphError(429, "throttled")


async def get(path: str, params: Optional[dict] = None, beta: bool = False) -> dict:
    async with _client() as client:
        return await _request(client, (GRAPH_BETA if beta else GRAPH) + path, params)


async def get_all(path: str, params: Optional[dict] = None, beta: bool = False,
                  max_items: int = 50000) -> list[dict[str, Any]]:
    """Follow @odata.nextLink until exhausted or max_items reached."""
    items: list[dict] = []
    url: Optional[str] = (GRAPH_BETA if beta else GRAPH) + path
    async with _client() as client:
        while url and len(items) < max_items:
            data = await _request(client, url, params)
            items.extend(data.get("value", []))
            url, params = data.get("@odata.nextLink"), None
    return items[:max_items]


async def batch_get(paths: list[str], beta: bool = False, chunk: int = 20,
                    concurrency: int = 4) -> dict[str, dict]:
    """
    GET many paths through Graph JSON batching (20 per request).
    Returns {path: {"status": int, "body": dict}}. Throttled sub-requests are retried once.
    """
    base = GRAPH_BETA if beta else GRAPH
    results: dict[str, dict] = {}
    sem = asyncio.Semaphore(concurrency)

    async def run(group: list[str], client: httpx.AsyncClient) -> None:
        pending = group
        for attempt in range(3):
            async with sem:
                token = await teams_service._get_token()
                resp = await client.post(f"{base}/$batch", headers={"Authorization": f"Bearer {token}"},
                                         json={"requests": [{"id": str(i), "method": "GET", "url": p}
                                                            for i, p in enumerate(pending)]})
            if resp.status_code != 200:
                raise GraphError(resp.status_code, resp.text[:200])
            retry, wait = [], 0
            for r in resp.json().get("responses", []):
                path = pending[int(r["id"])]
                if r.get("status") == 429 and attempt < 2:
                    retry.append(path)
                    wait = max(wait, int((r.get("headers") or {}).get("Retry-After", 2)))
                else:
                    results[path] = {"status": r.get("status"), "body": r.get("body") or {}}
            if not retry:
                return
            await asyncio.sleep(min(wait or 2, 30))
            pending = retry

    async with _client() as client:
        await asyncio.gather(*(run(paths[i:i + chunk], client) for i in range(0, len(paths), chunk)))
    return results


async def hunt(query: str, timeout: float = 180.0) -> list[dict[str, Any]]:
    """Run a Defender advanced hunting (KQL) query via Graph; returns result rows without @odata annotations."""
    for attempt in range(3):
        token = await teams_service._get_token()
        async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(timeout, connect=20.0)) as client:
            resp = await client.post(f"{GRAPH}/security/runHuntingQuery",
                                     headers={"Authorization": f"Bearer {token}"}, json={"Query": query})
        if resp.status_code == 429 and attempt < 2:
            await asyncio.sleep(min(int(resp.headers.get("Retry-After", "10") or 10), 60))
            continue
        if resp.status_code != 200:
            try:
                msg = resp.json().get("error", {}).get("message", resp.text[:300])
            except Exception:
                msg = resp.text[:300]
            raise GraphError(resp.status_code, msg)
        return [{k: v for k, v in row.items() if "@odata" not in k} for row in resp.json().get("results", [])]
    raise GraphError(429, "hunting query throttled")
