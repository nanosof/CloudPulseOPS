"""CloudPulse Assistant AI assistant — streaming chat with read-only tools over CloudPulse, Elastic, Entra and Defender."""
from __future__ import annotations
import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.auth import get_current_user
from app.services import assistant_service as ai

router = APIRouter(prefix="/api/assistant", tags=["assistant"])


class ChatRequest(BaseModel):
    message: str
    chat_id: Optional[int] = None


@router.get("/chats")
async def chats(user: dict = Depends(get_current_user)):
    return {"chats": await ai.list_chats(user["username"])}


@router.get("/chats/{chat_id}")
async def chat(chat_id: int, user: dict = Depends(get_current_user)):
    c = await ai.get_chat(chat_id, user["username"])
    if not c:
        raise HTTPException(404, "Chat not found")
    return c


@router.delete("/chats/{chat_id}")
async def delete(chat_id: int, user: dict = Depends(get_current_user)):
    if not await ai.delete_chat(chat_id, user["username"]):
        raise HTTPException(404, "Chat not found")
    return {"ok": True}


@router.post("/chat")
async def send(body: ChatRequest, user: dict = Depends(get_current_user)):
    """Streams NDJSON events: chat · step · step_done · answer | error."""
    text_in = body.message.strip()
    if not text_in:
        raise HTTPException(400, "Empty message")
    if body.chat_id:
        if not await ai.get_chat(body.chat_id, user["username"]):
            raise HTTPException(404, "Chat not found")
        chat_id = body.chat_id
    else:
        chat_id = await ai.create_chat(user["username"], text_in[:80])
    history = await ai.history_for_llm(chat_id)
    await ai.add_message(chat_id, "user", text_in)

    async def stream():
        yield json.dumps({"type": "chat", "chat_id": chat_id}) + "\n"
        async for ev in ai.run(history, text_in):
            if ev["type"] == "answer":
                await ai.add_message(chat_id, "assistant", ev["content"], ev["datasets"], ev["steps"])
            elif ev["type"] == "error":
                await ai.add_message(chat_id, "assistant", "⚠️ " + ev["error"])
            yield json.dumps(ev, default=str) + "\n"

    return StreamingResponse(stream(), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
