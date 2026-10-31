"""Users management — create, list, deactivate, change password."""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from typing import Optional
import bcrypt as _bcrypt

from app.auth import require_admin, get_current_user
from app.database import AsyncSessionLocal

router = APIRouter(prefix="/api/users", tags=["users"])


def _pwd_hash(plain: str) -> str:
    return _bcrypt.hashpw(plain.encode(), _bcrypt.gensalt(12)).decode()


class CreateUser(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    password: Optional[str] = None
    is_admin: bool = False


class UpdateUser(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = None
    is_admin: Optional[bool] = None
    is_active: Optional[bool] = None


class ChangePassword(BaseModel):
    new_password: str


@router.get("")
async def list_users(admin: dict = Depends(require_admin)):
    async with AsyncSessionLocal() as db:
        rows = await db.execute(text("""
            SELECT id, username, email, full_name, is_active, is_admin,
                   entra_id, created_at, last_login
            FROM infraguardian_users ORDER BY username
        """))
        cols = ["id", "username", "email", "full_name", "is_active", "is_admin",
                "entra_id", "created_at", "last_login"]
        users = []
        for r in rows.fetchall():
            u = dict(zip(cols, r))
            u["created_at"] = u["created_at"].isoformat() if u["created_at"] else None
            u["last_login"]  = u["last_login"].isoformat()  if u["last_login"]  else None
            users.append(u)
    return users


@router.post("")
async def create_user(body: CreateUser, admin: dict = Depends(require_admin)):
    hashed = _pwd_hash(body.password) if body.password else None
    async with AsyncSessionLocal() as db:
        try:
            await db.execute(text("""
                INSERT INTO infraguardian_users
                    (username, email, full_name, hashed_pw, is_active, is_admin)
                VALUES (:u, :e, :n, :h, TRUE, :a)
            """), {"u": body.username, "e": body.email, "n": body.full_name,
                   "h": hashed, "a": body.is_admin})
            await db.commit()
        except Exception as ex:
            raise HTTPException(status_code=409, detail=f"Username already exists: {ex}")
    return {"ok": True}


@router.put("/{user_id}")
async def update_user(user_id: int, body: UpdateUser, admin: dict = Depends(require_admin)):
    sets, params = [], {"id": user_id}
    if body.email     is not None: sets.append("email = :email");     params["email"]     = body.email
    if body.full_name is not None: sets.append("full_name = :fn");    params["fn"]        = body.full_name
    if body.is_admin  is not None: sets.append("is_admin = :admin");  params["admin"]     = body.is_admin
    if body.is_active is not None: sets.append("is_active = :active");params["active"]    = body.is_active
    if not sets:
        return {"ok": True}
    async with AsyncSessionLocal() as db:
        await db.execute(text(f"UPDATE infraguardian_users SET {', '.join(sets)} WHERE id = :id"), params)
        await db.commit()
    return {"ok": True}


@router.post("/{user_id}/password")
async def change_password(user_id: int, body: ChangePassword, admin: dict = Depends(require_admin)):
    hashed = _pwd_hash(body.new_password)
    async with AsyncSessionLocal() as db:
        await db.execute(
            text("UPDATE infraguardian_users SET hashed_pw = :h WHERE id = :id"),
            {"h": hashed, "id": user_id},
        )
        await db.commit()
    return {"ok": True}


@router.delete("/{user_id}")
async def deactivate_user(user_id: int, admin: dict = Depends(require_admin)):
    """Soft-delete: set is_active = false."""
    async with AsyncSessionLocal() as db:
        await db.execute(
            text("UPDATE infraguardian_users SET is_active = FALSE WHERE id = :id"),
            {"id": user_id},
        )
        await db.commit()
    return {"ok": True}


@router.get("/me")
async def get_me(user: dict = Depends(get_current_user)):
    return user
