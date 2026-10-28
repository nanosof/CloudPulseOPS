"""
Authentication: local JWT + Entra ID SSO.
"""
from __future__ import annotations
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
import bcrypt as _bcrypt
from sqlalchemy import text

from app.database import AsyncSessionLocal, get_db
from sqlalchemy.ext.asyncio import AsyncSession

SECRET_KEY = os.environ.get("JWT_SECRET")
if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET is not set; generate one with: openssl rand -hex 32")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 hours

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token", auto_error=False)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


def hash_password(plain: str) -> str:
    return _bcrypt.hashpw(plain.encode(), _bcrypt.gensalt(12)).decode()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def authenticate_user(username: str, password: str) -> Optional[dict]:
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text("SELECT id, username, email, full_name, hashed_pw, is_active, is_admin FROM cloudpulse_users WHERE username = :u"),
            {"u": username}
        )
        row = result.fetchone()
        if not row:
            return None
        user = dict(zip(["id", "username", "email", "full_name", "hashed_pw", "is_active", "is_admin"], row))
        if not user["is_active"]:
            return None
        if not user["hashed_pw"] or not verify_password(password, user["hashed_pw"]):
            return None
        # Update last login
        await db.execute(
            text("UPDATE cloudpulse_users SET last_login = NOW() WHERE id = :id"),
            {"id": user["id"]}
        )
        await db.commit()
        return user


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text("SELECT id, username, email, full_name, is_active, is_admin FROM cloudpulse_users WHERE username = :u"),
            {"u": username}
        )
        row = result.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        user = dict(zip(["id", "username", "email", "full_name", "is_active", "is_admin"], row))
        if not user["is_active"]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User inactive")
        return user


async def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin required")
    return current_user


async def upsert_entra_user(entra_id: str, email: str, full_name: str) -> dict:
    """
    Allow Entra SSO login only if the email is pre-registered by an admin.
    - If user already linked by entra_id → allow and update last_login.
    - If email exists in DB (admin pre-registered) → link entra_id and allow.
    - Otherwise → raise 403 (email not pre-approved).
    """
    async with AsyncSessionLocal() as db:
        # 1. Already linked via entra_id?
        result = await db.execute(
            text("SELECT id, username, email, full_name, is_active, is_admin FROM cloudpulse_users WHERE entra_id = :eid"),
            {"eid": entra_id}
        )
        row = result.fetchone()
        if row:
            user = dict(zip(["id", "username", "email", "full_name", "is_active", "is_admin"], row))
            if not user["is_active"]:
                raise HTTPException(status_code=403, detail="Account is inactive. Contact your administrator.")
            await db.execute(
                text("UPDATE cloudpulse_users SET last_login = NOW(), full_name = :name WHERE entra_id = :eid"),
                {"name": full_name, "eid": entra_id}
            )
            await db.commit()
            return user

        # 2. Email pre-registered by admin?
        result2 = await db.execute(
            text("SELECT id, username, email, full_name, is_active, is_admin FROM cloudpulse_users WHERE LOWER(email) = LOWER(:email)"),
            {"email": email}
        )
        row2 = result2.fetchone()
        if row2:
            user2 = dict(zip(["id", "username", "email", "full_name", "is_active", "is_admin"], row2))
            if not user2["is_active"]:
                raise HTTPException(status_code=403, detail="Account is inactive. Contact your administrator.")
            # Link the Entra ID to the existing account
            await db.execute(
                text("UPDATE cloudpulse_users SET entra_id = :eid, last_login = NOW(), full_name = :name WHERE id = :id"),
                {"eid": entra_id, "name": full_name, "id": user2["id"]}
            )
            await db.commit()
            return user2

        # 3. Not pre-registered → deny
        raise HTTPException(
            status_code=403,
            detail=f"Access denied: {email} is not registered. Ask your administrator to add your email in User Management."
        )
