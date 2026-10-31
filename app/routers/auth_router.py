"""Authentication routes: login, logout, SSO callback, user management."""
from __future__ import annotations
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy import text

from app.auth import (
    authenticate_user, create_access_token, get_current_user,
    require_admin, hash_password, upsert_entra_user,
    ACCESS_TOKEN_EXPIRE_MINUTES
)
from app.database import AsyncSessionLocal
import app.config as cfg
import msal, uuid

router = APIRouter(prefix="/api/auth", tags=["auth"])

_entra_states: dict[str, str] = {}  # state → redirect_uri (in-memory; fine for single instance)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    full_name: str
    is_admin: bool


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class CreateUserRequest(BaseModel):
    username: str
    email: str
    full_name: str
    password: str
    is_admin: bool = False


@router.post("/token", response_model=TokenResponse)
async def login(form: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form.username, form.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token(
        {"sub": user["username"]},
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return TokenResponse(
        access_token=token,
        username=user["username"],
        full_name=user["full_name"] or user["username"],
        is_admin=user["is_admin"],
    )


@router.get("/me")
async def me(current_user: dict = Depends(get_current_user)):
    return {k: v for k, v in current_user.items() if k != "hashed_pw"}


@router.post("/change-password")
async def change_password(req: ChangePasswordRequest, current_user: dict = Depends(get_current_user)):
    user = await authenticate_user(current_user["username"], req.current_password)
    if not user:
        raise HTTPException(status_code=400, detail="Current password incorrect")
    async with AsyncSessionLocal() as db:
        await db.execute(
            text("UPDATE infraguardian_users SET hashed_pw = :pw WHERE username = :u"),
            {"pw": hash_password(req.new_password), "u": current_user["username"]}
        )
        await db.commit()
    return {"ok": True}


@router.get("/users")
async def list_users(admin: dict = Depends(require_admin)):
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text("SELECT id, username, email, full_name, is_active, is_admin, entra_id, created_at, last_login FROM infraguardian_users ORDER BY created_at")
        )
        cols = ["id", "username", "email", "full_name", "is_active", "is_admin", "entra_id", "created_at", "last_login"]
        return [dict(zip(cols, r)) for r in result.fetchall()]


@router.post("/users")
async def create_user(req: CreateUserRequest, admin: dict = Depends(require_admin)):
    async with AsyncSessionLocal() as db:
        try:
            await db.execute(
                text("""INSERT INTO infraguardian_users (username, email, full_name, hashed_pw, is_active, is_admin)
                        VALUES (:u, :email, :name, :pw, TRUE, :admin)"""),
                {"u": req.username, "email": req.email, "name": req.full_name,
                 "pw": hash_password(req.password), "admin": req.is_admin}
            )
            await db.commit()
            return {"ok": True}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))


@router.delete("/users/{username}")
async def delete_user(username: str, admin: dict = Depends(require_admin)):
    if username == "admin":
        raise HTTPException(status_code=400, detail="Cannot delete admin user")
    async with AsyncSessionLocal() as db:
        await db.execute(
            text("UPDATE infraguardian_users SET is_active = FALSE WHERE username = :u"), {"u": username}
        )
        await db.commit()
    return {"ok": True}


# ─── Entra SSO ────────────────────────────────────────────────

@router.get("/entra/login")
async def entra_login(request: Request):
    tenant    = await cfg.get("entra.tenant_id")
    client_id = await cfg.get("entra.client_id")
    secret    = await cfg.get("entra.client_secret")
    if not tenant or not client_id:
        return RedirectResponse("/login?error=Entra+not+configured+(missing+tenant_id+or+client_id)")
    if not secret:
        return RedirectResponse("/login?error=Entra+client_secret+not+set+(configure+in+Admin+%E2%86%92+Azure%2FEntra)")

    # Use stored public redirect URI (must match Azure App Registration exactly).
    # Set this in Admin → Azure/Entra → entra.redirect_uri
    redirect = await cfg.get("entra.redirect_uri", "")
    if not redirect:
        # Fallback: try to build from request (works only when NOT behind a reverse proxy)
        redirect = str(request.base_url).rstrip("/") + "/api/auth/entra/callback"

    state = str(uuid.uuid4())
    _entra_states[state] = redirect

    authority = f"https://login.microsoftonline.com/{tenant}"
    app_ = msal.ConfidentialClientApplication(
        client_id, authority=authority, client_credential=secret,
    )
    url = app_.get_authorization_request_url(
        scopes=["User.Read"],
        state=state,
        redirect_uri=redirect,
    )
    return RedirectResponse(url)


@router.get("/entra/callback")
async def entra_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    if error:
        return RedirectResponse(f"/login?error={error}")

    tenant        = await cfg.get("entra.tenant_id")
    client_id     = await cfg.get("entra.client_id")
    client_secret = await cfg.get("entra.client_secret")
    # Use the same redirect URI that was stored when the login flow started
    stored_redirect = _entra_states.pop(state, "")
    redirect_uri = stored_redirect or await cfg.get("entra.redirect_uri", "") or \
                   str(request.base_url).rstrip("/") + "/api/auth/entra/callback"

    authority = f"https://login.microsoftonline.com/{tenant}"
    msal_app  = msal.ConfidentialClientApplication(
        client_id, authority=authority, client_credential=client_secret
    )
    result = msal_app.acquire_token_by_authorization_code(
        code,
        scopes=["User.Read"],
        redirect_uri=redirect_uri,
    )
    if "error" in result:
        desc = result.get("error_description", result.get("error", "SSO failed"))
        return RedirectResponse(f"/login?error={desc}")

    claims = result.get("id_token_claims", {})
    entra_id  = claims.get("oid", "")
    email     = claims.get("email") or claims.get("preferred_username", "")
    full_name = claims.get("name", email)

    try:
        user  = await upsert_entra_user(entra_id, email, full_name)
    except HTTPException as e:
        return RedirectResponse(f"/login?error={e.detail}")
    token = create_access_token({"sub": user["username"]})
    return RedirectResponse(f"/login?token={token}")
