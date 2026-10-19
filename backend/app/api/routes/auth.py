"""
Rutas de Autenticacion - Guardia Flow
"""
from __future__ import annotations

import asyncio
import re
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, status, Depends, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
import httpx

from app.core.auth import (
    UserCreate,
    UserLogin,
    UserInDB,
    TokenResponse,
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    revoke_token,
    is_token_revoked,
    get_user,
    create_user,
    require_auth,
    set_user_trial_start,
    users_db,
)
from app.core.config import settings
from app.core.security import get_client_ip, rate_limit_store

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"


def _frontend_redirect(fragment: dict[str, str]) -> RedirectResponse:
    frontend_url = settings.FRONTEND_URL.rstrip("/")
    return RedirectResponse(f"{frontend_url}/app#{urlencode(fragment)}")


def _google_redirect_uri(request: Request) -> str:
    return settings.GOOGLE_OAUTH_REDIRECT_URI or str(
        request.url_for("google_callback")
    )


def _find_user_by_email(email: str) -> UserInDB | None:
    normalized = email.strip().lower()
    for user in users_db.values():
        if user.email.lower() == normalized:
            return user
    return None


def _username_from_email(email: str) -> str:
    base = email.split("@", 1)[0].lower()
    base = re.sub(r"[^a-z0-9_-]+", "-", base).strip("-_") or "google-user"
    username = base[:40]
    if username not in users_db:
        return username

    suffix = secrets.token_hex(3)
    return f"{username[:32]}-{suffix}"


async def _create_google_user(email: str) -> UserInDB:
    hashed = await asyncio.to_thread(hash_password, secrets.token_urlsafe(32))
    user = UserInDB(
        id=str(uuid.uuid4()),
        username=_username_from_email(email),
        email=email.strip().lower(),
        hashed_password=hashed,
        is_active=True,
        is_admin=False,
    )
    create_user(user)
    set_user_trial_start(user)  # trial local de 3 dias desde el registro
    return user


def _issue_tokens(user: UserInDB) -> TokenResponse:
    access_token = create_access_token(data={"sub": user.username})
    refresh_token = create_refresh_token(data={"sub": user.username})
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )


def _create_oauth_state() -> str:
    return create_access_token(
        data={"sub": "google-oauth", "nonce": secrets.token_urlsafe(16)},
        expires_delta=timedelta(minutes=10),
    )


@router.post("/register", response_model=TokenResponse)
async def register(request: Request, user_data: UserCreate):
    """Registrar nuevo usuario."""
    if get_user(user_data.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El nombre de usuario ya existe",
        )

    # Email normalizado a minusculas: evita duplicados por mayusculas
    # (Gabi@correo.com vs gabi@correo.com) y unifica el criterio de busqueda.
    normalized_email = user_data.email.strip().lower()

    # Check if email already used (case-insensitive)
    from app.core.auth import users_db
    for u in users_db.values():
        if u.email.lower() == normalized_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El email ya esta registrado",
            )

    # bcrypt es costoso a proposito: correrlo fuera del event loop para no
    # congelar las demas solicitudes del servidor.
    hashed = await asyncio.to_thread(hash_password, user_data.password)

    user = UserInDB(
        id=str(uuid.uuid4()),
        username=user_data.username,
        email=normalized_email,
        hashed_password=hashed,
    )
    create_user(user)
    set_user_trial_start(user)  # trial local de 3 dias desde el registro

    access_token = create_access_token(data={"sub": user.username})
    refresh_token = create_refresh_token(data={"sub": user.username})

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/login", response_model=TokenResponse)
async def login(request: Request, credentials: UserLogin):
    """Iniciar sesion."""
    client_ip = get_client_ip(request)

    # Check brute force
    if rate_limit_store.get_failed_auth_count(client_ip) >= 5:
        rate_limit_store.block_ip(client_ip, 900)  # 15 min block
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados intentos fallidos. Cuenta bloqueada por 15 minutos.",
        )

    user = get_user(credentials.username)
    # bcrypt fuera del event loop para no congelar el servidor.
    password_ok = await asyncio.to_thread(
        verify_password, credentials.password, user.hashed_password
    ) if user else False
    if not user or not password_ok:
        rate_limit_store.add_failed_auth(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cuenta desactivada",
        )

    access_token = create_access_token(data={"sub": user.username})
    refresh_token = create_refresh_token(data={"sub": user.username})

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.get("/google/login")
async def google_login(request: Request):
    """Iniciar sesion con Google OAuth."""
    if not settings.GOOGLE_OAUTH_CLIENT_ID or not settings.GOOGLE_OAUTH_CLIENT_SECRET:
        return _frontend_redirect({"auth_error": "google_not_configured"})

    params = {
        "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
        "redirect_uri": _google_redirect_uri(request),
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "select_account",
        "state": _create_oauth_state(),
    }
    return RedirectResponse(f"{GOOGLE_AUTH_URL}?{urlencode(params)}")


@router.get("/google/callback", name="google_callback")
async def google_callback(request: Request, code: str | None = None, state: str | None = None):
    """Recibir respuesta de Google, crear usuario y emitir JWT local."""
    if not code or not state:
        return _frontend_redirect({"auth_error": "google_missing_code"})

    try:
        payload = decode_token(state)
        if payload.get("sub") != "google-oauth":
            raise HTTPException(status_code=400, detail="Estado OAuth invalido")
    except HTTPException:
        return _frontend_redirect({"auth_error": "google_invalid_state"})

    try:
        async with httpx.AsyncClient(timeout=12) as client:
            token_response = await client.post(
                GOOGLE_TOKEN_URL,
                data={
                    "code": code,
                    "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
                    "client_secret": settings.GOOGLE_OAUTH_CLIENT_SECRET,
                    "redirect_uri": _google_redirect_uri(request),
                    "grant_type": "authorization_code",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            token_response.raise_for_status()
            google_access_token = token_response.json().get("access_token")
            if not google_access_token:
                return _frontend_redirect({"auth_error": "google_token_missing"})

            user_response = await client.get(
                GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {google_access_token}"},
            )
            user_response.raise_for_status()
            profile = user_response.json()
    except httpx.HTTPError:
        return _frontend_redirect({"auth_error": "google_exchange_failed"})

    email = str(profile.get("email") or "").strip().lower()
    email_verified = bool(profile.get("email_verified"))
    if not email or not email_verified:
        return _frontend_redirect({"auth_error": "google_email_unverified"})

    user = _find_user_by_email(email) or await _create_google_user(email)
    tokens = _issue_tokens(user)

    return _frontend_redirect(
        {
            "access_token": tokens.access_token,
            "refresh_token": tokens.refresh_token,
            "auth_provider": "google",
        }
    )


@router.post("/logout")
async def logout(request: Request, user: UserInDB = Depends(require_auth)):
    """Cerrar sesion (revocar token)."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
    if token:
        payload = decode_token(token)
        jti = payload.get("jti")
        if jti:
            revoke_token(jti)
    return {"detail": "Sesion cerrada exitosamente"}


class RefreshTokenRequest(BaseModel):
    refresh_token: Optional[str] = None


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: Request, body: Optional[RefreshTokenRequest] = None):
    """Intercambiar un refresh token por un nuevo par de tokens (rotacion)."""
    token = body.refresh_token if body and body.refresh_token else None

    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token requerido",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_token(token)

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tipo de token invalido: se requiere un refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    jti = payload.get("jti")
    if jti and is_token_revoked(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token revocado",
        )

    username = payload.get("sub")
    user = get_user(username) if username else None
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario no encontrado",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cuenta desactivada",
        )

    # Rotacion: revocar el refresh token usado y emitir par nuevo
    if jti:
        revoke_token(jti)

    access_token = create_access_token(data={"sub": user.username})
    new_refresh_token = create_refresh_token(data={"sub": user.username})

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
    )


@router.get("/me")
async def get_me(user: UserInDB = Depends(require_auth)):
    """Obtener perfil del usuario autenticado."""
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "is_admin": user.is_admin,
        "created_at": user.created_at.isoformat(),
    }
