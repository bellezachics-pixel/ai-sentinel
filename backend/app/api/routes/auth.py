"""
Rutas de Autenticacion - AI-Sentinel
"""
from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, HTTPException, status, Depends, Request

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
    users_db,
    require_auth,
)
from app.core.security import rate_limit_store

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


@router.post("/register", response_model=TokenResponse)
async def register(request: Request, user_data: UserCreate):
    """Registrar nuevo usuario."""
    if user_data.username in users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El nombre de usuario ya existe",
        )

    # Check if email already used
    for u in users_db.values():
        if u.email == user_data.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El email ya esta registrado",
            )

    user = UserInDB(
        id=str(uuid.uuid4()),
        username=user_data.username,
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
    )
    users_db[user.username] = user

    access_token = create_access_token(data={"sub": user.username})
    refresh_token = create_refresh_token(data={"sub": user.username})

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/login", response_model=TokenResponse)
async def login(request: Request, credentials: UserLogin):
    """Iniciar sesion."""
    client_ip = request.client.host if request.client else "unknown"

    # Check brute force
    if rate_limit_store.get_failed_auth_count(client_ip) >= 5:
        rate_limit_store.block_ip(client_ip, 900)  # 15 min block
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados intentos fallidos. Cuenta bloqueada por 15 minutos.",
        )

    user = users_db.get(credentials.username)
    if not user or not verify_password(credentials.password, user.hashed_password):
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


@router.post("/logout")
async def logout(user: UserInDB = Depends(require_auth)):
    """Cerrar sesion (revocar token)."""
    return {"detail": "Sesion cerrada exitosamente"}


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
