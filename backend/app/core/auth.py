"""
Autenticacion JWT - AI-Sentinel
- Registro/Login de usuarios
- Tokens JWT con expiracion
- Hash seguro de passwords con bcrypt
- Proteccion de endpoints
"""
from __future__ import annotations

import os
import time
import uuid
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field, validator

from app.core.config import settings
from app.core.user_store import get_users, set_users, add_to_blacklist, is_blacklisted


# ============================================================
# Password Hashing
# ============================================================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# ============================================================
# JWT Token Management
# ============================================================
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": str(uuid.uuid4()),
    })
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=7)
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": str(uuid.uuid4()),
        "type": "refresh",
    })
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalido o expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ============================================================
# User Models
# ============================================================
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)
    email: str = Field(..., max_length=255)

    @validator("username")
    def username_alphanumeric(cls, v):
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Username solo puede contener letras, numeros, _ y -")
        return v

    @validator("password")
    def password_strength(cls, v):
        if len(v) < 8:
            raise ValueError("Password debe tener al menos 8 caracteres")
        if not any(c.isupper() for c in v):
            raise ValueError("Password debe contener al menos una mayuscula")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password debe contener al menos un numero")
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in v):
            raise ValueError("Password debe contener al menos un caracter especial")
        return v


class UserLogin(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60


class UserInDB(BaseModel):
    id: str
    username: str
    email: str
    hashed_password: str
    is_active: bool = True
    is_admin: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ============================================================
# User Store (JSON-backed, use real DB in production)
# ============================================================
users_db: Dict[str, UserInDB] = {}


def _load_users():
    global users_db
    raw = get_users()
    users_db = {}
    for username, data in raw.items():
        try:
            users_db[username] = UserInDB(**data)
        except Exception:
            continue

    # Create admin only if ADMIN_PASSWORD is set
    admin_password = settings.ADMIN_PASSWORD
    if admin_password and "admin" not in users_db:
        users_db["admin"] = UserInDB(
            id=str(uuid.uuid4()),
            username="admin",
            email="admin@ai-sentinel.local",
            hashed_password=hash_password(admin_password),
            is_active=True,
            is_admin=True,
        )
        _persist_users()


def _persist_users():
    data = {u.username: u.model_dump() for u in users_db.values()}
    set_users(data)


_load_users()


def get_user(username: str) -> Optional[UserInDB]:
    return users_db.get(username)


def create_user(user: UserInDB):
    users_db[user.username] = user
    _persist_users()


# ============================================================
# Token Blacklist
# ============================================================
def revoke_token(jti: str):
    add_to_blacklist(jti)


def is_token_revoked(jti: str) -> bool:
    return is_blacklisted(jti)


# ============================================================
# Auth Dependencies
# ============================================================
security_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> Optional[UserInDB]:
    """Obtener usuario actual del token JWT. Retorna None si no hay token."""
    if not credentials:
        return None

    payload = decode_token(credentials.credentials)

    # Check blacklist
    jti = payload.get("jti")
    if jti and is_token_revoked(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token revocado",
        )

    username = payload.get("sub")
    if not username or username not in users_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario no encontrado",
        )

    user = users_db[username]
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuario desactivado",
        )

    return user


async def require_auth(
    user: Optional[UserInDB] = Depends(get_current_user),
) -> UserInDB:
    """Requiere autenticacion obligatoria."""
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autenticacion requerida",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def require_admin(
    user: UserInDB = Depends(require_auth),
) -> UserInDB:
    """Requiere rol de administrador."""
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requieren permisos de administrador",
        )
    return user


async def optional_or_required_auth(
    user: Optional[UserInDB] = Depends(get_current_user),
) -> Optional[UserInDB]:
    """Requiere auth solo si REQUIRE_AUTH esta activado."""
    if settings.REQUIRE_AUTH and not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autenticacion requerida",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
