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
# Token Blacklist (revocacion de tokens)
# ============================================================
token_blacklist: set = set()


def revoke_token(jti: str):
    token_blacklist.add(jti)


def is_token_revoked(jti: str) -> bool:
    return jti in token_blacklist


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
# In-Memory User Store (usar DB en produccion)
# ============================================================
users_db: Dict[str, UserInDB] = {}

# Crear admin por defecto
# Pre-hashed password for admin (bcrypt hash of "Admin@Sentinel2024!")
# This avoids slow bcrypt hashing at startup on low-CPU environments
_admin_hash = "$2b$12$fmnucg5Clnn/IHv.tObj6Oo2.ilsOPuWBd0u8x0bWd6PGvWp56eNO"

users_db["admin"] = UserInDB(
    id=str(uuid.uuid4()),
    username="admin",
    email="admin@ai-sentinel.local",
    hashed_password=_admin_hash,
    is_active=True,
    is_admin=True,
)


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
