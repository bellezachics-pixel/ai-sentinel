"""
Security Middleware - Blindaje completo del backend AI-Sentinel
- Rate Limiting
- Security Headers (HSTS, CSP, X-Frame, etc.)
- Request sanitization
- IP blocking
- Request size limiting
- Brute force protection
"""
from __future__ import annotations

import time
import hashlib
import re
from typing import Dict, Set
from collections import defaultdict

from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


# ============================================================
# Rate Limiter - Proteccion contra abuso
# ============================================================
class RateLimitStore:
    def __init__(self):
        self.requests: Dict[str, list] = defaultdict(list)
        self.blocked_ips: Dict[str, float] = {}
        self.failed_auth: Dict[str, list] = defaultdict(list)

    def is_blocked(self, ip: str) -> bool:
        if ip in self.blocked_ips:
            if time.time() < self.blocked_ips[ip]:
                return True
            del self.blocked_ips[ip]
        return False

    def block_ip(self, ip: str, duration: int = 300):
        self.blocked_ips[ip] = time.time() + duration

    def add_request(self, ip: str):
        now = time.time()
        self.requests[ip] = [t for t in self.requests[ip] if now - t < 60]
        self.requests[ip].append(now)

    def get_request_count(self, ip: str, window: int = 60) -> int:
        now = time.time()
        self.requests[ip] = [t for t in self.requests[ip] if now - t < window]
        return len(self.requests[ip])

    def add_failed_auth(self, ip: str):
        now = time.time()
        self.failed_auth[ip] = [t for t in self.failed_auth[ip] if now - t < 900]
        self.failed_auth[ip].append(now)

    def get_failed_auth_count(self, ip: str) -> int:
        now = time.time()
        self.failed_auth[ip] = [t for t in self.failed_auth[ip] if now - t < 900]
        return len(self.failed_auth[ip])


rate_limit_store = RateLimitStore()

# Limits por endpoint
RATE_LIMITS = {
    "/api/v1/analyze/": 30,      # 30 requests/min para analisis
    "/api/v1/auth/login": 5,     # 5 intentos/min para login
    "/api/v1/auth/register": 3,  # 3 registros/min
    "/api/v1/threat-intel/": 20, # 20 consultas/min para TI
    "default": 60,               # 60 requests/min general
}


def get_rate_limit(path: str) -> int:
    for prefix, limit in RATE_LIMITS.items():
        if prefix != "default" and path.startswith(prefix):
            return limit
    return RATE_LIMITS["default"]


# ============================================================
# Security Headers Middleware
# ============================================================
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Strict-Transport-Security
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        # XSS Protection
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        # Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Permissions Policy
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        # Content Security Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        # Prevent caching of sensitive data
        if "/api/" in request.url.path:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"

        # Remove server header
        if "server" in response.headers:
            del response.headers["server"]

        return response


# ============================================================
# Rate Limiting Middleware
# ============================================================
class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_ip = self._get_client_ip(request)

        # Check if IP is blocked
        if rate_limit_store.is_blocked(client_ip):
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "IP bloqueada temporalmente por exceso de solicitudes.",
                    "retry_after": 300,
                },
                headers={"Retry-After": "300"},
            )

        # Check rate limit
        limit = get_rate_limit(request.url.path)
        current_count = rate_limit_store.get_request_count(client_ip)

        if current_count >= limit:
            # Block IP if way over limit
            if current_count >= limit * 3:
                rate_limit_store.block_ip(client_ip, 300)
            return JSONResponse(
                status_code=429,
                content={"detail": "Demasiadas solicitudes. Intenta de nuevo mas tarde."},
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                },
            )

        rate_limit_store.add_request(client_ip)

        response = await call_next(request)

        # Add rate limit headers
        remaining = max(0, limit - current_count - 1)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)

        return response

    def _get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"


# ============================================================
# Request Validation Middleware
# ============================================================
# Patrones maliciosos a bloquear
MALICIOUS_PATTERNS = [
    re.compile(r"<script", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"on\w+\s*=", re.IGNORECASE),
    re.compile(r"union\s+select", re.IGNORECASE),
    re.compile(r";\s*drop\s+table", re.IGNORECASE),
    re.compile(r"--\s*$"),
    re.compile(r"'\s*or\s+'1'\s*=\s*'1", re.IGNORECASE),
    re.compile(r"\.\./\.\./"),
    re.compile(r"%00"),
    re.compile(r"\\x00"),
]

MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10MB


class RequestValidationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Check request size
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_REQUEST_SIZE:
            return JSONResponse(
                status_code=413,
                content={"detail": "Solicitud demasiado grande. Maximo 10MB."},
            )

        # Check URL for malicious patterns
        url_str = str(request.url)
        for pattern in MALICIOUS_PATTERNS:
            if pattern.search(url_str):
                client_ip = request.client.host if request.client else "unknown"
                rate_limit_store.block_ip(client_ip, 600)
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Solicitud rechazada por contenido malicioso."},
                )

        # Check query parameters
        for key, value in request.query_params.items():
            for pattern in MALICIOUS_PATTERNS:
                if pattern.search(value):
                    return JSONResponse(
                        status_code=400,
                        content={"detail": "Parametro de consulta invalido."},
                    )

        return await call_next(request)


# ============================================================
# CORS estricto - solo origenes permitidos
# ============================================================
ALLOWED_ORIGINS: Set[str] = {
    "http://localhost:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    "https://frontend-kappa-wheat-28.vercel.app",
    "https://frontend-odqi9ejl1-bellezachics-pixels-projects.vercel.app",
}


def get_cors_origins():
    """Retorna origenes permitidos. En produccion, agregar dominios reales."""
    import os
    extra = os.environ.get("ALLOWED_ORIGINS", "")
    if extra:
        for origin in extra.split(","):
            ALLOWED_ORIGINS.add(origin.strip())
    return list(ALLOWED_ORIGINS)
