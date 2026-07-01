import os
import secrets
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.security import (
    SecurityHeadersMiddleware,
    RateLimitMiddleware,
    RequestValidationMiddleware,
    get_cors_origins,
)

logger = logging.getLogger(__name__)

# Validate/generate JWT secret
if not settings.SECRET_KEY:
    if os.environ.get("ENVIRONMENT", "development").lower() == "production":
        raise RuntimeError("SECRET_KEY environment variable is required in production")
    # Generate a random secret for development (tokens won't survive restarts)
    generated_secret = secrets.token_urlsafe(32)
    object.__setattr__(settings, "SECRET_KEY", generated_secret)
    logger.warning("SECRET_KEY not set. Generated a random key for this session. JWT tokens will not survive restarts.")

# Hide docs in production
is_production = os.environ.get("ENVIRONMENT", "development").lower() == "production"

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Aplicacion de Ciberseguridad Avanzada con IA",
    docs_url=None if is_production else "/docs",
    redoc_url=None if is_production else "/redoc",
)

# ============================================================
# Middleware Stack (se ejecutan en orden inverso)
# ============================================================

# 1. Security Headers
app.add_middleware(SecurityHeadersMiddleware)

# 2. Rate Limiting
app.add_middleware(RateLimitMiddleware)

# 3. Request Validation (anti-injection, size limits)
app.add_middleware(RequestValidationMiddleware)

# 4. CORS estricto
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
    expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining"],
    max_age=600,
)

# ============================================================
# Routes - lazy import para startup rápido
# ============================================================
from app.api.routes.auth import router as auth_router
from app.api.routes.analysis import router as analysis_router

app.include_router(auth_router)
app.include_router(analysis_router)


@app.get("/")
async def root():
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "operational",
        "security": {
            "rate_limiting": True,
            "security_headers": True,
            "jwt_auth": True,
            "input_validation": True,
            "cors_strict": True,
            "brute_force_protection": True,
        },
        "modules": [
            "URL Analyzer",
            "Content Analyzer",
            "Header Analyzer",
            "Network Integrity Guard",
            "QRishing Detector",
            "Deepfake Detector",
            "Threat Intelligence",
            "OCR & NLP Engine",
        ],
    }
