from pydantic_settings import BaseSettings
from typing import Optional, List


class Settings(BaseSettings):
    APP_NAME: str = "AI-Sentinel"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://127.0.0.1:3000", "https://frontend-kappa-wheat-28.vercel.app", "https://frontend-odqi9ejl1-bellezachics-pixels-projects.vercel.app"]
    REQUIRE_AUTH_FOR_ANALYSIS: bool = False

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./ai_sentinel.db"
    REDIS_URL: str = "redis://localhost:6379/0"

    # API Keys - Threat Intelligence
    VIRUSTOTAL_API_KEY: Optional[str] = None
    URLSCAN_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    HIBP_API_KEY: Optional[str] = None

    # OpenAI
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_CHAT_MODEL: str = "gpt-4o-mini"
    OPENAI_VISION_MODEL: str = "gpt-4o-mini"

    # Fact checking
    GOOGLE_FACT_CHECK_API_KEY: Optional[str] = None

    # Google OAuth login
    GOOGLE_OAUTH_CLIENT_ID: Optional[str] = None
    GOOGLE_OAUTH_CLIENT_SECRET: Optional[str] = None
    GOOGLE_OAUTH_REDIRECT_URI: Optional[str] = None
    FRONTEND_URL: str = "http://localhost:3000"

    # Phone intelligence
    NUMVERIFY_API_KEY: Optional[str] = None
    TWILIO_ACCOUNT_SID: Optional[str] = None
    TWILIO_AUTH_TOKEN: Optional[str] = None
    TWILIO_LOOKUP_FROM_COUNTRY: str = "US"

    # Risk Engine Weights
    WEIGHT_URL: float = 0.30
    WEIGHT_CONTENT: float = 0.25
    WEIGHT_HEADERS: float = 0.20
    WEIGHT_NETWORK: float = 0.25

    # JWT - MUST be changed in production via environment variable
    SECRET_KEY: str = ""
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Admin user (only created if ADMIN_PASSWORD is set)
    ADMIN_PASSWORD: Optional[str] = None

    # Auth requirement for analysis endpoints
    REQUIRE_AUTH: bool = True

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
