from pydantic_settings import BaseSettings
from typing import Optional, List


class Settings(BaseSettings):
    APP_NAME: str = "AI-Sentinel"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./ai_sentinel.db"
    REDIS_URL: str = "redis://localhost:6379/0"

    # API Keys - Threat Intelligence
    VIRUSTOTAL_API_KEY: Optional[str] = None
    URLSCAN_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None

    # OpenAI
    OPENAI_API_KEY: Optional[str] = None

    # Risk Engine Weights
    WEIGHT_URL: float = 0.30
    WEIGHT_CONTENT: float = 0.25
    WEIGHT_HEADERS: float = 0.20
    WEIGHT_NETWORK: float = 0.25

    # JWT
    SECRET_KEY: str = "ai-sentinel-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
