import os
import secrets
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "TLS Inspector"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # SQLite — used for scan history (existing behaviour)
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "sqlite+aiosqlite:///./tls_inspector.db",
    )

    # PostgreSQL (Neon) — used for user auth
    POSTGRES_URL: str = os.getenv(
        "POSTGRES_URL",
        "postgresql+asyncpg://neondb_owner:npg_ge3EhukscW2i@ep-young-heart-annqsby1-pooler.c-6.us-east-1.aws.neon.tech/neondb?ssl=require",
    )

    # JWT
    JWT_SECRET: str = os.getenv("JWT_SECRET", secrets.token_hex(32))
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_HOURS: int = 24

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Scanner defaults
    DEFAULT_PORT: int = 443
    SCAN_TIMEOUT: int = 30  # seconds

    class Config:
        env_file = ".env"


settings = Settings()
