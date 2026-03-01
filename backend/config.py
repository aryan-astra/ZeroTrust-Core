"""
ZeroTrust - Configuration Module
Environment-based configuration with .env file support.
"""

import os
from dotenv import load_dotenv

# Load .env file
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))


class Settings:
    """Application settings loaded from environment variables."""

    # Database
    DB_HOST: str = os.getenv("DB_HOST", "localhost")
    DB_PORT: int = int(os.getenv("DB_PORT", "3306"))
    DB_NAME: str = os.getenv("DB_NAME", "zerotrust")
    DB_USER: str = os.getenv("DB_USER", "root")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "password")

    # SQLAlchemy connection URL
    @property
    def DATABASE_URL(self) -> str:
        return f"mysql+pymysql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

    @property
    def ASYNC_DATABASE_URL(self) -> str:
        return f"mysql+aiomysql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

    # Fallback SQLite URL for development without MySQL
    SQLITE_URL: str = "sqlite:///data/zerotrust.db"

    # JWT
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "zerotrust-secret-key-2026")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

    # Server
    SERVER_HOST: str = os.getenv("SERVER_HOST", "0.0.0.0")
    SERVER_PORT: int = int(os.getenv("SERVER_PORT", "8000"))
    CORS_ORIGINS: list = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")

    # Rate Limiting
    RATE_LIMIT: str = os.getenv("RATE_LIMIT_PER_MINUTE", "120") + "/minute"

    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # ML Thresholds
    ANOMALY_CONTAMINATION: float = float(os.getenv("ANOMALY_CONTAMINATION", "0.05"))
    QUARANTINE_THRESHOLD: int = int(os.getenv("QUARANTINE_THRESHOLD", "50"))
    SUSPICIOUS_THRESHOLD: int = int(os.getenv("SUSPICIOUS_THRESHOLD", "80"))

    # AMD
    ENABLE_PARALLEL: bool = os.getenv("ENABLE_PARALLEL_INFERENCE", "true").lower() == "true"
    MAX_WORKERS: int = int(os.getenv("MAX_INFERENCE_WORKERS", "8"))

    # Paths
    BASE_DIR: str = os.path.dirname(os.path.abspath(__file__))
    PROJECT_DIR: str = os.path.dirname(BASE_DIR)
    MODELS_DIR: str = os.path.join(BASE_DIR, "models")
    PROCESSED_DIR: str = os.path.join(BASE_DIR, "data", "processed")
    DATASETS_DIR: str = os.path.join(PROJECT_DIR, "Datasets")


settings = Settings()
