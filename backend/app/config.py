"""Central configuration — environment variables only, never committed secrets."""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- Live providers (all optional; backend degrades gracefully) ---
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""

    # --- Behaviour ---
    CORS_ORIGINS: str = "http://localhost:8080,http://localhost:5173,http://localhost:3000"
    MAX_EML_BYTES: int = 8 * 1024 * 1024
    MAX_ATTACHMENT_BYTES: int = 8 * 1024 * 1024
    EXTERNAL_TIMEOUT_S: float = 12.0
    AI_TIMEOUT_S: float = 45.0
    AI_MAX_BODY_CHARS: int = 4000
    AI_MAX_URLS: int = 10
    MAX_URLS: int = 15
    MAX_IPS: int = 15
    MAX_DOMAINS: int = 15
    MAX_ATTACHMENTS: int = 5
    ENABLE_RATE_LIMITING: bool = False

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
