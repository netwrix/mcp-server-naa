# mcp_naa/config.py
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from .logging_config import get_logger

logger = get_logger(__name__)


class Settings(BaseSettings):
    """Application configuration settings."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DB_SERVER: str | None = None
    DB_NAME: str | None = None
    DB_USER: str | None = None
    DB_PASSWORD: str | None = None
    DB_USE_WINDOWS_AUTH: bool = False
    DB_TRUST_SERVER_CERTIFICATE: bool = False
    DB_ENCRYPT: bool = True


# Create a single instance of settings to be imported
settings = Settings()
