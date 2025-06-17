# mcp_naa/config.py
import os
from dotenv import load_dotenv
from .logging_config import get_logger

logger = get_logger(__name__)

# Load environment variables from .env file only once
dotenv_path = os.path.join(os.path.dirname(__file__), '..', '.env') # Assumes .env is in parent dir
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path=dotenv_path)
    logger.info(f"Loaded environment variables from: {dotenv_path}")
else:
    logger.warning(f".env file not found at expected location: {dotenv_path}. Relying on system environment variables.")


class Settings:
    """Application configuration settings."""
    DB_SERVER: str | None = os.getenv("DB_SERVER")
    DB_NAME: str | None = os.getenv("DB_NAME")
    DB_USER: str | None = os.getenv("DB_USER")
    DB_PASSWORD: str | None = os.getenv("DB_PASSWORD")
    DB_USE_WINDOWS_AUTH: bool = os.getenv("DB_USE_WINDOWS_AUTH", "FALSE").upper() == "TRUE"
    MCP_AGENT_NAME: str = "NAA_MCP" # Or getenv if needed

    def __post_init__(self):
        # Perform basic validation
        if not self.DB_SERVER or not self.DB_NAME:
            logger.warning("DB_SERVER or DB_NAME not configured.")
        if not self.DB_USE_WINDOWS_AUTH and (not self.DB_USER or not self.DB_PASSWORD):
             logger.warning("DB User/Password required when Windows Auth is disabled.")

# Create a single instance of settings to be imported
settings = Settings()
settings.__post_init__() # Trigger validation logging

logger.info(f"Configuration loaded: Server={settings.DB_SERVER}, DB={settings.DB_NAME}, WinAuth={settings.DB_USE_WINDOWS_AUTH}")