# mcp_naa/logging_config.py
import logging
import sys
import os

def setup_logging():
    """Configures logging for the application."""
    log_level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_name, logging.INFO)

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        stream=sys.stderr
    )
    # Suppress overly verbose logs from libraries if necessary
    # logging.getLogger("pyodbc").setLevel(logging.WARNING)
    logger = logging.getLogger(__name__)
    logger.info(f"Logging configured with level: {log_level_name}")

def get_logger(name: str) -> logging.Logger:
    """Gets a logger instance."""
    return logging.getLogger(name)