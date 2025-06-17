# mcp_naa/app.py (Should already be like this from previous step)
from mcp.server.fastmcp import FastMCP
from . import config
from . import logging_config
from . import database

logger = logging_config.get_logger(__name__)

# --- Initialize Logging and Config (implicitly via imports) ---

logger.info(f"Initializing MCP agent: {config.settings.MCP_AGENT_NAME}")
mcp_agent = FastMCP(config.settings.MCP_AGENT_NAME) # Define the agent
logger.info("MCP agent object created")

# --- Register Tools ---
logger.info("Registering tools...")
from .tools import db_tools
from .tools import fs_tools
from .tools import ad_tools
logger.info("Tools registered.")

# --- Initial DB Connection Attempt ---
def initialize_database_on_startup():
    # ... (keep the function as defined before) ...
    if config.settings.DB_SERVER and config.settings.DB_NAME:
        logger.info("Attempting initial database connection from environment variables...")
        if database.connect():
            logger.info("Initial database connection successful.")
            return True
        else:
            logger.warning("Initial database connection failed using environment variables. Check config and logs.")
            return False
    else:
        logger.info("Database connection details (server/name) missing in config. Skipping auto-connect.")
        return False

db_initialized_on_startup = initialize_database_on_startup()
if not db_initialized_on_startup:
    logger.warning("Database not connected on startup. Use the 'Connect-Database' tool.")

# --- No atexit here ---