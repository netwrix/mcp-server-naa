# mcp_naa/main.py
from . import logging_config # Keep for direct run logging setup
# config, database are imported indirectly via app
from .app import mcp_agent
from . import database # Import database directly for close_connection

logger = logging_config.get_logger(__name__)

# NOTE: Initial DB connection is now attempted when app.py is imported.
# This function is for direct execution (python run.py)

def run_server():
    """Sets up logging and runs the MCP server (for direct execution)."""
    # Logging setup is needed if running directly like this
    # If app.py already ran it, this might be redundant but harmless.
    logging_config.setup_logging()

    logger.info("--- MCP NAA Server Starting (Direct Run) ---")

    # Check status after app import attempt
    if not database.get_connection():
         logger.info("Database not connected. Use the 'Connect-Database' tool if needed.")
    else:
         logger.info("Database connection established during app import.")

    try:
        logger.info("Starting MCP server with stdio transport...")
        # Ensure the transport method matches how you intend to run it
        mcp_agent.run(transport="stdio") # mcp_agent is imported from app
        logger.info("MCP server stopped.")

    except Exception as e:
        logger.error(f"Fatal error running MCP server: {e}", exc_info=True)
        # Decide if you need to sys.exit(1) or just log

    finally:
        # This finally block WILL execute when running via `python run.py`
        logger.info("Shutting down (Direct Run). Closing database connection...")
        database.close_connection()
        logger.info("--- MCP NAA Server Exited (Direct Run) ---")