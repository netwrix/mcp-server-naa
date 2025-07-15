#!/usr/bin/env python3
# run.py
import sys
import os
import atexit  # Import atexit for cleanup

# --- Python Path Setup ---
# Ensure the package directory (the directory *containing* mcp_naa) is in the Python path.
# This assumes run.py is in the project root alongside the mcp_naa directory.
# project_root = os.path.dirname(os.path.abspath(__file__))
# if project_root not in sys.path:
#     sys.path.insert(0, project_root)

# --- Import the MCP Agent ---
# This import will trigger the execution of code in mcp_naa/app.py,
# including logging setup, config loading, agent initialization,
# tool registration, and the initial DB connection attempt.
try:
    from mcp_naa.app import mcp
    from mcp_naa import database          # <<< Import database for cleanup
    from mcp_naa.logging_config import get_logger # For logging cleanup message
    logger = get_logger(__name__)

    # --- Define Cleanup ---
    # Register a function to close the DB connection when Python exits.
    # This will be called regardless of whether the exit is normal or due to an error
    # *after* fastmcp run has finished or been interrupted (usually).
    @atexit.register
    def cleanup_on_exit():
        logger.info("Application exiting. Running cleanup...")
        database.close_connection()
        logger.info("Cleanup finished.")

    logger.info(f"MCP Agent '{mcp.name}' loaded successfully in run.py.")

except ImportError as e:
    print(f"ERROR: Failed to import MCP agent from mcp_naa.app.", file=sys.stderr)
    print(f"       Ensure mcp_naa package is in the Python path:", file=sys.stderr)
    print(f"       sys.path: {sys.path}", file=sys.stderr)
    print(f"       Error: {e}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    # Log critical errors during import/setup if logging is available
    try:
        from mcp_naa.logging_config import get_logger
        logger = get_logger(__name__)
        logger.critical(f"Critical error during initial setup in run.py: {e}", exc_info=True)
    except ImportError:
        print(f"CRITICAL ERROR during initial setup in run.py: {e}", file=sys.stderr)
    sys.exit(1)

def run_server():
    """Sets up logging and runs the MCP server (for direct execution)."""
    # Logging setup is needed if running directly like this
    # If app.py already ran it, this might be redundant but harmless.
    logger.info("--- MCP NAA Server Starting (Direct Run) ---")

    # Check status after app import attempt
    if not database.get_connection():
         logger.info("Database not connected. Use the 'Connect-Database' tool if needed.")
    else:
         logger.info("Database connection established during app import.")

    try:
        logger.info("Starting MCP server with stdio transport...")
        # Ensure the transport method matches how you intend to run it
        mcp.run(transport="stdio") # mcp_agent is imported from app
        logger.info("MCP server stopped.")

    except Exception as e:
        logger.error(f"Fatal error running MCP server: {e}", exc_info=True)
        # Decide if you need to sys.exit(1) or just log

    finally:
        # This finally block WILL execute when running via `python run.py`
        logger.info("Shutting down (Direct Run). Closing database connection...")
        database.close_connection()
        logger.info("--- MCP NAA Server Exited (Direct Run) ---")

if __name__ == "__main__":
    run_server()


# --- No need to call mcp_agent.run() here ---
# `fastmcp run` will take the 'app' object and run it itself.

# The code in mcp_naa/main.py (specifically run_server) is now only
# relevant if you were to execute `python mcp_naa/main.py` directly,
# which is not the intended way when using `fastmcp run`.