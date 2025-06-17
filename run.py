#!/usr/bin/env python3
# run.py
import sys
import os
import atexit  # Import atexit for cleanup

# --- Python Path Setup ---
# Ensure the package directory (the directory *containing* mcp_naa) is in the Python path.
# This assumes run.py is in the project root alongside the mcp_naa directory.
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# --- Import the MCP Agent ---
# This import will trigger the execution of code in mcp_naa/app.py,
# including logging setup, config loading, agent initialization,
# tool registration, and the initial DB connection attempt.
try:
    from mcp_naa.app import mcp_agent as app # <<< Assign to 'app'
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

    logger.info(f"MCP Agent '{app.name}' loaded successfully in run.py.")

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


# --- No need to call mcp_agent.run() here ---
# `fastmcp run` will take the 'app' object and run it itself.

# The code in mcp_naa/main.py (specifically run_server) is now only
# relevant if you were to execute `python mcp_naa/main.py` directly,
# which is not the intended way when using `fastmcp run`.