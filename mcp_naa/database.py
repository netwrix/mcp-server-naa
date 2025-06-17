# mcp_naa/database.py
import pyodbc
from typing import Optional, List, Tuple, Any
import re

from .config import settings
from .logging_config import get_logger
# Import the custom error classes from the new module
from .db_errors import (
    DBConnectionError,
    DBConfigurationError,
    DBNotConnectedError,
    DBQueryError,
    DBTransactionError,
    DBUnexpectedError,
)

logger = get_logger(__name__)

# Module-level variable to hold the connection (managed via functions)
_db_connection: Optional[pyodbc.Connection] = None

# --- Error classes and constants are now defined in mcp_naa.db_errors ---


def sanitize_for_logging(text: str, max_length: int = 200) -> str:
    """
    Sanitize text for safe logging to prevent log injection.
    
    Args:
        text: The text to sanitize
        max_length: Maximum length of the output (default 200)
    
    Returns:
        Sanitized text safe for logging
    """
    if not text:
        return ""
    
    # Convert to string if not already
    text = str(text)
    
    # Remove newlines, carriage returns, and tabs to prevent log injection
    # Replace with spaces to maintain readability
    sanitized = text.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    
    # Remove other control characters
    sanitized = ''.join(char if ord(char) >= 32 or char in ' \t' else '' for char in sanitized)
    
    # Normalize multiple spaces to single space
    sanitized = re.sub(r'\s+', ' ', sanitized).strip()
    
    # Truncate if needed
    if len(sanitized) > max_length:
        return sanitized[:max_length] + "..."
    
    return sanitized


def get_query_fingerprint(query: str, max_length: int = 150) -> str:
    """
    Generate a safe query fingerprint for logging.
    Removes potentially sensitive values while preserving query structure.
    
    Args:
        query: The SQL query
        max_length: Maximum length of the fingerprint
    
    Returns:
        Safe query fingerprint for logging
    """
    if not query:
        return ""
    
    # Replace string literals with placeholders
    fingerprint = re.sub(r"'[^']*'", "'?'", query)
    fingerprint = re.sub(r'"[^"]*"', '"?"', fingerprint)
    
    # Replace numeric values with placeholders
    fingerprint = re.sub(r'\b\d+\.?\d*\b', '?', fingerprint)
    
    # Replace common patterns that might contain sensitive data
    # Email-like patterns
    fingerprint = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '?@?', fingerprint)
    
    # Apply general sanitization
    return sanitize_for_logging(fingerprint, max_length)


def connect() -> bool:
    """
    Connects to the MSSQL database using configuration settings.
    Returns True on success. Raises JsonRpcDBError subclasses on failure.
    SECURITY: Avoids logging sensitive credentials.
    """
    global _db_connection
    if _db_connection:
        logger.info("Already connected to the database.")
        return True

    # --- Configuration Validation ---
    if not settings.DB_SERVER or not settings.DB_NAME:
        err_msg = "Database connection failed due to missing configuration (server or database name)."
        log_issue = "DB_SERVER or DB_NAME is not configured."
        logger.error(f"Configuration Error: {log_issue}. Raising DBConfigurationError.")
        raise DBConfigurationError(err_msg, config_issue=log_issue)

    # Sanitize server and database names for logging
    safe_server = sanitize_for_logging(settings.DB_SERVER, 100)
    safe_db_name = sanitize_for_logging(settings.DB_NAME, 100)
    
    auth_method = "Windows Authentication" if settings.DB_USE_WINDOWS_AUTH else "SQL Server Authentication"
    logger.info(f"Attempting to connect to MSSQL server: {safe_server}, database: {safe_db_name} using {auth_method}")

    try:
        connection_string_parts = [
            "DRIVER={ODBC Driver 17 for SQL Server}",
            f"SERVER={settings.DB_SERVER}",
            f"DATABASE={settings.DB_NAME}",
            "Timeout=30"
        ]

        if settings.DB_USE_WINDOWS_AUTH:
            connection_string_parts.append("Trusted_Connection=yes")
            logger.info("Using Trusted Connection (Windows Authentication)")
        else:
            if settings.DB_USER and settings.DB_PASSWORD:
                connection_string_parts.append(f"UID={settings.DB_USER}")
                connection_string_parts.append("PWD=...") # Placeholder for logging
                
                # Sanitize username for logging
                safe_user = sanitize_for_logging(settings.DB_USER, 50)
                logger.info(f"Using SQL Login. User: {safe_user}. Password: [REDACTED]")
            else:
                err_msg = "Database connection failed. Username and password are required for SQL Server Authentication."
                log_issue = "DB_USER or DB_PASSWORD missing for SQL Server Authentication."
                logger.error(f"Configuration Error: {log_issue}. Raising DBConfigurationError.")
                raise DBConfigurationError(err_msg, config_issue=log_issue)

        final_connection_string = ";".join(connection_string_parts).replace("PWD=...", f"PWD={settings.DB_PASSWORD}" if not settings.DB_USE_WINDOWS_AUTH else "PWD=")

        _db_connection = pyodbc.connect(final_connection_string, autocommit=False)

        logger.info(f"Successfully connected to MSSQL server: {safe_server}, database: {safe_db_name}")
        return True

    except pyodbc.Error as e:
        _db_connection = None
        client_err_msg = f"Failed to connect to the database server."
        db_conn_error = DBConnectionError(
            client_message=client_err_msg,
            server=settings.DB_SERVER,
            db_name=settings.DB_NAME,
            original_exception=e
        )
        logger.error(f"{db_conn_error.get_log_message()} Raising DBConnectionError.", exc_info=False)
        raise db_conn_error
    except DBConfigurationError: # Re-raise config errors directly
         raise
    except Exception as e:
        _db_connection = None
        client_err_msg = "An unexpected error occurred during database connection."
        unexpected_error = DBUnexpectedError(
            client_message=client_err_msg,
            context="Database connection attempt",
            original_exception=e
        )
        logger.error(f"{unexpected_error.get_log_message()} Raising DBUnexpectedError.", exc_info=False)
        raise unexpected_error


def connect_with_details(server: str, database: str, username: Optional[str] = None,
                         password: Optional[str] = None, trusted_connection: bool = False) -> bool:
    """
    Connects to a specific MSSQL server, overriding environment settings.
    Used by the Connect-Database tool. Handles credentials securely.
    Returns True on success. Raises JsonRpcDBError subclasses on failure.
    """
    global _db_connection
    close_connection() # Close existing connection if any

    # Sanitize inputs for logging
    safe_server = sanitize_for_logging(server, 100)
    safe_database = sanitize_for_logging(database, 100)
    
    auth_method = "Windows Authentication" if trusted_connection else "SQL Server Authentication"
    logger.info(f"Attempting explicit connection to MSSQL server: {safe_server}, database: {safe_database} using {auth_method}")

    try:
        connection_string_parts = [
            "DRIVER={ODBC Driver 17 for SQL Server}",
            f"SERVER={server}",
            f"DATABASE={database}",
            "Timeout=30"
        ]

        if trusted_connection:
            connection_string_parts.append("Trusted_Connection=yes")
            logger.info("Using Trusted Connection for explicit connection.")
        else:
            if username and password:
                connection_string_parts.append(f"UID={username}")
                connection_string_parts.append("PWD=...") # Placeholder for logging
                
                # Sanitize username for logging
                safe_username = sanitize_for_logging(username, 50)
                logger.info(f"Using SQL Login for explicit connection. User: {safe_username}. Password: [REDACTED]")
            else:
                err_msg = "Explicit database connection failed. Username and password required for SQL Server Authentication."
                log_issue = "Username or password missing for explicit non-trusted connection."
                logger.error(f"Configuration Error: {log_issue}. Raising DBConfigurationError.")
                raise DBConfigurationError(err_msg, config_issue=log_issue)

        final_connection_string = ";".join(connection_string_parts).replace("PWD=...", f"PWD={password}" if not trusted_connection else "PWD=")

        _db_connection = pyodbc.connect(final_connection_string, autocommit=False)
        logger.info(f"Successfully connected explicitly to MSSQL server: {safe_server}, database: {safe_database}")
        return True

    except pyodbc.Error as e:
        _db_connection = None
        client_err_msg = f"Failed to connect explicitly to the database server."
        db_conn_error = DBConnectionError(
            client_message=client_err_msg,
            server=server,
            db_name=database,
            original_exception=e
        )
        logger.error(f"{db_conn_error.get_log_message()} Raising DBConnectionError.", exc_info=False)
        raise db_conn_error
    except DBConfigurationError: # Re-raise config errors directly
         raise
    except Exception as e:
        _db_connection = None
        client_err_msg = "An unexpected error occurred during explicit database connection."
        unexpected_error = DBUnexpectedError(
            client_message=client_err_msg,
            context="Explicit database connection attempt",
            original_exception=e
        )
        logger.error(f"{unexpected_error.get_log_message()} Raising DBUnexpectedError.", exc_info=False)
        raise unexpected_error


def close_connection():
    """Closes the database connection if it's open. Handles potential errors during close."""
    global _db_connection
    if _db_connection:
        try:
            _db_connection.close()
            logger.info("Database connection closed.")
        except pyodbc.Error as e:
            logger.error(f"Error closing database connection (SQLSTATE: {e.args[0] if e.args else 'N/A'}): {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Unexpected error closing database connection: {e}", exc_info=True)
        finally:
            _db_connection = None

def get_connection() -> Optional[pyodbc.Connection]:
    """Returns the current database connection object, if connected."""
    global _db_connection # Ensures we are referring to the module-level variable
    if _db_connection:
        try:
            # Check if the connection object itself reports being closed
            # The 'closed' attribute might not exist on all pyodbc connection objects
            # or might behave differently depending on the driver.
            if hasattr(_db_connection, 'closed') and _db_connection.closed:
                logger.warning("Connection object exists but is marked as closed. Resetting.")
                _db_connection = None # Modifies the global variable
                return None

            # A more robust check could be a simple "SELECT 1" or a driver-specific ping,
            # but that adds overhead and potential transaction side-effects.
            # For now, we rely on execute_query to handle errors if the connection is truly stale.
            pass
        except pyodbc.Error as e: # Catches errors like "Attempt to use a closed connection."
             logger.warning(f"Connection object exists but is invalid ({type(e).__name__}: {e}). Resetting.")
             _db_connection = None # Modifies the global variable
             return None
    return _db_connection


def execute_query(query: str, params: Optional[tuple] = None) -> Tuple[List[pyodbc.Row], List[str], int]:
    """
    Executes a SQL query with enhanced, secure error handling.

    Args:
        query: The SQL query string (should use placeholders like ?).
        params: Optional tuple of parameters for the query.

    Returns:
        A tuple containing: (List[pyodbc.Row], List[column_names], row_count)

    Raises:
        DBNotConnectedError: If not connected to the database.
        DBQueryError: If the query execution fails.
        DBTransactionError: If committing the transaction fails.
        DBUnexpectedError: For other unexpected errors.
    """
    conn = get_connection()
    if not conn:
        raise DBNotConnectedError("Cannot execute query: Not connected to a database.")

    cursor: Optional[pyodbc.Cursor] = None
    try:
        cursor = conn.cursor()
        
        # SECURITY FIX: Don't log parameter values, only count
        params_info = f"<{len(params)} parameters>" if params else "<No parameters>"
        query_fingerprint = get_query_fingerprint(query)
        logger.debug(f"Executing query: {query_fingerprint} with {params_info}")

        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)

        rows: List[pyodbc.Row] = []
        columns: List[str] = []
        row_count: int = cursor.rowcount

        is_select = bool(cursor.description)

        if is_select:
            columns = [column[0] for column in cursor.description]
            rows = cursor.fetchall()
            
            # Sanitize column names for logging (they could contain injected values)
            safe_columns = [sanitize_for_logging(col, 50) for col in columns]
            logger.debug(f"SELECT query executed. Column count: {len(columns)}. Rows fetched: {len(rows)}. Cursor rowcount: {row_count}.")
        else:
            try:
                conn.commit()
                logger.debug(f"Non-SELECT query executed and committed. Rows affected: {row_count}")
            except pyodbc.Error as commit_e:
                client_msg = "Database error: Failed to finalize changes."
                trans_error = DBTransactionError(
                    client_message=client_msg,
                    operation="commit",
                    original_exception=commit_e
                )
                logger.error(f"{trans_error.get_log_message()} Attempting rollback. Raising DBTransactionError.", exc_info=False)
                try:
                    conn.rollback()
                    logger.warning("Transaction rolled back due to commit error.")
                except pyodbc.Error as rb_e:
                    logger.error(f"Critical: Error during rollback attempt after commit failure (SQLSTATE: {rb_e.args[0] if rb_e.args else 'N/A'}): {rb_e}", exc_info=True)
                raise trans_error

        return rows, columns, row_count

    except pyodbc.Error as e:
        client_msg = "Database error: Failed to execute query."
        query_error = DBQueryError(
            client_message=client_msg,
            query=query,
            params=params,
            original_exception=e
        )
        
        # Log sanitized query fingerprint for debugging
        safe_context = sanitize_for_logging(f"Query fingerprint: {get_query_fingerprint(query)}", 200)
        logger.error(f"{query_error.get_log_message()} Context: {safe_context}. Attempting rollback. Raising DBQueryError.", exc_info=False)
        
        try:
            # Check connection validity before rollback
            # Safely check if 'closed' attribute exists and its state
            connection_is_usable_for_rollback = conn and not (hasattr(conn, 'closed') and conn.closed)

            if connection_is_usable_for_rollback:
                 conn.rollback()
                 logger.warning("Transaction rolled back due to query execution error.")
            else:
                 logger.warning("Skipping rollback attempt as connection seems closed or invalid.")
                 # If the connection is bad, it might be good to ensure _db_connection is None
                 # global _db_connection # Already global in this scope if modified
                 # if conn is _db_connection: # Ensure we're nullifying the global one
                 # _db_connection = None
                 # logger.info("Global database connection reset due to unusable state during error handling.")
        except pyodbc.Error as rb_e:
            logger.error(f"Critical: Error during rollback attempt after query failure (SQLSTATE: {rb_e.args[0] if rb_e.args else 'N/A'}): {rb_e}", exc_info=True)
        # Removed the AttributeError catch as hasattr handles it more gracefully.

        raise query_error

    except Exception as e:
        client_msg = "An unexpected error occurred while processing the database request."
        
        # Create safe context for logging
        safe_query_context = sanitize_for_logging(f"Query fingerprint: {get_query_fingerprint(query)}", 200)
        
        unexpected_error = DBUnexpectedError(
            client_message=client_msg,
            context=f"Query execution: {safe_query_context}",
            original_exception=e
        )
        logger.error(f"{unexpected_error.get_log_message()} Raising DBUnexpectedError.", exc_info=False)
        raise unexpected_error

    finally:
        if cursor:
            try:
                cursor.close()
            except pyodbc.Error as cur_close_e:
                logger.warning(f"Error closing database cursor (SQLSTATE: {cur_close_e.args[0] if cur_close_e.args else 'N/A'}): {cur_close_e}", exc_info=True)


def format_results(rows: List[pyodbc.Row], columns: List[str]) -> str:
    """
    Formats query results into a simple text table.
    """
    if not rows:
        return "Query executed successfully. No results returned."
    if not columns:
         return "Query executed successfully, but column names are missing."

    col_widths = {col: len(col) for col in columns}
    for row in rows:
        for i, value in enumerate(row):
            if i < len(columns):
                col_name = columns[i]
                value_str = str(value) if value is not None else "NULL"
                col_widths[col_name] = max(col_widths.get(col_name, 0), len(value_str))

    header_parts = [f"{col:<{col_widths.get(col, len(col))}}" for col in columns]
    header = " | ".join(header_parts)
    separator = "-+-".join("-" * col_widths.get(col, len(col)) for col in columns)

    data_lines = []
    for row in rows:
        row_parts = []
        for i, value in enumerate(row):
             if i < len(columns):
                col_name = columns[i]
                value_str = str(value) if value is not None else "NULL"
                row_parts.append(f"{value_str:<{col_widths.get(col_name, len(value_str))}}")
        data_lines.append(" | ".join(row_parts))

    return f"Results ({len(rows)} rows):\n\n{header}\n{separator}\n" + "\n".join(data_lines)