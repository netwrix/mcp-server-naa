# mcp_naa/tools/db_tools.py
from typing import Optional
from .. import app # Import the initialized agentad
from .. import database     # Import the database module
from ..logging_config import get_logger
import pyodbc

logger = get_logger(__name__)

@app.mcp_agent.tool("Connect-Database")
def connect_database(server: str, database_name: str, username: Optional[str] = None,
                     password: Optional[str] = None, trusted_connection: bool = False) -> str:
    """Connects to a specified MSSQL database server, overriding environment settings."""
    from ..config import settings
    
    logger.info(f"Tool 'Connect-Database' called for {server}/{database_name}")
    
    # Close existing connection first
    database.close_connection()
    
    # Store original settings
    original_server = settings.DB_SERVER
    original_db_name = settings.DB_NAME
    original_user = settings.DB_USER
    original_password = settings.DB_PASSWORD
    original_windows_auth = settings.DB_USE_WINDOWS_AUTH
    
    try:
        # Temporarily override settings
        settings.DB_SERVER = server
        settings.DB_NAME = database_name
        settings.DB_USER = username
        settings.DB_PASSWORD = password
        settings.DB_USE_WINDOWS_AUTH = trusted_connection
        
        # Use the standard connect() function
        if database.connect():
            return f"Successfully connected to the database {database_name} on {server}."
        else:
            return "Failed to connect to the database. Check logs for details."
    finally:
        # Restore original settings
        settings.DB_SERVER = original_server
        settings.DB_NAME = original_db_name
        settings.DB_USER = original_user
        settings.DB_PASSWORD = original_password
        settings.DB_USE_WINDOWS_AUTH = original_windows_auth

@app.mcp_agent.tool("Show-ConnectionStatus")
def show_connection_status() -> str:
    """Shows the current database connection status."""
    conn = database.get_connection()
    if conn:
        try:
            # Attempt a simple query to verify connection is live
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            cursor.close()
            # Could fetch server/db name from connection info if needed
            return f"Connected to database." # Add server/db details if available easily
        except pyodbc.Error as e:
            logger.warning(f"Connection test failed: {e}")
            return f"Connection appears stale or broken. Error: {e}. Please reconnect."
        except Exception as e:
             logger.warning(f"Unexpected error checking connection: {e}")
             return f"Error checking connection status: {e}"
    else:
        return "Not connected to a database. Use Connect-Database or ensure .env is configured."

def run_query(query: str) -> str:
    """
    Runs an arbitrary SQL query against the connected database.
    For SELECT statements, returns formatted results.
    For DML statements (INSERT, UPDATE, DELETE), commits changes and returns rows affected.
    """
    conn = database.get_connection()
    if not conn:
        return "Not connected to a database. Please connect first using Connect-Database."

    try:
        rows, columns, row_count = database.execute_query(query)

        if columns: # Indicates a SELECT statement
            return database.format_results(rows, columns)
        else: # Non-SELECT DML statement
             return f"Query executed successfully. Rows affected: {row_count}"

    except RuntimeError as e: # Handles not connected case from execute_query
        logger.warning(f"Run query failed: {e}")
        return str(e)
    except pyodbc.Error as e:
        logger.error(f"Error running query: {e}\nQuery: {query}", exc_info=True)
        # Provide SQLSTATE if available, helpful for debugging
        sqlstate = e.args[0] if e.args else 'N/A'
        return f"Error running query (SQLSTATE: {sqlstate}): {str(e)}"
    except Exception as e:
        logger.error(f"Unexpected error running query: {e}\nQuery: {query}", exc_info=True)
        return f"Unexpected error running query: {str(e)}"


@app.mcp_agent.tool("Show-TableSchema")
def explain_table(table_name: str) -> str:
    """Provides the schema definition (columns, types, keys) for a given table."""
    logger.info(f"Tool 'Show-TableSchema' called for table: {table_name}")
    conn = database.get_connection()
    if not conn:
        return "Not connected to a database. Please connect first."

    # Basic validation to prevent trivial SQL injection - use parameters!
    if not table_name or not table_name.replace('_','').isalnum():
         return f"Invalid table name format: {table_name}"

    try:
        # Check if table exists (using parameterized query)
        table_check_query = """
        SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES
        WHERE TABLE_SCHEMA = SCHEMA_NAME() AND TABLE_NAME = ? AND TABLE_TYPE = 'BASE TABLE'
        """
        rows, _, _ = database.execute_query(table_check_query, (table_name,))
        if not rows or rows[0][0] == 0:
            return f"Table '{table_name}' does not exist or is not accessible."

        # Get columns (using parameterized query)
        column_query = """
        SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = SCHEMA_NAME() AND TABLE_NAME = ?
        ORDER BY ORDINAL_POSITION
        """
        column_rows, _, _ = database.execute_query(column_query, (table_name,))

        schema = f"Schema for table: {table_name}\n\nColumns:\n"
        if not column_rows:
             schema += "  (No columns found)\n"
        for column in column_rows:
            col_name, data_type, max_length, is_nullable = column
            type_info = data_type
            if max_length is not None: # Check for None specifically
                type_info += f"({max_length})"
            nullable_info = "NULL" if is_nullable == "YES" else "NOT NULL"
            schema += f"  - {col_name}: {type_info} {nullable_info}\n"

        # Get primary keys (using parameterized query)
        pk_query = """
        SELECT KCU.COLUMN_NAME
        FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS AS TC
        JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE AS KCU
          ON TC.CONSTRAINT_NAME = KCU.CONSTRAINT_NAME
          AND TC.TABLE_SCHEMA = KCU.TABLE_SCHEMA
          AND TC.TABLE_NAME = KCU.TABLE_NAME
        WHERE TC.CONSTRAINT_TYPE = 'PRIMARY KEY'
          AND TC.TABLE_SCHEMA = SCHEMA_NAME()
          AND TC.TABLE_NAME = ?
        ORDER BY KCU.ORDINAL_POSITION;
        """
        pk_rows, _, _ = database.execute_query(pk_query, (table_name,))

        if pk_rows:
            schema += "\nPrimary Key(s):\n"
            for pk in pk_rows:
                schema += f"  - {pk[0]}\n"
        else:
            schema += "\nPrimary Key(s): None\n"


        # Get foreign keys (using parameterized query)
        fk_query = """
        SELECT
            KCU1.COLUMN_NAME AS FK_COLUMN_NAME,
            KCU2.TABLE_NAME AS REFERENCED_TABLE_NAME,
            KCU2.COLUMN_NAME AS REFERENCED_COLUMN_NAME
        FROM INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS AS RC
        INNER JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE AS KCU1
            ON KCU1.CONSTRAINT_NAME = RC.CONSTRAINT_NAME
            AND KCU1.TABLE_SCHEMA = RC.CONSTRAINT_SCHEMA
        INNER JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE AS KCU2
            ON KCU2.CONSTRAINT_NAME = RC.UNIQUE_CONSTRAINT_NAME
            AND KCU2.TABLE_SCHEMA = RC.UNIQUE_CONSTRAINT_SCHEMA
        WHERE KCU1.TABLE_SCHEMA = SCHEMA_NAME()
          AND KCU1.TABLE_NAME = ?;
        """
        fk_rows, _, _ = database.execute_query(fk_query, (table_name,))

        if fk_rows:
            schema += "\nForeign Key(s):\n"
            for fk in fk_rows:
                schema += f"  - {fk[0]} references {fk[1]}({fk[2]})\n"
        else:
            schema += "\nForeign Key(s): None\n"

        return schema

    except RuntimeError as e: # Handles not connected case from execute_query
        logger.warning(f"Explain table failed: {e}")
        return str(e)
    except pyodbc.Error as e:
        logger.error(f"Error explaining table '{table_name}': {e}", exc_info=True)
        sqlstate = e.args[0] if e.args else 'N/A'
        return f"Error explaining table (SQLSTATE: {sqlstate}): {str(e)}"
    except Exception as e:
        logger.error(f"Unexpected error explaining table '{table_name}': {e}", exc_info=True)
        return f"Unexpected error explaining table: {str(e)}"

@app.mcp_agent.tool()
def get_table_schema(table_name: str) -> str:
    """Alias for Show-TableSchema. Provides the schema for a given table."""
    # This just calls the other tool function directly.
    return explain_table(table_name)