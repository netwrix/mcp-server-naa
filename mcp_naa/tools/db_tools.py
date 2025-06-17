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
    logger.info(f"Tool 'Connect-Database' called for {server}/{database_name}")
    if database.connect_with_details(server, database_name, username, password, trusted_connection):
        return f"Successfully connected to the database {database_name} on {server}."
    else:
        # More detailed error might be in logs
        return "Failed to connect to the database. Check logs for details."

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

@app.mcp_agent.tool()
def run_query(query: str) -> str:
    """
    Runs an arbitrary SQL query against the connected database.
    For SELECT statements, returns formatted results.
    For DML statements (INSERT, UPDATE, DELETE), commits changes and returns rows affected.
    """
    logger.info(f"Tool 'run_query' called.")
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


@app.mcp_agent.tool("Sample-Table")
def get_table_sample(table_name: str, rows: int = 10) -> str:
    """Gets a sample number of rows (default 10) from the specified table."""
    logger.info(f"Tool 'Sample-Table' called for table: {table_name}, rows: {rows}")

    if not isinstance(rows, int) or rows < 1:
        return "Number of rows must be a positive integer."

    # Basic validation - Parameterize table name is tricky in SELECT * FROM ?,
    # so we sanitize carefully. Be very cautious here.
    # Allow alphanumeric and underscores. Reject others.
    if not table_name or not all(c.isalnum() or c == '_' for c in table_name):
         return f"Invalid table name format: {table_name}. Only alphanumeric and underscores allowed."

    # Construct query safely using the validated table name
    # Use f-string ONLY after validation. Parameterize 'rows' count.
    # Note: TOP clause syntax might differ slightly in older SQL Server versions
    query = f"SELECT TOP (?) * FROM {table_name};" # Parameterize row count

    conn = database.get_connection()
    if not conn:
        return "Not connected to a database. Please connect first."

    try:
        result_rows, columns, _ = database.execute_query(query, (rows,))
        if not columns:
            # Check if the table actually exists if no columns are returned
             table_check_query = """
             SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES
             WHERE TABLE_SCHEMA = SCHEMA_NAME() AND TABLE_NAME = ? AND TABLE_TYPE = 'BASE TABLE'
             """
             exists_rows, _, _ = database.execute_query(table_check_query, (table_name,))
             if not exists_rows or exists_rows[0][0] == 0:
                 return f"Table '{table_name}' does not exist or is not accessible."
             else:
                 return f"Table '{table_name}' exists but appears to have no columns or data." # Or maybe query failed silently?

        return database.format_results(result_rows, columns)

    except RuntimeError as e:
        logger.warning(f"Sample table failed: {e}")
        return str(e)
    except pyodbc.Error as e:
        logger.error(f"Error sampling table '{table_name}': {e}", exc_info=True)
        sqlstate = e.args[0] if e.args else 'N/A'
        # Check for common errors like invalid object name
        if 'Invalid object name' in str(e):
             return f"Error sampling table: Table '{table_name}' not found or invalid (SQLSTATE: {sqlstate})."
        return f"Error sampling table (SQLSTATE: {sqlstate}): {str(e)}"
    except Exception as e:
        logger.error(f"Unexpected error sampling table '{table_name}': {e}", exc_info=True)
        return f"Unexpected error sampling table: {str(e)}"