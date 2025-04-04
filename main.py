import logging
import os
import sys

import pyodbc
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

# Load environment variables from .env file
load_dotenv()

# Configure logging to stderr
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("mcp_server")

# Database connection
db_connection = None


def connect_to_mssql(
    server: str,
    database: str,
    username: str | None = None,
    password: str | None = None,
    trusted_connection: bool = False,
) -> bool:
    """Connect to a MSSQL server"""
    global db_connection

    logger.info(f"Connecting to MSSQL server: {server}, database: {database}")

    try:
        connection_string = "DRIVER={ODBC Driver 17 for SQL Server};"
        connection_string += f"SERVER={server};"
        connection_string += f"DATABASE={database};"

        if trusted_connection:
            connection_string += "Trusted_Connection=yes;"
        else:
            if username and password:
                connection_string += f"UID={username};PWD={password};"
            else:
                raise ValueError("Username and password are required when not using trusted connection")

        db_connection = pyodbc.connect(connection_string)
        logger.info("Successfully connected to MSSQL server")
        return True
    except Exception as e:
        logger.error(f"Error connecting to MSSQL server: {e}", exc_info=True)
        return False


def close_connection():
    """Close the database connection"""
    global db_connection
    if db_connection:
        db_connection.close()
        db_connection = None
        logger.info("Database connection closed")


# Initialize database connection from environment variables
def init_db_from_env():
    """Initialize database connection from environment variables"""
    server = os.getenv("DB_SERVER")
    database = os.getenv("DB_NAME")
    username = os.getenv("DB_USER")
    password = os.getenv("DB_PASSWORD")
    use_windows_auth = os.getenv("DB_USE_WINDOWS_AUTH", "FALSE").upper() == "TRUE"

    if not server or not database:
        logger.warning("Database connection information not found in environment variables")
        return False

    if use_windows_auth:
        return connect_to_mssql(server, database, trusted_connection=True)
    else:
        if not username or not password:
            logger.warning(
                "Database credentials not found in environment variables and Windows Authentication is disabled"
            )
            return False
        return connect_to_mssql(server, database, username, password)


logger.info("Initializing MCP server")
mcp = FastMCP("NAA_MCP")

logger.info("MCP server initialized")

# Try to initialize database connection from environment variables
db_initialized = init_db_from_env()
if db_initialized:
    logger.info("Database connection initialized from environment variables")
else:
    logger.info("Database connection not initialized, use connect_database tool to connect")


def run_query(query: str) -> str:
    """Run a query"""
    global db_connection

    if not db_connection:
        return "Not connected to a database. Please connect first."

    try:
        cursor = db_connection.cursor()
        cursor.execute(query)

        # Check if the query is a SELECT statement
        if query.strip().upper().startswith("SELECT"):
            rows = cursor.fetchall()
            if not rows:
                return "Query executed successfully. No results returned."

            # Get column names
            columns = [column[0] for column in cursor.description]

            # Format results as a table
            result = "Results:\n\n"

            # Add header
            result += " | ".join(columns) + "\n"
            result += "-" * (sum(len(col) for col in columns) + 3 * (len(columns) - 1)) + "\n"

            # Add data rows
            for row in rows:
                result += " | ".join(str(value) for value in row) + "\n"

            return result
        else:
            # For non-SELECT queries (INSERT, UPDATE, DELETE, etc.)
            row_count = cursor.rowcount
            db_connection.commit()
            return f"Query executed successfully. Rows affected: {row_count}"

    except Exception as e:
        logger.error(f"Error running query: {e}", exc_info=True)
        return f"Error running query: {str(e)}"


@mcp.tool("Connect-Database")
def connect_database(
    server: str,
    database: str,
    username: str | None = None,
    password: str | None = None,
    trusted_connection: bool = False,
) -> str:
    """Connect to a Netwrix Access Analyzer database server"""
    if connect_to_mssql(server, database, username, password, trusted_connection):
        return "Successfully connected to the database"
    else:
        return "Failed to connect to the database. Check credentials and server availability."


@mcp.tool("Show-TableSchema")
def explain_table(table_name: str) -> str:
    """Explain the schema of a table"""
    global db_connection

    if not db_connection:
        return "Not connected to a database. Please connect first."

    try:
        cursor = db_connection.cursor()

        # Check if table exists
        table_check = """
        SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES 
        WHERE TABLE_NAME = ? AND TABLE_TYPE = 'BASE TABLE'
        """
        cursor.execute(table_check, table_name)
        if cursor.fetchone()[0] == 0:
            return f"Table '{table_name}' does not exist."

        # Get columns
        column_query = """
        SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_NAME = ?
        ORDER BY ORDINAL_POSITION
        """
        cursor.execute(column_query, table_name)
        column_rows = cursor.fetchall()

        schema = f"Table: {table_name}\n\nColumns:\n"
        for column in column_rows:
            col_name = column[0]
            data_type = column[1]
            max_length = column[2]
            is_nullable = column[3]

            type_info = data_type
            if max_length:
                type_info += f"({max_length})"

            nullable = "NULL" if is_nullable == "YES" else "NOT NULL"
            schema += f"  - {col_name}: {type_info} {nullable}\n"

        # Get primary keys
        pk_query = """
        SELECT COLUMN_NAME
        FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
        WHERE OBJECTPROPERTY(OBJECT_ID(CONSTRAINT_NAME), 'IsPrimaryKey') = 1
        AND TABLE_NAME = ?
        """
        cursor.execute(pk_query, table_name)
        pk_rows = cursor.fetchall()

        if pk_rows:
            schema += "\nPrimary Key(s):\n"
            for pk in pk_rows:
                schema += f"  - {pk[0]}\n"

        # Get foreign keys
        fk_query = """
        SELECT
            COL.COLUMN_NAME,
            PT.TABLE_NAME AS REFERENCED_TABLE,
            PT.COLUMN_NAME AS REFERENCED_COLUMN
        FROM 
            INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS RC
        JOIN 
            INFORMATION_SCHEMA.KEY_COLUMN_USAGE COL ON RC.CONSTRAINT_NAME = COL.CONSTRAINT_NAME
        JOIN 
            INFORMATION_SCHEMA.KEY_COLUMN_USAGE PT ON RC.UNIQUE_CONSTRAINT_NAME = PT.CONSTRAINT_NAME
        WHERE 
            COL.TABLE_NAME = ?
        """
        cursor.execute(fk_query, table_name)
        fk_rows = cursor.fetchall()

        if fk_rows:
            schema += "\nForeign Key(s):\n"
            for fk in fk_rows:
                schema += f"  - {fk[0]} references {fk[1]}({fk[2]})\n"

        return schema

    except Exception as e:
        logger.error(f"Error explaining table: {e}", exc_info=True)
        return f"Error explaining table: {str(e)}"


@mcp.tool("Get-TableSchema")
def get_table_schema(table_name: str) -> str:
    """Get the schema of a table"""
    return explain_table(table_name)


@mcp.tool("Show-ConnectionStatus")
def show_connection_status() -> str:
    """Show the connection status."""
    global db_connection
    if db_connection:
        return "Connected to database."
    else:
        return "Not connected to a database. Please connect first."


@mcp.tool("Discover-SensitiveData")
def get_sensitivedata() -> str:
    """Discover where sensitive data exists.
    Returns a list of shares with sensitive data."""
    global db_connection

    if not db_connection:
        return "Not connected to a database. Please connect first."

    try:
        query = """
        select	stv.HostName, stv.ShareName, mv.CriteriaName, sum(mv.MatchCount) as TotalMatches
        from	SA_FSDLP_MatchesView mv with (nolock)
        left join SA_FSAA_SharesTraversalView stv with (nolock)
        on mv.HostID = stv.hostid
        and mv.ParentResourceID = stv.ResourceID
        group by stv.hostname, stv.sharename, mv.criteriaName
        order by TotalMatches desc
        """
        return run_query(query)
    except Exception as e:
        logger.error(f"Error getting sensitive data: {e}", exc_info=True)
        return f"Error getting sensitive data: {str(e)}"


@mcp.tool("Get-OpenShares")
def get_open_shares() -> str:
    """Discover open shares. Returns a list of shares with open access.
    Open access is defined as where the share is accessible to all users,
    including principals such as Domain Users or the Everyone group."""
    global db_connection

    if not db_connection:
        return "Not connected to a database. Please connect first."

    try:
        query = """
        select  
            networkpath as Share,
            count(distinct ResourceID) as Folders
        from (select distinct networkpath, hostid, gateid from SA_FSAA_SharesTraversalView with (nolock)
        where NestedLevel = 0) stv
        left join SA_FSAA_ExceptionsView ev with (nolock)
        on stv.HostID = ev.HostID
        and stv.GateID = ev.GateID
        where ParentType = 1
        group by NetworkPath
        """
        return run_query(query)
    except Exception as e:
        logger.error(f"Error getting open access data: {e}", exc_info=True)
        return f"Error getting open access data: {str(e)}"


@mcp.tool("Get-TrusteeAccess")
def get_trustee_access(trustee: str, levelsdown: int = 0) -> str:
    """Find where a user has access. Filter by trustee name (Domain\\Name) and levels down from the share."""
    global db_connection

    if not db_connection:
        return "Not connected to a database. Please connect first."

    try:
        query = f"""
        select 'FileSystem' as DataSource, stv.NetworkPath, (CASE WHEN (p.AllowRights & 32) <> 0 THEN 'L' ELSE '' END) + (CASE WHEN (p.AllowRights & 1) <> 0 THEN 'R' ELSE '' END) + (CASE WHEN (p.AllowRights & 2) 
                      <> 0 THEN 'W' ELSE '' END) + (CASE WHEN (p.AllowRights & 4) <> 0 THEN 'D' ELSE '' END) + (CASE WHEN (p.AllowRights & 8) <> 0 THEN 'M' ELSE '' END) 
                      + (CASE WHEN (p.AllowRights & 16) <> 0 THEN 'A' ELSE '' END) AS AllowRightsDescription, 
					  (CASE WHEN (p.DenyRights & 32) <> 0 THEN 'L' ELSE '' END)  + (CASE WHEN (p.DenyRights & 1) <> 0 THEN 'R' ELSE '' END) 
                      + (CASE WHEN (p.DenyRights & 2) <> 0 THEN 'W' ELSE '' END) + (CASE WHEN (p.DenyRights & 4) <> 0 THEN 'D' ELSE '' END) + (CASE WHEN (p.DenyRights & 8)
                       <> 0 THEN 'M' ELSE '' END) + (CASE WHEN (p.DenyRights & 16) <> 0 THEN 'A' ELSE '' END) AS DenyRightsDescription from(
		select objectsid from SA_ADInventory_PrincipalsView
		where NTAccount = '{trustee}') a
		left join SA_FSAA_SharesTraversalView stv on 1=1
		and NestedLevel = {levelsdown}
		and ResourceType = 3
		outer apply SA_AIC_FSAA_GetTrusteeShareAccessEx(stv.hostid, stv.gateid, a.objectsid,0,1) p
		where p.HOST is not null
        """  # noqa

        return run_query(query)
    except Exception as e:
        logger.error(f"Error getting trustee access: {e}", exc_info=True)
        return f"Error getting trustee access: {str(e)}"


@mcp.tool("Get-TrusteePermissionSource")
def get_permission_source(trustee: str = "", resourcepath: str = "") -> str:
    """For a given trustee and network path, find the source of their access"""
    global db_connection

    if not db_connection:
        return "Not connected to a database. Please connect first."

    try:
        query = f"""
        select
		SourceTrusteePath, ps.ResourcePath, ps.PermissionSourceType, ps.AllowRightsDescription, AllowMaskDescription, DenyRightsDescription,DenyMaskDescription 
		from SA_FSAA_LookupUncPath('{resourcepath}') a
		inner join (select ObjectSID from SA_ADInventory_PrincipalsView pv
		where pv.NTAccount = '{trustee}'
        union 
        select SID from SA_FSAA_LocalTrustees T
        where ntdomain + '\' + ntname = '{trustee}') pv on 1=1
		outer apply SA_FSAA_GetTrusteePermissionSource(hostid,resourceid, gateid,pv.ObjectSid)ps
        """  # noqa

        return run_query(query)
    except Exception as e:
        logger.error(f"Error getting trustee access: {e}", exc_info=True)
        return f"Error getting trustee access: {str(e)}"


@mcp.tool("Get-ResourceAccess")
def get_resource_access(resource: str) -> str:
    """Get access information for a resource given a path (URL or UNC)"""
    global db_connection

    if not db_connection:
        return "Not connected to a database. Please connect first."

    try:
        query = f"""
        select eav.NetworkPath as Share, 
        stv.NetworkPath as Folder, TrusteeNTStyleName, AllowRightsDescription,
        DenyRightsDescription
        from SA_FSAA_LookupUncPath('{resource}') a
        left join SA_FSAA_EffectiveAccessView eav with (nolock)
        on eav.HostID = a.HostID
        and eav.GateID = a.GateID
        and eav.ResourceID = a.ResourceID
        left join SA_FSAA_SharesTraversalView stv with (nolock)
        on stv.HostID = a.HostID
        and stv.ResourceID = a.ResourceID
        and stv.GateID = a.GateID
        """
        return run_query(query)
    except Exception as e:
        logger.error(f"Error getting resource access: {e}", exc_info=True)
        return f"Error getting resource access: {str(e)}"


@mcp.tool("Get-UnusedAccess")
def get_unused_access(resource: str) -> str:
    """For the specified share, identifies users that have not used their access in the last 365 days"""
    global db_connection

    if not db_connection:
        return "Not connected to a database. Please connect first."

    try:
        query = f"""
        select stv.HostName, stv.ShareName, eav.TrusteeNTStyleName, eav.AllowRightsDescription, eav.DenyRightsDescription, ActivityDate as LastActive
        from SA_FSAA_SharesTraversalView stv with (nolock)  
        inner join SA_FSAA_LookupUncPath('{resource}') lup
        on lup.GateID = stv.GateID
        and lup.HostID = stv.HostID
        left join SA_FSAA_EffectiveAccessView eav with (nolock)
        on stv.HostID = eav.HostID
        and stv.GateID = eav.GateID
        and stv.ResourceID = eav.ResourceID
        left join (select stv.hostid, stv.GateID, UserNTStyleName, MAX(ActivityDate) as ActivityDate
        from SA_FSAA_SharesTraversalView stv with (nolock)
        left join SA_FSAC_DailyActivityView DAV with (nolock)
        on stv.ResourceID = dav.FolderID
        and stv.HostID = dav.HostID
        group by stv.hostid, stv.gateid, UserNTStyleName
        having MAX(ActivityDate) < GETUTCDATE() - 365) a
        on a.GateID = eav.GateID
        and a.HostID = eav.HostID
        and a.UserNTStyleName = eav.TrusteeNTStyleName
        where stv.NestedLevel = 0
        and exists (select top 1 * from SA_ADInventory_UsersView uv WHERE
        uv.NTAccount = TrusteeNTStyleName)
        """  # noqa
        return run_query(query)
    except Exception as e:
        logger.error(f"Error getting resource access: {e}", exc_info=True)
        return f"Error getting resource access: {str(e)}"


@mcp.tool("Get-RunningJobs")
def get_running_jobs() -> str:
    """Gets currently running Access Analyzer jobs."""
    global db_connection

    if not db_connection:
        return "Not connected to a database. Please connect first."

    try:
        query = """
        select	* 
        from	SA_JobStatsTbl with (nolock)
        where EndTime is null
        order by JobRunTimeKey desc
        """
        return run_query(query)
    except Exception as e:
        logger.error(f"Error getting currently running jobs: {e}", exc_info=True)
        return f"Error getting currently running jobs: {str(e)}"


@mcp.tool("Get-ShadowAccess")
def get_shadow_access() -> str:
    """Shadow access is the presence of backdoor or ungoverned access routes to your critical assets
    Returns a list of users with shadow access."""
    global db_connection

    if not db_connection:
        return "Not connected to a database. Please connect first."

    try:
        query = """
        select	* 
        from	SA_ShadowAccess_Details
        """
        return run_query(query)
    except Exception as e:
        logger.error(f"Error getting shadow access: {e}", exc_info=True)
        return f"Error getting shadow access: {str(e)}"


@mcp.tool("Sample-Table")
def get_table_sample(tablename: str) -> str:
    """Gets 10 rows from the specified table."""
    global db_connection

    if not db_connection:
        return "Not connected to a database. Please connect first."

    try:
        query = f"""
        select	top 10 * 
        from	{tablename}
        """
        return run_query(query)
    except Exception as e:
        logger.error(f"Error getting data: {e}", exc_info=True)
        return f"Error getting data: {str(e)}"


if __name__ == "__main__":
    logger.info("Starting MCP server with stdio transport")
    try:
        mcp.run(transport="stdio")
        logger.info("MCP server exited successfully")
    except Exception as e:
        logger.error(f"Error running MCP server: {e}", exc_info=True)
        raise
    finally:
        # Make sure to close the database connection when the server exits
        close_connection()
