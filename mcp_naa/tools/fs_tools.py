# mcp_naa/tools/report_tools.py
from typing import Optional
from .. import app
from .. import database
from .db_tools import run_query # Reuse the run_query tool for execution and formatting
from ..logging_config import get_logger
import pyodbc

logger = get_logger(__name__)

# Helper to check connection and run a predefined query using the run_query tool
def _run_predefined_query(query: str, tool_name: str) -> str:
    """Checks connection and executes a query using the run_query tool."""
    if not database.get_connection():
        return "Not connected to a database. Please connect first."
    try:
        logger.debug(f"Executing predefined query for {tool_name}")
        # We call the run_query *tool function* which handles execution,
        # formatting, and error reporting specific to tools.
        return run_query(query)
    except Exception as e:
        # Catch unexpected errors during the call itself
        logger.error(f"Unexpected error in {tool_name} wrapper: {e}", exc_info=True)
        return f"An unexpected error occurred while preparing the query for {tool_name}."

@app.mcp.tool("Discover-SensitiveData")
def get_sensitive_data() -> str:
    """
    Discovers where sensitive data exists based on DLP matches.
    Returns a list of shares, criteria, and match counts.
    """
    tool_name = "Discover-SensitiveData"
    logger.info(f"Tool '{tool_name}' called.")
    query = """
    SELECT
        stv.HostName,
        stv.ShareName,
        mv.CriteriaName,
        SUM(mv.MatchCount) AS TotalMatches
    FROM SA_FSDLP_MatchesView AS mv
    LEFT JOIN SA_FSAA_SharesTraversalView AS stv
        ON mv.HostID = stv.HostID AND mv.ParentResourceID = stv.ResourceID
    -- WHERE clause might be needed if stv can have nulls for relevant matches
    WHERE stv.HostName IS NOT NULL AND stv.ShareName IS NOT NULL
    GROUP BY
        stv.HostName,
        stv.ShareName,
        mv.CriteriaName
    ORDER BY
        TotalMatches DESC;
    """
    return _run_predefined_query(query, tool_name)


@app.mcp.tool("Get-OpenShares")
def get_open_shares() -> str:
    """
    Discovers open shares (accessible to broad groups like 'Everyone' or 'Domain Users').
    Returns a list of shares and the count of folders directly within them marked as exceptions.
    Note: The original query's definition of 'open' seems tied to 'ExceptionsView', verify this logic.
    """
    tool_name = "Get-OpenShares"
    logger.info(f"Tool '{tool_name}' called.")
    # This query identifies shares associated with exceptions where ParentType=1.
    # Verify if SA_FSAA_ExceptionsView accurately represents 'open access'.
    # It might be better to query effective access for 'Everyone' or 'Domain Users'.
    query = """
    SELECT
        stv.NetworkPath AS SharePath,
        COUNT(DISTINCT ev.ResourceID) AS ExceptionFolderCountInShare -- Count folders with exceptions directly in the share
    FROM (
        -- Select distinct shares at the root level
        SELECT DISTINCT NetworkPath, HostID, GateID
        FROM SA_FSAA_SharesTraversalView
        WHERE NestedLevel = 0 AND ResourceType = 2 -- Assuming ResourceType 2 is Share
    ) AS stv
    LEFT JOIN SA_FSAA_ExceptionsView AS ev
        ON stv.HostID = ev.HostID AND stv.GateID = ev.GateID
    WHERE ev.ParentType = 1 -- Filter based on exceptions view, definition might need review
       -- AND ev.ResourceType = 3 -- Optional: Filter for folder exceptions only?
    GROUP BY
        stv.NetworkPath
    ORDER BY
        stv.NetworkPath;
    """

    return _run_predefined_query(query, tool_name)


@app.mcp.tool("Get-TrusteeAccess")
def get_trustee_access(trustee: str, levels_down: int = 0) -> str:
    """
    Finds filesystem resources where a specific trustee (Domain\\Name) has access.
    Filters by levels down from the share root (0 = share level only).
    """
    tool_name = "Get-TrusteeAccess"
    logger.info(f"Tool '{tool_name}' called for trustee: {trustee}, levels: {levels_down}")

    # Parameterize inputs to prevent SQL injection
    if not trustee or '\\' not in trustee:
        return "Invalid trustee format. Use Domain\\Name."
    if levels_down < 0:
        return "Levels down must be a non-negative integer."

    # Use parameterized query
    query = """
    -- Find the SID for the given trustee (AD or Local)
    WITH TrusteeSID AS (
        SELECT ObjectSID AS sid FROM SA_ADInventory_PrincipalsView WHERE NTAccount = ?
        UNION
        SELECT SID FROM SA_FSAA_LocalTrustees WHERE NTDomain + '\\' + NTName = ?
    )
    -- Find access using the SID
    SELECT
        'FileSystem' AS DataSource,
        stv.NetworkPath,
        -- Simplified Allow Rights (adjust bitmask values if needed)
        CASE WHEN (p.AllowRights & 1) <> 0 THEN 'R' ELSE '' END + -- Read
        CASE WHEN (p.AllowRights & 2) <> 0 THEN 'W' ELSE '' END + -- Write
        CASE WHEN (p.AllowRights & 4) <> 0 THEN 'D' ELSE '' END + -- Delete
        CASE WHEN (p.AllowRights & 32) <> 0 THEN 'L' ELSE '' END + -- List
        CASE WHEN (p.AllowRights & 8) <> 0 THEN 'M' ELSE '' END + -- Modify/ChangePerms?
        CASE WHEN (p.AllowRights & 16) <> 0 THEN 'A' ELSE '' END AS AllowRightsDescription, -- Full/Admin?
        -- Simplified Deny Rights
        CASE WHEN (p.DenyRights & 1) <> 0 THEN 'R' ELSE '' END +
        CASE WHEN (p.DenyRights & 2) <> 0 THEN 'W' ELSE '' END +
        CASE WHEN (p.DenyRights & 4) <> 0 THEN 'D' ELSE '' END +
        CASE WHEN (p.DenyRights & 32) <> 0 THEN 'L' ELSE '' END +
        CASE WHEN (p.DenyRights & 8) <> 0 THEN 'M' ELSE '' END +
        CASE WHEN (p.DenyRights & 16) <> 0 THEN 'A' ELSE '' END AS DenyRightsDescription
    FROM TrusteeSID AS ts
    CROSS JOIN SA_FSAA_SharesTraversalView AS stv
    -- Apply the function to get access for the SID on the resource
    OUTER APPLY SA_AIC_FSAA_GetTrusteeShareAccessEx(stv.HostID, stv.GateID, ts.sid, 0, 1) AS p
    WHERE
        stv.NestedLevel = ?       -- Filter by levels down
        AND stv.ResourceType = 3  -- Assuming ResourceType 3 is Folder/File
        AND p.HOST IS NOT NULL;   -- Ensure the function returned some access info
    """

    conn = database.get_connection()
    if not conn:
        return "Not connected to a database. Please connect first."

    try:
        logger.debug(f"Executing parameterized query for {tool_name}")
        # Use the core execute_query directly for parameterized queries
        rows, columns, _ = database.execute_query(query, (trustee, trustee, levels_down))
        return database.format_results(rows, columns)
    except RuntimeError as e:
        logger.warning(f"{tool_name} failed: {e}")
        return str(e)
    except pyodbc.Error as e:
        logger.error(f"Error getting trustee access for '{trustee}': {e}", exc_info=True)
        sqlstate = e.args[0] if e.args else 'N/A'
        return f"Error getting trustee access (SQLSTATE: {sqlstate}): {str(e)}"
    except Exception as e:
        logger.error(f"Unexpected error getting trustee access for '{trustee}': {e}", exc_info=True)
        return f"Unexpected error getting trustee access: {str(e)}"


@app.mcp.tool("Get-TrusteePermissionSource")
def get_permission_source(trustee: str, resource_path: str) -> str:
    """For a given trustee (Domain\\Name) and network resource path (UNC), finds the source of their access."""
    tool_name = "Get-TrusteePermissionSource"
    logger.info(f"Tool '{tool_name}' called for trustee: {trustee}, resource: {resource_path}")

    # Parameterize inputs
    if not trustee or '\\' not in trustee:
        return "Invalid trustee format. Use Domain\\Name."
    if not resource_path or not (resource_path.startswith('\\\\') or resource_path.startswith('//')):
         return "Invalid resource path format. Use UNC path (e.g., \\\\server\\share\\folder)."

    query = """
    -- Find the resource details
    WITH ResourceInfo AS (
        SELECT HostID, ResourceID, GateID
        FROM SA_FSAA_LookupUncPath(?) -- Parameterize resource path
    ),
    -- Find the SID for the given trustee
    TrusteeSID AS (
        SELECT ObjectSID AS sid FROM SA_ADInventory_PrincipalsView WHERE NTAccount = ? -- Parameterize trustee
        UNION
        SELECT SID FROM SA_FSAA_LocalTrustees WHERE NTDomain + '\\' + NTName = ? -- Parameterize trustee
    )
    -- Get permission source using resource details and trustee SID
    SELECT
        ps.SourceTrusteePath,
        ps.ResourcePath,
        ps.PermissionSourceType,
        ps.AllowRightsDescription,
        ps.AllowMaskDescription,
        ps.DenyRightsDescription,
        ps.DenyMaskDescription
    FROM ResourceInfo AS ri
    INNER JOIN TrusteeSID AS ts ON 1=1 -- Join trustee SID
    -- Apply function to get permission source
    OUTER APPLY SA_FSAA_GetTrusteePermissionSource(ri.HostID, ri.ResourceID, ri.GateID, ts.sid) AS ps
    WHERE ps.ResourcePath IS NOT NULL; -- Ensure the function returned results
    """

    conn = database.get_connection()
    if not conn:
        return "Not connected to a database. Please connect first."

    try:
        logger.debug(f"Executing parameterized query for {tool_name}")
        rows, columns, _ = database.execute_query(query, (resource_path, trustee, trustee))
        if not rows:
            # Check if resource path or trustee is invalid
            check_res_q = "SELECT COUNT(*) FROM SA_FSAA_LookupUncPath(?)"
            res_exists, _, _ = database.execute_query(check_res_q, (resource_path,))
            check_trustee_q = """
                SELECT COUNT(*) FROM (
                    SELECT 1 FROM SA_ADInventory_PrincipalsView WHERE NTAccount = ?
                    UNION ALL
                    SELECT 1 FROM SA_FSAA_LocalTrustees WHERE NTDomain + '\\' + NTName = ?
                ) AS t
            """
            trustee_exists, _, _ = database.execute_query(check_trustee_q, (trustee, trustee))

            if not res_exists or res_exists[0][0] == 0:
                return f"Resource path '{resource_path}' not found or not scanned by Access Auditor."
            if not trustee_exists or trustee_exists[0][0] == 0:
                 return f"Trustee '{trustee}' not found."
            return f"No specific permission source found for trustee '{trustee}' on resource '{resource_path}', or trustee has no permissions there."

        return database.format_results(rows, columns)
    except RuntimeError as e:
         logger.warning(f"{tool_name} failed: {e}")
         return str(e)
    except pyodbc.Error as e:
        logger.error(f"Error getting permission source for '{trustee}' on '{resource_path}': {e}", exc_info=True)
        sqlstate = e.args[0] if e.args else 'N/A'
        return f"Error getting permission source (SQLSTATE: {sqlstate}): {str(e)}"
    except Exception as e:
        logger.error(f"Unexpected error getting permission source for '{trustee}' on '{resource_path}': {e}", exc_info=True)
        return f"Unexpected error getting permission source: {str(e)}"


@app.mcp.tool("Get-ResourceAccess")
def get_resource_access(resource_path: str) -> str:
    """Gets the effective access list for a specific resource path (UNC)."""
    tool_name = "Get-ResourceAccess"
    logger.info(f"Tool '{tool_name}' called for resource: {resource_path}")

    # Parameterize input
    if not resource_path or not (resource_path.startswith('\\\\') or resource_path.startswith('//')):
         return "Invalid resource path format. Use UNC path (e.g., \\\\server\\share\\folder)."

    query = """
    -- Find resource details
    WITH ResourceInfo AS (
        SELECT HostID, ResourceID, GateID
        FROM SA_FSAA_LookupUncPath(?) -- Parameterize resource path
    )
    -- Get effective access using resource details
    SELECT
        -- eav.NetworkPath AS Share, -- This might be redundant if resource_path is specific
        stv.NetworkPath AS FolderFullPath, -- Get the actual path from traversal view
        eav.TrusteeNTStyleName,
        eav.AllowRightsDescription,
        eav.DenyRightsDescription
    FROM ResourceInfo AS ri
    LEFT JOIN SA_FSAA_EffectiveAccessView AS eav
        ON eav.HostID = ri.HostID
        AND eav.GateID = ri.GateID
        AND eav.ResourceID = ri.ResourceID
    LEFT JOIN SA_FSAA_SharesTraversalView AS stv -- Join to get the canonical path
        ON stv.HostID = ri.HostID
        AND stv.ResourceID = ri.ResourceID
        AND stv.GateID = ri.GateID
    WHERE eav.TrusteeNTStyleName IS NOT NULL -- Filter out potential nulls if any
    ORDER BY eav.TrusteeNTStyleName;
    """
    conn = database.get_connection()
    if not conn:
        return "Not connected to a database. Please connect first."

    try:
        logger.debug(f"Executing parameterized query for {tool_name}")
        rows, columns, _ = database.execute_query(query, (resource_path,))
        if not rows:
             # Check if resource exists but has no explicit permissions listed
             check_res_q = "SELECT COUNT(*) FROM SA_FSAA_LookupUncPath(?)"
             res_exists, _, _ = database.execute_query(check_res_q, (resource_path,))
             if not res_exists or res_exists[0][0] == 0:
                  return f"Resource path '{resource_path}' not found or not scanned by Access Auditor."
             else:
                 # Could have implicit permissions (e.g., via inheritance not shown here) or be empty
                 return f"Resource path '{resource_path}' found, but no specific effective access entries listed in SA_FSAA_EffectiveAccessView."

        return database.format_results(rows, columns)
    except RuntimeError as e:
        logger.warning(f"{tool_name} failed: {e}")
        return str(e)
    except pyodbc.Error as e:
        logger.error(f"Error getting resource access for '{resource_path}': {e}", exc_info=True)
        sqlstate = e.args[0] if e.args else 'N/A'
        return f"Error getting resource access (SQLSTATE: {sqlstate}): {str(e)}"
    except Exception as e:
        logger.error(f"Unexpected error getting resource access for '{resource_path}': {e}", exc_info=True)
        return f"Unexpected error getting resource access: {str(e)}"


@app.mcp.tool("Get-UnusedAccess")
def get_unused_access(resource_path: str, days_inactive: int = 90) -> str:
    """
    For a specified share path, identifies users whose last activity was more than N days ago (default 90).
    """
    tool_name = "Get-UnusedAccess"
    logger.info(f"Tool '{tool_name}' called for resource: {resource_path}, days: {days_inactive}")

    # Parameterize inputs
    if not resource_path or not (resource_path.startswith('\\\\') or resource_path.startswith('//')):
        return "Invalid resource path format. Use UNC path (e.g., \\\\server\\share)."
    if days_inactive <= 0:
        return "Days inactive must be a positive integer."

    query = """
    -- Find the target share details
    WITH TargetShare AS (
        SELECT HostID, GateID, ResourceID
        FROM SA_FSAA_LookupUncPath(?) -- Parameterize resource path
        WHERE NestedLevel = 0 -- Ensure it's the share root
    ),
    -- Find last activity date per user on the target share/subfolders
    LastActivity AS (
        SELECT
            dav.HostID,
            dav.GateID,
            dav.UserNTStyleName,
            MAX(dav.ActivityDate) AS LastActivityDate
        FROM SA_FSAC_DailyActivityView AS dav
        INNER JOIN TargetShare AS ts
            ON dav.HostID = ts.HostID AND dav.GateID = ts.GateID
        -- We need to ensure the activity is *within* the target share tree.
        -- This requires joining activity folder path back to traversal view.
        INNER JOIN SA_FSAA_SharesTraversalView stv_activity
             ON dav.HostID = stv_activity.HostID
             AND dav.GateID = stv_activity.GateID
             AND dav.FolderID = stv_activity.ResourceID
        INNER JOIN SA_FSAA_SharesTraversalView stv_share
             ON dav.HostID = stv_share.HostID
             AND dav.GateID = stv_share.GateID
             AND stv_share.ResourceID = ts.ResourceID -- Match the share root
        WHERE stv_activity.NetworkPath LIKE stv_share.NetworkPath + '%' -- Activity path starts with share path
        GROUP BY
            dav.HostID, dav.GateID, dav.UserNTStyleName
    )
    -- Combine effective access with last activity
    SELECT
        stv.HostName,
        stv.ShareName,
        eav.TrusteeNTStyleName,
        eav.AllowRightsDescription,
        eav.DenyRightsDescription,
        la.LastActivityDate
    FROM TargetShare AS ts
    INNER JOIN SA_FSAA_SharesTraversalView AS stv -- Get share details
        ON ts.HostID = stv.HostID AND ts.GateID = stv.GateID AND ts.ResourceID = stv.ResourceID
    INNER JOIN SA_FSAA_EffectiveAccessView AS eav -- Get who has access
        ON ts.HostID = eav.HostID AND ts.GateID = eav.GateID AND ts.ResourceID = eav.ResourceID
    LEFT JOIN LastActivity AS la -- Join last activity info
        ON eav.HostID = la.HostID
        AND eav.GateID = la.GateID
        AND eav.TrusteeNTStyleName = la.UserNTStyleName
    -- Filter for AD Users only (optional, based on original query)
    WHERE EXISTS (
        SELECT 1 FROM SA_ADInventory_UsersView AS uv
        WHERE uv.NTAccount = eav.TrusteeNTStyleName
    )
    -- Filter for users whose last activity was longer ago than specified days, or never
    AND (la.LastActivityDate IS NULL OR la.LastActivityDate < DATEADD(day, -?, GETUTCDATE())) -- Parameterize days
    ORDER BY
        stv.HostName, stv.ShareName, eav.TrusteeNTStyleName;

    """
    # Note: The activity data join might be complex/slow depending on data volume.
    # Consider indexing relevant columns in SA_FSAC_DailyActivityView and SA_FSAA_SharesTraversalView.

    conn = database.get_connection()
    if not conn:
        return "Not connected to a database. Please connect first."

    try:
        logger.debug(f"Executing parameterized query for {tool_name}")
        rows, columns, _ = database.execute_query(query, (resource_path, days_inactive))
        if not rows:
            check_res_q = "SELECT COUNT(*) FROM SA_FSAA_LookupUncPath(?)"
            res_exists, _, _ = database.execute_query(check_res_q, (resource_path,))
            if not res_exists or res_exists[0][0] == 0:
                 return f"Resource path '{resource_path}' not found or not scanned."
            else:
                return f"No users with unused access found for '{resource_path}' within the last {days_inactive} days, or activity data is unavailable."

        return database.format_results(rows, columns)
    except RuntimeError as e:
        logger.warning(f"{tool_name} failed: {e}")
        return str(e)
    except pyodbc.Error as e:
        logger.error(f"Error getting unused access for '{resource_path}': {e}", exc_info=True)
        sqlstate = e.args[0] if e.args else 'N/A'
        return f"Error getting unused access (SQLSTATE: {sqlstate}): {str(e)}"
    except Exception as e:
        logger.error(f"Unexpected error getting unused access for '{resource_path}': {e}", exc_info=True)
        return f"Unexpected error getting unused access: {str(e)}"

@app.mcp.tool("Get-RunningJobs")
def get_running_jobs() -> str:
    """Gets currently running Netwrix Access Auditor jobs from SA_JobStatsTbl."""
    tool_name = "Get-RunningJobs"
    logger.info(f"Tool '{tool_name}' called.")
    query = """
    SELECT *
    FROM SA_JobStatsTbl
    WHERE EndTime IS NULL
    ORDER BY JobRunTimeKey DESC;
    """
    return _run_predefined_query(query, tool_name)


@app.mcp.tool("Get-ShadowAccess")
def get_shadow_access() -> str:
    """
    Retrieves details about shadow access (potential ungoverned access routes).
    Returns results from SA_ShadowAccess_Details.
    """
    tool_name = "Get-ShadowAccess"
    logger.info(f"Tool '{tool_name}' called.")
    query = """
    SELECT *
    FROM SA_ShadowAccess_Details;
    """
    # Add ORDER BY if needed, e.g., ORDER BY TrusteeName, ResourcePath
    return _run_predefined_query(query, tool_name)