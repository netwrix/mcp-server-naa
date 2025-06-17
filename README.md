# Netwrix Access Analyzer MCP Server

An MCP server for Netwrix Access Analyzer, designed to integrate with Claude Desktop. Currently supports Active Directory and File System solutions. 

## Features

- SQL Server integration with automatic connection on startup
- Dynamic database schema exploration
- SQL query execution
- Netwrix Access Analyzer File System tools

## Dependencies

This MCP server requires the following dependencies:

- Python 3.12 or higher
- MCP SDK
- pyodbc 4.0.39 or higher (for SQL Server connectivity)
- python-dotenv 1.0.0 or higher (for environment variable management)
- ODBC Driver 17 for SQL Server or later (must be installed on your system)

### Netwrix Access Analyzer (NAA) Dependencies

This MCP Server requires Netwrix Access Analyzer (NAA) File System or Active Directory scans to be completed.

## Available Tools

| Solution         | Tool Name                       | Description |
|------------------|---------------------------------|-------------|
| Active Directory | get_ad_effective_group_members  | Discovers effective group membership in AD with filters. |
| Active Directory | get_ad_exceptions               | Retrieves AD exceptions with optional filters. |
| Active Directory | get_ad_permissions              | Retrieves AD permissions from the permissions view with filters. |
| Active Directory | get_domain_controllers          | Lists domain controllers. |
| Active Directory | get_certificate_vulnerabilities | Lists certificate vulnerabilities. |
| Active Directory | get_adca_rights                 | Lists AD CA rights. |
| Active Directory | get_ad_security_assessment      | Retrieves AD security assessment results. |
| Active Directory | get_ad_users                    | Retrieves AD user details with filters. |
| Active Directory | get_ad_groups                   | Retrieves AD group details with filters. |
| Active Directory | get_ad_computers                | Retrieves AD computer details with filters. |
| Database         | connect_database                | Connects to a specified MSSQL database. |
| Database         | show_connection_status          | Shows the current DB connection status. |
| Database         | run_query                       | Runs an arbitrary SQL query. |
| Database         | show_table_schema               | Shows the schema for a given table. |
| Database         | get_table_schema                | Alias for show_table_schema. |
| Database         | get_table_sample                | Gets a sample of rows from a table. |
| File System      | discover_sensitive_data         | Discovers where sensitive data exists (DLP matches). |
| File System      | get_open_shares                 | Finds open shares accessible to broad groups. |
| File System      | get_trustee_access              | Finds resources where a trustee has access. |
| File System      | get_permission_source           | Finds the source of access for a trustee/resource. |
| File System      | get_resource_access             | Gets effective access for a resource path. |
| File System      | get_unused_access               | Finds users with unused access to a share. |
| File System      | Get-RunningJobs                 | Lists running Netwrix Access Auditor jobs. |
| File System      | Get-ShadowAccess                | Retrieves details about shadow access. |

## Installation Instructions (Claude Desktop)

1. **Install Claude Desktop**
   - Download and install Claude Desktop from the official website: https://claude.ai/desktop
   - Follow the installation prompts for your operating system (macOS, Windows, or Linux).

2. **Clone this repository**
   ```sh
   git clone https://github.com/netwrix/mcp-server-naa.git
   cd <repo-directory>
   ```

3. **Install Python dependencies**
   ```sh
   uv sync
   ```

4. **Connect Claude Desktop to this Server**
   - Add the following configuration to your Claude Desktop MCP Configuration:
    ```
    "NAA_AD": {
      "command": "/Users/berg/.local/bin/uv",
      "args": [
        "run",
        "--with",
        "pyodbc, fastmcp",
        "fastmcp",
        "run",
        "/path/to/run.py"
      ],
      "env": {
        "DB_SERVER": "HOST OR IP",
        "DB_NAME": "DATABASENAME",
        "DB_USER": "USERNAME",
        "DB_PASSWORD": "PASSWORD",
        "DB_USE_WINDOWS_AUTH": "FALSE|TRUE"
      }
    }
    ```
---



---
# Troubleshooting
## Connection Issues

If you encounter connection issues:

1. Verify your SQL Server is running and accessible from your network   
2. Check your credentials in the .env file
3. Ensure the ODBC driver is correctly installed
4. Check the logs for detailed error messages

## Claude Desktop Integration

If Claude Desktop can't find the uv command:

1. Use the full path to uv in your configuration (use which uv or where uv to find it)
2. Make sure you've restarted Claude Desktop after configuration changes
3. Check the Claude logs for any error messages related to the MCP server