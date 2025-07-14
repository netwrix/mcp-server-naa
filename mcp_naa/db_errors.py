# mcp_naa/db_errors.py
"""
Defines custom database-related exceptions formatted for JSON-RPC responses.
"""

import pyodbc # pyodbc is used for isinstance checks within error classes
import traceback
from typing import Optional, Any, Dict

# --- JSON-RPC Error Codes (Server Error Range) ---
# Defined by JSON-RPC 2.0 spec: -32000 to -32099: Server error.
DB_ERROR_BASE = -32000
DB_CONNECTION_FAILED = DB_ERROR_BASE - 1          # -32001
DB_QUERY_FAILED = DB_ERROR_BASE - 2               # -32002
DB_CONFIGURATION_INVALID = DB_ERROR_BASE - 3      # -32003
DB_NOT_CONNECTED = DB_ERROR_BASE - 4              # -32004
DB_TRANSACTION_ERROR = DB_ERROR_BASE - 5          # -32005
DB_UNEXPECTED_ERROR = DB_ERROR_BASE               # -32000 (generic)

# --- Custom JSON-RPC Compatible Exceptions ---

class JsonRpcDBError(Exception):
    """
    Base class for database related errors intended for JSON-RPC responses.
    Includes separate handling for client-facing message/data and internal log details.
    """
    def __init__(self, message: str, code: int, data: Optional[Dict[str, Any]] = None, log_details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message  # Client-facing message (should be relatively generic)
        self.code = code
        # Data field for JSON-RPC error (should contain non-sensitive context)
        self.data = data if data is not None else {}
        # Details for internal logging (can contain sensitive info like query, params, original exception)
        self.log_details = log_details if log_details is not None else {}

    def to_json_rpc_error(self) -> Dict[str, Any]:
        """Returns a dictionary representation of the error for JSON-RPC (client-facing)."""
        error_obj: Dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data: # Only add non-sensitive data if it exists
            error_obj["data"] = self.data
        return error_obj

    def get_log_message(self) -> str:
        """Formats a detailed message suitable for internal logging."""
        base_msg = f"{self.__class__.__name__} occurred. Client message: '{self.message}'. Code: {self.code}."
        if self.log_details:
            # Safely format details, handling potential representation errors
            details_parts = []
            for k, v in self.log_details.items():
                try:
                    details_parts.append(f"{k}: {repr(v)}") # Use repr for potentially complex objects
                except Exception:
                    details_parts.append(f"{k}: [Error representing value]")
            details_str = ", ".join(details_parts)
            base_msg += f" Log Details: {{{details_str}}}"
        return base_msg

    def __str__(self):
        # __str__ can be used in various contexts, keep it informative but maybe not overly verbose
        return f"{self.__class__.__name__}(code={self.code}, message='{self.message}', data={self.data})"


class DBConnectionError(JsonRpcDBError):
    """Error during database connection attempt."""
    def __init__(self, client_message: str, server: Optional[str] = None, db_name: Optional[str] = None, original_exception: Optional[Exception] = None):
        # Client-facing data (avoid exposing too much detail)
        data: Dict[str, Any] = {"type": "DatabaseConnectionError"}
        if server: data["server_hint"] = f"Target server: {server}" # Example hint

        # Internal log details (include sensitive specifics here)
        log_details: Dict[str, Any] = {}
        if server: log_details["server"] = server
        if db_name: log_details["database"] = db_name
        if original_exception:
            log_details["original_exception_type"] = type(original_exception).__name__
            log_details["original_exception_message"] = str(original_exception)
            # Capture SQLSTATE if available (useful for DB admins)
            if isinstance(original_exception, pyodbc.Error) and original_exception.args:
                log_details["sqlstate"] = original_exception.args[0]
            # Capture minimal traceback for context in logs
            log_details["traceback_snippet"] = traceback.format_exc(limit=2)

        super().__init__(client_message, DB_CONNECTION_FAILED, data, log_details)

class DBConfigurationError(JsonRpcDBError):
    """Error related to database configuration."""
    def __init__(self, client_message: str, config_issue: Optional[str] = None):
        # Client-facing data
        data: Dict[str, Any] = {"type": "DatabaseConfigurationError"}

        # Internal log details
        log_details: Dict[str, Any] = {}
        if config_issue: log_details["configuration_issue"] = config_issue

        super().__init__(client_message, DB_CONFIGURATION_INVALID, data, log_details)

class DBNotConnectedError(JsonRpcDBError):
    """Error when an operation is attempted without an active database connection."""
    def __init__(self, message: str = "Database operation failed. Not connected."):
        # Client-facing data
        data: Dict[str, Any] = {"type": "DatabaseNotConnectedError"}
        # Internal log details
        log_details: Dict[str, Any] = {"context": "Operation attempted without connection."}

        super().__init__(message, DB_NOT_CONNECTED, data, log_details)

class DBQueryError(JsonRpcDBError):
    """Error during SQL query execution."""
    def __init__(self, client_message: str, query: Optional[str] = None, params: Optional[tuple] = None, original_exception: Optional[Exception] = None):
        # Client-facing data (keep minimal, avoid query/params)
        data: Dict[str, Any] = {"type": "DatabaseQueryError"}

        # Internal log details (include sensitive specifics here)
        log_details: Dict[str, Any] = {}
        if query:
            log_details["query_template"] = query # Log the template query.
        if params:
            try:
                log_details["params_repr"] = repr(params) # Use repr for better type info
            except Exception:
                log_details["params_repr"] = "[Could not represent parameters]"
        if original_exception:
            log_details["original_exception_type"] = type(original_exception).__name__
            log_details["original_exception_message"] = str(original_exception)
            if isinstance(original_exception, pyodbc.Error) and original_exception.args:
                log_details["sqlstate"] = original_exception.args[0]
            log_details["traceback_snippet"] = traceback.format_exc(limit=2)

        super().__init__(client_message, DB_QUERY_FAILED, data, log_details)

class DBTransactionError(JsonRpcDBError):
    """Error during transaction commit or rollback."""
    def __init__(self, client_message: str, operation: str, original_exception: Optional[Exception] = None):
        # Client-facing data
        data: Dict[str, Any] = {"type": "DatabaseTransactionError", "failed_operation": operation}

        # Internal log details
        log_details: Dict[str, Any] = {"operation": operation}
        if original_exception:
            log_details["original_exception_type"] = type(original_exception).__name__
            log_details["original_exception_message"] = str(original_exception)
            if isinstance(original_exception, pyodbc.Error) and original_exception.args:
                log_details["sqlstate"] = original_exception.args[0]
            log_details["traceback_snippet"] = traceback.format_exc(limit=2)

        super().__init__(client_message, DB_TRANSACTION_ERROR, data, log_details)

class DBUnexpectedError(JsonRpcDBError):
    """An unexpected error occurred in the database module."""
    def __init__(self, client_message: str, context: Optional[str] = None, original_exception: Optional[Exception] = None):
        # Client-facing data
        data: Dict[str, Any] = {"type": "UnexpectedDatabaseError"}

        # Internal log details
        log_details: Dict[str, Any] = {}
        if context: log_details["context"] = context
        if original_exception:
            log_details["original_exception_type"] = type(original_exception).__name__
            log_details["original_exception_message"] = str(original_exception)
            log_details["full_traceback"] = traceback.format_exc() # Log full traceback

        super().__init__(client_message, DB_UNEXPECTED_ERROR, data, log_details)