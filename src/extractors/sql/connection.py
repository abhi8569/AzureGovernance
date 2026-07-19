"""SQL connection abstraction — uses mssql-python (no ODBC driver needed).

Provides a unified connection factory that:
1. Uses mssql-python (Microsoft's official pure-Python driver) by default
2. Falls back to pyodbc if mssql-python is not available
3. Supports Azure AD token auth via MSAL (SSO)

This ensures SQL deep extraction works out of the box with just `pip install`.
"""
from __future__ import annotations

import struct
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# SQL Server token scope for Azure AD auth
SQL_TOKEN_SCOPE = "https://database.windows.net/.default"

# pyodbc constant for passing access token
SQL_COPT_SS_ACCESS_TOKEN = 1256


def _format_token_bytes(access_token: str) -> bytes:
    """Format an Azure AD access token for TDS LOGIN7 protocol.

    The SQL Server TDS protocol expects the token as:
    - 4-byte little-endian length prefix
    - UTF-16-LE encoded token string

    Args:
        access_token: Raw JWT access token string.

    Returns:
        Binary-encoded token ready for TDS.
    """
    token_bytes = access_token.encode("UTF-16-LE")
    return struct.pack(f"<I{len(token_bytes)}s", len(token_bytes), token_bytes)


class SQLConnection:
    """Abstraction over mssql-python / pyodbc for SQL Server connectivity.

    Automatically selects the best available driver and handles
    Azure AD token-based authentication.

    Usage:
        conn = SQLConnection.connect(
            server="myserver.database.windows.net",
            database="mydb",
            access_token="eyJ...",
        )
        cursor = conn.cursor()
        cursor.execute("SELECT @@VERSION")
    """

    _driver: str | None = None

    @classmethod
    def detect_driver(cls) -> str:
        """Detect the best available SQL driver.

        Returns:
            "mssql-python" or "pyodbc".

        Raises:
            ImportError: If no SQL driver is available.
        """
        if cls._driver:
            return cls._driver

        # Try mssql-python first (no ODBC driver needed)
        try:
            import mssql_python  # noqa: F401
            cls._driver = "mssql-python"
            logger.info("sql_driver_detected", driver="mssql-python")
            return cls._driver
        except ImportError:
            pass

        # Fall back to pyodbc
        try:
            import pyodbc  # noqa: F401
            cls._driver = "pyodbc"
            logger.info("sql_driver_detected", driver="pyodbc")
            return cls._driver
        except ImportError:
            pass

        raise ImportError(
            "No SQL driver found. Install one:\n"
            "  pip install mssql-python    (recommended, no ODBC driver needed)\n"
            "  pip install pyodbc          (requires ODBC Driver 18 installed on OS)"
        )

    @classmethod
    def connect(
        cls,
        server: str,
        database: str,
        access_token: str | None = None,
        connection_string: str | None = None,
        timeout: int = 30,
    ) -> Any:
        """Connect to a SQL Server instance.

        Uses Azure AD token auth when access_token is provided,
        or a raw connection string as fallback.

        Args:
            server: SQL server hostname (e.g. myserver.database.windows.net).
            database: Database name.
            access_token: Azure AD / MSAL access token for SSO auth.
            connection_string: Raw connection string (pyodbc-style fallback).
            timeout: Connection timeout in seconds.

        Returns:
            A DB-API 2.0 connection object.

        Raises:
            ImportError: If no SQL driver is available.
            Exception: If connection fails.
        """
        driver = cls.detect_driver()

        if driver == "mssql-python":
            return cls._connect_mssql_python(server, database, access_token, timeout)
        else:
            return cls._connect_pyodbc(server, database, access_token, connection_string, timeout)

    @classmethod
    def _connect_mssql_python(
        cls,
        server: str,
        database: str,
        access_token: str | None,
        timeout: int,
    ) -> Any:
        """Connect using mssql-python (no ODBC driver required)."""
        from mssql_python import connect

        conn_str = (
            f"SERVER=tcp:{server},1433;"
            f"DATABASE={database};"
            f"Encrypt=yes;"
            f"TrustServerCertificate=no;"
            f"Connection Timeout={timeout};"
        )

        if access_token:
            token_struct = _format_token_bytes(access_token)
            conn = connect(conn_str, attrs_before={SQL_COPT_SS_ACCESS_TOKEN: token_struct})
        else:
            conn = connect(conn_str)

        logger.info("sql_connected", driver="mssql-python", server=server, database=database)
        return conn

    @classmethod
    def _connect_pyodbc(
        cls,
        server: str,
        database: str,
        access_token: str | None,
        connection_string: str | None,
        timeout: int,
    ) -> Any:
        """Connect using pyodbc (requires ODBC Driver 18)."""
        import pyodbc

        if connection_string:
            if access_token:
                token_struct = _format_token_bytes(access_token)
                conn = pyodbc.connect(
                    connection_string,
                    timeout=timeout,
                    attrs_before={SQL_COPT_SS_ACCESS_TOKEN: token_struct},
                )
            else:
                conn = pyodbc.connect(connection_string, timeout=timeout)
        else:
            conn_str = (
                f"DRIVER={{ODBC Driver 18 for SQL Server}};"
                f"SERVER=tcp:{server},1433;"
                f"DATABASE={database};"
                f"Encrypt=yes;"
                f"TrustServerCertificate=no;"
                f"Connection Timeout={timeout};"
            )
            if access_token:
                token_struct = _format_token_bytes(access_token)
                conn = pyodbc.connect(
                    conn_str,
                    attrs_before={SQL_COPT_SS_ACCESS_TOKEN: token_struct},
                )
            else:
                conn = pyodbc.connect(conn_str)

        logger.info("sql_connected", driver="pyodbc", server=server, database=database)
        return conn
