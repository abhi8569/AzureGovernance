"""Tests for SQL Server deep permissions extractor."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src.extractors.sql.permissions import SQLServerExtractor
from src.utils.id_generator import generate_surrogate_key


@pytest.fixture
def extractor():
    return SQLServerExtractor("tenant-1", 1)


class TestMapDbUser:
    """Tests for _map_db_user mapping."""

    def test_returns_principal_and_assignment(self, extractor) -> None:
        row = SimpleNamespace(
            principal_id=1, user_name="alice", principal_type="SQL_USER",
            authentication_type_desc="DATABASE", default_schema_name="dbo",
            create_date="2024-01-01", modify_date=None, sid=b"", sid_hex="0x01",
        )
        result = extractor._map_db_user(row, 100, "server1", "db1")
        assert "principal" in result
        assert "assignment" in result
        assert result["principal"]["display_name"] == "alice"
        assert result["assignment"]["assignment_type"] == "SQL_DB_ROLE"

    def test_maps_external_user_type(self, extractor) -> None:
        row = SimpleNamespace(
            principal_id=2, user_name="ext@domain.com", principal_type="EXTERNAL_USER",
            authentication_type_desc="EXTERNAL", default_schema_name="dbo",
            create_date=None, modify_date=None, sid=b"", sid_hex="",
        )
        result = extractor._map_db_user(row, 100, "srv", "db")
        assert result["principal"]["principal_type"] == "USER"


class TestMapDbPermission:
    """Tests for _map_db_permission mapping."""

    def test_grant_permission(self, extractor) -> None:
        row = SimpleNamespace(
            class_desc="OBJECT_OR_COLUMN", major_id=1, minor_id=0,
            grantee_principal_id=10, grantee_name="alice", grantee_type="SQL_USER",
            grantor_principal_id=1, grantor_name="dbo",
            type="SL", permission_name="SELECT", permission_state="GRANT",
            object_name="Employees", column_name=None,
        )
        result = extractor._map_db_permission(row, 200, "HR_DB")
        assert result["_permission_name"] == "SELECT"
        assert result["_permission_state"] == "GRANT"
        assert result["assignment_type"] == "SQL_PERMISSION"

    def test_deny_column_permission(self, extractor) -> None:
        row = SimpleNamespace(
            class_desc="OBJECT_OR_COLUMN", major_id=1, minor_id=3,
            grantee_principal_id=10, grantee_name="bob", grantee_type="SQL_USER",
            grantor_principal_id=1, grantor_name="dbo",
            type="SL", permission_name="SELECT", permission_state="DENY",
            object_name="Salaries", column_name="Amount",
        )
        result = extractor._map_db_permission(row, 200, "HR_DB")
        assert result["_permission_state"] == "DENY"
        assert result["_column_name"] == "Amount"


class TestMapRlsPolicy:
    """Tests for _map_rls_policy mapping."""

    def test_rls_with_filter(self, extractor) -> None:
        row = SimpleNamespace(
            policy_name="SalesFilter", is_enabled=True, is_schema_bound=True,
            target_table="Sales", target_schema="dbo",
            predicate_type_desc="FILTER", predicate_definition="[Region] = USER_NAME()",
            predicate_target_table="Sales", filter_function_name="fn_securitypredicate",
            filter_function_definition="CREATE FUNCTION dbo.fn_securitypredicate...",
        )
        result = extractor._map_rls_policy(row, 300, "SalesDB")
        assert result["policy_name"] == "SalesFilter"
        assert result["is_enabled"] is True
        assert "fn_securitypredicate" in result["filter_function_name"]
        assert result["target_table"] == "dbo.Sales"


class TestMapSqlPrincipalType:
    """Tests for _map_sql_principal_type static method."""

    def test_sql_user(self) -> None:
        assert SQLServerExtractor._map_sql_principal_type("SQL_USER") == "USER"

    def test_windows_group(self) -> None:
        assert SQLServerExtractor._map_sql_principal_type("WINDOWS_GROUP") == "GROUP"

    def test_unknown(self) -> None:
        assert SQLServerExtractor._map_sql_principal_type("SOMETHING_ELSE") == "UNKNOWN"


class TestExtractRg:
    """Tests for _extract_rg static method."""

    def test_valid_resource_id(self) -> None:
        rid = "/subscriptions/sub-1/resourceGroups/myRG/providers/Microsoft.Sql/servers/srv"
        assert SQLServerExtractor._extract_rg(rid) == "myRG"

    def test_empty_string(self) -> None:
        assert SQLServerExtractor._extract_rg("") == ""


class TestConnectionFailure:
    """Tests for SQL connection error handling."""

    @patch("src.extractors.sql.permissions.pyodbc", create=True)
    def test_connection_error_captured(self, mock_pyodbc, extractor) -> None:
        import importlib
        mock_pyodbc.Error = Exception
        mock_pyodbc.connect.side_effect = Exception("Connection refused")

        with patch.dict("sys.modules", {"pyodbc": mock_pyodbc}):
            result = extractor.extract_database("bad-conn", "srv", "db")
        assert len(result.errors) > 0
        assert result.record_count == 0
