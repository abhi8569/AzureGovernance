"""Tests for the DataNormalizer ETL component."""
from __future__ import annotations

import pytest

from src.etl.normalizer import DataNormalizer
from src.utils.id_generator import generate_surrogate_key


class TestNormalizePrincipals:
    """Tests for DataNormalizer.normalize_principals."""

    def test_basic_normalization(self) -> None:
        """Test that raw principal records are normalized with surrogate keys."""
        raw = [
            {
                "object_id": "user-001",
                "principal_type": "USER",
                "display_name": "Alice",
                "userPrincipalName": "alice@contoso.com",
                "mail": "alice@contoso.com",
                "accountEnabled": True,
            }
        ]
        result = DataNormalizer.normalize_principals(raw, "entra", "tenant-1")
        assert len(result) == 1
        assert result[0]["principal_id"] == generate_surrogate_key("entra", "user-001")
        assert result[0]["display_name"] == "Alice"
        assert result[0]["user_principal_name"] == "alice@contoso.com"
        assert result[0]["account_enabled"] is True
        assert result[0]["tenant_id"] == "tenant-1"

    def test_deduplication(self) -> None:
        """Test that duplicate object_ids are deduplicated (last write wins)."""
        raw = [
            {"object_id": "dup-001", "display_name": "First"},
            {"object_id": "dup-001", "display_name": "Second"},
        ]
        result = DataNormalizer.normalize_principals(raw, "entra", "t")
        assert len(result) == 1
        assert result[0]["display_name"] == "Second"

    def test_missing_object_id_skipped(self) -> None:
        """Test that records without object_id are skipped."""
        raw = [{"display_name": "No ID"}]
        result = DataNormalizer.normalize_principals(raw, "entra", "t")
        assert len(result) == 0


class TestNormalizeResources:
    """Tests for DataNormalizer.normalize_resources."""

    def test_basic_resource(self) -> None:
        """Test basic resource normalization."""
        raw = [
            {
                "resource_guid": "sub-123",
                "resource_type": "SUBSCRIPTION",
                "name": "My Sub",
                "subscription_id": "sub-123",
                "location": "eastus",
            }
        ]
        result = DataNormalizer.normalize_resources(raw, "azure", "t")
        assert len(result) == 1
        assert result[0]["resource_id"] == generate_surrogate_key("azure", "sub-123")
        assert result[0]["resource_type"] == "SUBSCRIPTION"
        assert result[0]["name"] == "My Sub"

    def test_parent_resolution(self) -> None:
        """Test that parent_guid is resolved to surrogate key."""
        raw = [
            {
                "resource_guid": "child-1",
                "resource_type": "GENERIC",
                "name": "Child",
                "parent_guid": "parent-1",
            }
        ]
        result = DataNormalizer.normalize_resources(raw, "azure", "t")
        assert result[0]["parent_id"] == generate_surrogate_key("azure", "parent-1")


class TestNormalizeRoleAssignments:
    """Tests for DataNormalizer.normalize_role_assignments."""

    def test_basic_assignment(self) -> None:
        """Test basic role assignment normalization."""
        raw = [
            {
                "principal_id": 12345,
                "role_id": 67890,
                "resource_id": 11111,
                "assignment_type": "AZURE_RBAC",
                "inherited": False,
                "snapshot_id": 1,
            }
        ]
        result = DataNormalizer.normalize_role_assignments(raw, "azure_rbac")
        assert len(result) == 1
        assert result[0]["assignment_type"] == "AZURE_RBAC"
        assert result[0]["source"] == "azure_rbac"

    def test_deduplication_by_composite_key(self) -> None:
        """Test that assignments with identical natural keys are deduplicated."""
        raw = [
            {"principal_id": 1, "role_id": 2, "resource_id": 3, "assignment_type": "AZURE_RBAC"},
            {"principal_id": 1, "role_id": 2, "resource_id": 3, "assignment_type": "AZURE_RBAC"},
        ]
        result = DataNormalizer.normalize_role_assignments(raw, "test")
        assert len(result) == 1


class TestNormalizeRLSPolicies:
    """Tests for DataNormalizer.normalize_rls_policies."""

    def test_sql_rls(self) -> None:
        """Test SQL RLS policy normalization."""
        raw = [
            {
                "resource_id": 100,
                "database": "SalesDB",
                "policy_name": "SalesFilter",
                "is_enabled": True,
                "target_table": "dbo.Sales",
                "predicate_type": "FILTER",
                "filter_function_definition": "CREATE FUNCTION dbo.fn_sales...",
                "snapshot_id": 1,
            }
        ]
        result = DataNormalizer.normalize_rls_policies(raw, "sql")
        assert len(result) == 1
        assert result[0]["policy_name"] == "SalesFilter"
        assert result[0]["filter_function_definition"] == "CREATE FUNCTION dbo.fn_sales..."

    def test_aas_rls_with_dax(self) -> None:
        """Test AAS RLS with DAX filter expression."""
        raw = [
            {
                "resource_id": 200,
                "database": "SalesModel",
                "policy_name": "SalesRole",
                "target_table": "Sales",
                "filter_expression_dax": "[Region] = USERPRINCIPALNAME()",
                "role_name": "SalesRole",
                "model_permission": "Read",
                "snapshot_id": 1,
            }
        ]
        result = DataNormalizer.normalize_rls_policies(raw, "aas")
        assert len(result) == 1
        assert result[0]["filter_function_definition"] == "[Region] = USERPRINCIPALNAME()"
        assert result[0]["role_name"] == "SalesRole"


class TestNormalizeDDMRules:
    """Tests for DataNormalizer.normalize_ddm_rules."""

    def test_basic_ddm(self) -> None:
        """Test DDM rule normalization."""
        raw = [
            {
                "resource_id": 100,
                "database": "HR_DB",
                "table": "dbo.Employees",
                "column": "SSN",
                "masking_function": "partial(0,\"XXX-XX-\",4)",
                "snapshot_id": 1,
            }
        ]
        result = DataNormalizer.normalize_ddm_rules(raw)
        assert len(result) == 1
        assert result[0]["column_name"] == "SSN"
        assert "partial" in result[0]["masking_function"]


class TestNormalizeSharingLinks:
    """Tests for DataNormalizer.normalize_sharing_links."""

    def test_anonymous_link(self) -> None:
        """Test anonymous sharing link."""
        raw = [
            {
                "item_name": "Budget.xlsx",
                "drive_id": "drive-1",
                "item_id": "item-1",
                "link_type": "view",
                "link_scope": "anonymous",
                "snapshot_id": 1,
            }
        ]
        result = DataNormalizer.normalize_sharing_links(raw)
        assert len(result) == 1
        assert result[0]["link_scope"] == "anonymous"
        assert result[0]["item_name"] == "Budget.xlsx"


class TestNormalizeNSGRules:
    """Tests for DataNormalizer.normalize_nsg_rules."""

    def test_allow_rule(self) -> None:
        """Test NSG allow rule normalization."""
        raw = [
            {
                "nsg_resource_id": 100,
                "nsg_name": "web-nsg",
                "rule_name": "AllowHTTPS",
                "priority": 100,
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "TCP",
                "source_address_prefix": "*",
                "destination_port_range": "443",
                "snapshot_id": 1,
            }
        ]
        result = DataNormalizer.normalize_nsg_rules(raw)
        assert len(result) == 1
        assert result[0]["access"] == "Allow"
        assert result[0]["destination_port"] == "443"


class TestMergeRecords:
    """Tests for DataNormalizer.merge_records."""

    def test_merge_overwrite(self) -> None:
        """Test that new records overwrite existing by key."""
        existing = [{"id": 1, "name": "Old"}]
        new = [{"id": 1, "name": "New"}]
        result = DataNormalizer.merge_records(existing, new, "id")
        assert len(result) == 1
        assert result[0]["name"] == "New"

    def test_merge_combine(self) -> None:
        """Test that non-overlapping records are combined."""
        existing = [{"id": 1, "name": "A"}]
        new = [{"id": 2, "name": "B"}]
        result = DataNormalizer.merge_records(existing, new, "id")
        assert len(result) == 2
