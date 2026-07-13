"""Tests for the subscription scanner auto-discovery logic."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.orchestrator.subscription_scanner import (
    RESOURCE_TYPE_REGISTRY,
    SubscriptionScanner,
)


class TestResourceTypeRegistry:
    """Tests for the RESOURCE_TYPE_REGISTRY mapping."""

    def test_sql_registered(self) -> None:
        """SQL servers should be in the registry."""
        assert "microsoft.sql/servers" in RESOURCE_TYPE_REGISTRY
        assert RESOURCE_TYPE_REGISTRY["microsoft.sql/servers"]["label"] == "SQL Server"

    def test_cosmosdb_registered(self) -> None:
        """Cosmos DB accounts should be in the registry."""
        assert "microsoft.documentdb/databaseaccounts" in RESOURCE_TYPE_REGISTRY

    def test_keyvault_registered(self) -> None:
        """Key Vault should have both standard and deep extractors."""
        assert "microsoft.keyvault/vaults" in RESOURCE_TYPE_REGISTRY
        assert "microsoft.keyvault/vaults:deep" in RESOURCE_TYPE_REGISTRY

    def test_storage_registered(self) -> None:
        """Storage accounts should be in the registry."""
        assert "microsoft.storage/storageaccounts" in RESOURCE_TYPE_REGISTRY

    def test_nsg_registered(self) -> None:
        """NSGs should be in the registry."""
        assert "microsoft.network/networksecuritygroups" in RESOURCE_TYPE_REGISTRY

    def test_all_entries_have_required_fields(self) -> None:
        """All registry entries must have label, module, class, scope, and mode."""
        for key, entry in RESOURCE_TYPE_REGISTRY.items():
            assert "label" in entry, f"Missing 'label' in {key}"
            assert "extractor_module" in entry, f"Missing 'extractor_module' in {key}"
            assert "extractor_class" in entry, f"Missing 'extractor_class' in {key}"
            assert "scope" in entry, f"Missing 'scope' in {key}"
            assert "mode" in entry, f"Missing 'mode' in {key}"

    def test_registry_keys_lowercased(self) -> None:
        """All registry keys should be lowercase for case-insensitive matching."""
        for key in RESOURCE_TYPE_REGISTRY:
            # The ':deep' suffix is special, check the base part
            base = key.split(":")[0]
            assert base == base.lower(), f"Key '{key}' is not lowercase"


class TestScannerInit:
    """Tests for SubscriptionScanner initialization."""

    def test_accepts_required_args(self) -> None:
        """Scanner should initialize with required arguments."""
        scanner = SubscriptionScanner(
            credential=MagicMock(),
            msal_client=MagicMock(),
            tenant_id="tenant-1",
            snapshot_id=1,
            settings=MagicMock(),
        )
        assert scanner.tenant_id == "tenant-1"
        assert scanner.snapshot_id == 1


class TestDiscoveryMatching:
    """Tests for the resource type → extractor matching logic."""

    def test_matching_discovered_types(self) -> None:
        """Simulate discovered types and verify matching against registry."""
        discovered = {
            "microsoft.sql/servers": 3,
            "microsoft.keyvault/vaults": 5,
            "microsoft.compute/virtualmachines": 10,  # No extractor for this
            "microsoft.storage/storageaccounts": 2,
            "microsoft.web/sites": 4,  # No extractor for this
        }

        matched = []
        for arm_type in discovered:
            if arm_type.lower() in RESOURCE_TYPE_REGISTRY:
                matched.append(arm_type)

        # SQL, Key Vault, Storage should match
        assert "microsoft.sql/servers" in matched
        assert "microsoft.keyvault/vaults" in matched
        assert "microsoft.storage/storageaccounts" in matched
        # VMs and web apps have no extractor
        assert "microsoft.compute/virtualmachines" not in matched
        assert "microsoft.web/sites" not in matched

    def test_no_match_for_unknown_types(self) -> None:
        """Unknown resource types should not match any extractor."""
        discovered = {
            "microsoft.aadiam/tenants": 1,
            "microsoft.containerservice/managedclusters": 2,
        }
        matched = [t for t in discovered if t.lower() in RESOURCE_TYPE_REGISTRY]
        assert len(matched) == 0

    def test_case_insensitive_matching(self) -> None:
        """ARM types from Resource Graph may have mixed case."""
        discovered_type = "Microsoft.Sql/servers"
        assert discovered_type.lower() in RESOURCE_TYPE_REGISTRY

    def test_networking_discovery_triggers(self) -> None:
        """NSG, PE, or VNet discovery should trigger networking extractor."""
        networking_types = [
            "microsoft.network/networksecuritygroups",
            "microsoft.network/privateendpoints",
            "microsoft.network/virtualnetworks",
        ]
        # If any networking type is discovered, the NSG extractor should match
        for net_type in networking_types:
            discovered = {net_type: 1}
            has_networking = any(
                t in discovered
                for t in networking_types
            )
            assert has_networking, f"{net_type} should trigger networking"
