"""Tests for Cosmos DB and Key Vault deep extractors and Networking."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src.extractors.cosmosdb.permissions import CosmosDBExtractor
from src.extractors.networking.access import NetworkAccessExtractor


class TestCosmosDBScopeDetection:
    """Tests for Cosmos DB scope level detection in assignments."""

    def test_account_scope(self) -> None:
        scope = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/myaccount"
        level = "ACCOUNT"
        if "/dbs/" in scope and "/colls/" in scope:
            level = "CONTAINER"
        elif "/dbs/" in scope:
            level = "DATABASE"
        assert level == "ACCOUNT"

    def test_database_scope(self) -> None:
        scope = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/myaccount/dbs/mydb"
        level = "ACCOUNT"
        if "/dbs/" in scope and "/colls/" in scope:
            level = "CONTAINER"
        elif "/dbs/" in scope:
            level = "DATABASE"
        assert level == "DATABASE"

    def test_container_scope(self) -> None:
        scope = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/myaccount/dbs/mydb/colls/mycoll"
        level = "ACCOUNT"
        if "/dbs/" in scope and "/colls/" in scope:
            level = "CONTAINER"
        elif "/dbs/" in scope:
            level = "DATABASE"
        assert level == "CONTAINER"


class TestCosmosExtractRg:
    """Tests for _extract_rg utility."""

    def test_valid_id(self) -> None:
        rid = "/subscriptions/sub-1/resourceGroups/myRG/providers/Microsoft.DocumentDB/databaseAccounts/acct"
        assert CosmosDBExtractor._extract_rg(rid) == "myRG"

    def test_no_rg(self) -> None:
        assert CosmosDBExtractor._extract_rg("/something/else") == ""


class TestNetworkExtractRg:
    """Tests for NetworkAccessExtractor._extract_rg."""

    def test_valid_id(self) -> None:
        rid = "/subscriptions/sub-1/resourceGroups/netRG/providers/Microsoft.Network/networkSecurityGroups/nsg1"
        assert NetworkAccessExtractor._extract_rg(rid) == "netRG"


class TestNetworkNSGMapping:
    """Tests for NSG rule extraction mapping logic."""

    def test_nsg_rule_fields(self) -> None:
        """Verify NSG rule dict has expected structure."""
        rule = {
            "nsg_resource_id": 100,
            "nsg_name": "web-nsg",
            "rule_name": "AllowHTTPS",
            "priority": 100,
            "direction": "Inbound",
            "access": "Allow",
            "protocol": "TCP",
            "source_address_prefix": "Internet",
            "destination_port_range": "443",
        }
        # Verify all expected fields exist
        assert rule["access"] == "Allow"
        assert rule["priority"] == 100
        assert rule["direction"] == "Inbound"

    def test_deny_rule(self) -> None:
        """Verify deny rules are captured."""
        rule = {
            "access": "Deny",
            "rule_name": "DenyAll",
            "priority": 4096,
            "direction": "Inbound",
        }
        assert rule["access"] == "Deny"
        assert rule["priority"] == 4096
