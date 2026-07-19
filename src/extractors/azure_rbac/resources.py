"""Azure Resource Graph extractor for inventorying all resources."""
from __future__ import annotations

import time
from typing import Any, TYPE_CHECKING

import structlog

from src.extractors.base import ExtractResult
from src.utils.id_generator import generate_surrogate_key

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

logger = structlog.get_logger(__name__)

# Azure Resource Graph query for all resources
ARG_QUERY = """
Resources
| project id, name, type, location, resourceGroup, subscriptionId, tags,
          properties, identity, sku, kind
| order by id asc
"""


class ResourceGraphExtractor:
    """Extracts resource inventory using Azure Resource Graph.

    Uses the Azure Resource Graph service to efficiently query all
    resources across subscriptions in a single query.

    Args:
        credential: Azure token credential.
        tenant_id: Azure AD tenant ID.
        snapshot_id: Current snapshot ID.
        subscription_ids: List of subscription IDs to query.
    """

    def __init__(
        self,
        credential: TokenCredential,
        tenant_id: str,
        snapshot_id: int,
        subscription_ids: list[str],
        resource_groups: list[str] | None = None,
    ) -> None:
        self.credential = credential
        self.tenant_id = tenant_id
        self.snapshot_id = snapshot_id
        self.subscription_ids = subscription_ids
        self.resource_groups = resource_groups
        self.logger = structlog.get_logger(self.__class__.__name__)

    def extract(self) -> ExtractResult:
        """Extract all resources via Azure Resource Graph.

        Returns:
            ExtractResult with DimResource-shaped records.
        """
        from azure.mgmt.resourcegraph import ResourceGraphClient
        from azure.mgmt.resourcegraph.models import (
            QueryRequest,
            QueryRequestOptions,
            ResultFormat,
        )

        start_time = time.monotonic()
        records: list[dict[str, Any]] = []
        errors: list[str] = []

        # Build dynamic query
        query_parts = ["Resources"]
        if self.resource_groups:
            rg_list = ", ".join(f"'{rg}'" for rg in self.resource_groups)
            query_parts.append(f"where resourceGroup in~ ({rg_list})")
        query_parts.append(
            "project id, name, type, location, resourceGroup, subscriptionId, tags, properties, identity, sku, kind"
        )
        query_parts.append("order by id asc")
        query_str = " | ".join(query_parts)

        try:
            client = ResourceGraphClient(self.credential)
            skip_token: str | None = None

            while True:
                options = QueryRequestOptions(
                    result_format=ResultFormat.OBJECT_ARRAY,
                    skip_token=skip_token,
                    top=1000,
                )
                request = QueryRequest(
                    subscriptions=self.subscription_ids,
                    query=query_str,
                    options=options,
                )

                response = client.resources(request)

                if response.data:
                    for raw in response.data:
                        records.append(self._map_resource(raw))

                skip_token = response.skip_token
                if not skip_token:
                    break

            self.logger.info("resources_extracted", count=len(records))

        except Exception as e:
            errors.append(f"Resource Graph query failed: {e}")
            self.logger.error("resource_graph_failed", error=str(e))

        duration = time.monotonic() - start_time
        return ExtractResult(
            records=records,
            errors=errors,
            record_count=len(records),
            duration_seconds=duration,
            extractor_name="ResourceGraphExtractor",
        )

    def _map_resource(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Map ARG result row to DimResource schema."""
        resource_id_str = raw.get("id", "")
        resource_type_raw = raw.get("type", "").lower()
        subscription_id = raw.get("subscriptionId", "")

        # Map Azure resource type to our enum
        type_mapping = {
            "microsoft.storage/storageaccounts": "STORAGE_ACCOUNT",
            "microsoft.keyvault/vaults": "KEY_VAULT",
            "microsoft.sql/servers": "SQL_SERVER",
            "microsoft.sql/servers/databases": "SQL_DATABASE",
            "microsoft.compute/virtualmachines": "VIRTUAL_MACHINE",
            "microsoft.web/sites": "APP_SERVICE",
            "microsoft.web/sites/functions": "FUNCTION_APP",
            "microsoft.containerservice/managedclusters": "AKS_CLUSTER",
            "microsoft.documentdb/databaseaccounts": "COSMOS_DB",
            "microsoft.cache/redis": "REDIS_CACHE",
            "microsoft.network/virtualnetworks": "VNET",
            "microsoft.network/virtualnetworks/subnets": "SUBNET",
            "microsoft.network/networksecuritygroups": "NSG",
        }
        resource_type = type_mapping.get(resource_type_raw, "GENERIC")

        return {
            "resource_id": generate_surrogate_key("azure", resource_id_str),
            "tenant_id": self.tenant_id,
            "resource_guid": resource_id_str,
            "resource_type": resource_type,
            "name": raw.get("name", ""),
            "parent_id": None,
            "subscription_id": subscription_id,
            "resource_group": raw.get("resourceGroup", ""),
            "location": raw.get("location", ""),
            "tags": str(raw.get("tags", {})) if raw.get("tags") else None,
            "created_date": None,
            "deleted_date": None,
        }
