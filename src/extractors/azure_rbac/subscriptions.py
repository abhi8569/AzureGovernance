"""Azure subscription and resource group extractor."""
from __future__ import annotations

import time
from typing import Any, TYPE_CHECKING

import structlog

from src.extractors.base import ExtractResult
from src.utils.id_generator import generate_surrogate_key

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

logger = structlog.get_logger(__name__)


class SubscriptionExtractor:
    """Extracts subscriptions and resource groups from Azure.

    Args:
        credential: Azure token credential.
        tenant_id: Azure AD tenant ID.
        snapshot_id: Current snapshot ID.
    """

    def __init__(
        self,
        credential: TokenCredential,
        tenant_id: str,
        snapshot_id: int,
    ) -> None:
        self.credential = credential
        self.tenant_id = tenant_id
        self.snapshot_id = snapshot_id
        self.logger = structlog.get_logger(self.__class__.__name__)

    def extract(self) -> ExtractResult:
        """Extract all subscriptions and their resource groups.

        Returns:
            ExtractResult with DimResource and FactResourceHierarchy records.
        """
        from azure.mgmt.resource.resources import ResourceManagementClient
        from azure.mgmt.resource.subscriptions import SubscriptionClient

        start_time = time.monotonic()
        resources: list[dict[str, Any]] = []
        hierarchy_edges: list[dict[str, Any]] = []
        subscription_ids: list[str] = []
        errors: list[str] = []

        try:
            sub_client = SubscriptionClient(self.credential)

            for sub in sub_client.subscriptions.list():
                sub_resource = self._map_subscription(sub)
                resources.append(sub_resource)
                subscription_ids.append(sub.subscription_id)

                # List resource groups for this subscription
                try:
                    rg_client = ResourceManagementClient(
                        self.credential, sub.subscription_id
                    )
                    for rg in rg_client.resource_groups.list():
                        rg_resource = self._map_resource_group(rg, sub.subscription_id)
                        resources.append(rg_resource)

                        hierarchy_edges.append({
                            "parent_resource_id": sub_resource["resource_id"],
                            "child_resource_id": rg_resource["resource_id"],
                            "relationship_type": "CONTAINS",
                            "snapshot_id": self.snapshot_id,
                        })

                except Exception as e:
                    errors.append(f"RGs for {sub.subscription_id}: {e}")
                    self.logger.warning(
                        "rg_list_failed",
                        subscription=sub.subscription_id,
                        error=str(e),
                    )

            self.logger.info(
                "subscriptions_extracted",
                subscriptions=len(subscription_ids),
                resource_groups=len(resources) - len(subscription_ids),
                edges=len(hierarchy_edges),
            )

        except Exception as e:
            errors.append(f"Subscription listing: {e}")
            self.logger.error("subscription_extraction_failed", error=str(e))

        duration = time.monotonic() - start_time
        return ExtractResult(
            records=[{
                "resources": resources,
                "hierarchy": hierarchy_edges,
                "subscription_ids": subscription_ids,
            }],
            errors=errors,
            record_count=len(resources),
            duration_seconds=duration,
            extractor_name="SubscriptionExtractor",
        )

    def _map_subscription(self, sub: Any) -> dict[str, Any]:
        """Map Azure SDK subscription to DimResource schema."""
        sub_id = f"/subscriptions/{sub.subscription_id}"
        return {
            "resource_id": generate_surrogate_key("azure", sub_id),
            "tenant_id": self.tenant_id,
            "resource_guid": sub_id,
            "resource_type": "SUBSCRIPTION",
            "name": sub.display_name or "",
            "subscription_id": sub.subscription_id,
            "parent_id": None,
            "resource_group": None,
            "location": None,
            "tags": str(sub.tags) if sub.tags else None,
        }

    def _map_resource_group(self, rg: Any, subscription_id: str) -> dict[str, Any]:
        """Map Azure SDK resource group to DimResource schema."""
        rg_id = f"/subscriptions/{subscription_id}/resourceGroups/{rg.name}"
        return {
            "resource_id": generate_surrogate_key("azure", rg_id),
            "tenant_id": self.tenant_id,
            "resource_guid": rg_id,
            "resource_type": "RESOURCE_GROUP",
            "name": rg.name or "",
            "subscription_id": subscription_id,
            "parent_id": generate_surrogate_key("azure", f"/subscriptions/{subscription_id}"),
            "resource_group": rg.name,
            "location": rg.location or "",
            "tags": str(rg.tags) if rg.tags else None,
        }
