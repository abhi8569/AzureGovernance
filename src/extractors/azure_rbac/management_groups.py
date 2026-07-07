"""Azure Management Group hierarchy extractor."""
from __future__ import annotations

import time
from typing import Any, TYPE_CHECKING

import structlog

from src.extractors.base import ExtractResult
from src.utils.id_generator import generate_surrogate_key

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

logger = structlog.get_logger(__name__)


class ManagementGroupExtractor:
    """Extracts management group hierarchy from Azure.

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
        """Extract all management groups and their hierarchy.

        Returns:
            ExtractResult with DimResource and FactResourceHierarchy records.
        """
        from azure.mgmt.managementgroups import ManagementGroupsAPI

        start_time = time.monotonic()
        resources: list[dict[str, Any]] = []
        hierarchy_edges: list[dict[str, Any]] = []
        errors: list[str] = []

        try:
            client = ManagementGroupsAPI(self.credential)

            # List all management groups
            for mg in client.management_groups.list():
                mg_detail = client.management_groups.get(
                    mg.name,
                    expand="children",
                    recurse=True,
                )
                resource = self._map_management_group(mg_detail)
                resources.append(resource)

                # Process children to build hierarchy edges
                if mg_detail.children:
                    self._process_children(
                        parent_id=resource["resource_id"],
                        children=mg_detail.children,
                        resources=resources,
                        hierarchy_edges=hierarchy_edges,
                    )

            self.logger.info(
                "management_groups_extracted",
                groups=len(resources),
                edges=len(hierarchy_edges),
            )

        except Exception as e:
            errors.append(f"Management groups: {e}")
            self.logger.error("mg_extraction_failed", error=str(e))

        duration = time.monotonic() - start_time
        return ExtractResult(
            records=[{"resources": resources, "hierarchy": hierarchy_edges}],
            errors=errors,
            record_count=len(resources) + len(hierarchy_edges),
            duration_seconds=duration,
            extractor_name="ManagementGroupExtractor",
        )

    def _process_children(
        self,
        parent_id: int,
        children: list[Any],
        resources: list[dict[str, Any]],
        hierarchy_edges: list[dict[str, Any]],
    ) -> None:
        """Recursively process management group children."""
        for child in children:
            child_type = getattr(child, "type", "") or ""
            child_id_str = getattr(child, "id", "") or ""
            child_name = getattr(child, "display_name", "") or getattr(child, "name", "") or ""

            if "managementGroups" in child_type:
                child_resource_type = "MANAGEMENT_GROUP"
            else:
                child_resource_type = "SUBSCRIPTION"

            child_resource_id = generate_surrogate_key("azure", child_id_str)

            resources.append({
                "resource_id": child_resource_id,
                "tenant_id": self.tenant_id,
                "resource_guid": child_id_str,
                "resource_type": child_resource_type,
                "name": child_name,
                "parent_id": parent_id,
            })

            hierarchy_edges.append({
                "parent_resource_id": parent_id,
                "child_resource_id": child_resource_id,
                "relationship_type": "CONTAINS",
                "snapshot_id": self.snapshot_id,
            })

            # Recurse into nested children
            child_children = getattr(child, "children", None)
            if child_children:
                self._process_children(
                    parent_id=child_resource_id,
                    children=child_children,
                    resources=resources,
                    hierarchy_edges=hierarchy_edges,
                )

    def _map_management_group(self, mg: Any) -> dict[str, Any]:
        """Map Azure SDK management group to DimResource schema."""
        mg_id = getattr(mg, "id", "") or ""
        return {
            "resource_id": generate_surrogate_key("azure", mg_id),
            "tenant_id": self.tenant_id,
            "resource_guid": mg_id,
            "resource_type": "MANAGEMENT_GROUP",
            "name": getattr(mg, "display_name", "") or getattr(mg, "name", "") or "",
            "parent_id": None,
        }
