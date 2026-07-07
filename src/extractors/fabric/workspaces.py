"""Microsoft Fabric workspace and item extractor."""
from __future__ import annotations

import time
from typing import Any

import httpx
import structlog

from src.extractors.base import BaseExtractor, ExtractResult
from src.utils.id_generator import generate_surrogate_key
from src.utils.pagination import paginate_fabric
from src.utils.rate_limiter import FABRIC_RATE_LIMITER

logger = structlog.get_logger(__name__)

FABRIC_API_BASE = "https://api.fabric.microsoft.com/v1"
WORKSPACES_URL = f"{FABRIC_API_BASE}/workspaces"


class FabricWorkspaceExtractor(BaseExtractor):
    """Extracts Fabric workspaces and their items.

    Queries the Fabric REST API for workspaces, role assignments,
    and items (lakehouses, warehouses, notebooks, pipelines, etc.).
    """

    async def extract(self) -> ExtractResult:
        """Extract all Fabric workspaces, roles, and items.

        Returns:
            ExtractResult with workspace resources, role assignments, and items.
        """
        start_time = time.monotonic()
        resources: list[dict[str, Any]] = []
        assignments: list[dict[str, Any]] = []
        errors: list[str] = []

        async with httpx.AsyncClient(timeout=60.0) as client:
            # List workspaces
            try:
                async for page in paginate_fabric(client, WORKSPACES_URL, self.headers):
                    await FABRIC_RATE_LIMITER.acquire()
                    for ws in page:
                        ws_resource = self._map_workspace(ws)
                        resources.append(ws_resource)

                        ws_id = ws.get("id", "")
                        # Get workspace role assignments
                        try:
                            roles_url = f"{WORKSPACES_URL}/{ws_id}/roleAssignments"
                            resp = await client.get(roles_url, headers=self.headers)
                            resp.raise_for_status()
                            role_data = resp.json().get("value", [])
                            for role in role_data:
                                assignments.append(
                                    self._map_role_assignment(role, ws_resource["resource_id"])
                                )
                        except Exception as e:
                            errors.append(f"Workspace {ws_id} roles: {e}")

                        # Get workspace items
                        try:
                            items_url = f"{WORKSPACES_URL}/{ws_id}/items"
                            async for item_page in paginate_fabric(client, items_url, self.headers):
                                for item in item_page:
                                    resources.append(
                                        self._map_item(item, ws_resource["resource_id"])
                                    )
                        except Exception as e:
                            errors.append(f"Workspace {ws_id} items: {e}")

                self.logger.info(
                    "fabric_workspaces_extracted",
                    resources=len(resources),
                    assignments=len(assignments),
                )

            except Exception as e:
                errors.append(f"Fabric workspaces: {e}")
                self.logger.error("fabric_extraction_failed", error=str(e))

        duration = time.monotonic() - start_time
        return ExtractResult(
            records=[{"resources": resources, "assignments": assignments}],
            errors=errors,
            record_count=len(resources) + len(assignments),
            duration_seconds=duration,
            extractor_name="FabricWorkspaceExtractor",
        )

    def _map_workspace(self, ws: dict[str, Any]) -> dict[str, Any]:
        """Map Fabric workspace to DimResource."""
        ws_id = ws.get("id", "")
        return {
            "resource_id": generate_surrogate_key("fabric", ws_id),
            "tenant_id": self.tenant_id,
            "resource_guid": ws_id,
            "resource_type": "FABRIC_WORKSPACE",
            "name": ws.get("displayName", ""),
            "parent_id": None,
        }

    def _map_item(self, item: dict[str, Any], workspace_resource_id: int) -> dict[str, Any]:
        """Map Fabric item to DimResource."""
        item_id = item.get("id", "")
        item_type = item.get("type", "").lower()

        type_mapping = {
            "lakehouse": "FABRIC_LAKEHOUSE",
            "warehouse": "FABRIC_WAREHOUSE",
            "semanticmodel": "SEMANTIC_MODEL",
            "report": "REPORT",
            "dashboard": "DASHBOARD",
            "dataflow": "DATAFLOW",
            "datapipeline": "PIPELINE",
            "notebook": "NOTEBOOK",
        }
        resource_type = type_mapping.get(item_type, "GENERIC")

        return {
            "resource_id": generate_surrogate_key("fabric", item_id),
            "tenant_id": self.tenant_id,
            "resource_guid": item_id,
            "resource_type": resource_type,
            "name": item.get("displayName", ""),
            "parent_id": workspace_resource_id,
        }

    def _map_role_assignment(
        self, role: dict[str, Any], workspace_resource_id: int
    ) -> dict[str, Any]:
        """Map Fabric workspace role assignment to FactRoleAssignment."""
        principal = role.get("principal", {})
        principal_id = principal.get("id", "")

        return {
            "assignment_id": generate_surrogate_key(
                "fabric_role",
                f"{workspace_resource_id}:{principal_id}:{role.get('role', '')}",
            ),
            "principal_id": generate_surrogate_key("entra", principal_id),
            "role_id": None,
            "resource_id": workspace_resource_id,
            "assignment_type": "FABRIC_WORKSPACE_ROLE",
            "start_date": None,
            "end_date": None,
            "inherited": False,
            "source": "FabricAPI",
            "snapshot_id": self.snapshot_id,
            "_role_name": role.get("role", ""),
        }
