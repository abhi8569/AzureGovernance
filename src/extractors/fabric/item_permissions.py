"""Fabric item-level permissions and OneLake security extractor.

Goes beyond workspace-level access to extract per-item permissions:
- Fabric Item permissions via scanner API
- OneLake data access roles (GA April 2026)
- Workspace scanner (getInfo with getArtifactUsers=true)
"""
from __future__ import annotations

import time
from typing import Any

import httpx
import structlog

from src.extractors.base import BaseExtractor, ExtractResult
from src.utils.id_generator import generate_surrogate_key
from src.utils.rate_limiter import FABRIC_RATE_LIMITER

logger = structlog.get_logger(__name__)

PBI_ADMIN_BASE = "https://api.powerbi.com/v1.0/myorg/admin"
FABRIC_API_BASE = "https://api.fabric.microsoft.com/v1"


class FabricItemPermissionsExtractor(BaseExtractor):
    """Extracts per-item permissions via Fabric scanner and OneLake APIs.

    Uses the Power BI Admin scanner API (getInfo with getArtifactUsers)
    for bulk retrieval of per-artifact access, and Fabric REST API
    for OneLake data access roles.
    """

    async def extract(self) -> ExtractResult:
        """Extract item-level permissions across all workspaces.

        Returns:
            ExtractResult with per-item assignments and OneLake roles.
        """
        start_time = time.monotonic()
        assignments: list[dict[str, Any]] = []
        onelake_roles: list[dict[str, Any]] = []
        errors: list[str] = []

        async with httpx.AsyncClient(timeout=180.0) as client:
            # 1. Scanner API: bulk extract all workspace artifacts + users
            await self._extract_via_scanner(client, assignments, errors)

            # 2. OneLake data access roles (per-lakehouse/warehouse)
            await self._extract_onelake_roles(client, onelake_roles, errors)

        duration = time.monotonic() - start_time
        self.logger.info(
            "fabric_item_permissions_extracted",
            assignments=len(assignments),
            onelake_roles=len(onelake_roles),
            duration=round(duration, 1),
        )
        return ExtractResult(
            records=[{"assignments": assignments, "onelake_roles": onelake_roles}],
            errors=errors,
            record_count=len(assignments) + len(onelake_roles),
            duration_seconds=duration,
            extractor_name="FabricItemPermissionsExtractor",
        )

    async def _extract_via_scanner(
        self, client: httpx.AsyncClient, assignments: list, errors: list
    ) -> None:
        """Use Power BI Admin scanner API for bulk artifact user extraction.

        Flow:
        1. POST /admin/workspaces/getInfo (initiate scan with getArtifactUsers=true)
        2. GET /admin/workspaces/scanStatus/{scanId} (poll until ready)
        3. GET /admin/workspaces/scanResult/{scanId} (get results)
        """
        try:
            # Step 1: Initiate scan
            await FABRIC_RATE_LIMITER.acquire()
            scan_url = f"{PBI_ADMIN_BASE}/workspaces/getInfo?getArtifactUsers=true"

            # First, get all workspace IDs
            ws_url = f"{PBI_ADMIN_BASE}/groups?$top=5000"
            resp = await client.get(ws_url, headers=self.headers)
            resp.raise_for_status()
            workspace_ids = [ws.get("id") for ws in resp.json().get("value", [])]

            # Batch workspace IDs (max 100 per scan request)
            batch_size = 100
            for i in range(0, len(workspace_ids), batch_size):
                batch = workspace_ids[i:i + batch_size]
                try:
                    await FABRIC_RATE_LIMITER.acquire()
                    scan_resp = await client.post(
                        scan_url,
                        headers=self.headers,
                        json={"workspaces": batch},
                    )
                    scan_resp.raise_for_status()
                    scan_id = scan_resp.json().get("id")

                    if not scan_id:
                        continue

                    # Step 2: Poll for completion
                    for _ in range(30):  # Max 5 minutes
                        import asyncio
                        await asyncio.sleep(10)
                        await FABRIC_RATE_LIMITER.acquire()
                        status_resp = await client.get(
                            f"{PBI_ADMIN_BASE}/workspaces/scanStatus/{scan_id}",
                            headers=self.headers,
                        )
                        status_resp.raise_for_status()
                        status = status_resp.json().get("status", "")
                        if status == "Succeeded":
                            break
                        elif status == "Failed":
                            errors.append(f"Scan {scan_id} failed")
                            break
                    else:
                        errors.append(f"Scan {scan_id} timed out")
                        continue

                    # Step 3: Get results
                    await FABRIC_RATE_LIMITER.acquire()
                    result_resp = await client.get(
                        f"{PBI_ADMIN_BASE}/workspaces/scanResult/{scan_id}",
                        headers=self.headers,
                    )
                    result_resp.raise_for_status()
                    workspaces_data = result_resp.json().get("workspaces", [])

                    for ws in workspaces_data:
                        ws_id = ws.get("id", "")
                        ws_resource_id = generate_surrogate_key("powerbi", ws_id)

                        # Process each artifact type
                        for artifact_type in ["datasets", "reports", "dashboards", "dataflows"]:
                            for item in ws.get(artifact_type, []):
                                item_id = item.get("id", "")
                                item_resource_id = generate_surrogate_key("powerbi", item_id)

                                for user in item.get("users", []):
                                    identifier = user.get("identifier", "")
                                    access_right = (
                                        user.get("datasetUserAccessRight", "")
                                        or user.get("reportUserAccessRight", "")
                                        or user.get("dashboardUserAccessRight", "")
                                        or user.get("dataflowUserAccessRight", "")
                                        or ""
                                    )
                                    if identifier:
                                        assignments.append({
                                            "assignment_id": generate_surrogate_key(
                                                f"scanner_{artifact_type}",
                                                f"{item_resource_id}:{identifier}:{access_right}",
                                            ),
                                            "principal_id": generate_surrogate_key("entra", identifier),
                                            "resource_id": item_resource_id,
                                            "assignment_type": "FABRIC_WORKSPACE_ROLE",
                                            "source": f"Scanner_{artifact_type}",
                                            "snapshot_id": self.snapshot_id,
                                            "_access_right": access_right,
                                            "_principal_type": user.get("principalType", ""),
                                            "_display_name": user.get("displayName", ""),
                                            "_artifact_type": artifact_type,
                                            "_workspace_id": ws_id,
                                        })

                except Exception as e:
                    errors.append(f"Scanner batch {i}: {e}")

            self.logger.info("scanner_extraction_complete", workspaces=len(workspace_ids))

        except Exception as e:
            errors.append(f"Scanner API: {e}")
            self.logger.error("scanner_failed", error=str(e))

    async def _extract_onelake_roles(
        self, client: httpx.AsyncClient, roles: list, errors: list
    ) -> None:
        """Extract OneLake data access roles for Lakehouses/Warehouses.

        Uses Fabric REST API:
        GET /workspaces/{id}/items/{id}/dataAccessRoles
        """
        try:
            # List workspaces
            await FABRIC_RATE_LIMITER.acquire()
            ws_url = f"{FABRIC_API_BASE}/workspaces"
            resp = await client.get(ws_url, headers=self.headers)
            resp.raise_for_status()
            workspaces = resp.json().get("value", [])

            for ws in workspaces:
                ws_id = ws.get("id", "")

                # List items in workspace
                try:
                    await FABRIC_RATE_LIMITER.acquire()
                    items_url = f"{FABRIC_API_BASE}/workspaces/{ws_id}/items"
                    items_resp = await client.get(items_url, headers=self.headers)
                    items_resp.raise_for_status()

                    for item in items_resp.json().get("value", []):
                        item_type = item.get("type", "").lower()
                        item_id = item.get("id", "")

                        # OneLake security applies to lakehouses and warehouses
                        if item_type in ("lakehouse", "warehouse"):
                            try:
                                await FABRIC_RATE_LIMITER.acquire()
                                dar_url = f"{FABRIC_API_BASE}/workspaces/{ws_id}/items/{item_id}/dataAccessRoles"
                                dar_resp = await client.get(dar_url, headers=self.headers)
                                if dar_resp.status_code == 200:
                                    for role in dar_resp.json().get("value", []):
                                        roles.append({
                                            "workspace_id": ws_id,
                                            "item_id": item_id,
                                            "item_type": item_type,
                                            "item_name": item.get("displayName", ""),
                                            "role_name": role.get("name", ""),
                                            "role_id": role.get("id", ""),
                                            "decision_rules": str(role.get("decisionRules", [])),
                                            "members": str(role.get("members", [])),
                                            "snapshot_id": self.snapshot_id,
                                        })
                            except Exception as e:
                                pass  # OneLake security may not be enabled

                except Exception as e:
                    errors.append(f"Workspace {ws_id} items: {e}")

        except Exception as e:
            errors.append(f"OneLake roles: {e}")
            self.logger.warning("onelake_roles_failed", error=str(e))
