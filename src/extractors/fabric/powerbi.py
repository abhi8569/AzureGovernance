"""Power BI Admin REST API extractor."""
from __future__ import annotations

import time
from typing import Any

import httpx
import structlog

from src.extractors.base import BaseExtractor, ExtractResult
from src.utils.id_generator import generate_surrogate_key
from src.utils.pagination import paginate_rest
from src.utils.rate_limiter import POWERBI_RATE_LIMITER

logger = structlog.get_logger(__name__)

PBI_ADMIN_BASE = "https://api.powerbi.com/v1.0/myorg/admin"


class PowerBIExtractor(BaseExtractor):
    """Extracts Power BI workspaces, reports, datasets, and apps via Admin API.

    Uses the Power BI Admin REST API for tenant-wide visibility.
    Requires Power BI service admin or Fabric admin role.
    """

    async def extract(self) -> ExtractResult:
        """Extract Power BI workspaces and their contents.

        Returns:
            ExtractResult with resources and assignments.
        """
        start_time = time.monotonic()
        resources: list[dict[str, Any]] = []
        errors: list[str] = []

        async with httpx.AsyncClient(timeout=60.0) as client:
            # List workspaces (groups) via admin API
            try:
                workspaces_url = f"{PBI_ADMIN_BASE}/groups?$top=5000"
                async for page in paginate_rest(
                    client, workspaces_url, self.headers,
                    next_link_key="@odata.nextLink",
                ):
                    await POWERBI_RATE_LIMITER.acquire()
                    for ws in page:
                        resources.append(self._map_workspace(ws))

                self.logger.info("pbi_workspaces_extracted", count=len(resources))
            except Exception as e:
                errors.append(f"PBI workspaces: {e}")
                self.logger.error("pbi_workspace_failed", error=str(e))

            workspace_count = len(resources)

            # List reports via admin API
            try:
                reports_url = f"{PBI_ADMIN_BASE}/reports"
                async for page in paginate_rest(
                    client, reports_url, self.headers,
                    next_link_key="@odata.nextLink",
                ):
                    await POWERBI_RATE_LIMITER.acquire()
                    for report in page:
                        resources.append(self._map_report(report))
            except Exception as e:
                errors.append(f"PBI reports: {e}")

            # List datasets via admin API
            try:
                datasets_url = f"{PBI_ADMIN_BASE}/datasets"
                async for page in paginate_rest(
                    client, datasets_url, self.headers,
                    next_link_key="@odata.nextLink",
                ):
                    await POWERBI_RATE_LIMITER.acquire()
                    for dataset in page:
                        resources.append(self._map_dataset(dataset))
            except Exception as e:
                errors.append(f"PBI datasets: {e}")

            # List apps
            try:
                apps_url = f"{PBI_ADMIN_BASE}/apps?$top=5000"
                resp = await client.get(apps_url, headers=self.headers)
                resp.raise_for_status()
                apps = resp.json().get("value", [])
                for app in apps:
                    resources.append(self._map_app(app))
            except Exception as e:
                errors.append(f"PBI apps: {e}")

        duration = time.monotonic() - start_time
        return ExtractResult(
            records=resources,
            errors=errors,
            record_count=len(resources),
            duration_seconds=duration,
            extractor_name="PowerBIExtractor",
        )

    def _map_workspace(self, ws: dict[str, Any]) -> dict[str, Any]:
        """Map PBI workspace to DimResource."""
        ws_id = ws.get("id", "")
        return {
            "resource_id": generate_surrogate_key("powerbi", ws_id),
            "tenant_id": self.tenant_id,
            "resource_guid": ws_id,
            "resource_type": "FABRIC_WORKSPACE",
            "name": ws.get("name", ""),
            "parent_id": None,
        }

    def _map_report(self, report: dict[str, Any]) -> dict[str, Any]:
        """Map PBI report to DimResource."""
        report_id = report.get("id", "")
        ws_id = report.get("workspaceId", "")
        return {
            "resource_id": generate_surrogate_key("powerbi", report_id),
            "tenant_id": self.tenant_id,
            "resource_guid": report_id,
            "resource_type": "REPORT",
            "name": report.get("name", ""),
            "parent_id": generate_surrogate_key("powerbi", ws_id) if ws_id else None,
        }

    def _map_dataset(self, dataset: dict[str, Any]) -> dict[str, Any]:
        """Map PBI dataset to DimResource."""
        dataset_id = dataset.get("id", "")
        ws_id = dataset.get("workspaceId", "")
        return {
            "resource_id": generate_surrogate_key("powerbi", dataset_id),
            "tenant_id": self.tenant_id,
            "resource_guid": dataset_id,
            "resource_type": "SEMANTIC_MODEL",
            "name": dataset.get("name", ""),
            "parent_id": generate_surrogate_key("powerbi", ws_id) if ws_id else None,
        }

    def _map_app(self, app: dict[str, Any]) -> dict[str, Any]:
        """Map PBI app to DimResource."""
        app_id = app.get("id", "")
        return {
            "resource_id": generate_surrogate_key("powerbi", app_id),
            "tenant_id": self.tenant_id,
            "resource_guid": app_id,
            "resource_type": "POWER_BI_APP",
            "name": app.get("name", ""),
            "parent_id": None,
        }
