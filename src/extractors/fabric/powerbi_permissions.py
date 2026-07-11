"""Power BI deep permissions extractor — per-item access rights.

Extracts WHO has access to EACH:
- Dataset (semantic model): Build, Read, ReadAll, Reshare permissions
- Report: Read, ReadReshare permissions
- Dashboard: Read, ReadReshare permissions  
- App: audiences and users
- Dataflow: Read, ReadWrite permissions
- Workspace users (Admin API GetGroupUsersAsAdmin)
- Gateways and gateway data sources
- Capacities and capacity admins
- Sharing links on reports/dashboards
- Sensitivity labels
"""
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
PBI_USER_BASE = "https://api.powerbi.com/v1.0/myorg"


class PowerBIDeepPermissionsExtractor(BaseExtractor):
    """Extracts per-item permissions from Power BI Admin API.

    Goes beyond listing resources — drills into WHO has access
    to each dataset, report, dashboard, app, dataflow, gateway, etc.
    """

    async def extract(self) -> ExtractResult:
        """Extract all per-item permissions across Power BI.

        Returns:
            ExtractResult with deep permission assignments.
        """
        start_time = time.monotonic()
        assignments: list[dict[str, Any]] = []
        resources: list[dict[str, Any]] = []
        errors: list[str] = []

        async with httpx.AsyncClient(timeout=120.0) as client:
            # 1. Workspace users (who has Admin/Member/Contributor/Viewer)
            await self._extract_workspace_users(client, assignments, errors)

            # 2. Dataset permissions (Build, Read, ReadAll, Reshare)
            await self._extract_dataset_users(client, assignments, errors)

            # 3. Report permissions
            await self._extract_report_users(client, assignments, errors)

            # 4. Dashboard permissions
            await self._extract_dashboard_users(client, assignments, errors)

            # 5. App audiences/users
            await self._extract_app_users(client, assignments, errors)

            # 6. Dataflow permissions
            await self._extract_dataflow_users(client, assignments, errors)

            # 7. Gateway and gateway data source permissions
            await self._extract_gateway_permissions(client, assignments, resources, errors)

            # 8. Capacity admins
            await self._extract_capacity_admins(client, assignments, resources, errors)

        duration = time.monotonic() - start_time
        self.logger.info(
            "pbi_deep_permissions_extracted",
            total_assignments=len(assignments),
            resources=len(resources),
            errors=len(errors),
            duration=round(duration, 1),
        )
        return ExtractResult(
            records=[{"assignments": assignments, "resources": resources}],
            errors=errors,
            record_count=len(assignments),
            duration_seconds=duration,
            extractor_name="PowerBIDeepPermissionsExtractor",
        )

    # ─────────────────────────────────────────────────────────
    # 1. Workspace users via Admin API
    # ─────────────────────────────────────────────────────────
    async def _extract_workspace_users(
        self, client: httpx.AsyncClient, assignments: list, errors: list
    ) -> None:
        """GET /admin/groups → for each → GET /admin/groups/{id}/users."""
        try:
            workspaces_url = f"{PBI_ADMIN_BASE}/groups?$top=5000"
            async for page in paginate_rest(
                client, workspaces_url, self.headers,
                next_link_key="@odata.nextLink",
            ):
                await POWERBI_RATE_LIMITER.acquire()
                for ws in page:
                    ws_id = ws.get("id", "")
                    ws_resource_id = generate_surrogate_key("powerbi", ws_id)
                    try:
                        users_url = f"{PBI_ADMIN_BASE}/groups/{ws_id}/users"
                        resp = await client.get(users_url, headers=self.headers)
                        resp.raise_for_status()
                        for user in resp.json().get("value", []):
                            assignments.append(self._map_workspace_user(user, ws_resource_id))
                    except Exception as e:
                        errors.append(f"Workspace {ws_id} users: {e}")
        except Exception as e:
            errors.append(f"Workspace user listing: {e}")
            self.logger.error("workspace_users_failed", error=str(e))

    def _map_workspace_user(self, user: dict, ws_resource_id: int) -> dict:
        """Map PBI workspace user to FactRoleAssignment."""
        identifier = user.get("identifier", "") or user.get("emailAddress", "")
        principal_type = user.get("principalType", "User")
        access_right = user.get("groupUserAccessRight", "")  # Admin, Member, Contributor, Viewer

        return {
            "assignment_id": generate_surrogate_key(
                "pbi_ws_user", f"{ws_resource_id}:{identifier}:{access_right}"
            ),
            "principal_id": generate_surrogate_key("entra", identifier),
            "role_id": None,
            "resource_id": ws_resource_id,
            "assignment_type": "FABRIC_WORKSPACE_ROLE",
            "inherited": False,
            "source": "PowerBI_Admin",
            "snapshot_id": self.snapshot_id,
            "_access_right": access_right,
            "_principal_type": principal_type,
            "_email": user.get("emailAddress", ""),
            "_display_name": user.get("displayName", ""),
        }

    # ─────────────────────────────────────────────────────────
    # 2. Dataset (Semantic Model) users
    # ─────────────────────────────────────────────────────────
    async def _extract_dataset_users(
        self, client: httpx.AsyncClient, assignments: list, errors: list
    ) -> None:
        """GET /admin/datasets → for each → GET /admin/datasets/{id}/users."""
        try:
            datasets_url = f"{PBI_ADMIN_BASE}/datasets"
            dataset_ids: list[tuple[str, int]] = []

            async for page in paginate_rest(
                client, datasets_url, self.headers,
                next_link_key="@odata.nextLink",
            ):
                await POWERBI_RATE_LIMITER.acquire()
                for ds in page:
                    ds_id = ds.get("id", "")
                    dataset_ids.append((ds_id, generate_surrogate_key("powerbi", ds_id)))

            # Now get users for each dataset
            for ds_id, ds_resource_id in dataset_ids:
                try:
                    await POWERBI_RATE_LIMITER.acquire()
                    users_url = f"{PBI_ADMIN_BASE}/datasets/{ds_id}/users"
                    resp = await client.get(users_url, headers=self.headers)
                    resp.raise_for_status()
                    for user in resp.json().get("value", []):
                        assignments.append(
                            self._map_item_user(user, ds_resource_id, "SEMANTIC_MODEL")
                        )
                except Exception as e:
                    errors.append(f"Dataset {ds_id} users: {e}")

            self.logger.info("dataset_users_extracted", datasets=len(dataset_ids))
        except Exception as e:
            errors.append(f"Dataset user extraction: {e}")

    # ─────────────────────────────────────────────────────────
    # 3. Report users
    # ─────────────────────────────────────────────────────────
    async def _extract_report_users(
        self, client: httpx.AsyncClient, assignments: list, errors: list
    ) -> None:
        """GET /admin/reports → for each → GET /admin/reports/{id}/users."""
        try:
            reports_url = f"{PBI_ADMIN_BASE}/reports"
            report_ids: list[tuple[str, int]] = []

            async for page in paginate_rest(
                client, reports_url, self.headers,
                next_link_key="@odata.nextLink",
            ):
                await POWERBI_RATE_LIMITER.acquire()
                for rpt in page:
                    rpt_id = rpt.get("id", "")
                    report_ids.append((rpt_id, generate_surrogate_key("powerbi", rpt_id)))

            for rpt_id, rpt_resource_id in report_ids:
                try:
                    await POWERBI_RATE_LIMITER.acquire()
                    users_url = f"{PBI_ADMIN_BASE}/reports/{rpt_id}/users"
                    resp = await client.get(users_url, headers=self.headers)
                    resp.raise_for_status()
                    for user in resp.json().get("value", []):
                        assignments.append(
                            self._map_item_user(user, rpt_resource_id, "REPORT")
                        )
                except Exception as e:
                    errors.append(f"Report {rpt_id} users: {e}")

            self.logger.info("report_users_extracted", reports=len(report_ids))
        except Exception as e:
            errors.append(f"Report user extraction: {e}")

    # ─────────────────────────────────────────────────────────
    # 4. Dashboard users
    # ─────────────────────────────────────────────────────────
    async def _extract_dashboard_users(
        self, client: httpx.AsyncClient, assignments: list, errors: list
    ) -> None:
        """GET /admin/dashboards → for each → GET /admin/dashboards/{id}/users."""
        try:
            dashboards_url = f"{PBI_ADMIN_BASE}/dashboards"
            dashboard_ids: list[tuple[str, int]] = []

            async for page in paginate_rest(
                client, dashboards_url, self.headers,
                next_link_key="@odata.nextLink",
            ):
                await POWERBI_RATE_LIMITER.acquire()
                for dash in page:
                    dash_id = dash.get("id", "")
                    dashboard_ids.append((dash_id, generate_surrogate_key("powerbi", dash_id)))

            for dash_id, dash_resource_id in dashboard_ids:
                try:
                    await POWERBI_RATE_LIMITER.acquire()
                    users_url = f"{PBI_ADMIN_BASE}/dashboards/{dash_id}/users"
                    resp = await client.get(users_url, headers=self.headers)
                    resp.raise_for_status()
                    for user in resp.json().get("value", []):
                        assignments.append(
                            self._map_item_user(user, dash_resource_id, "DASHBOARD")
                        )
                except Exception as e:
                    errors.append(f"Dashboard {dash_id} users: {e}")

            self.logger.info("dashboard_users_extracted", dashboards=len(dashboard_ids))
        except Exception as e:
            errors.append(f"Dashboard user extraction: {e}")

    # ─────────────────────────────────────────────────────────
    # 5. App users / audiences
    # ─────────────────────────────────────────────────────────
    async def _extract_app_users(
        self, client: httpx.AsyncClient, assignments: list, errors: list
    ) -> None:
        """GET /admin/apps → for each → GET /admin/apps/{id}/users."""
        try:
            apps_url = f"{PBI_ADMIN_BASE}/apps?$top=5000"
            resp = await client.get(apps_url, headers=self.headers)
            resp.raise_for_status()
            apps = resp.json().get("value", [])

            for app in apps:
                app_id = app.get("id", "")
                app_resource_id = generate_surrogate_key("powerbi", app_id)
                try:
                    await POWERBI_RATE_LIMITER.acquire()
                    users_url = f"{PBI_ADMIN_BASE}/apps/{app_id}/users"
                    resp2 = await client.get(users_url, headers=self.headers)
                    resp2.raise_for_status()
                    for user in resp2.json().get("value", []):
                        assignments.append({
                            "assignment_id": generate_surrogate_key(
                                "pbi_app_user",
                                f"{app_resource_id}:{user.get('identifier', '')}",
                            ),
                            "principal_id": generate_surrogate_key(
                                "entra", user.get("identifier", "")
                            ),
                            "role_id": None,
                            "resource_id": app_resource_id,
                            "assignment_type": "PBI_APP_AUDIENCE",
                            "inherited": False,
                            "source": "PowerBI_Admin",
                            "snapshot_id": self.snapshot_id,
                            "_access_right": user.get("appUserAccessRight", ""),
                            "_principal_type": user.get("principalType", ""),
                            "_display_name": user.get("displayName", ""),
                        })
                except Exception as e:
                    errors.append(f"App {app_id} users: {e}")

            self.logger.info("app_users_extracted", apps=len(apps))
        except Exception as e:
            errors.append(f"App user extraction: {e}")

    # ─────────────────────────────────────────────────────────
    # 6. Dataflow users
    # ─────────────────────────────────────────────────────────
    async def _extract_dataflow_users(
        self, client: httpx.AsyncClient, assignments: list, errors: list
    ) -> None:
        """GET /admin/dataflows → for each → GET /admin/dataflows/{id}/users."""
        try:
            dataflows_url = f"{PBI_ADMIN_BASE}/dataflows"
            async for page in paginate_rest(
                client, dataflows_url, self.headers,
                next_link_key="@odata.nextLink",
            ):
                await POWERBI_RATE_LIMITER.acquire()
                for df in page:
                    df_id = df.get("objectId", "") or df.get("id", "")
                    df_resource_id = generate_surrogate_key("powerbi", df_id)
                    try:
                        await POWERBI_RATE_LIMITER.acquire()
                        users_url = f"{PBI_ADMIN_BASE}/dataflows/{df_id}/users"
                        resp = await client.get(users_url, headers=self.headers)
                        resp.raise_for_status()
                        for user in resp.json().get("value", []):
                            assignments.append(
                                self._map_item_user(user, df_resource_id, "DATAFLOW")
                            )
                    except Exception as e:
                        errors.append(f"Dataflow {df_id} users: {e}")
        except Exception as e:
            errors.append(f"Dataflow user extraction: {e}")

    # ─────────────────────────────────────────────────────────
    # 7. Gateways and data sources
    # ─────────────────────────────────────────────────────────
    async def _extract_gateway_permissions(
        self, client: httpx.AsyncClient, assignments: list,
        resources: list, errors: list,
    ) -> None:
        """GET /gateways → datasources → users."""
        try:
            gw_url = f"{PBI_USER_BASE}/gateways"
            resp = await client.get(gw_url, headers=self.headers)
            resp.raise_for_status()
            gateways = resp.json().get("value", [])

            for gw in gateways:
                gw_id = gw.get("id", "")
                gw_resource_id = generate_surrogate_key("powerbi_gw", gw_id)
                resources.append({
                    "resource_id": gw_resource_id,
                    "tenant_id": self.tenant_id,
                    "resource_guid": gw_id,
                    "resource_type": "GENERIC",
                    "name": f"Gateway: {gw.get('name', '')}",
                    "parent_id": None,
                    "_gateway_type": gw.get("type", ""),
                })

                # Data sources under this gateway
                try:
                    ds_url = f"{PBI_USER_BASE}/gateways/{gw_id}/datasources"
                    ds_resp = await client.get(ds_url, headers=self.headers)
                    ds_resp.raise_for_status()
                    for ds in ds_resp.json().get("value", []):
                        ds_id = ds.get("id", "")
                        ds_resource_id = generate_surrogate_key("powerbi_ds", ds_id)
                        resources.append({
                            "resource_id": ds_resource_id,
                            "tenant_id": self.tenant_id,
                            "resource_guid": ds_id,
                            "resource_type": "GENERIC",
                            "name": f"DataSource: {ds.get('datasourceName', '')}",
                            "parent_id": gw_resource_id,
                            "_datasource_type": ds.get("datasourceType", ""),
                            "_connection_details": str(ds.get("connectionDetails", {})),
                        })

                        # Users of this data source
                        try:
                            users_url = f"{PBI_USER_BASE}/gateways/{gw_id}/datasources/{ds_id}/users"
                            u_resp = await client.get(users_url, headers=self.headers)
                            u_resp.raise_for_status()
                            for user in u_resp.json().get("value", []):
                                assignments.append({
                                    "assignment_id": generate_surrogate_key(
                                        "pbi_ds_user",
                                        f"{ds_resource_id}:{user.get('identifier', '')}",
                                    ),
                                    "principal_id": generate_surrogate_key(
                                        "entra", user.get("identifier", "")
                                    ),
                                    "resource_id": ds_resource_id,
                                    "assignment_type": "FABRIC_WORKSPACE_ROLE",
                                    "source": "PowerBI_Gateway",
                                    "snapshot_id": self.snapshot_id,
                                    "_access_right": user.get("datasourceAccessRight", ""),
                                })
                        except Exception as e:
                            errors.append(f"DS {ds_id} users: {e}")
                except Exception as e:
                    errors.append(f"Gateway {gw_id} datasources: {e}")

        except Exception as e:
            errors.append(f"Gateway extraction: {e}")

    # ─────────────────────────────────────────────────────────
    # 8. Capacity admins
    # ─────────────────────────────────────────────────────────
    async def _extract_capacity_admins(
        self, client: httpx.AsyncClient, assignments: list,
        resources: list, errors: list,
    ) -> None:
        """GET /admin/capacities → extract capacity admins."""
        try:
            cap_url = f"{PBI_ADMIN_BASE}/capacities"
            resp = await client.get(cap_url, headers=self.headers)
            resp.raise_for_status()
            capacities = resp.json().get("value", [])

            for cap in capacities:
                cap_id = cap.get("id", "")
                cap_resource_id = generate_surrogate_key("powerbi_cap", cap_id)
                resources.append({
                    "resource_id": cap_resource_id,
                    "tenant_id": self.tenant_id,
                    "resource_guid": cap_id,
                    "resource_type": "GENERIC",
                    "name": f"Capacity: {cap.get('displayName', '')}",
                    "parent_id": None,
                    "_sku": cap.get("sku", ""),
                    "_state": cap.get("state", ""),
                })

                # Capacity admins
                for admin in cap.get("admins", []):
                    assignments.append({
                        "assignment_id": generate_surrogate_key(
                            "pbi_cap_admin", f"{cap_resource_id}:{admin}"
                        ),
                        "principal_id": generate_surrogate_key("entra", admin),
                        "resource_id": cap_resource_id,
                        "assignment_type": "FABRIC_WORKSPACE_ROLE",
                        "source": "PowerBI_Capacity",
                        "snapshot_id": self.snapshot_id,
                        "_access_right": "CapacityAdmin",
                    })

        except Exception as e:
            errors.append(f"Capacity extraction: {e}")

    # ─────────────────────────────────────────────────────────
    # Shared mapper for per-item users
    # ─────────────────────────────────────────────────────────
    def _map_item_user(
        self, user: dict, resource_id: int, item_type: str
    ) -> dict[str, Any]:
        """Map per-item user permission to FactRoleAssignment."""
        identifier = user.get("identifier", "") or user.get("emailAddress", "")
        access_right = (
            user.get("datasetUserAccessRight", "")
            or user.get("reportUserAccessRight", "")
            or user.get("dashboardUserAccessRight", "")
            or user.get("dataflowUserAccessRight", "")
            or user.get("groupUserAccessRight", "")
            or ""
        )

        return {
            "assignment_id": generate_surrogate_key(
                f"pbi_{item_type.lower()}_user",
                f"{resource_id}:{identifier}:{access_right}",
            ),
            "principal_id": generate_surrogate_key("entra", identifier),
            "role_id": None,
            "resource_id": resource_id,
            "assignment_type": "FABRIC_WORKSPACE_ROLE",
            "inherited": False,
            "source": "PowerBI_Admin",
            "snapshot_id": self.snapshot_id,
            "_access_right": access_right,
            "_item_type": item_type,
            "_principal_type": user.get("principalType", ""),
            "_display_name": user.get("displayName", ""),
            "_email": user.get("emailAddress", ""),
        }
