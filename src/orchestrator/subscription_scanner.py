"""Subscription scanner — auto-discover and extract all resources in a subscription.

Given one or more subscription IDs, this module:
1. Uses Azure Resource Graph to discover all resources
2. Groups them by resource type (e.g. Microsoft.Sql/servers, Microsoft.KeyVault/vaults)
3. Automatically invokes the appropriate deep extractors for each discovered type
4. Returns a unified extraction result

Usage:
    scanner = SubscriptionScanner(credential, msal_client, tenant_id, snapshot_id, settings)
    results = await scanner.scan(["sub-id-1", "sub-id-2"])
"""
from __future__ import annotations

import time
from typing import Any, TYPE_CHECKING

import structlog

from src.extractors.base import ExtractResult
from src.utils.id_generator import generate_surrogate_key

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential
    from config.settings import EAIPSettings
    from src.auth.msal_client import MSALClient

logger = structlog.get_logger(__name__)

# ─────────────────────────────────────────────────────────────
# ARM resource type → EAIP extractor mapping
# ─────────────────────────────────────────────────────────────
# Each entry maps an ARM resource type (lowercased) to:
#   - extractor: module path + class name
#   - scope: "subscription" (once per sub) or "resource" (per instance)
#   - needs_token: "arm" | "graph" | "fabric" | None
RESOURCE_TYPE_REGISTRY: dict[str, dict[str, Any]] = {
    # --- SQL Server ---
    "microsoft.sql/servers": {
        "label": "SQL Server",
        "extractor_module": "src.extractors.sql.permissions",
        "extractor_class": "SQLServerExtractor",
        "scope": "subscription",
        "mode": "arm",
    },
    # --- Cosmos DB ---
    "microsoft.documentdb/databaseaccounts": {
        "label": "Cosmos DB",
        "extractor_module": "src.extractors.cosmosdb.permissions",
        "extractor_class": "CosmosDBExtractor",
        "scope": "subscription",
        "mode": "arm",
    },
    # --- Key Vault ---
    "microsoft.keyvault/vaults": {
        "label": "Key Vault",
        "extractor_module": "src.extractors.keyvault.vaults",
        "extractor_class": "KeyVaultExtractor",
        "scope": "subscription",
        "mode": "arm",
    },
    "microsoft.keyvault/vaults:deep": {
        "label": "Key Vault (deep)",
        "extractor_module": "src.extractors.keyvault.deep_permissions",
        "extractor_class": "KeyVaultDeepExtractor",
        "scope": "subscription",
        "mode": "arm",
    },
    # --- Storage ---
    "microsoft.storage/storageaccounts": {
        "label": "Storage Account",
        "extractor_module": "src.extractors.storage.accounts",
        "extractor_class": "StorageAccountExtractor",
        "scope": "subscription",
        "mode": "arm",
    },
    # --- Networking ---
    "microsoft.network/networksecuritygroups": {
        "label": "Network Security Groups",
        "extractor_module": "src.extractors.networking.access",
        "extractor_class": "NetworkAccessExtractor",
        "scope": "subscription",
        "mode": "arm",
    },
}


class SubscriptionScanner:
    """Auto-discover and extract all resources in given subscriptions.

    This is the "just give me a subscription" mode. It:
    1. Queries Azure Resource Graph for all resource types
    2. Matches them against RESOURCE_TYPE_REGISTRY
    3. Runs the appropriate deep extractor for each match
    4. Also runs Entra ID, RBAC, Fabric/PBI, SharePoint, Teams, AAS
       (cross-subscription services that don't require per-resource discovery)

    Args:
        credential: Azure SDK token credential.
        msal_client: MSAL client for Graph/Fabric token acquisition.
        tenant_id: Azure AD tenant GUID.
        snapshot_id: Current extraction snapshot ID.
        settings: Application settings.
    """

    def __init__(
        self,
        credential: TokenCredential,
        msal_client: MSALClient,
        tenant_id: str,
        snapshot_id: int,
        settings: EAIPSettings,
    ) -> None:
        self.credential = credential
        self.msal_client = msal_client
        self.tenant_id = tenant_id
        self.snapshot_id = snapshot_id
        self.settings = settings

    async def scan(self, subscription_ids: list[str]) -> dict[str, Any]:
        """Scan subscriptions — discover resources and extract permissions.

        Args:
            subscription_ids: One or more Azure subscription GUIDs.

        Returns:
            Summary dict with extraction results per service.
        """
        start_time = time.monotonic()
        results: dict[str, Any] = {}

        logger.info(
            "subscription_scan_started",
            subscription_count=len(subscription_ids),
            subscriptions=subscription_ids,
        )

        # ─────────────────────────────────────────────
        # Step 1: Discover all resources via Resource Graph
        # ─────────────────────────────────────────────
        discovered_types = await self._discover_resource_types(subscription_ids, results)

        # ─────────────────────────────────────────────
        # Step 2: Extract Entra ID (always — not subscription-scoped)
        # ─────────────────────────────────────────────
        await self._extract_entra(results)

        # ─────────────────────────────────────────────
        # Step 3: Extract Azure RBAC (subscriptions, MGs, role defs, assignments)
        # ─────────────────────────────────────────────
        await self._extract_azure_rbac(subscription_ids, results)

        # ─────────────────────────────────────────────
        # Step 4: Auto-extract discovered resource types
        # ─────────────────────────────────────────────
        await self._extract_discovered_resources(subscription_ids, discovered_types, results)

        # ─────────────────────────────────────────────
        # Step 5: Extract Fabric / Power BI (tenant-wide, not sub-scoped)
        # ─────────────────────────────────────────────
        await self._extract_fabric(results)

        # ─────────────────────────────────────────────
        # Step 6: Extract SharePoint + Teams (tenant-wide via Graph)
        # ─────────────────────────────────────────────
        await self._extract_sharepoint_teams(results)

        # ─────────────────────────────────────────────
        # Step 7: Extract Analysis Services (if configured)
        # ─────────────────────────────────────────────
        await self._extract_aas(results)

        duration = time.monotonic() - start_time
        results["_scan_duration_seconds"] = round(duration, 2)
        results["_subscriptions_scanned"] = subscription_ids
        results["_discovered_resource_types"] = list(discovered_types.keys())

        logger.info(
            "subscription_scan_complete",
            duration=results["_scan_duration_seconds"],
            resource_types_discovered=len(discovered_types),
            extractors_matched=sum(
                1 for t in discovered_types if t.lower() in RESOURCE_TYPE_REGISTRY
            ),
        )
        return results

    # ─────────────────────────────────────────────────────────────
    # Internal: Resource Discovery
    # ─────────────────────────────────────────────────────────────

    async def _discover_resource_types(
        self,
        subscription_ids: list[str],
        results: dict[str, Any],
    ) -> dict[str, int]:
        """Use Resource Graph to discover all resource types and their counts.

        Returns:
            Dict mapping ARM resource type (lowercase) → count.
        """
        discovered: dict[str, int] = {}

        try:
            from azure.mgmt.resourcegraph import ResourceGraphClient
            from azure.mgmt.resourcegraph.models import (
                QueryRequest,
                QueryRequestOptions,
                ResultFormat,
            )

            client = ResourceGraphClient(self.credential)

            query = QueryRequest(
                subscriptions=subscription_ids,
                query="Resources | summarize count() by type | order by count_ desc",
                options=QueryRequestOptions(result_format=ResultFormat.OBJECT_ARRAY),
            )

            response = client.resources(query)

            for row in response.data:
                resource_type = row.get("type", "").lower()
                count = row.get("count_", 0)
                discovered[resource_type] = count

            # Also run full resource extraction
            from src.extractors.azure_rbac.resources import ResourceGraphExtractor
            rg_ext = ResourceGraphExtractor(
                self.credential, self.tenant_id, self.snapshot_id, subscription_ids
            )
            rg_result = rg_ext.extract()
            results["resource_graph"] = {
                "count": rg_result.record_count,
                "errors": rg_result.errors,
            }

            logger.info(
                "resource_discovery_complete",
                total_types=len(discovered),
                total_resources=sum(discovered.values()),
                types_with_extractors=sum(
                    1 for t in discovered if t in RESOURCE_TYPE_REGISTRY
                ),
            )

        except Exception as e:
            results["resource_discovery"] = {"error": str(e)}
            logger.error("resource_discovery_failed", error=str(e))

        results["_discovered_types_summary"] = {
            k: v for k, v in sorted(discovered.items(), key=lambda x: -x[1])
        }
        return discovered

    # ─────────────────────────────────────────────────────────────
    # Internal: Entra ID
    # ─────────────────────────────────────────────────────────────

    async def _extract_entra(self, results: dict[str, Any]) -> None:
        """Extract Entra ID objects (users, groups, memberships, roles, SPs)."""
        try:
            from config.scopes import GRAPH_DELEGATED_SCOPES
            graph_token = self.msal_client.get_token(GRAPH_DELEGATED_SCOPES)

            from src.extractors.entra.users import UserExtractor
            from src.extractors.entra.groups import GroupExtractor
            from src.extractors.entra.memberships import MembershipExtractor
            from src.extractors.entra.roles import DirectoryRoleExtractor
            from src.extractors.entra.service_principals import ServicePrincipalExtractor

            extractors = [
                ("users", UserExtractor(self.tenant_id, graph_token, self.snapshot_id)),
                ("groups", GroupExtractor(self.tenant_id, graph_token, self.snapshot_id)),
                ("memberships", MembershipExtractor(self.tenant_id, graph_token, self.snapshot_id)),
                ("directory_roles", DirectoryRoleExtractor(self.tenant_id, graph_token, self.snapshot_id)),
                ("service_principals", ServicePrincipalExtractor(self.tenant_id, graph_token, self.snapshot_id)),
            ]

            for name, extractor in extractors:
                try:
                    result = await extractor.extract()
                    results[name] = {
                        "count": result.record_count,
                        "errors": result.errors,
                        "duration": result.duration_seconds,
                    }
                    logger.info(f"extracted_{name}", count=result.record_count)
                except Exception as e:
                    results[name] = {"error": str(e)}
                    logger.error(f"extraction_failed_{name}", error=str(e))

        except Exception as e:
            results["entra"] = {"error": str(e)}
            logger.error("entra_extraction_failed", error=str(e))

    # ─────────────────────────────────────────────────────────────
    # Internal: Azure RBAC
    # ─────────────────────────────────────────────────────────────

    async def _extract_azure_rbac(
        self,
        subscription_ids: list[str],
        results: dict[str, Any],
    ) -> None:
        """Extract subscriptions, MGs, role definitions, and role assignments."""
        try:
            from src.extractors.azure_rbac.subscriptions import SubscriptionExtractor
            from src.extractors.azure_rbac.management_groups import ManagementGroupExtractor
            from src.extractors.azure_rbac.role_definitions import RoleDefinitionExtractor
            from src.extractors.azure_rbac.role_assignments import RoleAssignmentExtractor

            # Subscriptions + resource groups
            sub_ext = SubscriptionExtractor(self.credential, self.tenant_id, self.snapshot_id)
            sub_result = sub_ext.extract()
            results["subscriptions"] = {"count": sub_result.record_count, "errors": sub_result.errors}

            # Management groups
            try:
                mg_ext = ManagementGroupExtractor(self.credential, self.tenant_id, self.snapshot_id)
                mg_result = mg_ext.extract()
                results["management_groups"] = {"count": mg_result.record_count, "errors": mg_result.errors}
            except Exception as e:
                results["management_groups"] = {"error": str(e)}

            # Role definitions + assignments per subscription
            for sub_id in subscription_ids:
                scope = f"/subscriptions/{sub_id}"
                try:
                    rd_ext = RoleDefinitionExtractor(self.credential, self.tenant_id, self.snapshot_id)
                    rd_result = rd_ext.extract(scope)
                    results.setdefault("role_definitions", {"count": 0, "errors": []})
                    results["role_definitions"]["count"] += rd_result.record_count
                    results["role_definitions"]["errors"].extend(rd_result.errors)
                except Exception as e:
                    results.setdefault("role_definitions", {"errors": []})
                    results["role_definitions"]["errors"].append(str(e))

                try:
                    ra_ext = RoleAssignmentExtractor(self.credential, self.tenant_id, self.snapshot_id)
                    ra_result = ra_ext.extract(scope)
                    results.setdefault("role_assignments", {"count": 0, "errors": []})
                    results["role_assignments"]["count"] += ra_result.record_count
                    results["role_assignments"]["errors"].extend(ra_result.errors)
                except Exception as e:
                    results.setdefault("role_assignments", {"errors": []})
                    results["role_assignments"]["errors"].append(str(e))

        except Exception as e:
            results["azure_rbac"] = {"error": str(e)}
            logger.error("azure_rbac_failed", error=str(e))

    # ─────────────────────────────────────────────────────────────
    # Internal: Auto-extract discovered resource types
    # ─────────────────────────────────────────────────────────────

    async def _extract_discovered_resources(
        self,
        subscription_ids: list[str],
        discovered_types: dict[str, int],
        results: dict[str, Any],
    ) -> None:
        """For each discovered ARM resource type, invoke the matching extractor.

        This is the core "smart scan" logic: if we find SQL servers in the
        subscription, we automatically run the SQL deep extractor, etc.
        """
        import importlib

        matched_extractors: list[tuple[str, dict[str, Any]]] = []

        # Match discovered types to registry
        for arm_type, count in discovered_types.items():
            registry_key = arm_type.lower()
            if registry_key in RESOURCE_TYPE_REGISTRY:
                entry = RESOURCE_TYPE_REGISTRY[registry_key]
                matched_extractors.append((registry_key, entry))
                logger.info(
                    "extractor_matched",
                    resource_type=arm_type,
                    count=count,
                    extractor=entry["label"],
                )

            # Check for ":deep" companion extractors
            deep_key = f"{registry_key}:deep"
            if deep_key in RESOURCE_TYPE_REGISTRY:
                matched_extractors.append((deep_key, RESOURCE_TYPE_REGISTRY[deep_key]))

        # Also always add networking if NSGs or private endpoints are found
        networking_types = [
            "microsoft.network/networksecuritygroups",
            "microsoft.network/privateendpoints",
            "microsoft.network/virtualnetworks",
        ]
        has_networking = any(t in discovered_types for t in networking_types)
        if has_networking and "microsoft.network/networksecuritygroups" not in [m[0] for m in matched_extractors]:
            if "microsoft.network/networksecuritygroups" in RESOURCE_TYPE_REGISTRY:
                matched_extractors.append((
                    "microsoft.network/networksecuritygroups",
                    RESOURCE_TYPE_REGISTRY["microsoft.network/networksecuritygroups"],
                ))

        if not matched_extractors:
            logger.info("no_extractors_matched", discovered_types=list(discovered_types.keys()))
            return

        logger.info(
            "auto_extracting",
            matched_count=len(matched_extractors),
            types=[e[1]["label"] for e in matched_extractors],
        )

        # Execute matched extractors
        for registry_key, entry in matched_extractors:
            label = entry["label"]
            result_key = label.lower().replace(" ", "_").replace("(", "").replace(")", "")

            try:
                module = importlib.import_module(entry["extractor_module"])
                extractor_cls = getattr(module, entry["extractor_class"])

                for sub_id in subscription_ids:
                    try:
                        if entry["mode"] == "arm":
                            # ARM-based extractors: __init__(credential, tenant_id, snapshot_id)
                            ext = extractor_cls(self.credential, self.tenant_id, self.snapshot_id)

                            # Check if extract takes subscription_id param
                            import inspect
                            sig = inspect.signature(ext.extract)
                            if "subscription_id" in sig.parameters:
                                ext_result = ext.extract(sub_id)
                            elif len(sig.parameters) >= 1:
                                # Some extractors have extract(scope) or extract(sub_id)
                                ext_result = ext.extract(sub_id)
                            else:
                                ext_result = ext.extract()

                            results.setdefault(result_key, {"count": 0, "errors": []})
                            results[result_key]["count"] += ext_result.record_count
                            results[result_key]["errors"].extend(ext_result.errors)
                    except Exception as e:
                        results.setdefault(result_key, {"count": 0, "errors": []})
                        results[result_key]["errors"].append(f"{sub_id}: {str(e)}")
                        logger.warning(
                            "extractor_error",
                            label=label,
                            subscription=sub_id,
                            error=str(e),
                        )

                logger.info(f"auto_extracted_{result_key}", result=results.get(result_key))

            except Exception as e:
                results[result_key] = {"error": str(e)}
                logger.error("extractor_import_failed", label=label, error=str(e))

    # ─────────────────────────────────────────────────────────────
    # Internal: Fabric / Power BI
    # ─────────────────────────────────────────────────────────────

    async def _extract_fabric(self, results: dict[str, Any]) -> None:
        """Extract Fabric workspaces and deep Power BI permissions."""
        try:
            from config.scopes import FABRIC_SCOPES
            fabric_token = self.msal_client.get_token(FABRIC_SCOPES)

            from src.extractors.fabric.workspaces import FabricWorkspaceExtractor
            fabric_ext = FabricWorkspaceExtractor(self.tenant_id, fabric_token, self.snapshot_id)
            fabric_result = await fabric_ext.extract()
            results["fabric_workspaces"] = {"count": fabric_result.record_count, "errors": fabric_result.errors}

            from src.extractors.fabric.powerbi_permissions import PowerBIDeepPermissionsExtractor
            pbi_deep = PowerBIDeepPermissionsExtractor(self.tenant_id, fabric_token, self.snapshot_id)
            pbi_deep_result = await pbi_deep.extract()
            results["pbi_deep_permissions"] = {"count": pbi_deep_result.record_count, "errors": pbi_deep_result.errors}

            from src.extractors.fabric.item_permissions import FabricItemPermissionsExtractor
            item_ext = FabricItemPermissionsExtractor(self.tenant_id, fabric_token, self.snapshot_id)
            item_result = await item_ext.extract()
            results["fabric_item_permissions"] = {"count": item_result.record_count, "errors": item_result.errors}

            from src.extractors.fabric.powerbi import PowerBIExtractor
            pbi_ext = PowerBIExtractor(self.tenant_id, fabric_token, self.snapshot_id)
            pbi_result = await pbi_ext.extract()
            results["pbi_resources"] = {"count": pbi_result.record_count, "errors": pbi_result.errors}

        except Exception as e:
            results["fabric"] = {"error": str(e)}
            logger.warning("fabric_extraction_skipped", error=str(e))

    # ─────────────────────────────────────────────────────────────
    # Internal: SharePoint + Teams
    # ─────────────────────────────────────────────────────────────

    async def _extract_sharepoint_teams(self, results: dict[str, Any]) -> None:
        """Extract SharePoint site permissions and Teams membership."""
        try:
            from config.scopes import GRAPH_DELEGATED_SCOPES
            graph_token = self.msal_client.get_token(GRAPH_DELEGATED_SCOPES)

            if self.settings.extract_sharepoint:
                try:
                    from src.extractors.sharepoint.permissions import SharePointPermissionsExtractor
                    sp_ext = SharePointPermissionsExtractor(self.tenant_id, graph_token, self.snapshot_id)
                    sp_result = await sp_ext.extract()
                    results["sharepoint"] = {"count": sp_result.record_count, "errors": sp_result.errors}
                except Exception as e:
                    results["sharepoint"] = {"error": str(e)}

            if self.settings.extract_teams:
                try:
                    from src.extractors.sharepoint.teams import TeamsPermissionsExtractor
                    teams_ext = TeamsPermissionsExtractor(self.tenant_id, graph_token, self.snapshot_id)
                    teams_result = await teams_ext.extract()
                    results["teams"] = {"count": teams_result.record_count, "errors": teams_result.errors}
                except Exception as e:
                    results["teams"] = {"error": str(e)}

        except Exception as e:
            results["sharepoint_teams"] = {"error": str(e)}
            logger.warning("sharepoint_teams_skipped", error=str(e))

    # ─────────────────────────────────────────────────────────────
    # Internal: Analysis Services
    # ─────────────────────────────────────────────────────────────

    async def _extract_aas(self, results: dict[str, Any]) -> None:
        """Extract AAS/XMLA databases, roles, and RLS if servers are configured."""
        if not self.settings.aas_servers:
            return

        for server_url in self.settings.aas_servers:
            try:
                aas_token = self.msal_client.get_token(
                    ["https://analysis.windows.net/powerbi/api/.default"]
                )
                from src.extractors.aas.models import AnalysisServicesExtractor
                aas_ext = AnalysisServicesExtractor(
                    server_url, aas_token, self.tenant_id, self.snapshot_id
                )
                aas_result = await aas_ext.extract()
                results.setdefault("analysis_services", {"count": 0, "errors": []})
                results["analysis_services"]["count"] += aas_result.record_count
                results["analysis_services"]["errors"].extend(aas_result.errors)
            except Exception as e:
                results.setdefault("analysis_services", {"errors": []})
                results["analysis_services"]["errors"].append(str(e))
