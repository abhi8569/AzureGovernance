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
    # NOTE: SQL Server is NOT here — it has its own dedicated deep extraction
    # step in scan() that discovers servers, lists databases, and deep-extracts
    # each one via T-SQL with Azure AD token auth.

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
        self.resource_groups = getattr(settings, "resource_groups", [])

    def _is_rg_allowed(self, value: str | dict[str, Any]) -> bool:
        if not self.resource_groups:
            return True

        if isinstance(value, str):
            val_str = value
        elif isinstance(value, dict):
            rg = value.get("resource_group") or value.get("resourceGroup")
            if rg:
                return rg.lower() in [r.lower() for r in self.resource_groups]
            val_str = ""
            for key in ["resource_guid", "resource_id", "id", "scope", "resourceGroup"]:
                if key in value and isinstance(value[key], str):
                    val_str = value[key]
                    break
        else:
            return True

        if "/resourceGroups/" in val_str:
            parts = val_str.split("/")
            try:
                rg_idx = parts.index("resourceGroups")
                rg_name = parts[rg_idx + 1]
                return rg_name.lower() in [r.lower() for r in self.resource_groups]
            except (ValueError, IndexError):
                pass

        return True

    def _filter_records_by_rg(self, records: list[Any]) -> list[Any]:
        if not self.resource_groups:
            return records

        filtered = []
        for rec in records:
            if isinstance(rec, dict):
                new_rec = {}
                is_resource_list_holder = False
                for k, v in rec.items():
                    if isinstance(v, list) and k in ["resources", "assignments", "role_assignments", "permission_assignments", "rls_policies", "ddm_rules", "firewall_rules", "databases"]:
                        is_resource_list_holder = True
                        new_rec[k] = self._filter_records_by_rg(v)
                    else:
                        new_rec[k] = v
                if is_resource_list_holder:
                    filtered.append(new_rec)
                elif self._is_rg_allowed(rec):
                    filtered.append(rec)
            else:
                filtered.append(rec)
        return filtered

    def _add_result(self, results: dict[str, Any], name: str, result: Any) -> None:
        raw_records = getattr(result, "records", [])
        filtered_records = self._filter_records_by_rg(raw_records)
        results[name] = {
            "records": filtered_records,
            "count": len(filtered_records),
            "errors": getattr(result, "errors", []),
            "duration": getattr(result, "duration_seconds", 0.0),
        }

    def _append_result(self, results: dict[str, Any], name: str, result: Any) -> None:
        raw_records = getattr(result, "records", [])
        filtered_records = self._filter_records_by_rg(raw_records)
        results.setdefault(name, {"count": 0, "errors": [], "records": []})
        results[name]["count"] += len(filtered_records)
        results[name]["errors"].extend(getattr(result, "errors", []))
        results[name]["records"].extend(filtered_records)

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
        # Step 4: SQL Server deep extraction (mandatory — not optional)
        #   Auto-discovers SQL servers in each subscription,
        #   lists databases via ARM, then T-SQL deep-extracts each.
        # ─────────────────────────────────────────────
        await self._extract_sql_deep(subscription_ids, results)

        # ─────────────────────────────────────────────
        # Step 5: Auto-extract other discovered resource types
        # ─────────────────────────────────────────────
        await self._extract_discovered_resources(subscription_ids, discovered_types, results)

        # ─────────────────────────────────────────────
        # Step 6: Extract Fabric / Power BI (tenant-wide, not sub-scoped)
        # ─────────────────────────────────────────────
        await self._extract_fabric(results)

        # ─────────────────────────────────────────────
        # Step 7: Extract SharePoint + Teams (tenant-wide via Graph)
        # ─────────────────────────────────────────────
        await self._extract_sharepoint_teams(results)

        # ─────────────────────────────────────────────
        # Step 8: Extract Analysis Services (if configured)
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

            discover_query_parts = ["Resources"]
            if self.resource_groups:
                rg_list = ", ".join(f"'{rg}'" for rg in self.resource_groups)
                discover_query_parts.append(f"where resourceGroup in~ ({rg_list})")
            discover_query_parts.append("summarize count() by type")
            discover_query_parts.append("order by count_ desc")
            discover_query = " | ".join(discover_query_parts)

            query = QueryRequest(
                subscriptions=subscription_ids,
                query=discover_query,
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
                self.credential, self.tenant_id, self.snapshot_id, subscription_ids,
                resource_groups=self.resource_groups
            )
            rg_result = rg_ext.extract()
            self._add_result(results, "resource_graph", rg_result)

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
    # Internal: SQL Server Deep Extraction (mandatory)
    # ─────────────────────────────────────────────────────────────

    async def _extract_sql_deep(
        self,
        subscription_ids: list[str],
        results: dict[str, Any],
    ) -> None:
        """Discover SQL servers and deep-extract permissions from every database.

        This is NOT optional — if SQL servers exist in the subscription,
        they are automatically deep-extracted (users, roles, RLS, DDM, etc.).

        Uses mssql-python (pure Python, no ODBC driver) for data-plane access.
        """
        if not self.settings.extract_sql:
            logger.info("sql_extraction_disabled_by_config")
            return

        from src.extractors.sql.connection import SQL_TOKEN_SCOPE

        try:
            # Get a SQL data-plane token for T-SQL queries
            sql_token = self.msal_client.get_token([SQL_TOKEN_SCOPE])

            from src.extractors.sql.permissions import SQLServerExtractor
            sql_ext = SQLServerExtractor(self.tenant_id, self.snapshot_id)

            for sub_id in subscription_ids:
                try:
                    sql_result = sql_ext.extract_subscription(
                        credential=self.credential,
                        subscription_id=sub_id,
                        access_token=sql_token,
                        resource_groups=self.resource_groups,
                    )
                    self._append_result(results, "sql_deep", sql_result)

                    logger.info(
                        "sql_deep_extracted",
                        subscription=sub_id,
                        records=sql_result.record_count,
                        errors=len(sql_result.errors),
                    )
                except Exception as e:
                    results.setdefault("sql_deep", {"count": 0, "errors": [], "records": []})
                    results["sql_deep"]["errors"].append(f"{sub_id}: {e}")
                    logger.warning("sql_deep_failed", subscription=sub_id, error=str(e))

        except Exception as e:
            results["sql_deep"] = {"error": str(e)}
            logger.error("sql_token_acquisition_failed", error=str(e))

    # ─────────────────────────────────────────────────────────────
    # Internal: Entra ID
    # ─────────────────────────────────────────────────────────────

    async def _extract_entra(self, results: dict[str, Any]) -> None:
        """Extract Entra ID objects (users, groups, memberships, roles, SPs)."""
        if self.settings.extract_entra:
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
                        self._add_result(results, name, result)
                        logger.info(f"extracted_{name}", count=result.record_count)
                    except Exception as e:
                        results[name] = {"error": str(e)}
                        logger.error(f"extraction_failed_{name}", error=str(e))

            except Exception as e:
                results["entra"] = {"error": str(e)}
                logger.error("entra_extraction_failed", error=str(e))
        else:
            logger.info("entra_extraction_disabled_by_config")

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
            self._add_result(results, "subscriptions", sub_result)

            # Management groups
            try:
                mg_ext = ManagementGroupExtractor(self.credential, self.tenant_id, self.snapshot_id)
                mg_result = mg_ext.extract()
                self._add_result(results, "management_groups", mg_result)
            except Exception as e:
                results["management_groups"] = {"error": str(e)}

            # Role definitions + assignments per subscription
            for sub_id in subscription_ids:
                scope = f"/subscriptions/{sub_id}"
                try:
                    rd_ext = RoleDefinitionExtractor(self.credential, self.tenant_id, self.snapshot_id)
                    rd_result = rd_ext.extract(scope)
                    self._append_result(results, "role_definitions", rd_result)
                except Exception as e:
                    results.setdefault("role_definitions", {"errors": []})
                    results["role_definitions"]["errors"].append(str(e))

                try:
                    ra_ext = RoleAssignmentExtractor(self.credential, self.tenant_id, self.snapshot_id)
                    ra_result = ra_ext.extract(scope)
                    self._append_result(results, "role_assignments", ra_result)
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

            # Check config feature flags
            if "cosmos" in result_key and not self.settings.extract_cosmosdb:
                logger.info("cosmosdb_extraction_disabled_by_config")
                continue
            if "key_vault" in result_key and not self.settings.extract_keyvault:
                logger.info("key_vault_extraction_disabled_by_config")
                continue
            if "storage" in result_key and not self.settings.extract_storage:
                logger.info("storage_extraction_disabled_by_config")
                continue
            if "network" in result_key and not self.settings.extract_networking:
                logger.info("networking_extraction_disabled_by_config")
                continue

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

                            self._append_result(results, result_key, ext_result)
                    except Exception as e:
                        results.setdefault(result_key, {"count": 0, "errors": [], "records": []})
                        results[result_key]["errors"].append(f"{sub_id}: {str(e)}")
                        logger.warning(
                            "extractor_error",
                            label=label,
                            subscription=sub_id,
                            error=str(e),
                        )

                logger.info(f"auto_extracted_{result_key}", count=results.get(result_key, {}).get("count", 0))

            except Exception as e:
                results[result_key] = {"error": str(e)}
                logger.error("extractor_import_failed", label=label, error=str(e))

    # ─────────────────────────────────────────────────────────────
    # Internal: Fabric / Power BI
    # ─────────────────────────────────────────────────────────────

    async def _extract_fabric(self, results: dict[str, Any]) -> None:
        """Extract Fabric workspaces and deep Power BI permissions."""
        if self.settings.extract_fabric:
            try:
                from config.scopes import FABRIC_SCOPES
                fabric_token = self.msal_client.get_token(FABRIC_SCOPES)

                from src.extractors.fabric.workspaces import FabricWorkspaceExtractor
                fabric_ext = FabricWorkspaceExtractor(self.tenant_id, fabric_token, self.snapshot_id)
                fabric_result = await fabric_ext.extract()
                self._add_result(results, "fabric_workspaces", fabric_result)

                from src.extractors.fabric.powerbi_permissions import PowerBIDeepPermissionsExtractor
                pbi_deep = PowerBIDeepPermissionsExtractor(self.tenant_id, fabric_token, self.snapshot_id)
                pbi_deep_result = await pbi_deep.extract()
                self._add_result(results, "pbi_deep_permissions", pbi_deep_result)

                from src.extractors.fabric.item_permissions import FabricItemPermissionsExtractor
                item_ext = FabricItemPermissionsExtractor(self.tenant_id, fabric_token, self.snapshot_id)
                item_result = await item_ext.extract()
                self._add_result(results, "fabric_item_permissions", item_result)

                from src.extractors.fabric.powerbi import PowerBIExtractor
                pbi_ext = PowerBIExtractor(self.tenant_id, fabric_token, self.snapshot_id)
                pbi_result = await pbi_ext.extract()
                self._add_result(results, "pbi_resources", pbi_result)

            except Exception as e:
                results["fabric"] = {"error": str(e)}
                logger.warning("fabric_extraction_skipped", error=str(e))
        else:
            logger.info("fabric_extraction_disabled_by_config")

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
                    self._add_result(results, "sharepoint", sp_result)
                except Exception as e:
                    results["sharepoint"] = {"error": str(e)}

            if self.settings.extract_teams:
                try:
                    from src.extractors.sharepoint.teams import TeamsPermissionsExtractor
                    teams_ext = TeamsPermissionsExtractor(self.tenant_id, graph_token, self.snapshot_id)
                    teams_result = await teams_ext.extract()
                    self._add_result(results, "teams", teams_result)
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
        if self.settings.extract_aas:
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
                    self._append_result(results, "analysis_services", aas_result)
                except Exception as e:
                    results.setdefault("analysis_services", {"errors": []})
                    results["analysis_services"]["errors"].append(str(e))
        else:
            logger.info("aas_extraction_disabled_by_config")
