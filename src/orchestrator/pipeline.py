"""EAIP main pipeline orchestrator.

Coordinates the full extraction, transformation, and loading workflow.

Usage:
    python -m src.orchestrator.pipeline --full
    python -m src.orchestrator.pipeline --extract-only
    python -m src.orchestrator.pipeline --etl-only
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time
from datetime import date, datetime, timezone
from typing import Any

import structlog

from config.settings import get_settings
from src.auth.msal_client import MSALClient
from src.auth.credential_factory import get_credential, get_msal_client_id
from src.etl.closure import ClosureComputer
from src.etl.effective_permissions import EffectivePermissionResolver
from src.etl.access_paths import AccessPathBuilder
from src.etl.normalizer import DataNormalizer
from src.etl.snapshot import SnapshotManager
from src.etl.validation import DataValidator
from src.storage.database import DatabaseManager
from src.storage.parquet_writer import ParquetWriter
from src.utils.logging import setup_logging

logger = structlog.get_logger(__name__)


class Pipeline:
    """Main EAIP pipeline orchestrator.

    Coordinates extraction from all data sources, transformation
    (normalization, closure computation, effective permission resolution),
    and loading into DuckDB and Parquet.

    Args:
        settings: Application settings. Uses defaults if None.
    """

    def __init__(self, settings: Any | None = None) -> None:
        self.settings = settings or get_settings()
        setup_logging(self.settings.log_level)

        self.db = DatabaseManager(self.settings.database_path)
        self.parquet = ParquetWriter(self.settings.parquet_output_dir)
        self.normalizer = DataNormalizer()

        logger.info("pipeline_initialized", tenant=self.settings.tenant_id)

    async def run_full(self) -> dict[str, Any]:
        """Run the complete pipeline: extract → transform → load.

        Returns:
            Summary dict with extraction counts and timing.
        """
        start_time = time.monotonic()
        summary: dict[str, Any] = {"started_at": datetime.now(timezone.utc).isoformat()}

        # Initialize database schema
        self.db.initialize_schema()

        # Create snapshot
        session = self.db.get_session()
        try:
            snapshot_id = SnapshotManager.create_snapshot(
                session, description=f"Full extraction {date.today()}"
            )
            summary["snapshot_id"] = snapshot_id

            # Phase 1: Extract
            extract_results = await self._run_extraction(snapshot_id)
            summary["extraction"] = extract_results

            # Phase 2: Load extracted data into DuckDB
            load_results = self._load_to_database(session, extract_results, snapshot_id)
            summary["loading"] = load_results

            # Phase 3: Compute closures
            membership_edges = ClosureComputer.compute_membership_closure(session, snapshot_id)
            resource_edges = ClosureComputer.compute_resource_hierarchy_closure(session, snapshot_id)
            summary["closures"] = {
                "membership_edges": membership_edges,
                "resource_edges": resource_edges,
            }

            # Phase 4: Resolve effective permissions
            effective_count = EffectivePermissionResolver.resolve(session, snapshot_id)
            summary["effective_permissions"] = effective_count

            # Phase 5: Build access paths
            path_count = AccessPathBuilder.build_paths(session, snapshot_id)
            summary["access_paths"] = path_count

            # Phase 6: Validate
            validation = DataValidator.generate_report(session, snapshot_id)
            summary["validation"] = validation

            # Phase 7: Export to Parquet
            self._export_to_parquet(snapshot_id)
            summary["parquet_exported"] = True

        except Exception as e:
            logger.error("pipeline_failed", error=str(e))
            summary["error"] = str(e)
            raise
        finally:
            session.close()

        duration = time.monotonic() - start_time
        summary["duration_seconds"] = round(duration, 2)
        summary["completed_at"] = datetime.now(timezone.utc).isoformat()

        logger.info("pipeline_complete", duration=summary["duration_seconds"])
        return summary

    async def run_extract_only(self) -> dict[str, Any]:
        """Run extraction phase only."""
        self.db.initialize_schema()
        session = self.db.get_session()
        try:
            snapshot_id = SnapshotManager.create_snapshot(
                session, description=f"Extract-only {date.today()}"
            )
            results = await self._run_extraction(snapshot_id)
            self._load_to_database(session, results, snapshot_id)
            return {"snapshot_id": snapshot_id, "extraction": results}
        finally:
            session.close()

    async def run_etl_only(self, snapshot_id: int | None = None) -> dict[str, Any]:
        """Run ETL phase only on existing data."""
        session = self.db.get_session()
        try:
            if snapshot_id is None:
                snapshot_id = SnapshotManager.get_latest_snapshot(session)
                if snapshot_id is None:
                    raise ValueError("No snapshots found. Run extraction first.")

            closures = {
                "membership": ClosureComputer.compute_membership_closure(session, snapshot_id),
                "resources": ClosureComputer.compute_resource_hierarchy_closure(session, snapshot_id),
            }
            effective = EffectivePermissionResolver.resolve(session, snapshot_id)
            paths = AccessPathBuilder.build_paths(session, snapshot_id)
            validation = DataValidator.generate_report(session, snapshot_id)

            self._export_to_parquet(snapshot_id)

            return {
                "snapshot_id": snapshot_id,
                "closures": closures,
                "effective_permissions": effective,
                "access_paths": paths,
                "validation": validation,
            }
        finally:
            session.close()

    async def run_subscription_scan(self, subscription_ids: list[str]) -> dict[str, Any]:
        """Scan subscriptions: auto-discover all resources and extract permissions.

        This is the "just give me a subscription" mode. The scanner:
        1. Queries Azure Resource Graph for ALL resources in the subscriptions
        2. Groups them by ARM resource type
        3. Automatically invokes matching deep extractors (SQL, KV, Cosmos, Storage, etc.)
        4. Also runs Entra ID, RBAC, Fabric/PBI, SharePoint, Teams, AAS

        Args:
            subscription_ids: One or more Azure subscription GUIDs.

        Returns:
            Summary dict with extraction counts, discovered types, and timing.
        """
        start_time = time.monotonic()
        summary: dict[str, Any] = {
            "started_at": datetime.now(timezone.utc).isoformat(),
            "mode": "subscription_scan",
            "subscription_ids": subscription_ids,
        }

        # Initialize database schema
        self.db.initialize_schema()

        # Create snapshot
        session = self.db.get_session()
        try:
            snapshot_id = SnapshotManager.create_snapshot(
                session,
                description=f"Subscription scan {', '.join(subscription_ids[:3])} {date.today()}",
            )
            summary["snapshot_id"] = snapshot_id

            # Build auth clients
            credential = get_credential(self.settings)
            msal_client = MSALClient(
                tenant_id=self.settings.tenant_id,
                client_id=self.settings.client_id,
                client_secret=self.settings.client_secret.get_secret_value(),
                credential=credential,
            )

            # Run the subscription scanner
            from src.orchestrator.subscription_scanner import SubscriptionScanner
            scanner = SubscriptionScanner(
                credential=credential,
                msal_client=msal_client,
                tenant_id=self.settings.tenant_id,
                snapshot_id=snapshot_id,
                settings=self.settings,
            )
            scan_results = await scanner.scan(subscription_ids)
            summary["extraction"] = scan_results

            # Load extracted data
            load_results = self._load_to_database(session, scan_results, snapshot_id)
            summary["loading"] = load_results

            # Compute closures
            membership_edges = ClosureComputer.compute_membership_closure(session, snapshot_id)
            resource_edges = ClosureComputer.compute_resource_hierarchy_closure(session, snapshot_id)
            summary["closures"] = {
                "membership_edges": membership_edges,
                "resource_edges": resource_edges,
            }

            # Effective permissions + access paths
            summary["effective_permissions"] = EffectivePermissionResolver.resolve(session, snapshot_id)
            summary["access_paths"] = AccessPathBuilder.build_paths(session, snapshot_id)

            # Validate
            summary["validation"] = DataValidator.generate_report(session, snapshot_id)

            # Export to Parquet
            self._export_to_parquet(snapshot_id)
            summary["parquet_exported"] = True

        except Exception as e:
            logger.error("subscription_scan_failed", error=str(e))
            summary["error"] = str(e)
            raise
        finally:
            session.close()

        duration = time.monotonic() - start_time
        summary["duration_seconds"] = round(duration, 2)
        summary["completed_at"] = datetime.now(timezone.utc).isoformat()

        logger.info(
            "subscription_scan_complete",
            duration=summary["duration_seconds"],
            subscriptions=subscription_ids,
        )
        return summary

    async def _run_extraction(self, snapshot_id: int) -> dict[str, Any]:
        """Run all extractors (surface + deep) and return results.

        Extraction phases:
        1. Entra ID: users, groups, memberships, directory roles, service principals
        2. Azure RBAC: subscriptions, resource groups, management groups,
           role definitions, role assignments, resource graph
        3. Storage: accounts, ADLS containers, POSIX ACLs
        4. Key Vault: vault access policies + sub-resource RBAC (key/secret/cert level)
        5. SQL: ARM-level (AD admins, firewall, databases) + T-SQL deep (users, roles,
           permissions, RLS, DDM)
        6. Cosmos DB: data-plane RBAC (separate from ARM)
        7. Fabric/Power BI: workspaces + deep per-item permissions (dataset/report/
           dashboard/app users, gateway/capacity, OneLake security)
        8. SharePoint: site permissions, drive item sharing, sharing links
        9. Teams: members, owners, guests, private/shared channel access
        10. Analysis Services: XMLA databases, roles, RLS definitions
        11. Networking: NSGs, private endpoints, VNet service endpoints
        12. DevOps: projects, repos, pipelines
        """
        results: dict[str, Any] = {}

        # Get auth tokens
        credential = get_credential(self.settings)
        msal_client = MSALClient(
            tenant_id=self.settings.tenant_id,
            client_id=self.settings.client_id,
            client_secret=self.settings.client_secret.get_secret_value(),
            credential=credential,
        )

        # ─────────────────────────────────────────────────
        # 1. Entra ID (users, groups, memberships, roles, SPs)
        # ─────────────────────────────────────────────────
        if self.settings.extract_entra:
            try:
                from config.scopes import GRAPH_DELEGATED_SCOPES
                graph_token = msal_client.get_token(GRAPH_DELEGATED_SCOPES)

                from src.extractors.entra.users import UserExtractor
                from src.extractors.entra.groups import GroupExtractor
                from src.extractors.entra.memberships import MembershipExtractor
                from src.extractors.entra.roles import DirectoryRoleExtractor
                from src.extractors.entra.service_principals import ServicePrincipalExtractor

                entra_extractors = [
                    ("users", UserExtractor(self.settings.tenant_id, graph_token, snapshot_id)),
                    ("groups", GroupExtractor(self.settings.tenant_id, graph_token, snapshot_id)),
                    ("memberships", MembershipExtractor(self.settings.tenant_id, graph_token, snapshot_id)),
                    ("directory_roles", DirectoryRoleExtractor(self.settings.tenant_id, graph_token, snapshot_id)),
                    ("service_principals", ServicePrincipalExtractor(self.settings.tenant_id, graph_token, snapshot_id)),
                ]

                for name, extractor in entra_extractors:
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

        # ─────────────────────────────────────────────────
        # 2. Azure RBAC (subscriptions, MGs, role defs, assignments, resources)
        # ─────────────────────────────────────────────────
        subscription_ids: list[str] = []
        try:
            from src.extractors.azure_rbac.subscriptions import SubscriptionExtractor
            from src.extractors.azure_rbac.management_groups import ManagementGroupExtractor
            from src.extractors.azure_rbac.role_definitions import RoleDefinitionExtractor
            from src.extractors.azure_rbac.role_assignments import RoleAssignmentExtractor
            from src.extractors.azure_rbac.resources import ResourceGraphExtractor

            # Subscriptions + resource groups
            sub_ext = SubscriptionExtractor(credential, self.settings.tenant_id, snapshot_id)
            sub_result = sub_ext.extract()
            self._add_result(results, "subscriptions", sub_result)
            if sub_result.records:
                subscription_ids = sub_result.records[0].get("subscription_ids", [])

            # Management groups
            try:
                mg_ext = ManagementGroupExtractor(credential, self.settings.tenant_id, snapshot_id)
                mg_result = mg_ext.extract()
                self._add_result(results, "management_groups", mg_result)
            except Exception as e:
                results["management_groups"] = {"error": str(e)}

            # Role definitions + assignments per subscription
            for sub_id in subscription_ids:
                scope = f"/subscriptions/{sub_id}"
                try:
                    rd_ext = RoleDefinitionExtractor(credential, self.settings.tenant_id, snapshot_id)
                    rd_result = rd_ext.extract(scope)
                    self._append_result(results, "role_definitions", rd_result)
                except Exception as e:
                    results.setdefault("role_definitions", {"errors": []})
                    results["role_definitions"]["errors"].append(str(e))

                try:
                    ra_ext = RoleAssignmentExtractor(credential, self.settings.tenant_id, snapshot_id)
                    ra_result = ra_ext.extract(scope)
                    self._append_result(results, "role_assignments", ra_result)
                except Exception as e:
                    results.setdefault("role_assignments", {"errors": []})
                    results["role_assignments"]["errors"].append(str(e))

            # Resource Graph (all resources)
            if subscription_ids:
                try:
                    rg_ext = ResourceGraphExtractor(credential, self.settings.tenant_id, snapshot_id, subscription_ids)
                    rg_result = rg_ext.extract()
                    self._add_result(results, "resource_graph", rg_result)
                except Exception as e:
                    results["resource_graph"] = {"error": str(e)}

        except Exception as e:
            results["azure_rbac"] = {"error": str(e)}
            logger.error("azure_rbac_failed", error=str(e))

        # ─────────────────────────────────────────────────
        # ─────────────────────────────────────────────────
        # 3. Storage (accounts, containers, ACLs)
        # ─────────────────────────────────────────────────
        if self.settings.extract_storage:
            for sub_id in subscription_ids:
                try:
                    from src.extractors.storage.accounts import StorageAccountExtractor
                    sa_ext = StorageAccountExtractor(credential, self.settings.tenant_id, snapshot_id)
                    sa_result = sa_ext.extract(sub_id)
                    self._append_result(results, "storage_accounts", sa_result)
                except Exception as e:
                    results.setdefault("storage_accounts", {"errors": []})
                    results["storage_accounts"]["errors"].append(str(e))
        else:
            logger.info("storage_extraction_disabled_by_config")

        # ─────────────────────────────────────────────────
        # 4. Key Vault (vault access policies + sub-resource RBAC)
        # ─────────────────────────────────────────────────
        if self.settings.extract_keyvault:
            for sub_id in subscription_ids:
                try:
                    from src.extractors.keyvault.vaults import KeyVaultExtractor
                    kv_ext = KeyVaultExtractor(credential, self.settings.tenant_id, snapshot_id)
                    kv_result = kv_ext.extract(sub_id)
                    self._append_result(results, "keyvault", kv_result)
                except Exception as e:
                    results.setdefault("keyvault", {"errors": []})
                    results["keyvault"]["errors"].append(str(e))

                # Deep Key Vault: individual key/secret/cert RBAC
                try:
                    from src.extractors.keyvault.deep_permissions import KeyVaultDeepExtractor
                    kvd_ext = KeyVaultDeepExtractor(credential, self.settings.tenant_id, snapshot_id)
                    kvd_result = kvd_ext.extract(sub_id)
                    self._append_result(results, "keyvault_deep", kvd_result)
                except Exception as e:
                    results.setdefault("keyvault_deep", {"errors": []})
                    results["keyvault_deep"]["errors"].append(str(e))
        else:
            logger.info("keyvault_extraction_disabled_by_config")

        # ─────────────────────────────────────────────────
        # 5. SQL Server (ARM + deep T-SQL permissions)
        # ─────────────────────────────────────────────────
        if self.settings.extract_sql:
            for sub_id in subscription_ids:
                try:
                    from src.extractors.sql.permissions import SQLServerExtractor
                    sql_ext = SQLServerExtractor(self.settings.tenant_id, snapshot_id)
                    sql_arm_result = sql_ext.extract_via_arm(credential, sub_id)
                    self._append_result(results, "sql_arm", sql_arm_result)
                except Exception as e:
                    results.setdefault("sql_arm", {"errors": []})
                    results["sql_arm"]["errors"].append(str(e))
        else:
            logger.info("sql_extraction_disabled_by_config")
        # NOTE: Deep T-SQL extraction (database users, roles, RLS, DDM)
        # requires direct SQL connectivity via pyodbc. Connection strings
        # are configured per-database in settings.sql_connections.

        # ─────────────────────────────────────────────────
        # 6. Cosmos DB (data-plane RBAC — separate from ARM)
        # ─────────────────────────────────────────────────
        if self.settings.extract_cosmosdb:
            for sub_id in subscription_ids:
                try:
                    from src.extractors.cosmosdb.permissions import CosmosDBExtractor
                    cosmos_ext = CosmosDBExtractor(credential, self.settings.tenant_id, snapshot_id)
                    cosmos_result = cosmos_ext.extract(sub_id)
                    self._append_result(results, "cosmosdb", cosmos_result)
                except Exception as e:
                    results.setdefault("cosmosdb", {"errors": []})
                    results["cosmosdb"]["errors"].append(str(e))
        else:
            logger.info("cosmosdb_extraction_disabled_by_config")

        # ─────────────────────────────────────────────────
        # 7. Fabric / Power BI (deep per-item permissions)
        # ─────────────────────────────────────────────────
        if self.settings.extract_fabric:
            try:
                from config.scopes import FABRIC_SCOPES
                fabric_token = msal_client.get_token(FABRIC_SCOPES)

                # Workspace + items listing
                from src.extractors.fabric.workspaces import FabricWorkspaceExtractor
                fabric_ext = FabricWorkspaceExtractor(self.settings.tenant_id, fabric_token, snapshot_id)
                fabric_result = await fabric_ext.extract()
                self._add_result(results, "fabric_workspaces", fabric_result)

                # DEEP: Per-dataset/report/dashboard/app users, gateways, capacities
                from src.extractors.fabric.powerbi_permissions import PowerBIDeepPermissionsExtractor
                pbi_deep = PowerBIDeepPermissionsExtractor(self.settings.tenant_id, fabric_token, snapshot_id)
                pbi_deep_result = await pbi_deep.extract()
                self._add_result(results, "pbi_deep_permissions", pbi_deep_result)

                # DEEP: Fabric item-level permissions + OneLake data access roles
                from src.extractors.fabric.item_permissions import FabricItemPermissionsExtractor
                item_ext = FabricItemPermissionsExtractor(self.settings.tenant_id, fabric_token, snapshot_id)
                item_result = await item_ext.extract()
                self._add_result(results, "fabric_item_permissions", item_result)

                # Power BI Admin surface resources
                from src.extractors.fabric.powerbi import PowerBIExtractor
                pbi_ext = PowerBIExtractor(self.settings.tenant_id, fabric_token, snapshot_id)
                pbi_result = await pbi_ext.extract()
                self._add_result(results, "pbi_resources", pbi_result)

            except Exception as e:
                results["fabric"] = {"error": str(e)}
                logger.warning("fabric_extraction_skipped", error=str(e))
        else:
            logger.info("fabric_extraction_disabled_by_config")

        # ─────────────────────────────────────────────────
        # 8. SharePoint (site, list, item-level permissions + sharing links)
        # ─────────────────────────────────────────────────
        if self.settings.extract_sharepoint:
            try:
                if 'graph_token' in locals() or 'graph_token' in globals():
                    from src.extractors.sharepoint.permissions import SharePointPermissionsExtractor
                    sp_ext = SharePointPermissionsExtractor(self.settings.tenant_id, graph_token, snapshot_id)
                    sp_result = await sp_ext.extract()
                    self._add_result(results, "sharepoint", sp_result)
            except Exception as e:
                results["sharepoint"] = {"error": str(e)}
                logger.warning("sharepoint_extraction_skipped", error=str(e))
        else:
            logger.info("sharepoint_extraction_disabled_by_config")

        # ─────────────────────────────────────────────────
        # 9. Teams (members, owners, guests, channels, apps)
        # ─────────────────────────────────────────────────
        if self.settings.extract_teams:
            try:
                if 'graph_token' in locals() or 'graph_token' in globals():
                    from src.extractors.sharepoint.teams import TeamsPermissionsExtractor
                    teams_ext = TeamsPermissionsExtractor(self.settings.tenant_id, graph_token, snapshot_id)
                    teams_result = await teams_ext.extract()
                    self._add_result(results, "teams", teams_result)
            except Exception as e:
                results["teams"] = {"error": str(e)}
                logger.warning("teams_extraction_skipped", error=str(e))
        else:
            logger.info("teams_extraction_disabled_by_config")

        # ─────────────────────────────────────────────────
        # 10. Analysis Services / PBI Premium XMLA (roles, RLS, members)
        # ─────────────────────────────────────────────────
        if self.settings.extract_aas:
            if getattr(self.settings, "aas_servers", None):
                for server_url in self.settings.aas_servers:
                    try:
                        aas_token = msal_client.get_token(["https://analysis.windows.net/powerbi/api/.default"])
                        from src.extractors.aas.models import AnalysisServicesExtractor
                        aas_ext = AnalysisServicesExtractor(server_url, aas_token, self.settings.tenant_id, snapshot_id)
                        aas_result = await aas_ext.extract()
                        self._append_result(results, "analysis_services", aas_result)
                    except Exception as e:
                        results.setdefault("analysis_services", {"errors": []})
                        results["analysis_services"]["errors"].append(str(e))
        else:
            logger.info("aas_extraction_disabled_by_config")

        # ─────────────────────────────────────────────────
        # 11. Networking (NSGs, private endpoints, VNet service endpoints)
        # ─────────────────────────────────────────────────
        if self.settings.extract_networking:
            for sub_id in subscription_ids:
                try:
                    from src.extractors.networking.access import NetworkAccessExtractor
                    net_ext = NetworkAccessExtractor(credential, self.settings.tenant_id, snapshot_id)
                    net_result = net_ext.extract(sub_id)
                    self._append_result(results, "networking", net_result)
                except Exception as e:
                    results.setdefault("networking", {"errors": []})
                    results["networking"]["errors"].append(str(e))
        else:
            logger.info("networking_extraction_disabled_by_config")

        # ─────────────────────────────────────────────────
        # 12. DevOps (projects, repos, pipelines)
        # ─────────────────────────────────────────────────
        if self.settings.extract_devops:
            if getattr(self.settings, "devops_org", None) and self.settings.devops_pat.get_secret_value():
                try:
                    from src.extractors.devops.projects import DevOpsExtractor
                    devops_ext = DevOpsExtractor(
                        org_name=self.settings.devops_org,
                        pat=self.settings.devops_pat.get_secret_value(),
                        tenant_id=self.settings.tenant_id,
                        snapshot_id=snapshot_id,
                    )
                    devops_result = await devops_ext.extract()
                    self._add_result(results, "devops", devops_result)
                except Exception as e:
                    results["devops"] = {"error": str(e)}
                    logger.warning("devops_extraction_skipped", error=str(e))
        else:
            logger.info("devops_extraction_disabled_by_config")

        return results

    def _is_rg_allowed(self, value: str | dict[str, Any]) -> bool:
        if not self.settings.resource_groups:
            return True

        if isinstance(value, str):
            val_str = value
        elif isinstance(value, dict):
            rg = value.get("resource_group") or value.get("resourceGroup")
            if rg:
                return rg.lower() in [r.lower() for r in self.settings.resource_groups]
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
                return rg_name.lower() in [r.lower() for r in self.settings.resource_groups]
            except (ValueError, IndexError):
                pass

        return True

    def _filter_records_by_rg(self, records: list[Any]) -> list[Any]:
        if not self.settings.resource_groups:
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

    def _load_to_database(
        self, session: Any, extract_results: dict[str, Any], snapshot_id: int
    ) -> dict[str, int]:
        """Load extracted data into DuckDB tables."""
        from src.storage.schema import (
            DimPrincipal, DimResource, DimRole, DimPermission,
            FactMembership, FactRoleAssignment, FactPermissionAssignment,
            FactRLSPolicy, FactDDMRule, FactSharingLink, FactNSGRule,
            FactPrivateEndpoint, FactOneLakeRole, FactResourceHierarchy
        )
        from src.utils.id_generator import generate_surrogate_key

        counts: dict[str, int] = {}
        logger.info("loading_to_database", snapshot_id=snapshot_id)

        # 1. Load DimPrincipal (from users, groups, service_principals, sql_deep)
        principals = []
        if "users" in extract_results and "records" in extract_results["users"]:
            principals.extend(DataNormalizer.normalize_principals(
                extract_results["users"]["records"], "entra", self.settings.tenant_id
            ))
        if "groups" in extract_results and "records" in extract_results["groups"]:
            principals.extend(DataNormalizer.normalize_principals(
                extract_results["groups"]["records"], "entra", self.settings.tenant_id
            ))
        if "service_principals" in extract_results and "records" in extract_results["service_principals"]:
            principals.extend(DataNormalizer.normalize_principals(
                extract_results["service_principals"]["records"], "entra", self.settings.tenant_id
            ))
        if "sql_deep" in extract_results and "records" in extract_results["sql_deep"]:
            for rec in extract_results["sql_deep"]["records"]:
                if "principals" in rec:
                    principals.extend(DataNormalizer.normalize_principals(
                        rec["principals"], "sql", self.settings.tenant_id
                    ))

        if principals:
            seen_principals = {}
            for p in principals:
                seen_principals[p["principal_id"]] = p
            session.bulk_insert_mappings(DimPrincipal, list(seen_principals.values()))
            counts["dim_principal"] = len(seen_principals)
            logger.info("loaded_principals", count=len(seen_principals))

        # 2. Load FactMembership (from memberships, teams)
        memberships = []
        if "memberships" in extract_results and "records" in extract_results["memberships"]:
            memberships.extend(extract_results["memberships"]["records"])
        if "teams" in extract_results and "records" in extract_results["teams"]:
            for rec in extract_results["teams"]["records"]:
                if "assignments" in rec:
                    memberships.extend(rec["assignments"])

        if memberships:
            seen_memberships = {}
            for m in memberships:
                key = (m["member_id"], m["parent_id"], m["snapshot_id"])
                seen_memberships[key] = m
            session.bulk_insert_mappings(FactMembership, list(seen_memberships.values()))
            counts["fact_membership"] = len(seen_memberships)
            logger.info("loaded_memberships", count=len(seen_memberships))

        # 3. Load DimResource
        resources = []
        if "subscriptions" in extract_results and "records" in extract_results["subscriptions"]:
            for rec in extract_results["subscriptions"]["records"]:
                if "resources" in rec:
                    resources.extend(DataNormalizer.normalize_resources(
                        rec["resources"], "azure", self.settings.tenant_id
                    ))
        if "management_groups" in extract_results and "records" in extract_results["management_groups"]:
            for rec in extract_results["management_groups"]["records"]:
                if "resources" in rec:
                    resources.extend(DataNormalizer.normalize_resources(
                        rec["resources"], "azure", self.settings.tenant_id
                    ))
        if "resource_graph" in extract_results and "records" in extract_results["resource_graph"]:
            resources.extend(DataNormalizer.normalize_resources(
                extract_results["resource_graph"]["records"], "azure", self.settings.tenant_id
            ))
        for key in ["sql_arm", "keyvault", "storage_accounts", "containers", "cosmosdb", "fabric_workspaces", "pbi_resources"]:
            if key in extract_results and "records" in extract_results[key]:
                resources.extend(DataNormalizer.normalize_resources(
                    extract_results[key]["records"], "azure", self.settings.tenant_id
                ))
        if "sharepoint" in extract_results and "records" in extract_results["sharepoint"]:
            for rec in extract_results["sharepoint"]["records"]:
                if "resources" in rec:
                    resources.extend(DataNormalizer.normalize_resources(
                        rec["resources"], "sharepoint", self.settings.tenant_id
                    ))
        if "teams" in extract_results and "records" in extract_results["teams"]:
            for rec in extract_results["teams"]["records"]:
                if "resources" in rec:
                    resources.extend(DataNormalizer.normalize_resources(
                        rec["resources"], "teams", self.settings.tenant_id
                    ))
        if "devops" in extract_results and "records" in extract_results["devops"]:
            for rec in extract_results["devops"]["records"]:
                if "resources" in rec:
                    resources.extend(DataNormalizer.normalize_resources(
                        rec["resources"], "devops", self.settings.tenant_id
                    ))
        if "sql_deep" in extract_results and "records" in extract_results["sql_deep"]:
            for rec in extract_results["sql_deep"]["records"]:
                if "resources" in rec:
                    resources.extend(DataNormalizer.normalize_resources(
                        rec["resources"], "sql", self.settings.tenant_id
                    ))

        if resources:
            seen_resources = {}
            for r in resources:
                seen_resources[r["resource_id"]] = r
            session.bulk_insert_mappings(DimResource, list(seen_resources.values()))
            counts["dim_resource"] = len(seen_resources)
            logger.info("loaded_resources", count=len(seen_resources))

        # 4. Load FactResourceHierarchy
        hierarchies = []
        if "subscriptions" in extract_results and "records" in extract_results["subscriptions"]:
            for rec in extract_results["subscriptions"]["records"]:
                if "hierarchy" in rec:
                    hierarchies.extend(rec["hierarchy"])
        if "management_groups" in extract_results and "records" in extract_results["management_groups"]:
            for rec in extract_results["management_groups"]["records"]:
                if "hierarchy" in rec:
                    hierarchies.extend(rec["hierarchy"])
        if hierarchies:
            seen_h = {}
            for h in hierarchies:
                key = (h["parent_resource_id"], h["child_resource_id"], h["snapshot_id"])
                seen_h[key] = h
            session.bulk_insert_mappings(FactResourceHierarchy, list(seen_h.values()))
            counts["fact_resource_hierarchy"] = len(seen_h)
            logger.info("loaded_resource_hierarchies", count=len(seen_h))

        # 5. Load DimRole
        roles = []
        if "directory_roles" in extract_results and "records" in extract_results["directory_roles"]:
            roles.extend([r for r in extract_results["directory_roles"]["records"] if r.get("_record_type") == "role_definition"])
        if "role_definitions" in extract_results and "records" in extract_results["role_definitions"]:
            roles.extend(extract_results["role_definitions"]["records"])
        if "analysis_services" in extract_results and "records" in extract_results["analysis_services"]:
            roles.extend([r for r in extract_results["analysis_services"]["records"] if r.get("_record_type") == "role_definition"])

        if roles:
            seen_roles = {}
            for r in roles:
                cleaned_role = {k: v for k, v in r.items() if k != "_record_type"}
                seen_roles[cleaned_role["role_id"]] = cleaned_role
            session.bulk_insert_mappings(DimRole, list(seen_roles.values()))
            counts["dim_role"] = len(seen_roles)
            logger.info("loaded_roles", count=len(seen_roles))

        # 6. Load FactRoleAssignment
        assignments = []
        if "directory_roles" in extract_results and "records" in extract_results["directory_roles"]:
            assignments.extend([r for r in extract_results["directory_roles"]["records"] if r.get("_record_type") == "role_assignment"])
        for key in ["role_assignments", "keyvault_deep", "acls", "cosmosdb", "fabric_item_permissions", "pbi_deep_permissions"]:
            if key in extract_results and "records" in extract_results[key]:
                assignments.extend(extract_results[key]["records"])
        if "sharepoint" in extract_results and "records" in extract_results["sharepoint"]:
            for rec in extract_results["sharepoint"]["records"]:
                if "assignments" in rec:
                    assignments.extend(rec["assignments"])
        if "analysis_services" in extract_results and "records" in extract_results["analysis_services"]:
            assignments.extend([r for r in extract_results["analysis_services"]["records"] if r.get("_record_type") == "role_assignment"])
        if "devops" in extract_results and "records" in extract_results["devops"]:
            for rec in extract_results["devops"]["records"]:
                if "assignments" in rec:
                    assignments.extend(rec["assignments"])
        if "sql_deep" in extract_results and "records" in extract_results["sql_deep"]:
            for rec in extract_results["sql_deep"]["records"]:
                if "role_assignments" in rec:
                    assignments.extend(rec["role_assignments"])

        if assignments:
            normalized_assignments = DataNormalizer.normalize_role_assignments(assignments, "azure")
            seen_assign = {}
            for a in normalized_assignments:
                a["snapshot_id"] = snapshot_id
                seen_assign[a["assignment_id"]] = a
            session.bulk_insert_mappings(FactRoleAssignment, list(seen_assign.values()))
            counts["fact_role_assignment"] = len(seen_assign)
            logger.info("loaded_role_assignments", count=len(seen_assign))

        # 7. Load FactPermissionAssignment
        permission_assigns = []
        if "sql_deep" in extract_results and "records" in extract_results["sql_deep"]:
            for rec in extract_results["sql_deep"]["records"]:
                if "permission_assignments" in rec:
                    permission_assigns.extend(rec["permission_assignments"])
        if permission_assigns:
            seen_pa = {}
            for pa in permission_assigns:
                pa["snapshot_id"] = snapshot_id
                if "permission_assignment_id" not in pa:
                    pa["permission_assignment_id"] = generate_surrogate_key("sql_perm", f"{pa['principal_id']}:{pa['resource_id']}:{pa['permission_id']}")
                seen_pa[pa["permission_assignment_id"]] = pa
            session.bulk_insert_mappings(FactPermissionAssignment, list(seen_pa.values()))
            counts["fact_permission_assignment"] = len(seen_pa)
            logger.info("loaded_permission_assignments", count=len(seen_pa))

        # 8. Load FactRLSPolicy
        rls_policies = []
        if "sql_deep" in extract_results and "records" in extract_results["sql_deep"]:
            for rec in extract_results["sql_deep"]["records"]:
                if "rls_policies" in rec:
                    rls_policies.extend(rec["rls_policies"])
        if rls_policies:
            norm_rls = DataNormalizer.normalize_rls_policies(rls_policies, "sql")
            seen_rls = {}
            for r in norm_rls:
                r["snapshot_id"] = snapshot_id
                seen_rls[r["rls_id"]] = r
            session.bulk_insert_mappings(FactRLSPolicy, list(seen_rls.values()))
            counts["fact_rls_policy"] = len(seen_rls)
            logger.info("loaded_rls_policies", count=len(seen_rls))

        # 9. Load FactDDMRule
        ddm_rules = []
        if "sql_deep" in extract_results and "records" in extract_results["sql_deep"]:
            for rec in extract_results["sql_deep"]["records"]:
                if "ddm_rules" in rec:
                    ddm_rules.extend(rec["ddm_rules"])
        if ddm_rules:
            norm_ddm = DataNormalizer.normalize_ddm_rules(ddm_rules)
            seen_ddm = {}
            for d in norm_ddm:
                d["snapshot_id"] = snapshot_id
                seen_ddm[d["ddm_id"]] = d
            session.bulk_insert_mappings(FactDDMRule, list(seen_ddm.values()))
            counts["fact_ddm_rule"] = len(seen_ddm)
            logger.info("loaded_ddm_rules", count=len(seen_ddm))

        # 10. Load FactSharingLink
        sharing_links = []
        if "sharepoint" in extract_results and "records" in extract_results["sharepoint"]:
            for rec in extract_results["sharepoint"]["records"]:
                if "sharing_links" in rec:
                    sharing_links.extend(rec["sharing_links"])
        if sharing_links:
            norm_links = DataNormalizer.normalize_sharing_links(sharing_links)
            seen_links = {}
            for l in norm_links:
                l["snapshot_id"] = snapshot_id
                seen_links[l["link_id"]] = l
            session.bulk_insert_mappings(FactSharingLink, list(seen_links.values()))
            counts["fact_sharing_link"] = len(seen_links)
            logger.info("loaded_sharing_links", count=len(seen_links))

        # 11. Load FactNSGRule
        nsg_rules = []
        if "networking" in extract_results and "records" in extract_results["networking"]:
            for rec in extract_results["networking"]["records"]:
                if "rules" in rec:
                    nsg_rules.extend(rec["rules"])
        if nsg_rules:
            norm_nsg = DataNormalizer.normalize_nsg_rules(nsg_rules)
            seen_nsg = {}
            for n in norm_nsg:
                n["snapshot_id"] = snapshot_id
                seen_nsg[n["rule_id"]] = n
            session.bulk_insert_mappings(FactNSGRule, list(seen_nsg.values()))
            counts["fact_nsg_rule"] = len(seen_nsg)
            logger.info("loaded_nsg_rules", count=len(seen_nsg))

        # 12. Load FactPrivateEndpoint
        pe_endpoints = []
        if "networking" in extract_results and "records" in extract_results["networking"]:
            for rec in extract_results["networking"]["records"]:
                if "endpoints" in rec:
                    pe_endpoints.extend(rec["endpoints"])
        if pe_endpoints:
            norm_pe = DataNormalizer.normalize_private_endpoints(pe_endpoints)
            seen_pe = {}
            for p in norm_pe:
                p["snapshot_id"] = snapshot_id
                seen_pe[p["pe_id"]] = p
            session.bulk_insert_mappings(FactPrivateEndpoint, list(seen_pe.values()))
            counts["fact_private_endpoint"] = len(seen_pe)
            logger.info("loaded_private_endpoints", count=len(seen_pe))

        return counts

    def _export_to_parquet(self, snapshot_id: int) -> None:
        """Export all tables to Parquet files."""
        tables = [
            "dim_principal", "dim_resource", "dim_role", "dim_permission",
            "fact_membership", "fact_membership_closure",
            "fact_resource_hierarchy", "fact_resource_hierarchy_closure",
            "fact_role_assignment", "fact_effective_permission", "fact_access_path",
        ]

        for table in tables:
            try:
                output_path = f"{self.settings.parquet_output_dir}/{table}/snapshot={snapshot_id}/{table}.parquet"
                self.db.export_to_parquet(table, output_path)
            except Exception as e:
                logger.warning("parquet_export_failed", table=table, error=str(e))


def main() -> None:
    """CLI entry point for the EAIP pipeline."""
    parser = argparse.ArgumentParser(
        description="EAIP - Enterprise Access Intelligence Platform Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Full pipeline (all configured sources)
  python -m src.orchestrator.pipeline --full

  # Scan a single subscription (auto-discovers all resources)
  python -m src.orchestrator.pipeline --scan-subscription --subscription-ids abc-123

  # Scan multiple subscriptions
  python -m src.orchestrator.pipeline --scan-subscription --subscription-ids abc-123 def-456

  # Extract only (no ETL)
  python -m src.orchestrator.pipeline --extract-only

  # ETL only on existing data
  python -m src.orchestrator.pipeline --etl-only --snapshot-id 42
""",
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--full", action="store_true",
        help="Run the full pipeline (extract + ETL) using all configured sources",
    )
    mode_group.add_argument(
        "--scan-subscription", action="store_true",
        help="Auto-discover and extract all resources in the given subscription(s)",
    )
    mode_group.add_argument(
        "--extract-only", action="store_true",
        help="Run extraction only (no ETL processing)",
    )
    mode_group.add_argument(
        "--etl-only", action="store_true",
        help="Run ETL only on latest or specified snapshot",
    )

    parser.add_argument(
        "--subscription-ids", nargs="+", metavar="SUB_ID",
        help="One or more Azure subscription GUIDs (required for --scan-subscription)",
    )
    parser.add_argument(
        "--resource-groups", nargs="+", metavar="RG_NAME",
        help="Optional list of resource group names to restrict the scan scope to",
    )
    parser.add_argument(
        "--snapshot-id", type=int,
        help="Snapshot ID for --etl-only mode",
    )

    # Feature overrides
    parser.add_argument(
        "--sharepoint", action="store_true", default=None,
        help="Explicitly enable SharePoint site permission extraction",
    )
    parser.add_argument(
        "--no-sharepoint", action="store_true",
        help="Explicitly disable SharePoint site permission extraction",
    )
    parser.add_argument(
        "--teams", action="store_true", default=None,
        help="Explicitly enable Microsoft Teams membership extraction",
    )
    parser.add_argument(
        "--no-teams", action="store_true",
        help="Explicitly disable Microsoft Teams membership extraction",
    )

    args = parser.parse_args()
    pipeline = Pipeline()

    # Apply overrides from CLI arguments to settings
    if args.resource_groups:
        pipeline.settings.resource_groups = args.resource_groups

    if args.sharepoint is not None:
        pipeline.settings.extract_sharepoint = True
    if args.no_sharepoint:
        pipeline.settings.extract_sharepoint = False

    if args.teams is not None:
        pipeline.settings.extract_teams = True
    if args.no_teams:
        pipeline.settings.extract_teams = False

    if args.full:
        result = asyncio.run(pipeline.run_full())
    elif args.scan_subscription:
        sub_ids = args.subscription_ids or pipeline.settings.subscription_ids
        if not sub_ids:
            parser.error(
                "--scan-subscription requires --subscription-ids SUB_ID [SUB_ID ...] "
                "or EAIP_SUBSCRIPTION_IDS set in .env"
            )
        result = asyncio.run(pipeline.run_subscription_scan(sub_ids))
    elif args.extract_only:
        result = asyncio.run(pipeline.run_extract_only())
    elif args.etl_only:
        result = asyncio.run(pipeline.run_etl_only(args.snapshot_id))
    else:
        parser.print_help()
        sys.exit(1)

    import json
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
