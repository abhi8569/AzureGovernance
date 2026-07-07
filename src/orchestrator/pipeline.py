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
from datetime import date, datetime
from typing import Any

import structlog

from config.settings import get_settings
from src.auth.msal_client import MSALClient
from src.auth.credential_factory import get_credential
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
        summary: dict[str, Any] = {"started_at": datetime.utcnow().isoformat()}

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
        summary["completed_at"] = datetime.utcnow().isoformat()

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

    async def _run_extraction(self, snapshot_id: int) -> dict[str, Any]:
        """Run all extractors and return results."""
        results: dict[str, Any] = {}

        # Get auth tokens
        msal_client = MSALClient(
            tenant_id=self.settings.tenant_id,
            client_id=self.settings.client_id,
            client_secret=self.settings.client_secret.get_secret_value(),
        )

        credential = get_credential(self.settings)

        # Entra ID extraction (users, groups, memberships, roles, SPs)
        try:
            from config.scopes import GRAPH_DELEGATED_SCOPES
            graph_token = msal_client.get_token(GRAPH_DELEGATED_SCOPES)

            from src.extractors.entra.users import UserExtractor
            from src.extractors.entra.groups import GroupExtractor
            from src.extractors.entra.memberships import MembershipExtractor
            from src.extractors.entra.roles import DirectoryRoleExtractor
            from src.extractors.entra.service_principals import ServicePrincipalExtractor

            extractors = [
                ("users", UserExtractor(self.settings.tenant_id, graph_token, snapshot_id)),
                ("groups", GroupExtractor(self.settings.tenant_id, graph_token, snapshot_id)),
                ("memberships", MembershipExtractor(self.settings.tenant_id, graph_token, snapshot_id)),
                ("directory_roles", DirectoryRoleExtractor(self.settings.tenant_id, graph_token, snapshot_id)),
                ("service_principals", ServicePrincipalExtractor(self.settings.tenant_id, graph_token, snapshot_id)),
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

        # Azure RBAC extraction
        try:
            from src.extractors.azure_rbac.subscriptions import SubscriptionExtractor

            sub_extractor = SubscriptionExtractor(credential, self.settings.tenant_id, snapshot_id)
            sub_result = sub_extractor.extract()
            results["subscriptions"] = {"count": sub_result.record_count, "errors": sub_result.errors}

        except Exception as e:
            results["azure_rbac"] = {"error": str(e)}
            logger.error("azure_rbac_failed", error=str(e))

        # Fabric extraction (optional)
        try:
            from config.scopes import FABRIC_SCOPES
            fabric_token = msal_client.get_token(FABRIC_SCOPES)

            from src.extractors.fabric.workspaces import FabricWorkspaceExtractor
            fabric_ext = FabricWorkspaceExtractor(self.settings.tenant_id, fabric_token, snapshot_id)
            fabric_result = await fabric_ext.extract()
            results["fabric"] = {"count": fabric_result.record_count, "errors": fabric_result.errors}
        except Exception as e:
            results["fabric"] = {"error": str(e)}
            logger.warning("fabric_extraction_skipped", error=str(e))

        # DevOps extraction (optional)
        if self.settings.devops_org and self.settings.devops_pat.get_secret_value():
            try:
                from src.extractors.devops.projects import DevOpsExtractor
                devops_ext = DevOpsExtractor(
                    org_name=self.settings.devops_org,
                    pat=self.settings.devops_pat.get_secret_value(),
                    tenant_id=self.settings.tenant_id,
                    snapshot_id=snapshot_id,
                )
                devops_result = await devops_ext.extract()
                results["devops"] = {"count": devops_result.record_count, "errors": devops_result.errors}
            except Exception as e:
                results["devops"] = {"error": str(e)}
                logger.warning("devops_extraction_skipped", error=str(e))

        return results

    def _load_to_database(
        self, session: Any, extract_results: dict[str, Any], snapshot_id: int
    ) -> dict[str, int]:
        """Load extracted data into DuckDB tables."""
        counts: dict[str, int] = {}
        logger.info("loading_to_database", snapshot_id=snapshot_id)
        # Loading logic would insert extracted records into DimPrincipal,
        # DimResource, DimRole, FactMembership, FactRoleAssignment tables
        # using SQLAlchemy bulk insert operations.
        # Actual implementation depends on the record shapes from each extractor.
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
        description="EAIP - Enterprise Access Intelligence Platform Pipeline"
    )
    parser.add_argument(
        "--full", action="store_true", help="Run the full pipeline (extract + ETL)"
    )
    parser.add_argument(
        "--extract-only", action="store_true", help="Run extraction only"
    )
    parser.add_argument(
        "--etl-only", action="store_true", help="Run ETL only on latest snapshot"
    )
    parser.add_argument(
        "--snapshot-id", type=int, help="Snapshot ID for ETL-only mode"
    )

    args = parser.parse_args()
    pipeline = Pipeline()

    if args.full:
        result = asyncio.run(pipeline.run_full())
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
