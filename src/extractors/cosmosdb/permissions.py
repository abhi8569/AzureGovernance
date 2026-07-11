"""Cosmos DB deep permission extractor.

Extracts ALL layers of Cosmos DB access control:
- Data-plane RBAC: Role definitions and role assignments
  (separate from ARM RBAC — standard `az role assignment list` does NOT show these)
- Scoped permissions at account, database, and container level
- Databases and containers as resources
- Built-in and custom role definitions with data actions
"""
from __future__ import annotations

import time
from typing import Any, TYPE_CHECKING

import structlog

from src.extractors.base import ExtractResult
from src.utils.id_generator import generate_surrogate_key

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

logger = structlog.get_logger(__name__)


class CosmosDBExtractor:
    """Extracts Cosmos DB data-plane RBAC and resource hierarchy.

    IMPORTANT: Standard ARM RBAC (AuthorizationManagementClient) does NOT
    show Cosmos DB data-plane roles. Must use CosmosDBManagementClient's
    sql_resources operations.

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

    def extract(self, subscription_id: str) -> ExtractResult:
        """Extract all Cosmos DB accounts, databases, containers, and RBAC.

        Args:
            subscription_id: Azure subscription ID.

        Returns:
            ExtractResult with resources, role definitions, and assignments.
        """
        from azure.mgmt.cosmosdb import CosmosDBManagementClient

        start_time = time.monotonic()
        resources: list[dict[str, Any]] = []
        role_definitions: list[dict[str, Any]] = []
        assignments: list[dict[str, Any]] = []
        errors: list[str] = []

        try:
            client = CosmosDBManagementClient(self.credential, subscription_id)

            # List all Cosmos DB accounts
            for account in client.database_accounts.list():
                account_id = account.id or ""
                account_name = account.name or ""
                rg_name = self._extract_rg(account_id)

                account_resource_id = generate_surrogate_key("cosmos", account_id)
                resources.append({
                    "resource_id": account_resource_id,
                    "tenant_id": self.tenant_id,
                    "resource_guid": account_id,
                    "resource_type": "COSMOS_DB",
                    "name": account_name,
                    "parent_id": None,
                    "_kind": account.kind or "",
                    "_location": account.location or "",
                    "_document_endpoint": account.document_endpoint or "",
                })

                # Data-plane role definitions (custom + built-in)
                try:
                    for role_def in client.sql_resources.list_sql_role_definitions(
                        rg_name, account_name
                    ):
                        role_def_id = role_def.id or ""
                        data_actions = []
                        if role_def.permissions:
                            for perm in role_def.permissions:
                                data_actions.extend(perm.data_actions or [])

                        role_resource_id = generate_surrogate_key("cosmos_role", role_def_id)
                        role_definitions.append({
                            "role_id": role_resource_id,
                            "role_name": role_def.role_name or "",
                            "platform": "COSMOS_DB",
                            "is_built_in": role_def.type_properties_type == "BuiltInRole" if hasattr(role_def, "type_properties_type") else False,
                            "description": "",
                            "definition_json": str(data_actions),
                            "_assignable_scopes": str(role_def.assignable_scopes or []),
                            "_data_actions": data_actions,
                        })

                    self.logger.info("cosmos_role_defs_extracted", account=account_name)
                except Exception as e:
                    errors.append(f"Cosmos role defs {account_name}: {e}")

                # Data-plane role assignments
                try:
                    for assignment in client.sql_resources.list_sql_role_assignments(
                        rg_name, account_name
                    ):
                        assignment_id = assignment.id or ""
                        principal_id = assignment.principal_id or ""
                        role_def_id = assignment.role_definition_id or ""
                        scope = assignment.scope or ""

                        # Determine scope level
                        scope_level = "ACCOUNT"
                        if "/dbs/" in scope and "/colls/" in scope:
                            scope_level = "CONTAINER"
                        elif "/dbs/" in scope:
                            scope_level = "DATABASE"

                        assignments.append({
                            "assignment_id": generate_surrogate_key("cosmos_assign", assignment_id),
                            "principal_id": generate_surrogate_key("entra", principal_id),
                            "role_id": generate_surrogate_key("cosmos_role", role_def_id),
                            "resource_id": account_resource_id,
                            "assignment_type": "AZURE_RBAC",
                            "source": "CosmosDB_DataPlane",
                            "snapshot_id": self.snapshot_id,
                            "_scope": scope,
                            "_scope_level": scope_level,
                            "_role_definition_id": role_def_id,
                        })

                    self.logger.info("cosmos_assignments_extracted", account=account_name)
                except Exception as e:
                    errors.append(f"Cosmos assignments {account_name}: {e}")

                # List databases and containers
                try:
                    for db in client.sql_resources.list_sql_databases(rg_name, account_name):
                        db_name = db.name or ""
                        db_id = db.id or ""
                        db_resource_id = generate_surrogate_key("cosmos", db_id)

                        resources.append({
                            "resource_id": db_resource_id,
                            "tenant_id": self.tenant_id,
                            "resource_guid": db_id,
                            "resource_type": "COSMOS_DB",
                            "name": f"DB: {db_name}",
                            "parent_id": account_resource_id,
                        })

                        # Containers
                        try:
                            for container in client.sql_resources.list_sql_containers(
                                rg_name, account_name, db_name
                            ):
                                container_id = container.id or ""
                                resources.append({
                                    "resource_id": generate_surrogate_key("cosmos", container_id),
                                    "tenant_id": self.tenant_id,
                                    "resource_guid": container_id,
                                    "resource_type": "COSMOS_DB",
                                    "name": f"Container: {container.name or ''}",
                                    "parent_id": db_resource_id,
                                    "_partition_key": str(container.resource.partition_key) if container.resource else None,
                                })
                        except Exception as e:
                            errors.append(f"Cosmos containers {db_name}: {e}")

                except Exception as e:
                    errors.append(f"Cosmos databases {account_name}: {e}")

        except Exception as e:
            errors.append(f"Cosmos DB listing: {e}")
            self.logger.error("cosmos_extraction_failed", error=str(e))

        duration = time.monotonic() - start_time
        self.logger.info(
            "cosmos_deep_extracted",
            accounts=len([r for r in resources if r.get("resource_type") == "COSMOS_DB" and "DB:" not in r.get("name", "")]),
            role_definitions=len(role_definitions),
            assignments=len(assignments),
        )
        return ExtractResult(
            records=[{
                "resources": resources,
                "role_definitions": role_definitions,
                "assignments": assignments,
            }],
            errors=errors,
            record_count=len(resources) + len(role_definitions) + len(assignments),
            duration_seconds=duration,
            extractor_name="CosmosDBExtractor",
        )

    @staticmethod
    def _extract_rg(resource_id: str) -> str:
        """Extract resource group from ARM resource ID."""
        parts = resource_id.split("/")
        for i, part in enumerate(parts):
            if part.lower() == "resourcegroups" and i + 1 < len(parts):
                return parts[i + 1]
        return ""
