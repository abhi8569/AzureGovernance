"""Azure RBAC role assignment extractor."""
from __future__ import annotations

import time
from typing import Any, TYPE_CHECKING

import structlog

from src.extractors.base import ExtractResult
from src.utils.id_generator import generate_surrogate_key

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

logger = structlog.get_logger(__name__)


class RoleAssignmentExtractor:
    """Extracts Azure RBAC role assignments at a given scope.

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

    def extract(self, scope: str) -> ExtractResult:
        """Extract all role assignments at the given scope.

        Args:
            scope: Azure scope (e.g., '/subscriptions/{id}').

        Returns:
            ExtractResult with FactRoleAssignment-shaped records.
        """
        from azure.mgmt.authorization import AuthorizationManagementClient

        start_time = time.monotonic()
        records: list[dict[str, Any]] = []
        errors: list[str] = []

        try:
            sub_id = self._parse_subscription_id(scope)
            client = AuthorizationManagementClient(self.credential, sub_id)

            for assignment in client.role_assignments.list_for_scope(scope):
                records.append(self._map_role_assignment(assignment, scope))

            self.logger.info("role_assignments_extracted", count=len(records), scope=scope)

        except Exception as e:
            errors.append(f"Role assignments at {scope}: {e}")
            self.logger.error("role_assignment_extraction_failed", error=str(e), scope=scope)

        duration = time.monotonic() - start_time
        return ExtractResult(
            records=records,
            errors=errors,
            record_count=len(records),
            duration_seconds=duration,
            extractor_name="RoleAssignmentExtractor",
        )

    def _map_role_assignment(self, assignment: Any, scope: str) -> dict[str, Any]:
        """Map Azure SDK role assignment to FactRoleAssignment schema."""
        assignment_id_str = assignment.id or ""
        principal_id_str = assignment.principal_id or ""
        role_def_id = assignment.role_definition_id or ""
        assigned_scope = assignment.scope or scope

        # Determine principal type for surrogate key source
        principal_type_raw = getattr(assignment, "principal_type", "Unknown") or "Unknown"
        principal_type_map = {
            "User": "USER",
            "Group": "GROUP",
            "ServicePrincipal": "SERVICE_PRINCIPAL",
            "ForeignGroup": "GROUP",
        }
        principal_type = principal_type_map.get(principal_type_raw, "UNKNOWN")

        # Check if this assignment is inherited (scope differs from resource scope)
        inherited = assigned_scope.lower() != scope.lower()

        return {
            "assignment_id": generate_surrogate_key("azure_rbac_assignment", assignment_id_str),
            "principal_id": generate_surrogate_key("entra", principal_id_str),
            "role_id": generate_surrogate_key("azure_rbac_role", role_def_id),
            "resource_id": generate_surrogate_key("azure", assigned_scope),
            "assignment_type": "AZURE_RBAC",
            "start_date": None,
            "end_date": None,
            "granted_by_id": None,
            "inherited": inherited,
            "source": "AzureRBAC",
            "snapshot_id": self.snapshot_id,
        }

    @staticmethod
    def _parse_subscription_id(scope: str) -> str:
        """Extract subscription ID from a scope string."""
        parts = scope.strip("/").split("/")
        for i, part in enumerate(parts):
            if part.lower() == "subscriptions" and i + 1 < len(parts):
                return parts[i + 1]
        return ""
