"""Azure RBAC role definition extractor."""
from __future__ import annotations

import time
from typing import Any, TYPE_CHECKING

import structlog

from src.extractors.base import ExtractResult
from src.utils.id_generator import generate_surrogate_key

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

logger = structlog.get_logger(__name__)


class RoleDefinitionExtractor:
    """Extracts Azure RBAC role definitions.

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
        """Extract all role definitions at the given scope.

        Args:
            scope: Azure scope (e.g., '/subscriptions/{id}').

        Returns:
            ExtractResult with DimRole-shaped records.
        """
        from azure.mgmt.authorization import AuthorizationManagementClient

        start_time = time.monotonic()
        records: list[dict[str, Any]] = []
        errors: list[str] = []

        try:
            # Parse subscription ID from scope
            sub_id = self._parse_subscription_id(scope)
            client = AuthorizationManagementClient(self.credential, sub_id)

            for role_def in client.role_definitions.list(scope):
                records.append(self._map_role_definition(role_def))

            self.logger.info("role_definitions_extracted", count=len(records), scope=scope)

        except Exception as e:
            errors.append(f"Role definitions at {scope}: {e}")
            self.logger.error("role_definition_extraction_failed", error=str(e), scope=scope)

        duration = time.monotonic() - start_time
        return ExtractResult(
            records=records,
            errors=errors,
            record_count=len(records),
            duration_seconds=duration,
            extractor_name="RoleDefinitionExtractor",
        )

    def _map_role_definition(self, role_def: Any) -> dict[str, Any]:
        """Map Azure SDK role definition to DimRole schema."""
        role_id_str = role_def.id or ""
        permissions_list = []
        if role_def.permissions:
            for perm in role_def.permissions:
                if perm.actions:
                    permissions_list.extend(perm.actions)
                if perm.data_actions:
                    permissions_list.extend(perm.data_actions)

        return {
            "role_id": generate_surrogate_key("azure_rbac_role", role_id_str),
            "role_name": role_def.role_name or "",
            "platform": "AZURE_RBAC",
            "is_built_in": role_def.role_type == "BuiltInRole",
            "description": role_def.description or "",
            "definition_json": str({
                "actions": [p.actions for p in (role_def.permissions or [])],
                "not_actions": [p.not_actions for p in (role_def.permissions or [])],
                "data_actions": [p.data_actions for p in (role_def.permissions or [])],
                "not_data_actions": [p.not_data_actions for p in (role_def.permissions or [])],
            }),
        }

    @staticmethod
    def _parse_subscription_id(scope: str) -> str:
        """Extract subscription ID from a scope string."""
        parts = scope.strip("/").split("/")
        for i, part in enumerate(parts):
            if part.lower() == "subscriptions" and i + 1 < len(parts):
                return parts[i + 1]
        return ""
