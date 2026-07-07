"""Entra ID directory role extractor.

Extracts Entra ID role definitions from ``roleManagement/directory/roleDefinitions``
and active role assignments from ``roleManagement/directory/roleAssignments``,
producing ``DimRole`` and ``FactRoleAssignment`` records.
"""
from __future__ import annotations

import time
from typing import Any

import httpx
import structlog

from src.extractors.base import BaseExtractor, ExtractResult
from src.utils.id_generator import generate_composite_key, generate_surrogate_key
from src.utils.pagination import paginate_graph
from src.utils.rate_limiter import GRAPH_RATE_LIMITER
from src.utils.retry import api_retry

logger = structlog.get_logger(__name__)

GRAPH_ROLE_DEFINITIONS_URL = (
    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions"
)
GRAPH_ROLE_ASSIGNMENTS_URL = (
    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
)


class DirectoryRoleExtractor(BaseExtractor):
    """Extract Entra ID directory role definitions and assignments.

    Two-phase extraction:
    1. Role definitions → ``DimRole`` records.
    2. Role assignments → ``FactRoleAssignment`` records with
       ``assignment_type='DIRECTORY_ROLE'``.

    Args:
        tenant_id: Azure AD tenant ID.
        token: OAuth2 access token with ``RoleManagement.Read.Directory`` scope.
        snapshot_id: Current ETL snapshot identifier.
    """

    @api_retry
    async def extract(self) -> ExtractResult:
        """Extract all directory role definitions and their assignments.

        Returns:
            ExtractResult whose ``records`` list contains two categories
            of dicts, distinguished by the presence of a ``_record_type``
            key set to either ``"role_definition"`` or ``"role_assignment"``.
        """
        start = time.monotonic()
        records: list[dict[str, Any]] = []
        errors: list[str] = []
        role_id_map: dict[str, int] = {}  # templateId → surrogate key

        self.logger.info("directory_role_extraction_started")

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                # ── Phase 1: Role Definitions ─────────────────────────
                self.logger.info(
                    "role_definitions_fetch_started",
                    url=GRAPH_ROLE_DEFINITIONS_URL,
                )

                async for page in paginate_graph(
                    client=client,
                    url=GRAPH_ROLE_DEFINITIONS_URL,
                    headers=self.headers,
                ):
                    await GRAPH_RATE_LIMITER.acquire()
                    for raw_role in page:
                        try:
                            mapped = self._map_role_definition(raw_role)
                            records.append(mapped)
                            # Cache for assignment look-up
                            role_id_map[raw_role["id"]] = mapped["role_id"]
                        except Exception as exc:
                            error_msg = (
                                f"Failed to map role definition "
                                f"{raw_role.get('id', 'unknown')}: {exc}"
                            )
                            errors.append(error_msg)
                            self.logger.warning(
                                "role_definition_mapping_error",
                                role_id=raw_role.get("id"),
                                error=str(exc),
                            )

                self.logger.info(
                    "role_definitions_fetched",
                    count=len(role_id_map),
                )

                # ── Phase 2: Role Assignments ─────────────────────────
                self.logger.info(
                    "role_assignments_fetch_started",
                    url=GRAPH_ROLE_ASSIGNMENTS_URL,
                )

                params: dict[str, Any] = {
                    "$expand": "principal",
                }

                async for page in paginate_graph(
                    client=client,
                    url=GRAPH_ROLE_ASSIGNMENTS_URL,
                    headers=self.headers,
                    params=params,
                ):
                    await GRAPH_RATE_LIMITER.acquire()
                    for raw_assignment in page:
                        try:
                            mapped = self._map_role_assignment(
                                raw_assignment, role_id_map
                            )
                            records.append(mapped)
                        except Exception as exc:
                            error_msg = (
                                f"Failed to map role assignment "
                                f"{raw_assignment.get('id', 'unknown')}: {exc}"
                            )
                            errors.append(error_msg)
                            self.logger.warning(
                                "role_assignment_mapping_error",
                                assignment_id=raw_assignment.get("id"),
                                error=str(exc),
                            )

        except httpx.HTTPStatusError as exc:
            errors.append(
                f"Graph API error {exc.response.status_code}: {exc.response.text}"
            )
            self.logger.error(
                "directory_role_extraction_http_error",
                status_code=exc.response.status_code,
            )
        except Exception as exc:
            errors.append(f"Unexpected error during role extraction: {exc}")
            self.logger.error(
                "directory_role_extraction_failed", error=str(exc)
            )

        duration = time.monotonic() - start

        role_def_count = sum(
            1 for r in records if r.get("_record_type") == "role_definition"
        )
        role_assign_count = sum(
            1 for r in records if r.get("_record_type") == "role_assignment"
        )

        self.logger.info(
            "directory_role_extraction_completed",
            role_definitions=role_def_count,
            role_assignments=role_assign_count,
            error_count=len(errors),
            duration_seconds=round(duration, 2),
        )

        return ExtractResult(
            records=records,
            errors=errors,
            record_count=len(records),
            duration_seconds=round(duration, 2),
            extractor_name="DirectoryRoleExtractor",
        )

    def _map_role_definition(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Map a raw Graph role definition to a DimRole dict.

        Args:
            raw: Raw JSON from ``/roleManagement/directory/roleDefinitions``.

        Returns:
            Dict matching the DimRole schema with a ``_record_type`` marker.
        """
        role_template_id = raw["id"]
        role_permissions = raw.get("rolePermissions", [])

        # Flatten allowed resource actions from all permission entries
        permissions: list[str] = []
        for perm_entry in role_permissions:
            for action in perm_entry.get("allowedResourceActions", []):
                permissions.append(action)

        return {
            "_record_type": "role_definition",
            "role_id": generate_surrogate_key("entra_role", role_template_id),
            "role_name": raw.get("displayName", ""),
            "platform": "ENTRA_ID",
            "is_built_in": raw.get("isBuiltIn", True),
            "description": raw.get("description"),
            "definition_json": raw,
            "permissions": permissions,
        }

    def _map_role_assignment(
        self,
        raw: dict[str, Any],
        role_id_map: dict[str, int],
    ) -> dict[str, Any]:
        """Map a raw Graph role assignment to a FactRoleAssignment dict.

        Args:
            raw: Raw JSON from ``/roleManagement/directory/roleAssignments``.
            role_id_map: Mapping of role definition IDs to surrogate keys
                built during Phase 1.

        Returns:
            Dict matching the FactRoleAssignment schema with a
            ``_record_type`` marker.
        """
        assignment_id_raw = raw["id"]
        role_definition_id = raw.get("roleDefinitionId", "")
        principal_id = raw.get("principalId", "")
        resource_scope = raw.get("directoryScopeId", "/")

        # Resolve role surrogate key (fall back to generating one)
        role_key = role_id_map.get(
            role_definition_id,
            generate_surrogate_key("entra_role", role_definition_id),
        )

        return {
            "_record_type": "role_assignment",
            "assignment_id": generate_composite_key(
                "entra_role_assignment", assignment_id_raw
            ),
            "principal_id": generate_surrogate_key("entra", principal_id),
            "role_id": role_key,
            "resource_id": None,
            "assignment_type": "DIRECTORY_ROLE",
            "start_date": None,
            "end_date": None,
            "granted_by_id": None,
            "inherited": resource_scope != "/",
            "source": "entra_directory_role",
            "snapshot_id": self.snapshot_id,
        }
