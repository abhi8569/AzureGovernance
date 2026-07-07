"""Entra ID group extractor.

Extracts all security and Microsoft 365 groups from the Microsoft Graph
``/groups`` endpoint and maps them to ``DimPrincipal`` records with
``principal_type='Group'``.
"""
from __future__ import annotations

import time
from datetime import datetime
from typing import Any

import httpx
import structlog

from src.extractors.base import BaseExtractor, ExtractResult
from src.utils.id_generator import generate_surrogate_key
from src.utils.pagination import paginate_graph
from src.utils.rate_limiter import GRAPH_RATE_LIMITER
from src.utils.retry import api_retry

logger = structlog.get_logger(__name__)

GRAPH_GROUPS_URL = "https://graph.microsoft.com/v1.0/groups"
GRAPH_GROUPS_SELECT = (
    "id,displayName,mail,mailEnabled,securityEnabled,"
    "groupTypes,description,createdDateTime,deletedDateTime"
)


class GroupExtractor(BaseExtractor):
    """Extract Entra ID groups via Microsoft Graph API.

    Fetches all groups (security groups, Microsoft 365 groups, mail-enabled
    security groups, and distribution lists) with key attributes projected
    via ``$select``.

    Args:
        tenant_id: Azure AD tenant ID.
        token: OAuth2 access token with ``Group.Read.All`` scope.
        snapshot_id: Current ETL snapshot identifier.
    """

    @api_retry
    async def extract(self) -> ExtractResult:
        """Perform a full extraction of all Entra ID groups.

        Returns:
            ExtractResult containing mapped DimPrincipal records with
            ``principal_type='Group'``.
        """
        start = time.monotonic()
        records: list[dict[str, Any]] = []
        errors: list[str] = []

        self.logger.info("group_extraction_started", url=GRAPH_GROUPS_URL)

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                params: dict[str, Any] = {
                    "$select": GRAPH_GROUPS_SELECT,
                    "$top": 999,
                }

                async for page in paginate_graph(
                    client=client,
                    url=GRAPH_GROUPS_URL,
                    headers=self.headers,
                    params=params,
                ):
                    await GRAPH_RATE_LIMITER.acquire()
                    for raw_group in page:
                        try:
                            mapped = self._map_group(raw_group)
                            records.append(mapped)
                        except Exception as exc:
                            error_msg = (
                                f"Failed to map group "
                                f"{raw_group.get('id', 'unknown')}: {exc}"
                            )
                            errors.append(error_msg)
                            self.logger.warning(
                                "group_mapping_error",
                                group_id=raw_group.get("id"),
                                error=str(exc),
                            )

        except httpx.HTTPStatusError as exc:
            errors.append(
                f"Graph API error {exc.response.status_code}: {exc.response.text}"
            )
            self.logger.error(
                "group_extraction_http_error",
                status_code=exc.response.status_code,
            )
        except Exception as exc:
            errors.append(f"Unexpected error during group extraction: {exc}")
            self.logger.error("group_extraction_failed", error=str(exc))

        duration = time.monotonic() - start
        self.logger.info(
            "group_extraction_completed",
            record_count=len(records),
            error_count=len(errors),
            duration_seconds=round(duration, 2),
        )

        return ExtractResult(
            records=records,
            errors=errors,
            record_count=len(records),
            duration_seconds=round(duration, 2),
            extractor_name="GroupExtractor",
        )

    def _map_group(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Map a raw Graph API group response to a DimPrincipal dict.

        Determines the group sub-type (Security, Microsoft 365, Distribution,
        Mail-Enabled Security) based on ``groupTypes``, ``securityEnabled``,
        and ``mailEnabled`` properties.

        Args:
            raw: Raw JSON object from the ``/groups`` endpoint.

        Returns:
            Dict matching the DimPrincipal schema columns.
        """
        object_id = raw["id"]
        group_types = raw.get("groupTypes", [])
        security_enabled = raw.get("securityEnabled", False)
        mail_enabled = raw.get("mailEnabled", False)

        # Determine specific group sub-type for user_type field
        if "Unified" in group_types:
            user_type = "Microsoft365"
        elif security_enabled and mail_enabled:
            user_type = "MailEnabledSecurity"
        elif security_enabled:
            user_type = "Security"
        elif mail_enabled:
            user_type = "Distribution"
        else:
            user_type = "Other"

        return {
            "principal_id": generate_surrogate_key("entra", object_id),
            "tenant_id": self.tenant_id,
            "object_id": object_id,
            "principal_type": "Group",
            "display_name": raw.get("displayName", ""),
            "user_principal_name": None,
            "mail": raw.get("mail"),
            "account_enabled": security_enabled,
            "user_type": user_type,
            "created_date": _parse_datetime(raw.get("createdDateTime")),
            "modified_date": None,
            "is_deleted": raw.get("deletedDateTime") is not None,
        }


def _parse_datetime(value: str | None) -> datetime | None:
    """Parse an ISO 8601 datetime string from Graph API.

    Args:
        value: ISO 8601 datetime string or ``None``.

    Returns:
        Parsed ``datetime`` or ``None``.
    """
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
