"""Entra ID user extractor.

Extracts all users from Microsoft Graph ``/users`` endpoint and maps
them to ``DimPrincipal`` records with ``principal_type='User'``.
Supports full and incremental (delta-query) extraction.
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

GRAPH_USERS_URL = "https://graph.microsoft.com/v1.0/users"
GRAPH_USERS_DELTA_URL = "https://graph.microsoft.com/v1.0/users/delta"
GRAPH_USERS_SELECT = (
    "id,displayName,userPrincipalName,mail,"
    "accountEnabled,userType,createdDateTime,deletedDateTime"
)


class UserExtractor(BaseExtractor):
    """Extract Entra ID users via Microsoft Graph API.

    Fetches all users with ``$select`` projecting only required fields
    and ``$top=999`` for maximum page size.  Supports delta queries for
    incremental synchronisation.

    Args:
        tenant_id: Azure AD tenant ID.
        token: OAuth2 access token with ``User.Read.All`` scope.
        snapshot_id: Current ETL snapshot identifier.
    """

    @api_retry
    async def extract(self) -> ExtractResult:
        """Perform a full extraction of all Entra ID users.

        Returns:
            ExtractResult containing mapped DimPrincipal records.
        """
        start = time.monotonic()
        records: list[dict[str, Any]] = []
        errors: list[str] = []

        self.logger.info("user_extraction_started", url=GRAPH_USERS_URL)

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                params: dict[str, Any] = {
                    "$select": GRAPH_USERS_SELECT,
                    "$top": 999,
                }

                async for page in paginate_graph(
                    client=client,
                    url=GRAPH_USERS_URL,
                    headers=self.headers,
                    params=params,
                ):
                    await GRAPH_RATE_LIMITER.acquire()
                    for raw_user in page:
                        try:
                            mapped = self._map_user(raw_user)
                            records.append(mapped)
                        except Exception as exc:
                            error_msg = (
                                f"Failed to map user "
                                f"{raw_user.get('id', 'unknown')}: {exc}"
                            )
                            errors.append(error_msg)
                            self.logger.warning(
                                "user_mapping_error",
                                user_id=raw_user.get("id"),
                                error=str(exc),
                            )

        except httpx.HTTPStatusError as exc:
            errors.append(
                f"Graph API error {exc.response.status_code}: {exc.response.text}"
            )
            self.logger.error(
                "user_extraction_http_error",
                status_code=exc.response.status_code,
            )
        except Exception as exc:
            errors.append(f"Unexpected error during user extraction: {exc}")
            self.logger.error("user_extraction_failed", error=str(exc))

        duration = time.monotonic() - start
        self.logger.info(
            "user_extraction_completed",
            record_count=len(records),
            error_count=len(errors),
            duration_seconds=round(duration, 2),
        )

        return ExtractResult(
            records=records,
            errors=errors,
            record_count=len(records),
            duration_seconds=round(duration, 2),
            extractor_name="UserExtractor",
        )

    @api_retry
    async def extract_incremental(
        self, delta_token: str | None = None
    ) -> ExtractResult:
        """Perform an incremental extraction using Graph delta queries.

        Args:
            delta_token: Previous ``@odata.deltaLink`` token.  If ``None``
                the first full delta sync is triggered.

        Returns:
            ExtractResult with changed records and a new delta token.
        """
        start = time.monotonic()
        records: list[dict[str, Any]] = []
        errors: list[str] = []
        new_delta_token: str | None = None

        self.logger.info(
            "user_delta_extraction_started",
            has_token=delta_token is not None,
        )

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                # If we have a delta token, use the full deltaLink URL directly
                if delta_token:
                    url = delta_token
                    params = None
                else:
                    url = GRAPH_USERS_DELTA_URL
                    params = {
                        "$select": GRAPH_USERS_SELECT,
                        "$top": 999,
                    }

                current_url: str | None = url
                while current_url:
                    await GRAPH_RATE_LIMITER.acquire()
                    response = await client.get(
                        current_url,
                        headers=self.headers,
                        params=params,
                    )
                    response.raise_for_status()
                    data = response.json()

                    for raw_user in data.get("value", []):
                        try:
                            mapped = self._map_user(raw_user)
                            # Mark removed users
                            if raw_user.get("@removed"):
                                mapped["is_deleted"] = True
                            records.append(mapped)
                        except Exception as exc:
                            error_msg = (
                                f"Failed to map delta user "
                                f"{raw_user.get('id', 'unknown')}: {exc}"
                            )
                            errors.append(error_msg)
                            self.logger.warning(
                                "user_delta_mapping_error",
                                user_id=raw_user.get("id"),
                                error=str(exc),
                            )

                    # Advance to next page or capture delta link
                    current_url = data.get("@odata.nextLink")
                    if not current_url:
                        new_delta_token = data.get("@odata.deltaLink")

                    # Only send params on the first request
                    params = None

        except httpx.HTTPStatusError as exc:
            errors.append(
                f"Graph API error {exc.response.status_code}: {exc.response.text}"
            )
            self.logger.error(
                "user_delta_extraction_http_error",
                status_code=exc.response.status_code,
            )
        except Exception as exc:
            errors.append(f"Unexpected error during delta user extraction: {exc}")
            self.logger.error("user_delta_extraction_failed", error=str(exc))

        duration = time.monotonic() - start
        self.logger.info(
            "user_delta_extraction_completed",
            record_count=len(records),
            error_count=len(errors),
            duration_seconds=round(duration, 2),
            has_new_delta_token=new_delta_token is not None,
        )

        return ExtractResult(
            records=records,
            delta_token=new_delta_token,
            errors=errors,
            record_count=len(records),
            duration_seconds=round(duration, 2),
            extractor_name="UserExtractor",
        )

    def _map_user(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Map a raw Graph API user response to a DimPrincipal dict.

        Args:
            raw: Raw JSON object from the ``/users`` endpoint.

        Returns:
            Dict matching the DimPrincipal schema columns.
        """
        object_id = raw["id"]
        return {
            "principal_id": generate_surrogate_key("entra", object_id),
            "tenant_id": self.tenant_id,
            "object_id": object_id,
            "principal_type": "User",
            "display_name": raw.get("displayName", ""),
            "user_principal_name": raw.get("userPrincipalName"),
            "mail": raw.get("mail"),
            "account_enabled": raw.get("accountEnabled"),
            "user_type": raw.get("userType"),
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
        # Graph API returns ISO 8601 with trailing Z
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
