"""Entra ID service principal and application extractor.

Extracts service principals from ``/servicePrincipals`` and application
registrations from ``/applications``, mapping both to ``DimPrincipal``
records with ``principal_type='ServicePrincipal'`` and
``principal_type='Application'`` respectively.
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

GRAPH_SERVICE_PRINCIPALS_URL = (
    "https://graph.microsoft.com/v1.0/servicePrincipals"
)
GRAPH_SERVICE_PRINCIPALS_SELECT = (
    "id,displayName,appId,servicePrincipalType,"
    "accountEnabled,createdDateTime,deletedDateTime"
)

GRAPH_APPLICATIONS_URL = "https://graph.microsoft.com/v1.0/applications"
GRAPH_APPLICATIONS_SELECT = (
    "id,displayName,appId,createdDateTime,deletedDateTime,"
    "signInAudience,publisherDomain"
)


class ServicePrincipalExtractor(BaseExtractor):
    """Extract Entra ID service principals and application registrations.

    Two-phase extraction:
    1. Service principals → ``DimPrincipal`` with
       ``principal_type='ServicePrincipal'``.
    2. Application registrations → ``DimPrincipal`` with
       ``principal_type='Application'``.

    Args:
        tenant_id: Azure AD tenant ID.
        token: OAuth2 access token with ``Application.Read.All`` scope.
        snapshot_id: Current ETL snapshot identifier.
    """

    @api_retry
    async def extract(self) -> ExtractResult:
        """Extract all service principals and application registrations.

        Returns:
            ExtractResult with DimPrincipal-shaped records for both
            service principals and applications.
        """
        start = time.monotonic()
        records: list[dict[str, Any]] = []
        errors: list[str] = []

        self.logger.info("service_principal_extraction_started")

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                # ── Phase 1: Service Principals ────────────────────────
                sp_records, sp_errors = await self._extract_service_principals(
                    client
                )
                records.extend(sp_records)
                errors.extend(sp_errors)

                # ── Phase 2: Application Registrations ─────────────────
                app_records, app_errors = await self._extract_applications(
                    client
                )
                records.extend(app_records)
                errors.extend(app_errors)

        except httpx.HTTPStatusError as exc:
            errors.append(
                f"Graph API error {exc.response.status_code}: {exc.response.text}"
            )
            self.logger.error(
                "service_principal_extraction_http_error",
                status_code=exc.response.status_code,
            )
        except Exception as exc:
            errors.append(
                f"Unexpected error during service principal extraction: {exc}"
            )
            self.logger.error(
                "service_principal_extraction_failed", error=str(exc)
            )

        duration = time.monotonic() - start

        sp_count = sum(
            1
            for r in records
            if r.get("principal_type") == "ServicePrincipal"
        )
        app_count = sum(
            1
            for r in records
            if r.get("principal_type") == "Application"
        )

        self.logger.info(
            "service_principal_extraction_completed",
            service_principals=sp_count,
            applications=app_count,
            error_count=len(errors),
            duration_seconds=round(duration, 2),
        )

        return ExtractResult(
            records=records,
            errors=errors,
            record_count=len(records),
            duration_seconds=round(duration, 2),
            extractor_name="ServicePrincipalExtractor",
        )

    async def _extract_service_principals(
        self, client: httpx.AsyncClient
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Fetch and map all service principals.

        Args:
            client: Shared HTTPX async client.

        Returns:
            Tuple of (records, errors).
        """
        records: list[dict[str, Any]] = []
        errors: list[str] = []

        self.logger.info(
            "service_principals_fetch_started",
            url=GRAPH_SERVICE_PRINCIPALS_URL,
        )

        params: dict[str, Any] = {
            "$select": GRAPH_SERVICE_PRINCIPALS_SELECT,
            "$top": 999,
        }

        async for page in paginate_graph(
            client=client,
            url=GRAPH_SERVICE_PRINCIPALS_URL,
            headers=self.headers,
            params=params,
        ):
            await GRAPH_RATE_LIMITER.acquire()
            for raw_sp in page:
                try:
                    mapped = self._map_service_principal(raw_sp)
                    records.append(mapped)
                except Exception as exc:
                    error_msg = (
                        f"Failed to map service principal "
                        f"{raw_sp.get('id', 'unknown')}: {exc}"
                    )
                    errors.append(error_msg)
                    self.logger.warning(
                        "service_principal_mapping_error",
                        sp_id=raw_sp.get("id"),
                        error=str(exc),
                    )

        self.logger.info(
            "service_principals_fetched",
            count=len(records),
        )
        return records, errors

    async def _extract_applications(
        self, client: httpx.AsyncClient
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Fetch and map all application registrations.

        Args:
            client: Shared HTTPX async client.

        Returns:
            Tuple of (records, errors).
        """
        records: list[dict[str, Any]] = []
        errors: list[str] = []

        self.logger.info(
            "applications_fetch_started",
            url=GRAPH_APPLICATIONS_URL,
        )

        params: dict[str, Any] = {
            "$select": GRAPH_APPLICATIONS_SELECT,
            "$top": 999,
        }

        async for page in paginate_graph(
            client=client,
            url=GRAPH_APPLICATIONS_URL,
            headers=self.headers,
            params=params,
        ):
            await GRAPH_RATE_LIMITER.acquire()
            for raw_app in page:
                try:
                    mapped = self._map_application(raw_app)
                    records.append(mapped)
                except Exception as exc:
                    error_msg = (
                        f"Failed to map application "
                        f"{raw_app.get('id', 'unknown')}: {exc}"
                    )
                    errors.append(error_msg)
                    self.logger.warning(
                        "application_mapping_error",
                        app_id=raw_app.get("id"),
                        error=str(exc),
                    )

        self.logger.info(
            "applications_fetched",
            count=len(records),
        )
        return records, errors

    def _map_service_principal(
        self, raw: dict[str, Any]
    ) -> dict[str, Any]:
        """Map a raw Graph service principal to a DimPrincipal dict.

        Args:
            raw: Raw JSON from ``/servicePrincipals``.

        Returns:
            Dict matching the DimPrincipal schema.
        """
        object_id = raw["id"]
        sp_type = raw.get("servicePrincipalType", "Application")

        return {
            "principal_id": generate_surrogate_key("entra", object_id),
            "tenant_id": self.tenant_id,
            "object_id": object_id,
            "principal_type": "ServicePrincipal",
            "display_name": raw.get("displayName", ""),
            "user_principal_name": None,
            "mail": None,
            "account_enabled": raw.get("accountEnabled"),
            "user_type": sp_type,
            "created_date": _parse_datetime(raw.get("createdDateTime")),
            "modified_date": None,
            "is_deleted": raw.get("deletedDateTime") is not None,
        }

    def _map_application(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Map a raw Graph application registration to a DimPrincipal dict.

        Args:
            raw: Raw JSON from ``/applications``.

        Returns:
            Dict matching the DimPrincipal schema.
        """
        object_id = raw["id"]
        sign_in_audience = raw.get("signInAudience", "")

        return {
            "principal_id": generate_surrogate_key("entra", object_id),
            "tenant_id": self.tenant_id,
            "object_id": object_id,
            "principal_type": "Application",
            "display_name": raw.get("displayName", ""),
            "user_principal_name": None,
            "mail": None,
            "account_enabled": None,
            "user_type": sign_in_audience,
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
