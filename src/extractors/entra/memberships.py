"""Entra ID membership extractor.

Extracts direct group memberships from the Microsoft Graph
``/groups/{id}/members`` endpoint for each group, producing
``FactMembership`` records.  Captures both user-in-group and
group-in-group (nested) edges.
"""
from __future__ import annotations

import time
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
GRAPH_GROUP_MEMBERS_URL_TEMPLATE = (
    "https://graph.microsoft.com/v1.0/groups/{group_id}/members"
)
GRAPH_MEMBERS_SELECT = "id,displayName,@odata.type"


class MembershipExtractor(BaseExtractor):
    """Extract group membership edges from Entra ID.

    For each group, queries the ``/members`` endpoint to discover direct
    member principals.  The result set includes both user→group and
    group→group (nested) edges that together enable transitive closure
    computation downstream.

    Args:
        tenant_id: Azure AD tenant ID.
        token: OAuth2 access token with ``GroupMember.Read.All`` scope.
        snapshot_id: Current ETL snapshot identifier.
        group_object_ids: Optional pre-fetched list of group object IDs.
            If ``None``, groups are fetched from the ``/groups`` endpoint.
    """

    def __init__(
        self,
        tenant_id: str,
        token: str,
        snapshot_id: int,
        group_object_ids: list[str] | None = None,
    ) -> None:
        super().__init__(tenant_id, token, snapshot_id)
        self._group_object_ids = group_object_ids

    @api_retry
    async def extract(self) -> ExtractResult:
        """Extract membership edges for all groups.

        If ``group_object_ids`` was not provided at construction, first
        fetches the full list of groups from Graph.

        Returns:
            ExtractResult containing FactMembership-shaped records.
        """
        start = time.monotonic()
        records: list[dict[str, Any]] = []
        errors: list[str] = []

        group_ids = self._group_object_ids
        if group_ids is None:
            self.logger.info("membership_fetching_group_list")
            group_ids = await self._fetch_group_ids()
            self.logger.info(
                "membership_group_list_fetched", group_count=len(group_ids)
            )

        self.logger.info(
            "membership_extraction_started", total_groups=len(group_ids)
        )

        async with httpx.AsyncClient(timeout=60.0) as client:
            for idx, group_id in enumerate(group_ids, 1):
                try:
                    members = await self._extract_for_group(client, group_id)
                    records.extend(members)
                except httpx.HTTPStatusError as exc:
                    error_msg = (
                        f"Failed members for group {group_id}: "
                        f"HTTP {exc.response.status_code}"
                    )
                    errors.append(error_msg)
                    self.logger.warning(
                        "membership_group_error",
                        group_id=group_id,
                        status_code=exc.response.status_code,
                    )
                except Exception as exc:
                    error_msg = (
                        f"Unexpected error for group {group_id}: {exc}"
                    )
                    errors.append(error_msg)
                    self.logger.warning(
                        "membership_group_unexpected_error",
                        group_id=group_id,
                        error=str(exc),
                    )

                if idx % 100 == 0:
                    self.logger.info(
                        "membership_extraction_progress",
                        groups_processed=idx,
                        total_groups=len(group_ids),
                        records_so_far=len(records),
                    )

        duration = time.monotonic() - start
        self.logger.info(
            "membership_extraction_completed",
            record_count=len(records),
            error_count=len(errors),
            duration_seconds=round(duration, 2),
        )

        return ExtractResult(
            records=records,
            errors=errors,
            record_count=len(records),
            duration_seconds=round(duration, 2),
            extractor_name="MembershipExtractor",
        )

    async def extract_for_group(
        self, group_object_id: str
    ) -> list[dict[str, Any]]:
        """Extract membership edges for a single group.

        Convenience method for ad-hoc queries outside of the bulk
        ``extract()`` flow.

        Args:
            group_object_id: Entra object ID of the target group.

        Returns:
            List of dicts matching the FactMembership schema.
        """
        async with httpx.AsyncClient(timeout=60.0) as client:
            return await self._extract_for_group(client, group_object_id)

    async def _extract_for_group(
        self,
        client: httpx.AsyncClient,
        group_object_id: str,
    ) -> list[dict[str, Any]]:
        """Internal helper to fetch and map members of one group.

        Args:
            client: Shared HTTPX async client.
            group_object_id: Entra object ID of the group.

        Returns:
            List of FactMembership-shaped dicts.
        """
        await GRAPH_RATE_LIMITER.acquire()

        url = GRAPH_GROUP_MEMBERS_URL_TEMPLATE.format(group_id=group_object_id)
        params: dict[str, Any] = {
            "$select": GRAPH_MEMBERS_SELECT,
            "$top": 999,
        }

        memberships: list[dict[str, Any]] = []
        parent_key = generate_surrogate_key("entra", group_object_id)

        async for page in paginate_graph(
            client=client,
            url=url,
            headers=self.headers,
            params=params,
        ):
            for raw_member in page:
                member_object_id = raw_member.get("id")
                if not member_object_id:
                    continue

                member_key = generate_surrogate_key("entra", member_object_id)
                odata_type = raw_member.get("@odata.type", "")

                # Determine membership type for the edge
                if "#microsoft.graph.group" in odata_type:
                    membership_type = "AD_GROUP"
                else:
                    membership_type = "AD_GROUP"

                memberships.append(
                    {
                        "member_id": member_key,
                        "parent_id": parent_key,
                        "membership_type": membership_type,
                        "source": "entra_group_member",
                        "effective_from": None,
                        "effective_to": None,
                        "snapshot_id": self.snapshot_id,
                    }
                )

        self.logger.debug(
            "group_members_fetched",
            group_id=group_object_id,
            member_count=len(memberships),
        )
        return memberships

    async def _fetch_group_ids(self) -> list[str]:
        """Fetch all group object IDs from Graph for membership enumeration.

        Returns:
            List of group object ID strings.
        """
        group_ids: list[str] = []

        async with httpx.AsyncClient(timeout=60.0) as client:
            params: dict[str, Any] = {
                "$select": "id",
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
                    gid = raw_group.get("id")
                    if gid:
                        group_ids.append(gid)

        return group_ids
