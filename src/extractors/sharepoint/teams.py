"""Microsoft Teams deep permission extractor.

Extracts ALL layers of Teams access control:
- Team members and owners (including guests)
- Channel members (standard, private, shared channels)
- Shared channel cross-team access
- Team settings (guest permissions, member permissions)
- Installed apps per team
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

logger = structlog.get_logger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


class TeamsPermissionsExtractor(BaseExtractor):
    """Extracts Teams membership, channel access, and settings via Graph API.

    Drills into:
    - Team owners and members (including guest users)
    - Private and shared channel membership
    - Cross-team shared channel access
    - Guest access settings per team
    - Installed apps per team
    """

    async def extract(self) -> ExtractResult:
        """Extract all Teams and their deep permissions.

        Returns:
            ExtractResult with resources and membership assignments.
        """
        start_time = time.monotonic()
        resources: list[dict[str, Any]] = []
        assignments: list[dict[str, Any]] = []
        errors: list[str] = []

        async with httpx.AsyncClient(timeout=120.0) as client:
            # List all teams (via groups with resourceProvisioningOptions containing "Team")
            try:
                teams_url = (
                    f"{GRAPH_BASE}/groups?"
                    "$filter=resourceProvisioningOptions/Any(x:x eq 'Team')"
                    "&$select=id,displayName,description,visibility,createdDateTime"
                    "&$top=999"
                )
                async for page in paginate_graph(client, teams_url, self.headers):
                    await GRAPH_RATE_LIMITER.acquire()
                    for group in page:
                        team_id = group.get("id", "")
                        team_resource = self._map_team(group)
                        resources.append(team_resource)
                        team_resource_id = team_resource["resource_id"]

                        # Team members (owners + members + guests)
                        await self._extract_team_members(
                            client, team_id, team_resource_id, assignments, errors
                        )

                        # Channels (standard, private, shared)
                        await self._extract_channels(
                            client, team_id, team_resource_id,
                            resources, assignments, errors,
                        )

                        # Team settings
                        await self._extract_team_settings(
                            client, team_id, team_resource_id, resources, errors
                        )

                        # Installed apps
                        await self._extract_installed_apps(
                            client, team_id, team_resource_id, resources, errors
                        )

            except Exception as e:
                errors.append(f"Teams listing: {e}")
                self.logger.error("teams_listing_failed", error=str(e))

        duration = time.monotonic() - start_time
        self.logger.info(
            "teams_deep_extracted",
            teams=len([r for r in resources if r.get("resource_type") == "TEAM"]),
            channels=len([r for r in resources if r.get("resource_type") == "CHANNEL"]),
            assignments=len(assignments),
            duration=round(duration, 1),
        )
        return ExtractResult(
            records=[{"resources": resources, "assignments": assignments}],
            errors=errors,
            record_count=len(resources) + len(assignments),
            duration_seconds=duration,
            extractor_name="TeamsPermissionsExtractor",
        )

    async def _extract_team_members(
        self, client: httpx.AsyncClient, team_id: str,
        team_resource_id: int, assignments: list, errors: list,
    ) -> None:
        """Extract team owners, members, and guests."""
        try:
            await GRAPH_RATE_LIMITER.acquire()
            members_url = f"{GRAPH_BASE}/teams/{team_id}/members"
            resp = await client.get(members_url, headers=self.headers)
            resp.raise_for_status()

            for member in resp.json().get("value", []):
                user_id = member.get("userId", "")
                roles = member.get("roles", [])
                role = roles[0] if roles else "member"

                # Detect guest users
                is_guest = member.get("@odata.type", "").endswith("aadUserConversationMember") and not roles
                display_name = member.get("displayName", "")
                email = member.get("email", "")

                assignments.append({
                    "assignment_id": generate_surrogate_key(
                        "teams_member", f"{team_resource_id}:{user_id}:{role}"
                    ),
                    "principal_id": generate_surrogate_key("entra", user_id),
                    "resource_id": team_resource_id,
                    "assignment_type": "TEAM_MEMBERSHIP",
                    "source": "Teams",
                    "snapshot_id": self.snapshot_id,
                    "_role": role,  # "owner", "member", or "guest"
                    "_display_name": display_name,
                    "_email": email,
                    "_is_guest": "guest" in (member.get("@odata.type", "") + role).lower(),
                })
        except Exception as e:
            errors.append(f"Team {team_id} members: {e}")

    async def _extract_channels(
        self, client: httpx.AsyncClient, team_id: str,
        team_resource_id: int, resources: list, assignments: list, errors: list,
    ) -> None:
        """Extract channels and their members (especially private/shared)."""
        try:
            await GRAPH_RATE_LIMITER.acquire()
            channels_url = f"{GRAPH_BASE}/teams/{team_id}/channels"
            resp = await client.get(channels_url, headers=self.headers)
            resp.raise_for_status()

            for channel in resp.json().get("value", []):
                ch_id = channel.get("id", "")
                ch_type = channel.get("membershipType", "standard")
                ch_resource_id = generate_surrogate_key("teams_ch", f"{team_id}/{ch_id}")

                resources.append({
                    "resource_id": ch_resource_id,
                    "tenant_id": self.tenant_id,
                    "resource_guid": f"{team_id}/{ch_id}",
                    "resource_type": "CHANNEL",
                    "name": channel.get("displayName", ""),
                    "parent_id": team_resource_id,
                    "_membership_type": ch_type,
                    "_description": channel.get("description", ""),
                })

                # For private and shared channels, get explicit members
                if ch_type in ("private", "shared"):
                    try:
                        await GRAPH_RATE_LIMITER.acquire()
                        ch_members_url = f"{GRAPH_BASE}/teams/{team_id}/channels/{ch_id}/members"
                        m_resp = await client.get(ch_members_url, headers=self.headers)
                        m_resp.raise_for_status()

                        for member in m_resp.json().get("value", []):
                            user_id = member.get("userId", "")
                            roles = member.get("roles", [])
                            role = roles[0] if roles else "member"

                            assignments.append({
                                "assignment_id": generate_surrogate_key(
                                    "teams_ch_member",
                                    f"{ch_resource_id}:{user_id}:{role}",
                                ),
                                "principal_id": generate_surrogate_key("entra", user_id),
                                "resource_id": ch_resource_id,
                                "assignment_type": "TEAM_MEMBERSHIP",
                                "source": "Teams_Channel",
                                "snapshot_id": self.snapshot_id,
                                "_role": role,
                                "_channel_type": ch_type,
                                "_display_name": member.get("displayName", ""),
                            })
                    except Exception as e:
                        errors.append(f"Channel {ch_id} members: {e}")

                # For shared channels, get cross-team access
                if ch_type == "shared":
                    try:
                        await GRAPH_RATE_LIMITER.acquire()
                        shared_url = f"{GRAPH_BASE}/teams/{team_id}/channels/{ch_id}/sharedWithTeams"
                        s_resp = await client.get(shared_url, headers=self.headers)
                        s_resp.raise_for_status()

                        for shared_team in s_resp.json().get("value", []):
                            shared_team_id = shared_team.get("id", "")
                            shared_team_name = shared_team.get("displayName", "")
                            assignments.append({
                                "assignment_id": generate_surrogate_key(
                                    "teams_shared",
                                    f"{ch_resource_id}:shared:{shared_team_id}",
                                ),
                                "principal_id": generate_surrogate_key("teams", shared_team_id),
                                "resource_id": ch_resource_id,
                                "assignment_type": "TEAM_MEMBERSHIP",
                                "source": "Teams_SharedChannel",
                                "snapshot_id": self.snapshot_id,
                                "_role": "shared_access",
                                "_shared_team_name": shared_team_name,
                            })
                    except Exception as e:
                        errors.append(f"Shared channel {ch_id} teams: {e}")

        except Exception as e:
            errors.append(f"Team {team_id} channels: {e}")

    async def _extract_team_settings(
        self, client: httpx.AsyncClient, team_id: str,
        team_resource_id: int, resources: list, errors: list,
    ) -> None:
        """Extract team guest and member permission settings."""
        try:
            await GRAPH_RATE_LIMITER.acquire()
            team_url = f"{GRAPH_BASE}/teams/{team_id}"
            resp = await client.get(team_url, headers=self.headers)
            resp.raise_for_status()
            team_data = resp.json()

            guest_settings = team_data.get("guestSettings", {})
            member_settings = team_data.get("memberSettings", {})

            # Store as metadata on the team resource
            for r in resources:
                if r.get("resource_id") == team_resource_id:
                    r["_guest_can_create_channels"] = guest_settings.get("allowCreateUpdateChannels", False)
                    r["_guest_can_delete_channels"] = guest_settings.get("allowDeleteChannels", False)
                    r["_member_can_create_channels"] = member_settings.get("allowCreateUpdateChannels", True)
                    r["_member_can_delete_channels"] = member_settings.get("allowDeleteChannels", True)
                    r["_member_can_add_remove_apps"] = member_settings.get("allowAddRemoveApps", True)
                    r["_member_can_create_tabs"] = member_settings.get("allowCreateUpdateRemoveTabs", True)
                    break
        except Exception as e:
            errors.append(f"Team {team_id} settings: {e}")

    async def _extract_installed_apps(
        self, client: httpx.AsyncClient, team_id: str,
        team_resource_id: int, resources: list, errors: list,
    ) -> None:
        """Extract installed apps in a team."""
        try:
            await GRAPH_RATE_LIMITER.acquire()
            apps_url = f"{GRAPH_BASE}/teams/{team_id}/installedApps?$expand=teamsApp"
            resp = await client.get(apps_url, headers=self.headers)
            resp.raise_for_status()

            for app in resp.json().get("value", []):
                teams_app = app.get("teamsApp", {})
                app_id = teams_app.get("id", "")
                if app_id:
                    resources.append({
                        "resource_id": generate_surrogate_key("teams_app", f"{team_id}/{app_id}"),
                        "resource_type": "GENERIC",
                        "name": f"Teams App: {teams_app.get('displayName', '')}",
                        "parent_id": team_resource_id,
                        "_app_id": app_id,
                        "_distribution_method": teams_app.get("distributionMethod", ""),
                    })
        except Exception as e:
            errors.append(f"Team {team_id} apps: {e}")

    def _map_team(self, group: dict[str, Any]) -> dict[str, Any]:
        """Map Teams-enabled group to DimResource."""
        team_id = group.get("id", "")
        return {
            "resource_id": generate_surrogate_key("teams", team_id),
            "tenant_id": self.tenant_id,
            "resource_guid": team_id,
            "resource_type": "TEAM",
            "name": group.get("displayName", ""),
            "parent_id": None,
            "_visibility": group.get("visibility", ""),
            "_description": group.get("description", ""),
        }
