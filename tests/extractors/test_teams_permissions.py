"""Tests for Teams permissions extractor."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.extractors.sharepoint.teams import TeamsPermissionsExtractor
from src.utils.id_generator import generate_surrogate_key


@pytest.fixture
def extractor():
    return TeamsPermissionsExtractor("tenant-1", "fake-token", 1)


class TestMapTeam:
    """Tests for _map_team resource mapping."""

    def test_basic_team(self, extractor) -> None:
        group = {
            "id": "team-001",
            "displayName": "Engineering",
            "description": "Eng team",
            "visibility": "Private",
        }
        result = extractor._map_team(group)
        assert result["resource_id"] == generate_surrogate_key("teams", "team-001")
        assert result["resource_type"] == "TEAM"
        assert result["name"] == "Engineering"
        assert result["_visibility"] == "Private"


class TestTeamMemberExtraction:
    """Tests for _extract_team_members."""

    @pytest.mark.asyncio
    @patch("src.extractors.sharepoint.teams.GRAPH_RATE_LIMITER")
    async def test_owner_and_member(self, mock_limiter, extractor) -> None:
        mock_limiter.acquire = AsyncMock()
        mock_client = AsyncMock()
        mock_client.get.return_value = MagicMock(
            status_code=200,
            raise_for_status=MagicMock(),
            json=MagicMock(return_value={
                "value": [
                    {"userId": "u-1", "roles": ["owner"], "displayName": "Owner", "email": "o@c.com", "@odata.type": "#microsoft.graph.aadUserConversationMember"},
                    {"userId": "u-2", "roles": [], "displayName": "Member", "email": "m@c.com", "@odata.type": "#microsoft.graph.aadUserConversationMember"},
                ]
            }),
        )

        assignments = []
        errors = []
        await extractor._extract_team_members(mock_client, "team-1", 100, assignments, errors)
        assert len(assignments) == 2
        assert assignments[0]["_role"] == "owner"
        assert assignments[1]["_role"] == "member"
        assert len(errors) == 0

    @pytest.mark.asyncio
    @patch("src.extractors.sharepoint.teams.GRAPH_RATE_LIMITER")
    async def test_error_captured(self, mock_limiter, extractor) -> None:
        mock_limiter.acquire = AsyncMock()
        mock_client = AsyncMock()
        mock_client.get.side_effect = Exception("forbidden")

        assignments = []
        errors = []
        await extractor._extract_team_members(mock_client, "team-1", 100, assignments, errors)
        assert len(errors) == 1
        assert len(assignments) == 0


class TestChannelExtraction:
    """Tests for channel type detection."""

    @pytest.mark.asyncio
    @patch("src.extractors.sharepoint.teams.GRAPH_RATE_LIMITER")
    async def test_private_channel_members_extracted(self, mock_limiter, extractor) -> None:
        mock_limiter.acquire = AsyncMock()
        mock_client = AsyncMock()

        # Channels listing
        channels_resp = MagicMock(
            status_code=200, raise_for_status=MagicMock(),
            json=MagicMock(return_value={
                "value": [
                    {"id": "ch-1", "displayName": "General", "membershipType": "standard"},
                    {"id": "ch-2", "displayName": "Secret", "membershipType": "private"},
                ]
            }),
        )
        # Private channel members
        members_resp = MagicMock(
            status_code=200, raise_for_status=MagicMock(),
            json=MagicMock(return_value={
                "value": [
                    {"userId": "u-5", "roles": ["owner"], "displayName": "PM"},
                ]
            }),
        )
        mock_client.get.side_effect = [channels_resp, members_resp]

        resources = []
        assignments = []
        errors = []
        await extractor._extract_channels(mock_client, "team-1", 100, resources, assignments, errors)

        assert len(resources) == 2  # 2 channels
        assert resources[1]["_membership_type"] == "private"
        assert len(assignments) == 1  # 1 private channel member
