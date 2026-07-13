"""Tests for Power BI deep permissions extractor."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.extractors.fabric.powerbi_permissions import PowerBIDeepPermissionsExtractor
from src.utils.id_generator import generate_surrogate_key


@pytest.fixture
def extractor():
    return PowerBIDeepPermissionsExtractor("tenant-1", "fake-token", 1)


class TestMapWorkspaceUser:
    """Tests for _map_workspace_user mapping logic."""

    def test_correct_fields(self, extractor) -> None:
        user = {
            "identifier": "user@contoso.com",
            "principalType": "User",
            "groupUserAccessRight": "Admin",
            "emailAddress": "user@contoso.com",
            "displayName": "Test User",
        }
        result = extractor._map_workspace_user(user, 12345)
        assert result["assignment_type"] == "FABRIC_WORKSPACE_ROLE"
        assert result["resource_id"] == 12345
        assert result["_access_right"] == "Admin"
        assert result["_display_name"] == "Test User"
        assert result["principal_id"] == generate_surrogate_key("entra", "user@contoso.com")

    def test_group_principal(self, extractor) -> None:
        user = {
            "identifier": "group-id-123",
            "principalType": "Group",
            "groupUserAccessRight": "Viewer",
        }
        result = extractor._map_workspace_user(user, 99)
        assert result["_principal_type"] == "Group"
        assert result["_access_right"] == "Viewer"


class TestMapItemUser:
    """Tests for _map_item_user generic item permission mapper."""

    def test_dataset_access_right(self, extractor) -> None:
        user = {
            "identifier": "alice@contoso.com",
            "datasetUserAccessRight": "ReadAll",
            "principalType": "User",
            "displayName": "Alice",
        }
        result = extractor._map_item_user(user, 100, "SEMANTIC_MODEL")
        assert result["_access_right"] == "ReadAll"
        assert result["_item_type"] == "SEMANTIC_MODEL"
        assert result["resource_id"] == 100

    def test_report_access_right(self, extractor) -> None:
        user = {
            "identifier": "bob@contoso.com",
            "reportUserAccessRight": "ReadReshare",
            "principalType": "User",
        }
        result = extractor._map_item_user(user, 200, "REPORT")
        assert result["_access_right"] == "ReadReshare"
        assert result["_item_type"] == "REPORT"

    def test_dashboard_access_right(self, extractor) -> None:
        user = {
            "identifier": "carol@contoso.com",
            "dashboardUserAccessRight": "Read",
        }
        result = extractor._map_item_user(user, 300, "DASHBOARD")
        assert result["_access_right"] == "Read"


class TestExtractErrorHandling:
    """Test that individual extraction failures are captured, not raised."""

    @pytest.mark.asyncio
    @patch("src.extractors.fabric.powerbi_permissions.POWERBI_RATE_LIMITER")
    async def test_workspace_user_error_captured(self, mock_limiter, extractor) -> None:
        mock_limiter.acquire = AsyncMock()
        mock_client = AsyncMock()
        # Workspace listing succeeds
        mock_client.get.return_value = MagicMock(
            status_code=200,
            raise_for_status=MagicMock(),
            json=MagicMock(return_value={"value": [{"id": "ws-1"}]}),
        )
        # Users call fails
        mock_client.get.side_effect = [
            MagicMock(
                status_code=200,
                raise_for_status=MagicMock(),
                json=MagicMock(return_value={"value": [{"id": "ws-1"}]}),
            ),
            Exception("API Error"),
        ]

        errors = []
        assignments = []
        await extractor._extract_workspace_users(mock_client, assignments, errors)
        assert len(errors) > 0  # Error is captured, not raised
