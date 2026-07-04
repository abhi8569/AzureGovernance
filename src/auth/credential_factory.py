"""Credential factory for Azure SDK clients."""
from __future__ import annotations

from typing import TYPE_CHECKING

from azure.identity import ClientSecretCredential, InteractiveBrowserCredential
import structlog

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential
    from msgraph import GraphServiceClient
    from config.settings import EAIPSettings

logger = structlog.get_logger(__name__)


def get_credential(settings: EAIPSettings) -> TokenCredential:
    """Create an Azure credential based on settings.

    Uses interactive browser login if no client secret is configured,
    otherwise uses client secret credentials.

    Args:
        settings: Application settings.

    Returns:
        An Azure TokenCredential instance.
    """
    if settings.use_interactive_auth:
        logger.info("auth_mode", mode="interactive_browser")
        return InteractiveBrowserCredential(
            tenant_id=settings.tenant_id,
            client_id=settings.client_id,
        )
    else:
        logger.info("auth_mode", mode="client_secret")
        return ClientSecretCredential(
            tenant_id=settings.tenant_id,
            client_id=settings.client_id,
            client_secret=settings.client_secret.get_secret_value(),
        )


def get_graph_client(credential: TokenCredential) -> GraphServiceClient:
    """Create a Microsoft Graph client.

    Args:
        credential: Azure token credential.

    Returns:
        A configured GraphServiceClient.
    """
    from msgraph import GraphServiceClient
    return GraphServiceClient(credentials=credential)


def get_http_headers(token: str) -> dict[str, str]:
    """Create HTTP headers with Bearer token.

    Args:
        token: OAuth2 access token.

    Returns:
        Headers dict with Authorization header.
    """
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
