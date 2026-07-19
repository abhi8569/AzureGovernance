"""Credential factory for Azure SDK clients.

Supports three authentication modes (in priority order):
1. Azure CLI SSO — uses your existing `az login` session (DEFAULT, no app registration)
2. Interactive browser SSO — uses Azure CLI's well-known public client ID
3. Client secret — for service principal / headless automation
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from azure.identity import (
    AzureCliCredential,
    ClientSecretCredential,
    DefaultAzureCredential,
    InteractiveBrowserCredential,
)
import structlog

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential
    from msgraph import GraphServiceClient
    from config.settings import EAIPSettings

logger = structlog.get_logger(__name__)

# Azure CLI's well-known public client ID — registered in every Azure AD tenant.
# No app registration needed. Supports interactive browser auth for MSAL.
AZURE_CLI_CLIENT_ID = "04b07795-a72d-e811-80c3-00aa00394de7"


def get_credential(settings: EAIPSettings) -> TokenCredential:
    """Create an Azure credential based on settings.

    Authentication priority:
    1. If client_secret is set → ClientSecretCredential (service principal)
    2. If client_id is set → InteractiveBrowserCredential (custom app reg)
    3. Default → DefaultAzureCredential (az login / managed identity / etc.)

    Args:
        settings: Application settings.

    Returns:
        An Azure TokenCredential instance.
    """
    # Mode 1: Service principal with client secret
    if not settings.use_interactive_auth:
        logger.info("auth_mode", mode="client_secret")
        return ClientSecretCredential(
            tenant_id=settings.tenant_id,
            client_id=settings.client_id,
            client_secret=settings.client_secret.get_secret_value(),
        )

    # Mode 2: Custom app registration with interactive browser
    if settings.client_id:
        logger.info("auth_mode", mode="interactive_browser", client_id=settings.client_id)
        return InteractiveBrowserCredential(
            tenant_id=settings.tenant_id,
            client_id=settings.client_id,
        )

    # Mode 3: No app registration — use DefaultAzureCredential
    # This chains: Environment → Managed Identity → Azure CLI → Azure PowerShell → Interactive
    logger.info("auth_mode", mode="default_credential (az login / managed identity)")
    if settings.tenant_id:
        return DefaultAzureCredential(
            tenant_id=settings.tenant_id,
            exclude_interactive_browser_credential=False,
        )
    return DefaultAzureCredential(
        exclude_interactive_browser_credential=False,
    )


def get_msal_client_id(settings: EAIPSettings) -> str:
    """Get the MSAL client ID for token acquisition.

    Uses the configured client_id if set, otherwise falls back to
    Azure CLI's well-known public client ID (no app registration needed).

    Args:
        settings: Application settings.

    Returns:
        Client ID string for MSAL.
    """
    if settings.client_id:
        return settings.client_id
    logger.info("msal_client_id", mode="azure_cli_public_client")
    return AZURE_CLI_CLIENT_ID


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
