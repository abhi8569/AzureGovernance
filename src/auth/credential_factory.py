"""Credential factory for Azure SDK clients.

Supports three authentication modes (in priority order):
1. Azure CLI SSO — uses your existing `az login` session (DEFAULT, no app registration)
2. Interactive browser SSO — uses Azure CLI's well-known public client ID
3. Client secret — for service principal / headless automation
"""
from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING, Any

from azure.identity import (
    AzureCliCredential,
    ClientSecretCredential,
    InteractiveBrowserCredential,
)
import structlog

if TYPE_CHECKING:
    from azure.core.credentials import AccessToken, TokenCredential
    from msgraph import GraphServiceClient
    from config.settings import EAIPSettings

logger = structlog.get_logger(__name__)

# Azure CLI's well-known public client ID — registered in every Azure AD tenant.
# No app registration needed. Supports interactive browser auth for MSAL.
AZURE_CLI_CLIENT_ID = "04b07795-a72d-e811-80c3-00aa00394de7"


class AutoLoginAzureCliCredential:
    """Wrapper around AzureCliCredential that automatically runs 'az login' if needed."""

    def __init__(self, tenant_id: str | None = None) -> None:
        self.tenant_id = tenant_id
        self._credential = AzureCliCredential(tenant_id=tenant_id) if tenant_id else AzureCliCredential()

    def get_token(self, *scopes: str, **kwargs: Any) -> AccessToken:
        """Get token, automatically logging in if no session exists or has expired."""
        try:
            return self._credential.get_token(*scopes, **kwargs)
        except Exception as e:
            err_msg = str(e)
            # Detect if login is required or session has expired
            if (
                "az login" in err_msg
                or "expired" in err_msg.lower()
                or "interaction" in err_msg.lower()
                or "please run" in err_msg.lower()
            ):
                logger.info("az_login_required", reason=err_msg)
                print("\n" + "=" * 60)
                print("[INFO] Azure CLI login required or session expired.")
                print("       Starting automatic 'az login' process...")
                print("=" * 60 + "\n")

                # Verify if az is installed
                try:
                    subprocess.run(["az", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                except Exception:
                    raise RuntimeError(
                        "Azure CLI (az) is not installed on this machine.\n"
                        "Please download and install it from: https://aka.ms/InstallAzureCli"
                    )

                cmd = ["az", "login"]
                if self.tenant_id:
                    cmd.extend(["--tenant", self.tenant_id])

                try:
                    # Run az login interactively (opens browser)
                    subprocess.run(cmd, check=True)
                    # Recreate credential with the active session
                    self._credential = AzureCliCredential(tenant_id=self.tenant_id) if self.tenant_id else AzureCliCredential()
                    # Retry token acquisition
                    return self._credential.get_token(*scopes, **kwargs)
                except subprocess.CalledProcessError as login_err:
                    raise RuntimeError(f"Interactive 'az login' failed: {login_err}") from login_err
            else:
                raise e


def get_credential(settings: EAIPSettings) -> TokenCredential:
    """Create an Azure credential based on settings.

    Authentication priority:
    1. If client_secret is set → ClientSecretCredential (service principal)
    2. If client_id is set → InteractiveBrowserCredential (custom app reg)
    3. Default → AutoLoginAzureCliCredential (az login session)

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

    # Mode 3: No app registration — use Azure CLI credential with auto login fallback
    logger.info("auth_mode", mode="azure_cli (az login) with auto-login fallback")
    return AutoLoginAzureCliCredential(tenant_id=settings.tenant_id or None)


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
