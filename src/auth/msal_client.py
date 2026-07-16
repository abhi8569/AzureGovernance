"""MSAL client for Azure AD authentication."""
from __future__ import annotations

import msal
import structlog

from src.auth.token_cache import DEFAULT_CACHE_PATH, load_cache, save_cache

logger = structlog.get_logger(__name__)


class AuthenticationError(Exception):
    """Raised when authentication fails."""


class MSALClient:
    """Wrapper around MSAL for Public or Confidential client authentication.

    Uses PublicClientApplication for interactive flows (no client secret)
    and ConfidentialClientApplication for daemon/service flows (with client secret).
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str = "",
        cache_path: str = DEFAULT_CACHE_PATH,
    ) -> None:
        """Initialise the MSAL client.

        Args:
            tenant_id: Azure AD tenant ID.
            client_id: Application (client) ID.
            client_secret: Client secret for confidential apps. Leave empty for
                interactive/public client flows.
            cache_path: Path to the persistent token cache file.
        """
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._cache_path = cache_path
        self._cache = load_cache(cache_path)

        authority = f"https://login.microsoftonline.com/{tenant_id}"

        if client_secret:
            self._app: msal.ClientApplication = msal.ConfidentialClientApplication(
                client_id=client_id,
                client_credential=client_secret,
                authority=authority,
                token_cache=self._cache,
            )
            logger.info(
                "msal_client_created",
                mode="confidential",
                tenant_id=tenant_id,
                client_id=client_id,
            )
        else:
            self._app = msal.PublicClientApplication(
                client_id=client_id,
                authority=authority,
                token_cache=self._cache,
            )
            logger.info(
                "msal_client_created",
                mode="public",
                tenant_id=tenant_id,
                client_id=client_id,
            )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_interactive(self) -> bool:
        """Return True when the client uses interactive (public) auth."""
        return not bool(self._client_secret)

    # ------------------------------------------------------------------
    # Token acquisition
    # ------------------------------------------------------------------

    def get_token(self, scopes: list[str]) -> str:
        """Acquire an access token, using the cache when possible.

        Flow priority:
        1. ``acquire_token_silent`` across all cached accounts.
        2. If interactive mode → ``acquire_token_interactive``.
        3. If client-credentials mode → ``acquire_token_for_client``.

        Args:
            scopes: OAuth2 scopes to request.

        Returns:
            The access token string.

        Raises:
            AuthenticationError: If token acquisition fails.
        """
        # 1. Try silent acquisition
        accounts = self._app.get_accounts()
        result = None
        if accounts:
            logger.debug("silent_auth_attempt", accounts=len(accounts))
            result = self._app.acquire_token_silent(scopes=scopes, account=accounts[0])

        if result and "access_token" in result:
            logger.debug("token_acquired", method="silent")
            self._save_cache()
            return result["access_token"]

        # 2. Fall back to interactive or client-credentials
        if self.is_interactive:
            logger.info("interactive_auth_attempt")
            result = self._app.acquire_token_interactive(scopes=scopes)
        else:
            logger.info("client_credentials_auth_attempt")
            result = self._app.acquire_token_for_client(scopes=scopes)

        if result and "access_token" in result:
            logger.info("token_acquired", method="interactive" if self.is_interactive else "client_credentials")
            self._save_cache()
            return result["access_token"]

        # 3. Authentication failed
        error = result.get("error", "unknown") if result else "no_result"
        error_description = result.get("error_description", "") if result else ""
        logger.error(
            "token_acquisition_failed",
            error=error,
            error_description=error_description,
        )
        raise AuthenticationError(
            f"Failed to acquire token: {error} — {error_description}"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _save_cache(self) -> None:
        """Persist the token cache to disk."""
        save_cache(self._cache, self._cache_path)
