"""Azure Storage account extractor."""
from __future__ import annotations

import time
from typing import Any, TYPE_CHECKING

import structlog

from src.extractors.base import ExtractResult
from src.utils.id_generator import generate_surrogate_key

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

logger = structlog.get_logger(__name__)


class StorageAccountExtractor:
    """Extracts storage accounts from Azure subscriptions.

    Args:
        credential: Azure token credential.
        tenant_id: Azure AD tenant ID.
        snapshot_id: Current snapshot ID.
    """

    def __init__(
        self,
        credential: TokenCredential,
        tenant_id: str,
        snapshot_id: int,
    ) -> None:
        self.credential = credential
        self.tenant_id = tenant_id
        self.snapshot_id = snapshot_id
        self.logger = structlog.get_logger(self.__class__.__name__)

    def extract(self, subscription_id: str) -> ExtractResult:
        """Extract all storage accounts in a subscription.

        Args:
            subscription_id: Azure subscription ID.

        Returns:
            ExtractResult with DimResource-shaped records.
        """
        from azure.mgmt.storage import StorageManagementClient

        start_time = time.monotonic()
        records: list[dict[str, Any]] = []
        errors: list[str] = []

        try:
            client = StorageManagementClient(self.credential, subscription_id)

            for account in client.storage_accounts.list():
                records.append(self._map_storage_account(account, subscription_id))

            self.logger.info(
                "storage_accounts_extracted",
                count=len(records),
                subscription=subscription_id,
            )

        except Exception as e:
            errors.append(f"Storage accounts in {subscription_id}: {e}")
            self.logger.error("storage_extraction_failed", error=str(e))

        duration = time.monotonic() - start_time
        return ExtractResult(
            records=records,
            errors=errors,
            record_count=len(records),
            duration_seconds=duration,
            extractor_name="StorageAccountExtractor",
        )

    def _map_storage_account(self, account: Any, subscription_id: str) -> dict[str, Any]:
        """Map Azure SDK storage account to DimResource schema."""
        resource_id = account.id or ""
        rg_name = ""
        if resource_id:
            parts = resource_id.split("/")
            for i, part in enumerate(parts):
                if part.lower() == "resourcegroups" and i + 1 < len(parts):
                    rg_name = parts[i + 1]
                    break

        rg_id = f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}" if rg_name else None

        return {
            "resource_id": generate_surrogate_key("azure", resource_id),
            "tenant_id": self.tenant_id,
            "resource_guid": resource_id,
            "resource_type": "STORAGE_ACCOUNT",
            "name": account.name or "",
            "subscription_id": subscription_id,
            "resource_group": rg_name,
            "parent_id": generate_surrogate_key("azure", rg_id) if rg_id else None,
            "location": account.location or "",
            "tags": str(account.tags) if account.tags else None,
            "created_date": str(account.creation_time) if account.creation_time else None,
        }
