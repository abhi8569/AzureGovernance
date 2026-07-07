"""ADLS Gen2 filesystem/container extractor."""
from __future__ import annotations

import time
from typing import Any, TYPE_CHECKING

import structlog

from src.extractors.base import ExtractResult
from src.utils.id_generator import generate_surrogate_key

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

logger = structlog.get_logger(__name__)


class ContainerExtractor:
    """Extracts ADLS Gen2 filesystems (containers) from a storage account.

    Args:
        tenant_id: Azure AD tenant ID.
        snapshot_id: Current snapshot ID.
    """

    def __init__(self, tenant_id: str, snapshot_id: int) -> None:
        self.tenant_id = tenant_id
        self.snapshot_id = snapshot_id
        self.logger = structlog.get_logger(self.__class__.__name__)

    def extract(self, account_url: str, credential: TokenCredential) -> ExtractResult:
        """Extract all filesystems from a Data Lake storage account.

        Args:
            account_url: Storage account URL (e.g., https://account.dfs.core.windows.net).
            credential: Azure token credential.

        Returns:
            ExtractResult with DimResource-shaped records.
        """
        from azure.storage.filedatalake import DataLakeServiceClient

        start_time = time.monotonic()
        records: list[dict[str, Any]] = []
        errors: list[str] = []

        try:
            service_client = DataLakeServiceClient(
                account_url=account_url,
                credential=credential,
            )
            account_name = account_url.split("//")[1].split(".")[0] if "//" in account_url else account_url

            for fs in service_client.list_file_systems():
                fs_name = fs.name or ""
                fs_id = f"{account_url}/{fs_name}"

                records.append({
                    "resource_id": generate_surrogate_key("azure_storage", fs_id),
                    "tenant_id": self.tenant_id,
                    "resource_guid": fs_id,
                    "resource_type": "ADLS_FILESYSTEM",
                    "name": fs_name,
                    "parent_id": generate_surrogate_key("azure_storage", account_url),
                    "subscription_id": None,
                    "resource_group": None,
                    "location": None,
                    "tags": None,
                    "created_date": str(fs.last_modified) if fs.last_modified else None,
                })

            self.logger.info(
                "containers_extracted",
                count=len(records),
                account=account_name,
            )

        except Exception as e:
            errors.append(f"Containers at {account_url}: {e}")
            self.logger.error("container_extraction_failed", error=str(e))

        duration = time.monotonic() - start_time
        return ExtractResult(
            records=records,
            errors=errors,
            record_count=len(records),
            duration_seconds=duration,
            extractor_name="ContainerExtractor",
        )
