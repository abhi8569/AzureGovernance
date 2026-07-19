"""Abstract base extractor for all EAIP data sources."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class ExtractResult:
    """Result of an extraction operation."""
    records: list[dict[str, Any]] = field(default_factory=list)
    delta_token: str | None = None
    errors: list[str] = field(default_factory=list)
    record_count: int = 0
    duration_seconds: float = 0.0
    extractor_name: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def success(self) -> bool:
        return len(self.errors) == 0


class BaseExtractor(ABC):
    """Abstract base class for all data extractors.

    Each extractor authenticates with a target service and extracts
    data objects (users, groups, roles, resources, etc.).

    Args:
        tenant_id: Azure AD tenant ID.
        token: OAuth2 access token.
        snapshot_id: Current snapshot ID for tagging records.
    """

    def __init__(self, tenant_id: str, token: str, snapshot_id: int) -> None:
        self.tenant_id = tenant_id
        self.token = token
        self.snapshot_id = snapshot_id
        self.logger = structlog.get_logger(self.__class__.__name__)

    @property
    def headers(self) -> dict[str, str]:
        """HTTP headers with Bearer token."""
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "ConsistencyLevel": "eventual",
        }

    @abstractmethod
    async def extract(self) -> ExtractResult:
        """Run a full extraction."""
        ...

    async def extract_incremental(self, delta_token: str | None = None) -> ExtractResult:
        """Run an incremental extraction using a delta token.

        Default implementation falls back to full extraction.
        Override in subclasses that support delta queries.
        """
        self.logger.info("incremental_not_supported_falling_back_to_full")
        return await self.extract()
