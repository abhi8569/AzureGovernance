"""Resource data models for Azure and Microsoft service resources."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from src.models.enums import ResourceType


class Resource(BaseModel):
    """Represents any Azure or Microsoft service resource.

    Unified model for subscriptions, resource groups, storage accounts,
    Fabric workspaces, reports, databases, and all other resource types.
    """

    model_config = ConfigDict(from_attributes=True)

    resource_id: int | None = None
    tenant_id: str
    resource_guid: str = Field(description="Unique identifier from the source system (Azure resource ID, Fabric item ID, etc.)")
    resource_type: ResourceType
    name: str = ""
    parent_id: int | None = None
    subscription_id: str | None = None
    resource_group: str | None = None
    location: str | None = None
    tags: dict | None = None
    created_date: datetime | None = None
    deleted_date: datetime | None = None
    source_data: dict | None = Field(default=None, description="Raw source data for debugging")
