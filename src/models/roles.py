"""Role and permission data models."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from src.models.enums import Platform


class RoleDefinition(BaseModel):
    """Represents a role definition (Azure RBAC, Fabric, SQL, etc.)."""

    model_config = ConfigDict(from_attributes=True)

    role_id: int | None = None
    role_name: str
    platform: Platform
    is_built_in: bool = True
    description: str | None = None
    definition_json: dict | None = Field(default=None, description="Full role definition as JSON")
    permissions: list[str] = Field(default_factory=list, description="List of permission actions (e.g., 'Microsoft.Storage/*/read')")


class Permission(BaseModel):
    """Represents a granular permission action."""

    model_config = ConfigDict(from_attributes=True)

    permission_id: int | None = None
    permission_name: str
    description: str | None = None
    permission_category: str | None = Field(default=None, description="Category: Read, Write, Delete, Admin, Execute")
