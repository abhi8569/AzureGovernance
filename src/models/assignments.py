"""Assignment, membership, and effective permission models."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from src.models.enums import AssignmentType, MembershipType


class RoleAssignment(BaseModel):
    """Represents a direct role or permission assignment."""

    model_config = ConfigDict(from_attributes=True)

    assignment_id: int | None = None
    principal_id: int
    role_id: int | None = None
    resource_id: int | None = None
    assignment_type: AssignmentType
    start_date: datetime | None = None
    end_date: datetime | None = None
    granted_by_id: int | None = None
    inherited: bool = False
    source: str | None = None
    snapshot_id: int | None = None


class Membership(BaseModel):
    """Represents a direct group or role membership edge."""

    model_config = ConfigDict(from_attributes=True)

    member_id: int
    parent_id: int
    membership_type: MembershipType
    source: str | None = None
    effective_from: datetime | None = None
    effective_to: datetime | None = None
    snapshot_id: int | None = None


class EffectivePermission(BaseModel):
    """Represents a computed effective permission after inheritance resolution."""

    model_config = ConfigDict(from_attributes=True)

    effective_id: int | None = None
    principal_id: int
    resource_id: int
    permission_id: int
    source_assignment_id: int
    depth: int = 0
    inheritance_path: str | None = Field(default=None, description="Human-readable path: 'Alice -> GroupA -> Role -> Resource'")
    calculated_on: datetime | None = None
    snapshot_id: int | None = None


class AccessPath(BaseModel):
    """Represents the explanation path for an effective permission."""

    steps: list[str] = Field(default_factory=list, description="Ordered list of node names in the access path")
    description: str | None = None

    def to_string(self) -> str:
        """Format the access path as a readable string.

        Returns:
            Arrow-separated path string, e.g., 'Alice -> Engineering -> Contributor -> StorageAccount'.
        """
        return " → ".join(self.steps) if self.steps else "(empty path)"

    def __str__(self) -> str:
        return self.to_string()
