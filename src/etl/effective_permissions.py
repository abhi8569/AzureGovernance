"""Effective permission resolver - computes inherited permissions."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy import select, insert
from sqlalchemy.orm import Session

from src.storage.schema import (
    DimPrincipal,
    DimRole,
    FactEffectivePermission,
    FactMembershipClosure,
    FactResourceHierarchyClosure,
    FactRoleAssignment,
)
from src.utils.id_generator import generate_composite_key

logger = structlog.get_logger(__name__)


class EffectivePermissionResolver:
    """Resolves effective permissions by combining role assignments
    with membership closure and resource hierarchy closure.

    For each role assignment:
    1. Find all descendant members of the assignment's principal
       (via membership closure).
    2. Find all descendant resources of the assignment's resource
       (via resource hierarchy closure).
    3. Create FactEffectivePermission for each (member, resource) pair.
    """

    @staticmethod
    def resolve(session: Session, snapshot_id: int) -> int:
        """Compute effective permissions for a snapshot.

        Args:
            session: SQLAlchemy session.
            snapshot_id: Snapshot to resolve.

        Returns:
            Number of effective permission records created.
        """
        # Fetch all role assignments for this snapshot
        assignments = session.execute(
            select(FactRoleAssignment).where(
                FactRoleAssignment.snapshot_id == snapshot_id
            )
        ).scalars().all()

        if not assignments:
            logger.info("no_assignments_to_resolve", snapshot_id=snapshot_id)
            return 0

        # Build membership closure lookup: ancestor -> list of descendants
        membership_rows = session.execute(
            select(
                FactMembershipClosure.ancestor_id,
                FactMembershipClosure.descendant_id,
                FactMembershipClosure.depth,
                FactMembershipClosure.path,
            ).where(FactMembershipClosure.snapshot_id == snapshot_id)
        ).all()

        ancestor_to_descendants: dict[int, list[tuple[int, int, str]]] = {}
        for anc, desc, depth, path in membership_rows:
            ancestor_to_descendants.setdefault(anc, []).append((desc, depth, path or ""))

        # Build resource closure lookup: ancestor -> list of descendants
        resource_rows = session.execute(
            select(
                FactResourceHierarchyClosure.ancestor_resource_id,
                FactResourceHierarchyClosure.descendant_resource_id,
                FactResourceHierarchyClosure.depth,
                FactResourceHierarchyClosure.path,
            ).where(FactResourceHierarchyClosure.snapshot_id == snapshot_id)
        ).all()

        ancestor_to_child_resources: dict[int, list[tuple[int, int, str]]] = {}
        for anc, desc, depth, path in resource_rows:
            ancestor_to_child_resources.setdefault(anc, []).append((desc, depth, path or ""))

        # Resolve effective permissions
        effective_records: list[dict[str, Any]] = []
        now = datetime.now(timezone.utc)

        for assignment in assignments:
            principal_id = assignment.principal_id
            resource_id = assignment.resource_id
            assignment_id = assignment.assignment_id

            # Get all members who inherit from this principal (including self)
            member_entries = ancestor_to_descendants.get(principal_id, [(principal_id, 0, "")])

            # Get all resources under this resource (including self)
            if resource_id:
                resource_entries = ancestor_to_child_resources.get(
                    resource_id, [(resource_id, 0, "")]
                )
            else:
                resource_entries = [(resource_id, 0, "")]

            for member_id, member_depth, member_path in member_entries:
                for res_id, res_depth, res_path in resource_entries:
                    total_depth = member_depth + res_depth

                    # Build inheritance path description
                    parts = []
                    if member_path:
                        parts.append(f"member:{member_path}")
                    if res_path:
                        parts.append(f"resource:{res_path}")
                    inheritance_path = " | ".join(parts) if parts else None

                    effective_id = generate_composite_key(
                        str(member_id),
                        str(res_id or 0),
                        str(assignment_id),
                        str(snapshot_id),
                    )

                    effective_records.append({
                        "effective_id": effective_id,
                        "principal_id": member_id,
                        "resource_id": res_id or 0,
                        "permission_id": assignment.role_id or 0,
                        "source_assignment_id": assignment_id,
                        "depth": total_depth,
                        "inheritance_path": inheritance_path,
                        "calculated_on": now,
                        "snapshot_id": snapshot_id,
                    })

        # Deduplicate by effective_id
        seen: set[int] = set()
        unique_records = []
        for rec in effective_records:
            if rec["effective_id"] not in seen:
                seen.add(rec["effective_id"])
                unique_records.append(rec)

        # Insert in batches
        batch_size = 1000
        for i in range(0, len(unique_records), batch_size):
            batch = unique_records[i : i + batch_size]
            session.execute(insert(FactEffectivePermission), batch)

        session.commit()

        logger.info(
            "effective_permissions_resolved",
            assignments=len(assignments),
            effective_permissions=len(unique_records),
            snapshot_id=snapshot_id,
        )
        return len(unique_records)
