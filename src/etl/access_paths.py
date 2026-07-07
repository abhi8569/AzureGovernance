"""Access path builder for permission explainability."""
from __future__ import annotations

from typing import Any

import structlog
from sqlalchemy import select, insert
from sqlalchemy.orm import Session

from src.storage.schema import (
    DimPrincipal,
    DimResource,
    DimRole,
    FactAccessPath,
    FactEffectivePermission,
    FactMembershipClosure,
    FactResourceHierarchyClosure,
    FactRoleAssignment,
)
from src.utils.id_generator import generate_composite_key

logger = structlog.get_logger(__name__)


class AccessPathBuilder:
    """Builds human-readable access paths for effective permissions.

    For each effective permission, constructs a step-by-step path
    explaining how the principal obtained access to the resource,
    e.g., 'Alice -> Engineering Team -> Contributor -> Subscription -> RG-Data'.
    """

    @staticmethod
    def build_paths(session: Session, snapshot_id: int) -> int:
        """Build access path records for all effective permissions.

        Args:
            session: SQLAlchemy session.
            snapshot_id: Snapshot to process.

        Returns:
            Number of access path records created.
        """
        # Load name lookups
        principal_names = {
            row.principal_id: row.display_name or row.object_id
            for row in session.execute(select(DimPrincipal)).scalars()
        }
        resource_names = {
            row.resource_id: row.name or row.resource_guid
            for row in session.execute(select(DimResource)).scalars()
        }
        role_names = {
            row.role_id: row.role_name or "UnknownRole"
            for row in session.execute(select(DimRole)).scalars()
        }

        # Get all effective permissions
        effective_perms = session.execute(
            select(FactEffectivePermission).where(
                FactEffectivePermission.snapshot_id == snapshot_id
            )
        ).scalars().all()

        if not effective_perms:
            logger.info("no_effective_permissions", snapshot_id=snapshot_id)
            return 0

        # Get assignments for path lookup
        assignments = {
            a.assignment_id: a
            for a in session.execute(
                select(FactRoleAssignment).where(
                    FactRoleAssignment.snapshot_id == snapshot_id
                )
            ).scalars()
        }

        path_records: list[dict[str, Any]] = []

        for eff in effective_perms:
            assignment = assignments.get(eff.source_assignment_id)
            if not assignment:
                continue

            steps = AccessPathBuilder._build_steps(
                effective_principal_id=eff.principal_id,
                assignment_principal_id=assignment.principal_id,
                role_id=assignment.role_id,
                assignment_resource_id=assignment.resource_id,
                effective_resource_id=eff.resource_id,
                principal_names=principal_names,
                resource_names=resource_names,
                role_names=role_names,
            )

            for step_order, (node_id, node_type, node_name) in enumerate(steps):
                path_records.append({
                    "path_id": generate_composite_key(
                        str(eff.effective_id), str(step_order)
                    ),
                    "effective_id": eff.effective_id,
                    "step_order": step_order,
                    "node_id": node_id,
                    "node_type": node_type,
                    "node_name": node_name,
                    "snapshot_id": snapshot_id,
                })

        # Insert in batches
        batch_size = 1000
        for i in range(0, len(path_records), batch_size):
            batch = path_records[i : i + batch_size]
            session.execute(insert(FactAccessPath), batch)

        session.commit()

        logger.info(
            "access_paths_built",
            effective_permissions=len(effective_perms),
            path_steps=len(path_records),
            snapshot_id=snapshot_id,
        )
        return len(path_records)

    @staticmethod
    def _build_steps(
        effective_principal_id: int,
        assignment_principal_id: int,
        role_id: int | None,
        assignment_resource_id: int | None,
        effective_resource_id: int,
        principal_names: dict[int, str],
        resource_names: dict[int, str],
        role_names: dict[int, str],
    ) -> list[tuple[int, str, str]]:
        """Build ordered path steps from principal to resource.

        Returns:
            List of (node_id, node_type, node_name) tuples.
        """
        steps = []

        # Step 1: The effective (inheriting) principal
        steps.append((
            effective_principal_id,
            "PRINCIPAL",
            principal_names.get(effective_principal_id, "Unknown"),
        ))

        # Step 2: If inherited via group, show the assignment principal
        if effective_principal_id != assignment_principal_id:
            steps.append((
                assignment_principal_id,
                "GROUP",
                principal_names.get(assignment_principal_id, "Unknown Group"),
            ))

        # Step 3: The role
        if role_id:
            steps.append((
                role_id,
                "ROLE",
                role_names.get(role_id, "Unknown Role"),
            ))

        # Step 4: The assigned resource (if different from effective)
        if assignment_resource_id and assignment_resource_id != effective_resource_id:
            steps.append((
                assignment_resource_id,
                "RESOURCE",
                resource_names.get(assignment_resource_id, "Unknown Resource"),
            ))

        # Step 5: The effective (target) resource
        steps.append((
            effective_resource_id,
            "RESOURCE",
            resource_names.get(effective_resource_id, "Unknown Resource"),
        ))

        return steps

    @staticmethod
    def build_path_string(
        principal_id: int,
        resource_id: int,
        session: Session,
    ) -> str:
        """Build a human-readable path string for a specific principal+resource.

        Args:
            principal_id: DimPrincipal ID.
            resource_id: DimResource ID.
            session: SQLAlchemy session.

        Returns:
            Arrow-separated path like 'Alice → GroupA → Contributor → StorageAccount'.
        """
        # Get the principal name
        principal = session.execute(
            select(DimPrincipal).where(DimPrincipal.principal_id == principal_id)
        ).scalar_one_or_none()

        resource = session.execute(
            select(DimResource).where(DimResource.resource_id == resource_id)
        ).scalar_one_or_none()

        p_name = principal.display_name if principal else "Unknown"
        r_name = resource.name if resource else "Unknown"

        return f"{p_name} → {r_name}"
