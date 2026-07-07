"""Data validation for referential integrity and conflict detection."""
from __future__ import annotations

from typing import Any

import structlog
from sqlalchemy import select, func, and_, text
from sqlalchemy.orm import Session

from src.storage.schema import (
    DimPrincipal,
    DimResource,
    DimRole,
    FactEffectivePermission,
    FactMembership,
    FactRoleAssignment,
)

logger = structlog.get_logger(__name__)


class DataValidator:
    """Validates data integrity and detects anomalies.

    Runs referential integrity checks, orphan detection,
    and permission conflict analysis.
    """

    @staticmethod
    def validate_referential_integrity(
        session: Session, snapshot_id: int
    ) -> list[str]:
        """Check that all foreign key references exist.

        Args:
            session: SQLAlchemy session.
            snapshot_id: Snapshot to validate.

        Returns:
            List of integrity violation descriptions.
        """
        violations: list[str] = []

        # Check FactRoleAssignment.principal_id -> DimPrincipal
        orphan_principals = session.execute(
            select(FactRoleAssignment.principal_id)
            .where(FactRoleAssignment.snapshot_id == snapshot_id)
            .where(
                ~FactRoleAssignment.principal_id.in_(
                    select(DimPrincipal.principal_id)
                )
            )
            .distinct()
        ).scalars().all()

        if orphan_principals:
            violations.append(
                f"FactRoleAssignment references {len(orphan_principals)} "
                f"principals not in DimPrincipal"
            )

        # Check FactRoleAssignment.resource_id -> DimResource
        orphan_resources = session.execute(
            select(FactRoleAssignment.resource_id)
            .where(FactRoleAssignment.snapshot_id == snapshot_id)
            .where(FactRoleAssignment.resource_id.isnot(None))
            .where(
                ~FactRoleAssignment.resource_id.in_(
                    select(DimResource.resource_id)
                )
            )
            .distinct()
        ).scalars().all()

        if orphan_resources:
            violations.append(
                f"FactRoleAssignment references {len(orphan_resources)} "
                f"resources not in DimResource"
            )

        # Check FactRoleAssignment.role_id -> DimRole
        orphan_roles = session.execute(
            select(FactRoleAssignment.role_id)
            .where(FactRoleAssignment.snapshot_id == snapshot_id)
            .where(FactRoleAssignment.role_id.isnot(None))
            .where(
                ~FactRoleAssignment.role_id.in_(
                    select(DimRole.role_id)
                )
            )
            .distinct()
        ).scalars().all()

        if orphan_roles:
            violations.append(
                f"FactRoleAssignment references {len(orphan_roles)} "
                f"roles not in DimRole"
            )

        # Check FactMembership references
        orphan_members = session.execute(
            select(FactMembership.member_id)
            .where(FactMembership.snapshot_id == snapshot_id)
            .where(
                ~FactMembership.member_id.in_(
                    select(DimPrincipal.principal_id)
                )
            )
            .distinct()
        ).scalars().all()

        if orphan_members:
            violations.append(
                f"FactMembership references {len(orphan_members)} "
                f"member principals not in DimPrincipal"
            )

        logger.info(
            "referential_integrity_checked",
            violations=len(violations),
            snapshot_id=snapshot_id,
        )
        return violations

    @staticmethod
    def detect_orphaned_principals(
        session: Session, snapshot_id: int
    ) -> list[dict[str, Any]]:
        """Find principals referenced in assignments but missing from DimPrincipal.

        Args:
            session: SQLAlchemy session.
            snapshot_id: Snapshot to check.

        Returns:
            List of dicts with orphaned principal IDs and sources.
        """
        orphans = session.execute(
            select(
                FactRoleAssignment.principal_id,
                FactRoleAssignment.source,
                func.count().label("assignment_count"),
            )
            .where(FactRoleAssignment.snapshot_id == snapshot_id)
            .where(
                ~FactRoleAssignment.principal_id.in_(
                    select(DimPrincipal.principal_id)
                )
            )
            .group_by(FactRoleAssignment.principal_id, FactRoleAssignment.source)
        ).all()

        results = [
            {
                "principal_id": row.principal_id,
                "source": row.source,
                "assignment_count": row.assignment_count,
            }
            for row in orphans
        ]

        logger.info("orphaned_principals_detected", count=len(results))
        return results

    @staticmethod
    def detect_permission_conflicts(
        session: Session, snapshot_id: int
    ) -> list[dict[str, Any]]:
        """Find cases where the same principal has conflicting permissions on a resource.

        Looks for cases where ALLOW and DENY exist for the same
        principal + resource combination.

        Args:
            session: SQLAlchemy session.
            snapshot_id: Snapshot to check.

        Returns:
            List of dicts describing conflicts.
        """
        # This requires FactPermissionAssignment which tracks ALLOW/DENY states
        # For FactRoleAssignment, we check if same principal has inherited
        # and direct assignments on same resource with different roles
        conflicts = session.execute(
            select(
                FactRoleAssignment.principal_id,
                FactRoleAssignment.resource_id,
                func.count(FactRoleAssignment.assignment_id.distinct()).label("assignment_count"),
                func.count(FactRoleAssignment.role_id.distinct()).label("role_count"),
            )
            .where(FactRoleAssignment.snapshot_id == snapshot_id)
            .group_by(
                FactRoleAssignment.principal_id,
                FactRoleAssignment.resource_id,
            )
            .having(func.count(FactRoleAssignment.role_id.distinct()) > 1)
        ).all()

        results = [
            {
                "principal_id": row.principal_id,
                "resource_id": row.resource_id,
                "assignment_count": row.assignment_count,
                "distinct_roles": row.role_count,
            }
            for row in conflicts
        ]

        logger.info("permission_conflicts_detected", count=len(results))
        return results

    @staticmethod
    def generate_report(session: Session, snapshot_id: int) -> dict[str, Any]:
        """Generate a complete validation report for a snapshot.

        Args:
            session: SQLAlchemy session.
            snapshot_id: Snapshot to validate.

        Returns:
            Comprehensive validation report dict.
        """
        # Counts
        principal_count = session.execute(
            select(func.count()).select_from(DimPrincipal)
        ).scalar() or 0

        resource_count = session.execute(
            select(func.count()).select_from(DimResource)
        ).scalar() or 0

        assignment_count = session.execute(
            select(func.count()).select_from(FactRoleAssignment).where(
                FactRoleAssignment.snapshot_id == snapshot_id
            )
        ).scalar() or 0

        membership_count = session.execute(
            select(func.count()).select_from(FactMembership).where(
                FactMembership.snapshot_id == snapshot_id
            )
        ).scalar() or 0

        effective_count = session.execute(
            select(func.count()).select_from(FactEffectivePermission).where(
                FactEffectivePermission.snapshot_id == snapshot_id
            )
        ).scalar() or 0

        # Validations
        integrity_violations = DataValidator.validate_referential_integrity(
            session, snapshot_id
        )
        orphaned_principals = DataValidator.detect_orphaned_principals(
            session, snapshot_id
        )
        conflicts = DataValidator.detect_permission_conflicts(
            session, snapshot_id
        )

        report = {
            "snapshot_id": snapshot_id,
            "counts": {
                "principals": principal_count,
                "resources": resource_count,
                "role_assignments": assignment_count,
                "memberships": membership_count,
                "effective_permissions": effective_count,
            },
            "integrity": {
                "violations": integrity_violations,
                "violation_count": len(integrity_violations),
                "is_valid": len(integrity_violations) == 0,
            },
            "orphans": {
                "orphaned_principals": orphaned_principals,
                "orphan_count": len(orphaned_principals),
            },
            "conflicts": {
                "permission_conflicts": conflicts,
                "conflict_count": len(conflicts),
            },
            "overall_health": (
                "HEALTHY"
                if len(integrity_violations) == 0
                and len(orphaned_principals) == 0
                and len(conflicts) == 0
                else "ISSUES_FOUND"
            ),
        }

        logger.info(
            "validation_report_generated",
            health=report["overall_health"],
            snapshot_id=snapshot_id,
        )
        return report
