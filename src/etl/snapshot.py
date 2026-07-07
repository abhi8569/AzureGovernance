"""Snapshot lifecycle management for the EAIP ETL pipeline.

Creates, queries, and compares point-in-time snapshots that anchor
every fact row in the data warehouse.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any

import structlog
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.storage.schema import (
    DimSnapshot,
    FactRoleAssignment,
)

logger = structlog.get_logger(__name__)


class SnapshotManager:
    """Manage ETL snapshot records in :class:`DimSnapshot`."""

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    @staticmethod
    def create_snapshot(
        session: Session,
        description: str = "",
    ) -> int:
        """Insert a new snapshot row and return its ID.

        Args:
            session: Active SQLAlchemy session (caller manages commit).
            description: Optional human-readable label for the snapshot.

        Returns:
            The newly created ``snapshot_id``.
        """
        snapshot = DimSnapshot(
            snapshot_date=date.today(),
            description=description or f"Snapshot {datetime.now(tz=timezone.utc).isoformat()}",
        )
        session.add(snapshot)
        session.flush()  # assigns auto-increment PK

        logger.info(
            "snapshot_created",
            snapshot_id=snapshot.snapshot_id,
            snapshot_date=str(snapshot.snapshot_date),
            description=snapshot.description,
        )
        return snapshot.snapshot_id  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    @staticmethod
    def get_latest_snapshot(session: Session) -> int | None:
        """Return the most-recent ``snapshot_id``, or ``None`` if empty.

        Args:
            session: Active SQLAlchemy session.

        Returns:
            Latest snapshot_id or ``None``.
        """
        result = session.execute(
            select(func.max(DimSnapshot.snapshot_id))
        ).scalar()

        if result is not None:
            logger.debug("latest_snapshot_found", snapshot_id=result)
        else:
            logger.debug("no_snapshots_found")
        return result

    # ------------------------------------------------------------------
    # Diff
    # ------------------------------------------------------------------

    @staticmethod
    def diff_snapshots(
        session: Session,
        old_id: int,
        new_id: int,
    ) -> dict[str, Any]:
        """Compare two snapshots and return added / removed / changed assignments.

        Comparison is based on ``FactRoleAssignment`` rows keyed by their
        natural composite key ``(principal_id, role_id, resource_id,
        assignment_type)``.

        Args:
            session: Active SQLAlchemy session.
            old_id: The earlier snapshot ID.
            new_id: The later snapshot ID.

        Returns:
            Dict with ``added``, ``removed``, and ``changed`` lists, plus
            summary counts.
        """
        old_rows = session.execute(
            select(FactRoleAssignment).where(
                FactRoleAssignment.snapshot_id == old_id
            )
        ).scalars().all()

        new_rows = session.execute(
            select(FactRoleAssignment).where(
                FactRoleAssignment.snapshot_id == new_id
            )
        ).scalars().all()

        def _natural_key(row: FactRoleAssignment) -> tuple:
            return (
                row.principal_id,
                row.role_id,
                row.resource_id,
                row.assignment_type,
            )

        old_map: dict[tuple, FactRoleAssignment] = {_natural_key(r): r for r in old_rows}
        new_map: dict[tuple, FactRoleAssignment] = {_natural_key(r): r for r in new_rows}

        old_keys = set(old_map.keys())
        new_keys = set(new_map.keys())

        added_keys = new_keys - old_keys
        removed_keys = old_keys - new_keys
        common_keys = old_keys & new_keys

        # Detect changed fields in common assignments
        changed: list[dict[str, Any]] = []
        for key in common_keys:
            old_row = old_map[key]
            new_row = new_map[key]
            diffs: dict[str, Any] = {}
            for col in ("start_date", "end_date", "granted_by_id", "inherited", "source"):
                old_val = getattr(old_row, col)
                new_val = getattr(new_row, col)
                if old_val != new_val:
                    diffs[col] = {"old": str(old_val), "new": str(new_val)}
            if diffs:
                changed.append({
                    "key": {
                        "principal_id": key[0],
                        "role_id": key[1],
                        "resource_id": key[2],
                        "assignment_type": key[3],
                    },
                    "changes": diffs,
                })

        def _serialise_row(row: FactRoleAssignment) -> dict[str, Any]:
            return {
                "assignment_id": row.assignment_id,
                "principal_id": row.principal_id,
                "role_id": row.role_id,
                "resource_id": row.resource_id,
                "assignment_type": row.assignment_type,
                "source": row.source,
            }

        result: dict[str, Any] = {
            "old_snapshot_id": old_id,
            "new_snapshot_id": new_id,
            "summary": {
                "added_count": len(added_keys),
                "removed_count": len(removed_keys),
                "changed_count": len(changed),
                "unchanged_count": len(common_keys) - len(changed),
            },
            "added": [_serialise_row(new_map[k]) for k in added_keys],
            "removed": [_serialise_row(old_map[k]) for k in removed_keys],
            "changed": changed,
        }

        logger.info(
            "snapshot_diff_computed",
            old_id=old_id,
            new_id=new_id,
            added=len(added_keys),
            removed=len(removed_keys),
            changed=len(changed),
        )
        return result
