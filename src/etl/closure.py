"""Transitive-closure computation for membership and resource hierarchies.

Provides both a Python-side iterative BFS and an optional SQL-based
recursive-CTE approach for computing the full closure of group
memberships and resource containment.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

import structlog
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from src.storage.schema import (
    FactMembership,
    FactMembershipClosure,
    FactResourceHierarchy,
    FactResourceHierarchyClosure,
)

logger = structlog.get_logger(__name__)

# Safety limit to prevent infinite loops on pathological graphs
_MAX_DEPTH = 50


class ClosureComputer:
    """Compute transitive closures over membership and resource graphs."""

    # ==================================================================
    # Membership closure — BFS
    # ==================================================================

    @staticmethod
    def compute_membership_closure(
        session: Session,
        snapshot_id: int,
    ) -> int:
        """Compute transitive closure of principal-membership edges.

        Uses iterative BFS starting from direct edges (depth 1) and
        expanding until no new edges are discovered or ``_MAX_DEPTH`` is
        reached.  Results are bulk-inserted into
        :class:`FactMembershipClosure`.

        Args:
            session: Active SQLAlchemy session (caller manages commit).
            snapshot_id: Snapshot to operate on.

        Returns:
            Total number of closure edges inserted.
        """
        # 1. Load direct edges for this snapshot
        direct_rows = session.execute(
            select(FactMembership).where(
                FactMembership.snapshot_id == snapshot_id
            )
        ).scalars().all()

        if not direct_rows:
            logger.info("membership_closure_noop", snapshot_id=snapshot_id)
            return 0

        # Build adjacency: parent -> set of members
        adjacency: dict[int, set[int]] = defaultdict(set)
        for row in direct_rows:
            adjacency[row.parent_id].add(row.member_id)

        # 2. Seed with direct (depth-1) edges
        # Closure edge: (ancestor_id, descendant_id) -> (depth, path)
        closure: dict[tuple[int, int], tuple[int, str]] = {}
        frontier: set[tuple[int, int, int, str]] = set()  # (ancestor, descendant, depth, path)

        for row in direct_rows:
            edge_key = (row.parent_id, row.member_id)
            path = f"{row.parent_id}->{row.member_id}"
            if edge_key not in closure:
                closure[edge_key] = (1, path)
                frontier.add((row.parent_id, row.member_id, 1, path))

        logger.debug(
            "membership_closure_seeded",
            snapshot_id=snapshot_id,
            direct_edges=len(closure),
        )

        # 3. Iterative BFS expansion
        depth = 1
        while frontier and depth < _MAX_DEPTH:
            depth += 1
            next_frontier: set[tuple[int, int, int, str]] = set()

            for ancestor, descendant, _d, path in frontier:
                # For every child of *descendant*, create a transitive edge
                for child in adjacency.get(descendant, set()):
                    edge_key = (ancestor, child)
                    if edge_key not in closure:
                        new_path = f"{path}->{child}"
                        closure[edge_key] = (depth, new_path)
                        next_frontier.add((ancestor, child, depth, new_path))

            if not next_frontier:
                break
            frontier = next_frontier
            logger.debug(
                "membership_closure_depth",
                depth=depth,
                new_edges=len(next_frontier),
            )

        # 4. Also add reflexive edges (depth-0) for every principal that
        #    appears as either parent or member.
        all_principals: set[int] = set()
        for row in direct_rows:
            all_principals.add(row.parent_id)
            all_principals.add(row.member_id)
        for pid in all_principals:
            key = (pid, pid)
            if key not in closure:
                closure[key] = (0, str(pid))

        # 5. Detect cycles
        edges = {(a, d) for (a, d) in closure if a != d}
        cycles = ClosureComputer._detect_cycles(edges)
        if cycles:
            logger.warning(
                "membership_cycles_detected",
                snapshot_id=snapshot_id,
                cycle_count=len(cycles),
                sample_cycle=cycles[0],
            )

        # 6. Clear existing closure for this snapshot
        session.execute(
            FactMembershipClosure.__table__.delete().where(
                FactMembershipClosure.snapshot_id == snapshot_id
            )
        )

        # 7. Bulk insert
        closure_rows = [
            FactMembershipClosure(
                ancestor_id=ancestor,
                descendant_id=descendant,
                depth=depth_val,
                path=path_val,
                snapshot_id=snapshot_id,
            )
            for (ancestor, descendant), (depth_val, path_val) in closure.items()
        ]
        session.bulk_save_objects(closure_rows)
        session.flush()

        logger.info(
            "membership_closure_computed",
            snapshot_id=snapshot_id,
            closure_edges=len(closure_rows),
            max_depth_reached=depth,
        )
        return len(closure_rows)

    # ==================================================================
    # Membership closure — SQL recursive CTE
    # ==================================================================

    @staticmethod
    def compute_membership_closure_sql(
        conn: Any,
        snapshot_id: int,
    ) -> int:
        """Compute membership closure using a database-side recursive CTE.

        This is a DuckDB-compatible alternative that keeps the heavy
        lifting inside the database engine.

        Args:
            conn: A raw DB-API connection (e.g. ``duckdb.DuckDBPyConnection``).
            snapshot_id: Snapshot to operate on.

        Returns:
            Number of closure rows inserted.
        """
        # Clear old closure rows for this snapshot
        conn.execute(
            "DELETE FROM fact_membership_closure WHERE snapshot_id = ?",
            [snapshot_id],
        )

        cte_sql = """
        WITH RECURSIVE closure AS (
            -- Seed: direct edges at depth 1
            SELECT
                parent_id   AS ancestor_id,
                member_id   AS descendant_id,
                1           AS depth,
                CAST(parent_id AS VARCHAR) || '->' || CAST(member_id AS VARCHAR) AS path
            FROM fact_membership
            WHERE snapshot_id = ?

            UNION ALL

            -- Expand: join current frontier with direct edges
            SELECT
                c.ancestor_id,
                m.member_id   AS descendant_id,
                c.depth + 1   AS depth,
                c.path || '->' || CAST(m.member_id AS VARCHAR) AS path
            FROM closure c
            JOIN fact_membership m
              ON m.parent_id = c.descendant_id
             AND m.snapshot_id = ?
            WHERE c.depth < ?
              AND c.ancestor_id != m.member_id  -- avoid simple cycles
        )
        INSERT INTO fact_membership_closure
            (ancestor_id, descendant_id, depth, path, snapshot_id)
        SELECT
            ancestor_id,
            descendant_id,
            MIN(depth) AS depth,      -- keep shortest path
            MIN(path)  AS path,
            ?          AS snapshot_id
        FROM closure
        GROUP BY ancestor_id, descendant_id
        """

        conn.execute(cte_sql, [snapshot_id, snapshot_id, _MAX_DEPTH, snapshot_id])

        result = conn.execute(
            "SELECT COUNT(*) FROM fact_membership_closure WHERE snapshot_id = ?",
            [snapshot_id],
        ).fetchone()
        count = result[0] if result else 0

        logger.info(
            "membership_closure_computed_sql",
            snapshot_id=snapshot_id,
            closure_edges=count,
        )
        return count

    # ==================================================================
    # Resource hierarchy closure — BFS
    # ==================================================================

    @staticmethod
    def compute_resource_hierarchy_closure(
        session: Session,
        snapshot_id: int,
    ) -> int:
        """Compute transitive closure of the resource hierarchy.

        Follows the same iterative BFS strategy as
        :meth:`compute_membership_closure` but over
        :class:`FactResourceHierarchy` edges.

        Args:
            session: Active SQLAlchemy session (caller manages commit).
            snapshot_id: Snapshot to operate on.

        Returns:
            Total number of closure edges inserted.
        """
        direct_rows = session.execute(
            select(FactResourceHierarchy).where(
                FactResourceHierarchy.snapshot_id == snapshot_id
            )
        ).scalars().all()

        if not direct_rows:
            logger.info("resource_closure_noop", snapshot_id=snapshot_id)
            return 0

        # Build adjacency: parent_resource -> set of child_resources
        adjacency: dict[int, set[int]] = defaultdict(set)
        for row in direct_rows:
            adjacency[row.parent_resource_id].add(row.child_resource_id)

        # Seed depth-1
        closure: dict[tuple[int, int], tuple[int, str]] = {}
        frontier: set[tuple[int, int, int, str]] = set()

        for row in direct_rows:
            edge_key = (row.parent_resource_id, row.child_resource_id)
            path = f"{row.parent_resource_id}->{row.child_resource_id}"
            if edge_key not in closure:
                closure[edge_key] = (1, path)
                frontier.add((
                    row.parent_resource_id,
                    row.child_resource_id,
                    1,
                    path,
                ))

        # Iterative expansion
        depth = 1
        while frontier and depth < _MAX_DEPTH:
            depth += 1
            next_frontier: set[tuple[int, int, int, str]] = set()

            for ancestor, descendant, _d, path in frontier:
                for child in adjacency.get(descendant, set()):
                    edge_key = (ancestor, child)
                    if edge_key not in closure:
                        new_path = f"{path}->{child}"
                        closure[edge_key] = (depth, new_path)
                        next_frontier.add((ancestor, child, depth, new_path))

            if not next_frontier:
                break
            frontier = next_frontier
            logger.debug(
                "resource_closure_depth",
                depth=depth,
                new_edges=len(next_frontier),
            )

        # Reflexive edges for all resources
        all_resources: set[int] = set()
        for row in direct_rows:
            all_resources.add(row.parent_resource_id)
            all_resources.add(row.child_resource_id)
        for rid in all_resources:
            key = (rid, rid)
            if key not in closure:
                closure[key] = (0, str(rid))

        # Cycle detection
        edges = {(a, d) for (a, d) in closure if a != d}
        cycles = ClosureComputer._detect_cycles(edges)
        if cycles:
            logger.warning(
                "resource_hierarchy_cycles_detected",
                snapshot_id=snapshot_id,
                cycle_count=len(cycles),
                sample_cycle=cycles[0],
            )

        # Clear existing closure
        session.execute(
            FactResourceHierarchyClosure.__table__.delete().where(
                FactResourceHierarchyClosure.snapshot_id == snapshot_id
            )
        )

        # Bulk insert
        closure_rows = [
            FactResourceHierarchyClosure(
                ancestor_resource_id=ancestor,
                descendant_resource_id=descendant,
                depth=depth_val,
                path=path_val,
                snapshot_id=snapshot_id,
            )
            for (ancestor, descendant), (depth_val, path_val) in closure.items()
        ]
        session.bulk_save_objects(closure_rows)
        session.flush()

        logger.info(
            "resource_closure_computed",
            snapshot_id=snapshot_id,
            closure_edges=len(closure_rows),
            max_depth_reached=depth,
        )
        return len(closure_rows)

    # ==================================================================
    # Cycle detection
    # ==================================================================

    @staticmethod
    def _detect_cycles(edges: set[tuple[int, int]]) -> list[tuple[int, ...]]:
        """Find cycles in a directed graph defined by *(src, dst)* edges.

        Uses iterative DFS with a colour-map.

        Args:
            edges: Set of directed edges ``(from_node, to_node)``.

        Returns:
            List of cycles, each represented as a tuple of node IDs
            forming the cycle.  Empty list means acyclic.
        """
        adjacency: dict[int, set[int]] = defaultdict(set)
        for src, dst in edges:
            adjacency[src].add(dst)

        all_nodes = set()
        for src, dst in edges:
            all_nodes.add(src)
            all_nodes.add(dst)

        WHITE, GRAY, BLACK = 0, 1, 2
        colour: dict[int, int] = {n: WHITE for n in all_nodes}
        cycles: list[tuple[int, ...]] = []

        for start in all_nodes:
            if colour[start] != WHITE:
                continue

            # Iterative DFS with explicit stack
            stack: list[tuple[int, list[int]]] = [(start, [start])]
            colour[start] = GRAY

            while stack:
                node, path = stack.pop()

                has_unvisited = False
                for neighbour in adjacency.get(node, set()):
                    if colour[neighbour] == GRAY:
                        # Found a back-edge => cycle
                        cycle_start_idx = path.index(neighbour)
                        cycle = tuple(path[cycle_start_idx:])
                        cycles.append(cycle)
                    elif colour[neighbour] == WHITE:
                        colour[neighbour] = GRAY
                        stack.append((neighbour, path + [neighbour]))
                        has_unvisited = True

                if not has_unvisited:
                    colour[node] = BLACK

        if cycles:
            logger.warning("cycles_detected", count=len(cycles))
        return cycles
