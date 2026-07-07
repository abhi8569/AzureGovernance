"""Data normalisation for raw records from various discovery sources.

Ensures all records have deterministic surrogate keys, deduplicates
by natural key, and provides a generic merge strategy for incremental
loads.
"""
from __future__ import annotations

from typing import Any

import structlog

from src.utils.id_generator import generate_surrogate_key

logger = structlog.get_logger(__name__)


class DataNormalizer:
    """Normalise and deduplicate raw discovery records before warehouse load."""

    # ------------------------------------------------------------------
    # Principals
    # ------------------------------------------------------------------

    @staticmethod
    def normalize_principals(
        raw_records: list[dict[str, Any]],
        source: str,
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        """Normalise principal records.

        Ensures every record carries a deterministic ``principal_id``
        surrogate key derived from (source, object_id) and deduplicates
        by ``object_id``.

        Args:
            raw_records: Raw dicts from an API or file ingest.
            source: Source system identifier (e.g. ``'entra'``).
            tenant_id: Azure AD / Entra tenant GUID.

        Returns:
            Deduplicated list of normalised principal dicts.
        """
        seen: dict[str, dict[str, Any]] = {}
        normalized: list[dict[str, Any]] = []

        for record in raw_records:
            object_id = record.get("object_id") or record.get("id", "")
            if not object_id:
                logger.warning(
                    "principal_missing_object_id",
                    source=source,
                    record_keys=list(record.keys()),
                )
                continue

            # Deterministic surrogate key
            principal_id = generate_surrogate_key(source, object_id)

            # Deduplicate by object_id — last-write wins
            if object_id in seen:
                logger.debug(
                    "principal_duplicate_skipped",
                    object_id=object_id,
                    source=source,
                )

            norm: dict[str, Any] = {
                "principal_id": principal_id,
                "tenant_id": tenant_id,
                "object_id": object_id,
                "principal_type": record.get("principal_type", "UNKNOWN"),
                "display_name": record.get("display_name", record.get("displayName", "")),
                "user_principal_name": record.get(
                    "user_principal_name", record.get("userPrincipalName")
                ),
                "mail": record.get("mail"),
                "account_enabled": record.get(
                    "account_enabled", record.get("accountEnabled")
                ),
                "user_type": record.get("user_type", record.get("userType")),
                "created_date": record.get("created_date", record.get("createdDateTime")),
                "modified_date": record.get("modified_date"),
                "is_deleted": record.get("is_deleted", False),
            }
            seen[object_id] = norm

        normalized = list(seen.values())
        logger.info(
            "principals_normalized",
            source=source,
            raw_count=len(raw_records),
            normalized_count=len(normalized),
        )
        return normalized

    # ------------------------------------------------------------------
    # Resources
    # ------------------------------------------------------------------

    @staticmethod
    def normalize_resources(
        raw_records: list[dict[str, Any]],
        source: str,
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        """Normalise resource records.

        Generates a deterministic ``resource_id`` from (source,
        resource_guid) and deduplicates by ``resource_guid``.

        Args:
            raw_records: Raw resource dicts.
            source: Source system identifier.
            tenant_id: Azure tenant GUID.

        Returns:
            Deduplicated list of normalised resource dicts.
        """
        seen: dict[str, dict[str, Any]] = {}

        for record in raw_records:
            resource_guid = (
                record.get("resource_guid")
                or record.get("id")
                or record.get("resource_id_str", "")
            )
            if not resource_guid:
                logger.warning(
                    "resource_missing_guid",
                    source=source,
                    record_keys=list(record.keys()),
                )
                continue

            resource_id = generate_surrogate_key(source, resource_guid)

            if resource_guid in seen:
                logger.debug(
                    "resource_duplicate_skipped",
                    resource_guid=resource_guid,
                    source=source,
                )

            # Resolve parent_id if a parent GUID is supplied
            parent_guid = record.get("parent_guid") or record.get("parent_id_str")
            parent_id: int | None = None
            if parent_guid:
                parent_id = generate_surrogate_key(source, parent_guid)

            norm: dict[str, Any] = {
                "resource_id": resource_id,
                "tenant_id": tenant_id,
                "resource_guid": resource_guid,
                "resource_type": record.get("resource_type", "GENERIC"),
                "name": record.get("name", ""),
                "parent_id": parent_id,
                "subscription_id": record.get("subscription_id"),
                "resource_group": record.get("resource_group"),
                "location": record.get("location"),
                "tags": record.get("tags"),
                "created_date": record.get("created_date"),
                "deleted_date": record.get("deleted_date"),
            }
            seen[resource_guid] = norm

        normalized = list(seen.values())
        logger.info(
            "resources_normalized",
            source=source,
            raw_count=len(raw_records),
            normalized_count=len(normalized),
        )
        return normalized

    # ------------------------------------------------------------------
    # Role assignments
    # ------------------------------------------------------------------

    @staticmethod
    def normalize_role_assignments(
        raw_records: list[dict[str, Any]],
        source: str,
    ) -> list[dict[str, Any]]:
        """Normalise role-assignment records.

        Generates a deterministic ``assignment_id`` surrogate key from
        (source, <composite-natural-key>) and deduplicates.

        Args:
            raw_records: Raw assignment dicts.
            source: Source system identifier.

        Returns:
            Deduplicated assignment dicts.
        """
        seen: dict[int, dict[str, Any]] = {}

        for record in raw_records:
            # Build a composite natural key from available identifiers
            natural_key_parts = [
                str(record.get("principal_id", "")),
                str(record.get("role_id", "")),
                str(record.get("resource_id", "")),
                str(record.get("assignment_type", "")),
            ]
            assignment_id = generate_surrogate_key(source, "|".join(natural_key_parts))

            if assignment_id in seen:
                logger.debug(
                    "assignment_duplicate_skipped",
                    assignment_id=assignment_id,
                    source=source,
                )
                continue

            norm: dict[str, Any] = {
                "assignment_id": assignment_id,
                "principal_id": record.get("principal_id"),
                "role_id": record.get("role_id"),
                "resource_id": record.get("resource_id"),
                "assignment_type": record.get("assignment_type"),
                "start_date": record.get("start_date"),
                "end_date": record.get("end_date"),
                "granted_by_id": record.get("granted_by_id"),
                "inherited": record.get("inherited", False),
                "source": source,
                "snapshot_id": record.get("snapshot_id"),
            }
            seen[assignment_id] = norm

        normalized = list(seen.values())
        logger.info(
            "assignments_normalized",
            source=source,
            raw_count=len(raw_records),
            normalized_count=len(normalized),
        )
        return normalized

    # ------------------------------------------------------------------
    # Generic merge
    # ------------------------------------------------------------------

    @staticmethod
    def merge_records(
        existing: list[dict[str, Any]],
        new: list[dict[str, Any]],
        key_field: str,
    ) -> list[dict[str, Any]]:
        """Merge new records into an existing list, deduplicating by *key_field*.

        New records overwrite existing ones that share the same key
        (last-write-wins).

        Args:
            existing: Previously loaded records.
            new: Freshly normalised records to merge in.
            key_field: Dict key used for deduplication (e.g. ``"object_id"``).

        Returns:
            Merged and deduplicated list.
        """
        merged: dict[Any, dict[str, Any]] = {}
        for rec in existing:
            key = rec.get(key_field)
            if key is not None:
                merged[key] = rec

        overwritten = 0
        for rec in new:
            key = rec.get(key_field)
            if key is not None:
                if key in merged:
                    overwritten += 1
                merged[key] = rec

        result = list(merged.values())
        logger.info(
            "records_merged",
            existing_count=len(existing),
            new_count=len(new),
            merged_count=len(result),
            overwritten=overwritten,
            key_field=key_field,
        )
        return result
