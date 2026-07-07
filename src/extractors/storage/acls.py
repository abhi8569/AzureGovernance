"""ADLS Gen2 ACL (Access Control List) extractor."""
from __future__ import annotations

import time
from typing import Any, TYPE_CHECKING

import structlog

from src.extractors.base import ExtractResult
from src.utils.id_generator import generate_surrogate_key

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

logger = structlog.get_logger(__name__)


class ACLExtractor:
    """Extracts POSIX ACLs from ADLS Gen2 filesystems.

    Recursively traverses directories and reads access control
    entries, parsing them into FactRoleAssignment-compatible records.

    Args:
        tenant_id: Azure AD tenant ID.
        snapshot_id: Current snapshot ID.
    """

    def __init__(self, tenant_id: str, snapshot_id: int) -> None:
        self.tenant_id = tenant_id
        self.snapshot_id = snapshot_id
        self.logger = structlog.get_logger(self.__class__.__name__)

    def extract(
        self,
        account_url: str,
        filesystem_name: str,
        credential: TokenCredential,
        max_depth: int = 3,
    ) -> ExtractResult:
        """Extract ACLs from an ADLS Gen2 filesystem.

        Args:
            account_url: Storage account URL.
            filesystem_name: Filesystem (container) name.
            credential: Azure token credential.
            max_depth: Maximum directory depth to traverse.

        Returns:
            ExtractResult with FactRoleAssignment-shaped records.
        """
        from azure.storage.filedatalake import DataLakeServiceClient

        start_time = time.monotonic()
        records: list[dict[str, Any]] = []
        errors: list[str] = []

        try:
            service_client = DataLakeServiceClient(
                account_url=account_url,
                credential=credential,
            )
            fs_client = service_client.get_file_system_client(filesystem_name)

            # Get root directory ACL
            root_acl = self._get_directory_acl(fs_client, "", account_url, filesystem_name)
            records.extend(root_acl)

            # Traverse directories
            self._traverse_directory(
                fs_client=fs_client,
                path="",
                account_url=account_url,
                filesystem_name=filesystem_name,
                records=records,
                errors=errors,
                current_depth=0,
                max_depth=max_depth,
            )

            self.logger.info(
                "acls_extracted",
                count=len(records),
                filesystem=filesystem_name,
            )

        except Exception as e:
            errors.append(f"ACLs for {filesystem_name}: {e}")
            self.logger.error("acl_extraction_failed", error=str(e))

        duration = time.monotonic() - start_time
        return ExtractResult(
            records=records,
            errors=errors,
            record_count=len(records),
            duration_seconds=duration,
            extractor_name="ACLExtractor",
        )

    def _traverse_directory(
        self,
        fs_client: Any,
        path: str,
        account_url: str,
        filesystem_name: str,
        records: list[dict[str, Any]],
        errors: list[str],
        current_depth: int,
        max_depth: int,
    ) -> None:
        """Recursively traverse directories and extract ACLs."""
        if current_depth >= max_depth:
            return

        try:
            paths = fs_client.get_paths(path=path or "/", recursive=False)
            for item in paths:
                if item.is_directory:
                    dir_acl = self._get_directory_acl(
                        fs_client, item.name, account_url, filesystem_name
                    )
                    records.extend(dir_acl)

                    self._traverse_directory(
                        fs_client=fs_client,
                        path=item.name,
                        account_url=account_url,
                        filesystem_name=filesystem_name,
                        records=records,
                        errors=errors,
                        current_depth=current_depth + 1,
                        max_depth=max_depth,
                    )
        except Exception as e:
            errors.append(f"Traversal at {path}: {e}")
            self.logger.warning("directory_traversal_failed", path=path, error=str(e))

    def _get_directory_acl(
        self,
        fs_client: Any,
        path: str,
        account_url: str,
        filesystem_name: str,
    ) -> list[dict[str, Any]]:
        """Get ACL entries for a specific directory."""
        records = []
        try:
            if path:
                dir_client = fs_client.get_directory_client(path)
            else:
                dir_client = fs_client.get_directory_client("/")

            acl_props = dir_client.get_access_control()
            acl_string = acl_props.get("acl", "")

            if acl_string:
                entries = self._parse_acl_string(acl_string)
                resource_path = f"{account_url}/{filesystem_name}/{path}" if path else f"{account_url}/{filesystem_name}"

                for entry in entries:
                    if entry.get("principal_id"):
                        records.append({
                            "assignment_id": generate_surrogate_key(
                                "storage_acl",
                                f"{resource_path}:{entry['scope']}:{entry['principal_id']}",
                            ),
                            "principal_id": generate_surrogate_key("entra", entry["principal_id"]),
                            "role_id": None,
                            "resource_id": generate_surrogate_key("azure_storage", resource_path),
                            "assignment_type": "STORAGE_ACL",
                            "start_date": None,
                            "end_date": None,
                            "inherited": entry.get("scope") == "default",
                            "source": "ADLS_ACL",
                            "snapshot_id": self.snapshot_id,
                            "_acl_permissions": entry.get("permissions", ""),
                            "_acl_type": entry.get("type", ""),
                        })
        except Exception as e:
            self.logger.debug("acl_read_failed", path=path, error=str(e))

        return records

    @staticmethod
    def _parse_acl_string(acl_string: str) -> list[dict[str, str]]:
        """Parse a POSIX ACL string into structured entries.

        Format: 'scope:type:id:permissions' entries separated by commas.
        Examples:
            'user::rwx,user:oid:rwx,group::r-x,group:oid:r-x,other::---'
            'default:user::rwx,default:user:oid:rwx'

        Returns:
            List of dicts with keys: scope, type, principal_id, permissions.
        """
        entries = []
        for part in acl_string.split(","):
            part = part.strip()
            if not part:
                continue

            segments = part.split(":")
            scope = "access"

            if segments[0] == "default":
                scope = "default"
                segments = segments[1:]

            if len(segments) >= 3:
                acl_type = segments[0]    # user, group, other, mask
                principal_id = segments[1]  # empty for owning user/group
                permissions = segments[2]   # rwx, r-x, ---, etc.

                entries.append({
                    "scope": scope,
                    "type": acl_type,
                    "principal_id": principal_id,
                    "permissions": permissions,
                })

        return entries
