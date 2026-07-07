"""Azure Key Vault extractor for vaults and access policies."""
from __future__ import annotations

import time
from typing import Any, TYPE_CHECKING

import structlog

from src.extractors.base import ExtractResult
from src.utils.id_generator import generate_surrogate_key

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

logger = structlog.get_logger(__name__)


class KeyVaultExtractor:
    """Extracts Key Vault resources and access policies.

    Args:
        credential: Azure token credential.
        tenant_id: Azure AD tenant ID.
        snapshot_id: Current snapshot ID.
    """

    def __init__(
        self,
        credential: TokenCredential,
        tenant_id: str,
        snapshot_id: int,
    ) -> None:
        self.credential = credential
        self.tenant_id = tenant_id
        self.snapshot_id = snapshot_id
        self.logger = structlog.get_logger(self.__class__.__name__)

    def extract(self, subscription_id: str) -> ExtractResult:
        """Extract all Key Vaults and their access policies in a subscription.

        Args:
            subscription_id: Azure subscription ID.

        Returns:
            ExtractResult with DimResource and FactRoleAssignment records.
        """
        from azure.mgmt.keyvault import KeyVaultManagementClient

        start_time = time.monotonic()
        resources: list[dict[str, Any]] = []
        assignments: list[dict[str, Any]] = []
        errors: list[str] = []

        try:
            client = KeyVaultManagementClient(self.credential, subscription_id)

            for vault in client.vaults.list():
                vault_resource = self._map_vault(vault, subscription_id)
                resources.append(vault_resource)

                # Get detailed vault with access policies
                try:
                    rg_name = self._extract_resource_group(vault.id or "")
                    if rg_name:
                        vault_detail = client.vaults.get(rg_name, vault.name)
                        if vault_detail.properties and vault_detail.properties.access_policies:
                            for policy in vault_detail.properties.access_policies:
                                policy_records = self._map_access_policy(
                                    policy, vault_resource["resource_id"]
                                )
                                assignments.extend(policy_records)
                except Exception as e:
                    errors.append(f"Vault {vault.name} policies: {e}")
                    self.logger.warning(
                        "vault_policy_read_failed",
                        vault=vault.name,
                        error=str(e),
                    )

            self.logger.info(
                "keyvaults_extracted",
                vaults=len(resources),
                policies=len(assignments),
                subscription=subscription_id,
            )

        except Exception as e:
            errors.append(f"Key Vaults in {subscription_id}: {e}")
            self.logger.error("keyvault_extraction_failed", error=str(e))

        duration = time.monotonic() - start_time
        return ExtractResult(
            records=[{"resources": resources, "assignments": assignments}],
            errors=errors,
            record_count=len(resources) + len(assignments),
            duration_seconds=duration,
            extractor_name="KeyVaultExtractor",
        )

    def _map_vault(self, vault: Any, subscription_id: str) -> dict[str, Any]:
        """Map Key Vault to DimResource schema."""
        vault_id = vault.id or ""
        rg_name = self._extract_resource_group(vault_id)

        return {
            "resource_id": generate_surrogate_key("azure", vault_id),
            "tenant_id": self.tenant_id,
            "resource_guid": vault_id,
            "resource_type": "KEY_VAULT",
            "name": vault.name or "",
            "subscription_id": subscription_id,
            "resource_group": rg_name,
            "parent_id": generate_surrogate_key(
                "azure",
                f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}",
            ) if rg_name else None,
            "location": vault.location or "",
            "tags": str(vault.tags) if vault.tags else None,
        }

    def _map_access_policy(
        self, policy: Any, vault_resource_id: int
    ) -> list[dict[str, Any]]:
        """Map Key Vault access policy to FactRoleAssignment records."""
        records = []
        object_id = getattr(policy, "object_id", "") or ""
        if not object_id:
            return records

        # Each permission set (keys, secrets, certificates, storage) becomes a record
        permission_sets = {
            "keys": getattr(policy.permissions, "keys", []) or [],
            "secrets": getattr(policy.permissions, "secrets", []) or [],
            "certificates": getattr(policy.permissions, "certificates", []) or [],
            "storage": getattr(policy.permissions, "storage", []) or [],
        }

        for perm_type, perms in permission_sets.items():
            if perms:
                records.append({
                    "assignment_id": generate_surrogate_key(
                        "keyvault_policy",
                        f"{vault_resource_id}:{object_id}:{perm_type}",
                    ),
                    "principal_id": generate_surrogate_key("entra", object_id),
                    "role_id": None,
                    "resource_id": vault_resource_id,
                    "assignment_type": "KEY_VAULT_POLICY",
                    "start_date": None,
                    "end_date": None,
                    "inherited": False,
                    "source": "KeyVaultPolicy",
                    "snapshot_id": self.snapshot_id,
                    "_permission_type": perm_type,
                    "_permissions": [str(p) for p in perms],
                })

        return records

    @staticmethod
    def _extract_resource_group(resource_id: str) -> str:
        """Extract resource group name from a resource ID."""
        parts = resource_id.split("/")
        for i, part in enumerate(parts):
            if part.lower() == "resourcegroups" and i + 1 < len(parts):
                return parts[i + 1]
        return ""
