"""Key Vault deep permission extractor.

Goes beyond vault-level access to extract:
- Sub-resource RBAC: role assignments scoped to individual keys, secrets, certificates
- Data-plane inventory: list of keys, secrets, certificates
- RBAC data actions (encrypt, decrypt, sign, get, set, etc.)
- Access policy decomposition (keys vs secrets vs certificates vs storage)
"""
from __future__ import annotations

import time
from typing import Any, TYPE_CHECKING

import structlog

from src.extractors.base import ExtractResult
from src.utils.id_generator import generate_surrogate_key

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

logger = structlog.get_logger(__name__)


class KeyVaultDeepExtractor:
    """Extracts sub-resource level Key Vault permissions.

    Azure Key Vault supports RBAC at individual key/secret/certificate
    scope, separate from vault-level RBAC. This extractor retrieves:
    1. Data-plane sub-items (keys, secrets, certificates)
    2. RBAC assignments scoped to each sub-item
    3. Vault-level RBAC with data actions

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
        """Extract deep Key Vault permissions for a subscription.

        Args:
            subscription_id: Azure subscription ID.

        Returns:
            ExtractResult with sub-resource inventory and RBAC.
        """
        from azure.mgmt.keyvault import KeyVaultManagementClient
        from azure.mgmt.authorization import AuthorizationManagementClient

        start_time = time.monotonic()
        resources: list[dict[str, Any]] = []
        assignments: list[dict[str, Any]] = []
        errors: list[str] = []

        try:
            kv_client = KeyVaultManagementClient(self.credential, subscription_id)
            auth_client = AuthorizationManagementClient(self.credential, subscription_id)

            for vault in kv_client.vaults.list():
                vault_id = vault.id or ""
                vault_name = vault.name or ""
                vault_resource_id = generate_surrogate_key("azure", vault_id)
                rg_name = self._extract_rg(vault_id)

                if not rg_name:
                    continue

                # Get vault details
                try:
                    vault_detail = kv_client.vaults.get(rg_name, vault_name)
                    vault_uri = vault_detail.properties.vault_uri or ""
                except Exception as e:
                    errors.append(f"Vault detail {vault_name}: {e}")
                    continue

                # RBAC assignments at vault level (includes data actions)
                try:
                    for assignment in auth_client.role_assignments.list_for_scope(vault_id):
                        assignments.append(self._map_rbac_assignment(
                            assignment, vault_resource_id, vault_id, "VAULT"
                        ))
                except Exception as e:
                    errors.append(f"Vault RBAC {vault_name}: {e}")

                # Data-plane: list keys, secrets, certificates + their RBAC
                await_results = []

                # Keys
                try:
                    from azure.keyvault.keys import KeyClient
                    key_client = KeyClient(vault_uri, self.credential)
                    for key_props in key_client.list_properties_of_keys():
                        key_name = key_props.name or ""
                        key_scope = f"{vault_id}/keys/{key_name}"
                        key_resource_id = generate_surrogate_key("kv_key", key_scope)

                        resources.append({
                            "resource_id": key_resource_id,
                            "tenant_id": self.tenant_id,
                            "resource_guid": key_scope,
                            "resource_type": "GENERIC",
                            "name": f"Key: {key_name}",
                            "parent_id": vault_resource_id,
                            "_enabled": key_props.enabled,
                            "_key_type": key_props.key_type,
                            "_created": str(key_props.created_on) if key_props.created_on else None,
                            "_expires": str(key_props.expires_on) if key_props.expires_on else None,
                        })

                        # RBAC at key level
                        try:
                            for assignment in auth_client.role_assignments.list_for_scope(key_scope):
                                assignments.append(self._map_rbac_assignment(
                                    assignment, key_resource_id, key_scope, "KEY"
                                ))
                        except Exception:
                            pass
                except Exception as e:
                    errors.append(f"Keys {vault_name}: {e}")

                # Secrets
                try:
                    from azure.keyvault.secrets import SecretClient
                    secret_client = SecretClient(vault_uri, self.credential)
                    for secret_props in secret_client.list_properties_of_secrets():
                        secret_name = secret_props.name or ""
                        secret_scope = f"{vault_id}/secrets/{secret_name}"
                        secret_resource_id = generate_surrogate_key("kv_secret", secret_scope)

                        resources.append({
                            "resource_id": secret_resource_id,
                            "tenant_id": self.tenant_id,
                            "resource_guid": secret_scope,
                            "resource_type": "GENERIC",
                            "name": f"Secret: {secret_name}",
                            "parent_id": vault_resource_id,
                            "_enabled": secret_props.enabled,
                            "_content_type": secret_props.content_type,
                            "_created": str(secret_props.created_on) if secret_props.created_on else None,
                            "_expires": str(secret_props.expires_on) if secret_props.expires_on else None,
                        })

                        # RBAC at secret level
                        try:
                            for assignment in auth_client.role_assignments.list_for_scope(secret_scope):
                                assignments.append(self._map_rbac_assignment(
                                    assignment, secret_resource_id, secret_scope, "SECRET"
                                ))
                        except Exception:
                            pass
                except Exception as e:
                    errors.append(f"Secrets {vault_name}: {e}")

                # Certificates
                try:
                    from azure.keyvault.certificates import CertificateClient
                    cert_client = CertificateClient(vault_uri, self.credential)
                    for cert_props in cert_client.list_properties_of_certificates():
                        cert_name = cert_props.name or ""
                        cert_scope = f"{vault_id}/certificates/{cert_name}"
                        cert_resource_id = generate_surrogate_key("kv_cert", cert_scope)

                        resources.append({
                            "resource_id": cert_resource_id,
                            "tenant_id": self.tenant_id,
                            "resource_guid": cert_scope,
                            "resource_type": "GENERIC",
                            "name": f"Certificate: {cert_name}",
                            "parent_id": vault_resource_id,
                            "_enabled": cert_props.enabled,
                            "_created": str(cert_props.created_on) if cert_props.created_on else None,
                            "_expires": str(cert_props.expires_on) if cert_props.expires_on else None,
                        })

                        # RBAC at certificate level
                        try:
                            for assignment in auth_client.role_assignments.list_for_scope(cert_scope):
                                assignments.append(self._map_rbac_assignment(
                                    assignment, cert_resource_id, cert_scope, "CERTIFICATE"
                                ))
                        except Exception:
                            pass
                except Exception as e:
                    errors.append(f"Certificates {vault_name}: {e}")

        except Exception as e:
            errors.append(f"KeyVault deep: {e}")
            self.logger.error("kv_deep_failed", error=str(e))

        duration = time.monotonic() - start_time
        self.logger.info(
            "keyvault_deep_extracted",
            sub_resources=len(resources),
            assignments=len(assignments),
        )
        return ExtractResult(
            records=[{"resources": resources, "assignments": assignments}],
            errors=errors,
            record_count=len(resources) + len(assignments),
            duration_seconds=duration,
            extractor_name="KeyVaultDeepExtractor",
        )

    def _map_rbac_assignment(
        self, assignment: Any, resource_id: int, scope: str, scope_level: str
    ) -> dict[str, Any]:
        """Map ARM RBAC assignment to FactRoleAssignment."""
        return {
            "assignment_id": generate_surrogate_key("kv_rbac", assignment.id or ""),
            "principal_id": generate_surrogate_key("entra", assignment.principal_id or ""),
            "role_id": generate_surrogate_key("azure_rbac_role", assignment.role_definition_id or ""),
            "resource_id": resource_id,
            "assignment_type": "KEY_VAULT_RBAC",
            "source": "KeyVault_RBAC",
            "snapshot_id": self.snapshot_id,
            "_scope": scope,
            "_scope_level": scope_level,
            "_principal_type": getattr(assignment, "principal_type", "Unknown"),
        }

    @staticmethod
    def _extract_rg(resource_id: str) -> str:
        """Extract resource group from ARM resource ID."""
        parts = resource_id.split("/")
        for i, part in enumerate(parts):
            if part.lower() == "resourcegroups" and i + 1 < len(parts):
                return parts[i + 1]
        return ""
