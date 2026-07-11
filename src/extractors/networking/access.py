"""Azure Networking access extractor.

Extracts network-level access controls that determine
who/what can REACH resources:
- NSG rules (allow/deny per IP/port/protocol)
- NSG effective rules on NICs
- Private endpoints (what resources are privately connected)
- VNet service endpoints (subnet → Azure service connectivity)
- VNet peering (cross-network access)
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


class NetworkAccessExtractor:
    """Extracts network-level access controls from Azure.

    Network access is a critical dimension of "who has access" —
    even with RBAC grants, resources may be unreachable without
    network connectivity.

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
        """Extract all network access controls in a subscription.

        Args:
            subscription_id: Azure subscription ID.

        Returns:
            ExtractResult with network resources and access rules.
        """
        from azure.mgmt.network import NetworkManagementClient

        start_time = time.monotonic()
        resources: list[dict[str, Any]] = []
        nsg_rules: list[dict[str, Any]] = []
        private_endpoints: list[dict[str, Any]] = []
        service_endpoints: list[dict[str, Any]] = []
        errors: list[str] = []

        try:
            client = NetworkManagementClient(self.credential, subscription_id)

            # 1. NSGs and their rules
            try:
                for nsg in client.network_security_groups.list_all():
                    nsg_id = nsg.id or ""
                    nsg_resource_id = generate_surrogate_key("azure", nsg_id)
                    rg_name = self._extract_rg(nsg_id)

                    resources.append({
                        "resource_id": nsg_resource_id,
                        "tenant_id": self.tenant_id,
                        "resource_guid": nsg_id,
                        "resource_type": "NSG",
                        "name": nsg.name or "",
                        "parent_id": None,
                        "_location": nsg.location or "",
                    })

                    # Custom security rules
                    for rule in (nsg.security_rules or []):
                        nsg_rules.append({
                            "nsg_resource_id": nsg_resource_id,
                            "nsg_name": nsg.name,
                            "rule_name": rule.name or "",
                            "priority": rule.priority,
                            "direction": rule.direction or "",
                            "access": rule.access or "",  # Allow / Deny
                            "protocol": rule.protocol or "",
                            "source_address_prefix": rule.source_address_prefix or "",
                            "source_address_prefixes": list(rule.source_address_prefixes or []),
                            "source_port_range": rule.source_port_range or "",
                            "destination_address_prefix": rule.destination_address_prefix or "",
                            "destination_address_prefixes": list(rule.destination_address_prefixes or []),
                            "destination_port_range": rule.destination_port_range or "",
                            "destination_port_ranges": list(rule.destination_port_ranges or []),
                            "description": rule.description or "",
                            "snapshot_id": self.snapshot_id,
                        })

                    # Default rules
                    for rule in (nsg.default_security_rules or []):
                        nsg_rules.append({
                            "nsg_resource_id": nsg_resource_id,
                            "nsg_name": nsg.name,
                            "rule_name": f"Default: {rule.name or ''}",
                            "priority": rule.priority,
                            "direction": rule.direction or "",
                            "access": rule.access or "",
                            "protocol": rule.protocol or "",
                            "source_address_prefix": rule.source_address_prefix or "",
                            "source_address_prefixes": [],
                            "source_port_range": rule.source_port_range or "",
                            "destination_address_prefix": rule.destination_address_prefix or "",
                            "destination_address_prefixes": [],
                            "destination_port_range": rule.destination_port_range or "",
                            "destination_port_ranges": [],
                            "description": rule.description or "",
                            "snapshot_id": self.snapshot_id,
                        })

                self.logger.info("nsgs_extracted", count=len(resources))
            except Exception as e:
                errors.append(f"NSGs: {e}")

            # 2. Private endpoints
            try:
                for ep in client.private_endpoints.list_by_subscription():
                    ep_id = ep.id or ""
                    ep_resource_id = generate_surrogate_key("azure", ep_id)

                    connected_resources = []
                    for conn in (ep.private_link_service_connections or []):
                        connected_resources.append({
                            "target_resource": conn.private_link_service_id or "",
                            "group_ids": list(conn.group_ids or []),
                            "status": (
                                conn.private_link_service_connection_state.status
                                if conn.private_link_service_connection_state else "Unknown"
                            ),
                        })

                    private_endpoints.append({
                        "resource_id": ep_resource_id,
                        "name": ep.name or "",
                        "location": ep.location or "",
                        "subnet_id": ep.subnet.id if ep.subnet else None,
                        "connected_resources": connected_resources,
                        "snapshot_id": self.snapshot_id,
                    })

                self.logger.info("private_endpoints_extracted", count=len(private_endpoints))
            except Exception as e:
                errors.append(f"Private endpoints: {e}")

            # 3. VNets with service endpoints
            try:
                for vnet in client.virtual_networks.list_all():
                    vnet_id = vnet.id or ""
                    vnet_resource_id = generate_surrogate_key("azure", vnet_id)

                    resources.append({
                        "resource_id": vnet_resource_id,
                        "tenant_id": self.tenant_id,
                        "resource_guid": vnet_id,
                        "resource_type": "VNET",
                        "name": vnet.name or "",
                        "parent_id": None,
                        "_location": vnet.location or "",
                        "_address_space": str(vnet.address_space.address_prefixes) if vnet.address_space else None,
                    })

                    for subnet in (vnet.subnets or []):
                        subnet_id = subnet.id or ""
                        subnet_resource_id = generate_surrogate_key("azure", subnet_id)

                        resources.append({
                            "resource_id": subnet_resource_id,
                            "tenant_id": self.tenant_id,
                            "resource_guid": subnet_id,
                            "resource_type": "SUBNET",
                            "name": subnet.name or "",
                            "parent_id": vnet_resource_id,
                            "_address_prefix": subnet.address_prefix or "",
                        })

                        # Service endpoints on this subnet
                        for se in (subnet.service_endpoints or []):
                            service_endpoints.append({
                                "subnet_resource_id": subnet_resource_id,
                                "subnet_name": subnet.name or "",
                                "vnet_name": vnet.name or "",
                                "service": se.service or "",
                                "locations": list(se.locations or []),
                                "provisioning_state": se.provisioning_state or "",
                                "snapshot_id": self.snapshot_id,
                            })

                self.logger.info(
                    "vnets_extracted",
                    vnets=len([r for r in resources if r.get("resource_type") == "VNET"]),
                    service_endpoints=len(service_endpoints),
                )
            except Exception as e:
                errors.append(f"VNets: {e}")

        except Exception as e:
            errors.append(f"Network access: {e}")
            self.logger.error("network_extraction_failed", error=str(e))

        duration = time.monotonic() - start_time
        return ExtractResult(
            records=[{
                "resources": resources,
                "nsg_rules": nsg_rules,
                "private_endpoints": private_endpoints,
                "service_endpoints": service_endpoints,
            }],
            errors=errors,
            record_count=len(resources) + len(nsg_rules) + len(private_endpoints) + len(service_endpoints),
            duration_seconds=duration,
            extractor_name="NetworkAccessExtractor",
        )

    @staticmethod
    def _extract_rg(resource_id: str) -> str:
        """Extract resource group from ARM resource ID."""
        parts = resource_id.split("/")
        for i, part in enumerate(parts):
            if part.lower() == "resourcegroups" and i + 1 < len(parts):
                return parts[i + 1]
        return ""
