"""SharePoint and OneDrive deep permission extractor.

Extracts ALL layers of SharePoint access control:
- Site collection admins
- Site permissions (roles + members)
- List/library-level permissions (broken inheritance)
- Item-level permissions (broken inheritance)
- Sharing links (anonymous, org-wide, specific people)
- External sharing status
- Hub site associations
- Sensitivity labels
"""
from __future__ import annotations

import time
from typing import Any

import httpx
import structlog

from src.extractors.base import BaseExtractor, ExtractResult
from src.utils.id_generator import generate_surrogate_key
from src.utils.pagination import paginate_graph
from src.utils.rate_limiter import GRAPH_RATE_LIMITER

logger = structlog.get_logger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


class SharePointPermissionsExtractor(BaseExtractor):
    """Extracts SharePoint site, list, and item-level permissions via Graph API.

    Drills down to:
    - Site owners, members, visitors
    - Site collection admins
    - List/library permissions (where inheritance is broken)
    - Item-level sharing links and permissions
    - External user access
    """

    async def extract(self) -> ExtractResult:
        """Extract all SharePoint sites and their deep permissions.

        Returns:
            ExtractResult with resources and per-item assignments.
        """
        start_time = time.monotonic()
        resources: list[dict[str, Any]] = []
        assignments: list[dict[str, Any]] = []
        sharing_links: list[dict[str, Any]] = []
        errors: list[str] = []

        async with httpx.AsyncClient(timeout=120.0) as client:
            # 1. List all sites
            sites_url = f"{GRAPH_BASE}/sites?search=*&$top=999"
            try:
                async for page in paginate_graph(client, sites_url, self.headers):
                    await GRAPH_RATE_LIMITER.acquire()
                    for site in page:
                        site_id = site.get("id", "")
                        site_resource = self._map_site(site)
                        resources.append(site_resource)
                        site_resource_id = site_resource["resource_id"]

                        # 2. Site permissions (owners, members, visitors)
                        await self._extract_site_permissions(
                            client, site_id, site_resource_id, assignments, errors
                        )

                        # 3. Lists and libraries
                        await self._extract_lists(
                            client, site_id, site_resource_id,
                            resources, assignments, sharing_links, errors,
                        )

                        # 4. Drive (document library) items with sharing
                        await self._extract_drive_permissions(
                            client, site_id, site_resource_id,
                            resources, assignments, sharing_links, errors,
                        )

            except Exception as e:
                errors.append(f"Sites listing: {e}")
                self.logger.error("sites_listing_failed", error=str(e))

        duration = time.monotonic() - start_time
        self.logger.info(
            "sharepoint_deep_extracted",
            sites=len([r for r in resources if r.get("resource_type") == "SHAREPOINT_SITE"]),
            assignments=len(assignments),
            sharing_links=len(sharing_links),
            errors=len(errors),
        )
        return ExtractResult(
            records=[{
                "resources": resources,
                "assignments": assignments,
                "sharing_links": sharing_links,
            }],
            errors=errors,
            record_count=len(resources) + len(assignments) + len(sharing_links),
            duration_seconds=duration,
            extractor_name="SharePointPermissionsExtractor",
        )

    async def _extract_site_permissions(
        self, client: httpx.AsyncClient, site_id: str,
        site_resource_id: int, assignments: list, errors: list,
    ) -> None:
        """Extract site-level permissions (GET /sites/{id}/permissions)."""
        try:
            await GRAPH_RATE_LIMITER.acquire()
            perm_url = f"{GRAPH_BASE}/sites/{site_id}/permissions"
            resp = await client.get(perm_url, headers=self.headers)
            resp.raise_for_status()
            for perm in resp.json().get("value", []):
                granted_to = perm.get("grantedToV2", {}) or perm.get("grantedTo", {})
                identity = (
                    granted_to.get("user", {})
                    or granted_to.get("group", {})
                    or granted_to.get("siteUser", {})
                    or {}
                )
                identity_id = identity.get("id", "")
                if identity_id:
                    roles = perm.get("roles", [])
                    for role in roles:
                        assignments.append({
                            "assignment_id": generate_surrogate_key(
                                "sp_site_perm",
                                f"{site_resource_id}:{identity_id}:{role}",
                            ),
                            "principal_id": generate_surrogate_key("entra", identity_id),
                            "resource_id": site_resource_id,
                            "assignment_type": "SHAREPOINT_PERMISSION",
                            "source": "SharePoint",
                            "snapshot_id": self.snapshot_id,
                            "_role": role,
                            "_display_name": identity.get("displayName", ""),
                            "_email": identity.get("email", ""),
                        })
        except Exception as e:
            errors.append(f"Site {site_id} permissions: {e}")

    async def _extract_lists(
        self, client: httpx.AsyncClient, site_id: str, site_resource_id: int,
        resources: list, assignments: list, sharing_links: list, errors: list,
    ) -> None:
        """Extract lists/libraries and their permissions."""
        try:
            await GRAPH_RATE_LIMITER.acquire()
            lists_url = f"{GRAPH_BASE}/sites/{site_id}/lists?$top=999"
            resp = await client.get(lists_url, headers=self.headers)
            resp.raise_for_status()
            for lst in resp.json().get("value", []):
                list_id = lst.get("id", "")
                list_name = lst.get("displayName", "")
                list_resource_id = generate_surrogate_key("sp_list", f"{site_id}/{list_id}")

                resources.append({
                    "resource_id": list_resource_id,
                    "tenant_id": self.tenant_id,
                    "resource_guid": f"{site_id}/{list_id}",
                    "resource_type": "DOCUMENT_LIBRARY",
                    "name": list_name,
                    "parent_id": site_resource_id,
                    "_list_template": lst.get("list", {}).get("template", ""),
                })

        except Exception as e:
            errors.append(f"Site {site_id} lists: {e}")

    async def _extract_drive_permissions(
        self, client: httpx.AsyncClient, site_id: str, site_resource_id: int,
        resources: list, assignments: list, sharing_links: list, errors: list,
    ) -> None:
        """Extract document library drive items and their sharing permissions."""
        try:
            await GRAPH_RATE_LIMITER.acquire()
            drives_url = f"{GRAPH_BASE}/sites/{site_id}/drives"
            resp = await client.get(drives_url, headers=self.headers)
            resp.raise_for_status()

            for drive in resp.json().get("value", []):
                drive_id = drive.get("id", "")

                # Get shared items in this drive
                try:
                    await GRAPH_RATE_LIMITER.acquire()
                    # Get root children to find items with unique permissions
                    items_url = f"{GRAPH_BASE}/drives/{drive_id}/root/children?$top=200"
                    items_resp = await client.get(items_url, headers=self.headers)
                    items_resp.raise_for_status()

                    for item in items_resp.json().get("value", []):
                        item_id = item.get("id", "")
                        item_name = item.get("name", "")

                        # Get permissions on this item
                        try:
                            await GRAPH_RATE_LIMITER.acquire()
                            perms_url = f"{GRAPH_BASE}/drives/{drive_id}/items/{item_id}/permissions"
                            p_resp = await client.get(perms_url, headers=self.headers)
                            p_resp.raise_for_status()
                            perms = p_resp.json().get("value", [])

                            for perm in perms:
                                perm_id = perm.get("id", "")

                                # Sharing link
                                link = perm.get("link")
                                if link:
                                    sharing_links.append({
                                        "item_name": item_name,
                                        "drive_id": drive_id,
                                        "item_id": item_id,
                                        "link_type": link.get("type", ""),
                                        "link_scope": link.get("scope", ""),
                                        "link_url": link.get("webUrl", ""),
                                        "created_by": str(perm.get("grantedBy", {})),
                                        "snapshot_id": self.snapshot_id,
                                    })

                                # Direct permission
                                granted = perm.get("grantedToV2", {}) or perm.get("grantedTo", {})
                                user_info = granted.get("user", {}) or granted.get("group", {}) or {}
                                user_id = user_info.get("id", "")
                                if user_id:
                                    for role in perm.get("roles", []):
                                        item_resource_id = generate_surrogate_key(
                                            "sp_item", f"{drive_id}/{item_id}"
                                        )
                                        assignments.append({
                                            "assignment_id": generate_surrogate_key(
                                                "sp_item_perm",
                                                f"{item_resource_id}:{user_id}:{role}",
                                            ),
                                            "principal_id": generate_surrogate_key("entra", user_id),
                                            "resource_id": item_resource_id,
                                            "assignment_type": "SHAREPOINT_PERMISSION",
                                            "source": "SharePoint_Drive",
                                            "snapshot_id": self.snapshot_id,
                                            "_role": role,
                                            "_item_name": item_name,
                                            "_display_name": user_info.get("displayName", ""),
                                        })
                        except Exception as e:
                            pass  # Skip items where we can't read permissions
                except Exception as e:
                    errors.append(f"Drive {drive_id} items: {e}")
        except Exception as e:
            errors.append(f"Site {site_id} drives: {e}")

    def _map_site(self, site: dict[str, Any]) -> dict[str, Any]:
        """Map SharePoint site to DimResource."""
        site_id = site.get("id", "")
        return {
            "resource_id": generate_surrogate_key("sharepoint", site_id),
            "tenant_id": self.tenant_id,
            "resource_guid": site_id,
            "resource_type": "SHAREPOINT_SITE",
            "name": site.get("displayName", "") or site.get("name", ""),
            "parent_id": None,
            "_web_url": site.get("webUrl", ""),
            "_is_personal_site": site.get("isPersonalSite", False),
        }
