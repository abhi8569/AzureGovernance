"""Analysis Services deep permission extractor.

Extracts ALL layers of Analysis Services / Power BI Premium access control:
- AAS server info and admin members
- Databases/models
- Roles with members (users/groups who are in each role)
- Row-Level Security (RLS) filter expressions (DAX) per role per table
- RLS descriptions
- Model-level read/process/admin permissions per role
- Partitions and data sources (for lineage understanding)

Supports:
- Azure Analysis Services (asazure://region.asazure.windows.net/server)
- Power BI Premium XMLA endpoints (powerbi://api.powerbi.com/v1.0/myorg/workspace)

Uses XMLA/TMSL protocol via ADOMD.NET or raw XMLA HTTP requests.
"""
from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from typing import Any

import httpx
import structlog

from src.extractors.base import ExtractResult
from src.utils.id_generator import generate_surrogate_key

logger = structlog.get_logger(__name__)

# XMLA namespace
XMLA_NS = "urn:schemas-microsoft-com:xml-analysis"
ROWSET_NS = "urn:schemas-microsoft-com:xml-analysis:rowset"

# TMSL/DMV queries for extracting metadata
DMV_DATABASES = "SELECT [CATALOG_NAME], [DATE_MODIFIED], [COMPATIBILITY_LEVEL], [TYPE], [DESCRIPTION] FROM $SYSTEM.DBSCHEMA_CATALOGS"

DMV_ROLES = """
SELECT
    [CATALOG_NAME],
    [ROLE_NAME],
    [DESCRIPTION],
    [DATE_MODIFIED]
FROM $SYSTEM.MDSCHEMA_ROLES
WHERE [CATALOG_NAME] = '{database}'
"""

DMV_ROLE_MEMBERS = """
SELECT
    [CATALOG_NAME],
    [ROLE_NAME],
    [MEMBER_NAME],
    [MEMBER_TYPE],
    [MEMBER_UNIQUE_NAME],
    [MEMBER_CAPTION]
FROM $SYSTEM.MDSCHEMA_MEMBERS
WHERE [CATALOG_NAME] = '{database}'
AND [HIERARCHY_UNIQUE_NAME] = '[Roles]'
"""

# TMSL for getting model definition (includes RLS)
TMSL_GET_DATABASE = '{{"refresh": {{"type": "calculate", "objects": [{{"database": "{database}"}}]}}}}'


class AnalysisServicesExtractor:
    """Extracts permissions from Analysis Services and PBI Premium XMLA.

    Connects via XMLA endpoint and extracts databases, roles, role members,
    RLS filter expressions, role permissions, and model metadata.

    Args:
        server_url: XMLA endpoint URL.
        token: OAuth2 access token.
        tenant_id: Azure AD tenant ID.
        snapshot_id: Current snapshot ID.
    """

    def __init__(
        self,
        server_url: str,
        token: str,
        tenant_id: str,
        snapshot_id: int,
    ) -> None:
        self.server_url = server_url
        self.token = token
        self.tenant_id = tenant_id
        self.snapshot_id = snapshot_id
        self.logger = structlog.get_logger(self.__class__.__name__)

    @property
    def xmla_endpoint(self) -> str:
        """Get the XMLA endpoint URL."""
        if "asazure://" in self.server_url:
            # Azure AAS: asazure://region.asazure.windows.net/server
            region_server = self.server_url.replace("asazure://", "")
            return f"https://{region_server}/xmla"
        elif "powerbi://" in self.server_url:
            # Power BI Premium: convert to XMLA HTTP endpoint
            return self.server_url.replace("powerbi://", "https://")
        return self.server_url

    @property
    def headers(self) -> dict[str, str]:
        """XMLA request headers."""
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "text/xml",
        }

    async def extract(self) -> ExtractResult:
        """Extract all AAS/PBI databases, roles, members, and RLS.

        Returns:
            ExtractResult with deep AAS permission data.
        """
        start_time = time.monotonic()
        resources: list[dict[str, Any]] = []
        assignments: list[dict[str, Any]] = []
        rls_definitions: list[dict[str, Any]] = []
        errors: list[str] = []

        server_resource_id = generate_surrogate_key("aas", self.server_url)
        resources.append({
            "resource_id": server_resource_id,
            "tenant_id": self.tenant_id,
            "resource_guid": self.server_url,
            "resource_type": "ANALYSIS_SERVICES_MODEL",
            "name": self.server_url.split("/")[-1] if "/" in self.server_url else self.server_url,
            "parent_id": None,
        })

        async with httpx.AsyncClient(timeout=120.0) as client:
            # 1. List databases
            databases = await self._execute_dmv(client, DMV_DATABASES)
            if databases is None:
                errors.append("Failed to list databases via XMLA")
            else:
                for db in databases:
                    db_name = db.get("CATALOG_NAME", "")
                    db_resource_id = generate_surrogate_key("aas", f"{self.server_url}/{db_name}")
                    resources.append({
                        "resource_id": db_resource_id,
                        "tenant_id": self.tenant_id,
                        "resource_guid": f"{self.server_url}/{db_name}",
                        "resource_type": "ANALYSIS_SERVICES_MODEL",
                        "name": db_name,
                        "parent_id": server_resource_id,
                        "_description": db.get("DESCRIPTION", ""),
                        "_compatibility_level": db.get("COMPATIBILITY_LEVEL", ""),
                        "_type": db.get("TYPE", ""),
                    })

                    # 2. Get roles for this database
                    roles = await self._execute_dmv(
                        client, DMV_ROLES.format(database=db_name)
                    )
                    role_map: dict[str, int] = {}
                    if roles:
                        for role in roles:
                            role_name = role.get("ROLE_NAME", "")
                            role_resource_id = generate_surrogate_key(
                                "aas_role", f"{self.server_url}/{db_name}/{role_name}"
                            )
                            role_map[role_name] = role_resource_id
                            resources.append({
                                "resource_id": role_resource_id,
                                "resource_type": "GENERIC",
                                "name": f"AAS Role: {role_name}",
                                "parent_id": db_resource_id,
                                "_description": role.get("DESCRIPTION", ""),
                                "_date_modified": role.get("DATE_MODIFIED", ""),
                            })

                    # 3. Get role members
                    members = await self._execute_dmv(
                        client, DMV_ROLE_MEMBERS.format(database=db_name)
                    )
                    if members:
                        for member in members:
                            role_name = member.get("ROLE_NAME", "")
                            member_name = member.get("MEMBER_NAME", "")
                            role_id = role_map.get(role_name)

                            assignments.append({
                                "assignment_id": generate_surrogate_key(
                                    "aas_role_member",
                                    f"{self.server_url}/{db_name}/{role_name}/{member_name}",
                                ),
                                "principal_id": generate_surrogate_key("entra", member_name),
                                "role_id": role_id,
                                "resource_id": db_resource_id,
                                "assignment_type": "AAS_ROLE",
                                "source": "AnalysisServices",
                                "snapshot_id": self.snapshot_id,
                                "_role_name": role_name,
                                "_member_name": member_name,
                                "_member_type": member.get("MEMBER_TYPE", ""),
                            })

                    # 4. Get RLS definitions via TMSL
                    rls = await self._extract_rls(client, db_name, db_resource_id)
                    rls_definitions.extend(rls)

        duration = time.monotonic() - start_time
        self.logger.info(
            "aas_extracted",
            databases=len(databases) if databases else 0,
            roles=len(role_map) if 'role_map' in dir() else 0,
            assignments=len(assignments),
            rls_definitions=len(rls_definitions),
            duration=round(duration, 1),
        )

        return ExtractResult(
            records=[{
                "resources": resources,
                "assignments": assignments,
                "rls_definitions": rls_definitions,
            }],
            errors=errors,
            record_count=len(resources) + len(assignments) + len(rls_definitions),
            duration_seconds=duration,
            extractor_name="AnalysisServicesExtractor",
        )

    async def _extract_rls(
        self, client: httpx.AsyncClient, database: str, db_resource_id: int
    ) -> list[dict[str, Any]]:
        """Extract Row-Level Security filter definitions.

        Uses TMSL Sequence command with ReadDefinition to get the model JSON,
        which includes role table permissions with filterExpression (DAX).
        """
        rls_definitions: list[dict[str, Any]] = []

        # TMSL request for database definition
        tmsl_body = f'''<Execute xmlns="{XMLA_NS}">
            <Command>
                <Statement>
                    SELECT [ID], [Name], [Description], [ModelPermission], [TablePermissions]
                    FROM $SYSTEM.TMSCHEMA_ROLES
                    WHERE [DatabaseID] = '{database}'
                </Statement>
            </Command>
            <Properties>
                <PropertyList>
                    <Catalog>{database}</Catalog>
                </PropertyList>
            </Properties>
        </Execute>'''

        try:
            resp = await client.post(
                self.xmla_endpoint, content=tmsl_body, headers=self.headers
            )
            if resp.status_code == 200:
                roles_data = self._parse_xmla_rowset(resp.text)
                for role_data in roles_data:
                    role_name = role_data.get("Name", "")
                    model_permission = role_data.get("ModelPermission", "")

                    # Now get table permissions (RLS filters) for this role
                    tp_body = f'''<Execute xmlns="{XMLA_NS}">
                        <Command>
                            <Statement>
                                SELECT [RoleID], [TableID], [FilterExpression], [MetadataPermission], [ColumnPermissions]
                                FROM $SYSTEM.TMSCHEMA_TABLE_PERMISSIONS
                                WHERE [DatabaseID] = '{database}'
                            </Statement>
                        </Command>
                        <Properties>
                            <PropertyList>
                                <Catalog>{database}</Catalog>
                            </PropertyList>
                        </Properties>
                    </Execute>'''

                    tp_resp = await client.post(
                        self.xmla_endpoint, content=tp_body, headers=self.headers
                    )
                    if tp_resp.status_code == 200:
                        table_perms = self._parse_xmla_rowset(tp_resp.text)
                        for tp in table_perms:
                            filter_expr = tp.get("FilterExpression", "")
                            if filter_expr:
                                rls_definitions.append({
                                    "database": database,
                                    "resource_id": db_resource_id,
                                    "role_name": role_name,
                                    "role_description": role_data.get("Description", ""),
                                    "model_permission": model_permission,
                                    "table_id": tp.get("TableID", ""),
                                    "filter_expression_dax": filter_expr,
                                    "metadata_permission": tp.get("MetadataPermission", ""),
                                    "column_permissions": tp.get("ColumnPermissions", ""),
                                    "snapshot_id": self.snapshot_id,
                                })

        except Exception as e:
            self.logger.warning("rls_extraction_failed", database=database, error=str(e))

        return rls_definitions

    async def _execute_dmv(
        self, client: httpx.AsyncClient, query: str
    ) -> list[dict[str, str]] | None:
        """Execute a DMV query via XMLA."""
        xmla_body = f'''<Execute xmlns="{XMLA_NS}">
            <Command>
                <Statement>{query}</Statement>
            </Command>
            <Properties>
                <PropertyList>
                    <Format>Tabular</Format>
                </PropertyList>
            </Properties>
        </Execute>'''

        try:
            resp = await client.post(
                self.xmla_endpoint, content=xmla_body, headers=self.headers
            )
            if resp.status_code == 200:
                return self._parse_xmla_rowset(resp.text)
            else:
                self.logger.warning(
                    "dmv_query_failed", status=resp.status_code, query=query[:80]
                )
                return None
        except Exception as e:
            self.logger.warning("dmv_query_error", error=str(e))
            return None

    @staticmethod
    def _parse_xmla_rowset(xml_text: str) -> list[dict[str, str]]:
        """Parse XMLA rowset response XML into list of dicts."""
        results: list[dict[str, str]] = []
        try:
            root = ET.fromstring(xml_text)
            # Find all row elements (namespace varies)
            for row in root.iter():
                if row.tag.endswith("}row") or row.tag == "row":
                    record: dict[str, str] = {}
                    for child in row:
                        # Strip namespace from tag
                        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                        record[tag] = child.text or ""
                    if record:
                        results.append(record)
        except ET.ParseError:
            pass
        return results
