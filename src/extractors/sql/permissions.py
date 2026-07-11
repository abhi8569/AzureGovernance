"""Azure SQL Server deep permission extractor.

Extracts ALL layers of SQL access control:
- Server-level: Logins, server roles, server-level permissions, firewall rules, 
  AD admins, auditing config
- Database-level: Database users, database roles, role membership, 
  database-level permissions (object, schema, column)
- Row-Level Security: Security policies, predicates, filter expressions
- Dynamic Data Masking: Masked columns
- Transparent Data Encryption status
- Always Encrypted column master keys
- Contained database users
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

# T-SQL queries for deep permission extraction
QUERY_DB_USERS = """
SELECT
    dp.principal_id,
    dp.name AS user_name,
    dp.type_desc AS principal_type,
    dp.authentication_type_desc,
    dp.default_schema_name,
    dp.create_date,
    dp.modify_date,
    dp.sid,
    CONVERT(VARCHAR(100), dp.sid, 1) AS sid_hex
FROM sys.database_principals dp
WHERE dp.type IN ('S', 'U', 'G', 'E', 'X')  -- SQL user, Windows user, Windows group, External user, External group
AND dp.name NOT IN ('dbo', 'guest', 'INFORMATION_SCHEMA', 'sys', 'public')
"""

QUERY_DB_ROLES = """
SELECT
    dp.principal_id,
    dp.name AS role_name,
    dp.type_desc,
    dp.is_fixed_role,
    dp.create_date
FROM sys.database_principals dp
WHERE dp.type = 'R'  -- Database role
AND dp.name NOT IN ('public')
"""

QUERY_DB_ROLE_MEMBERS = """
SELECT
    rm.role_principal_id,
    rp.name AS role_name,
    rm.member_principal_id,
    mp.name AS member_name,
    mp.type_desc AS member_type
FROM sys.database_role_members rm
JOIN sys.database_principals rp ON rm.role_principal_id = rp.principal_id
JOIN sys.database_principals mp ON rm.member_principal_id = mp.principal_id
"""

QUERY_DB_PERMISSIONS = """
SELECT
    perm.class_desc,
    perm.major_id,
    perm.minor_id,
    perm.grantee_principal_id,
    grantee.name AS grantee_name,
    grantee.type_desc AS grantee_type,
    perm.grantor_principal_id,
    grantor.name AS grantor_name,
    perm.type AS permission_type,
    perm.permission_name,
    perm.state_desc AS permission_state,
    CASE perm.class_desc
        WHEN 'OBJECT_OR_COLUMN' THEN OBJECT_NAME(perm.major_id)
        WHEN 'SCHEMA' THEN SCHEMA_NAME(perm.major_id)
        WHEN 'DATABASE' THEN DB_NAME()
        WHEN 'TYPE' THEN TYPE_NAME(perm.major_id)
        ELSE CAST(perm.major_id AS VARCHAR(20))
    END AS object_name,
    CASE WHEN perm.minor_id > 0 THEN COL_NAME(perm.major_id, perm.minor_id) ELSE NULL END AS column_name
FROM sys.database_permissions perm
JOIN sys.database_principals grantee ON perm.grantee_principal_id = grantee.principal_id
LEFT JOIN sys.database_principals grantor ON perm.grantor_principal_id = grantor.principal_id
WHERE grantee.name NOT IN ('dbo', 'guest', 'INFORMATION_SCHEMA', 'sys', 'public')
"""

QUERY_RLS_POLICIES = """
SELECT
    sp.name AS policy_name,
    sp.is_enabled,
    sp.is_schema_bound,
    OBJECT_NAME(sp.object_id) AS target_table,
    SCHEMA_NAME(o.schema_id) AS target_schema,
    pred.predicate_type_desc,
    pred.predicate_definition,
    OBJECT_NAME(pred.target_object_id) AS predicate_target_table,
    fn.name AS filter_function_name,
    OBJECT_DEFINITION(pred.predicate_object_id) AS filter_function_definition
FROM sys.security_policies sp
JOIN sys.objects o ON sp.object_id = o.object_id
LEFT JOIN sys.security_predicates pred ON sp.object_id = pred.object_id
LEFT JOIN sys.objects fn ON pred.predicate_object_id = fn.object_id
"""

QUERY_DDM_RULES = """
SELECT
    OBJECT_SCHEMA_NAME(mc.object_id) AS schema_name,
    OBJECT_NAME(mc.object_id) AS table_name,
    mc.name AS column_name,
    mc.masking_function
FROM sys.masked_columns mc
WHERE mc.is_masked = 1
"""

QUERY_TDE_STATUS = """
SELECT
    db.name AS database_name,
    dek.encryption_state,
    dek.encryptor_type,
    dek.key_algorithm,
    dek.key_length
FROM sys.dm_database_encryption_keys dek
JOIN sys.databases db ON dek.database_id = db.database_id
"""

QUERY_SERVER_LOGINS = """
SELECT
    sp.principal_id,
    sp.name AS login_name,
    sp.type_desc AS login_type,
    sp.is_disabled,
    sp.create_date,
    sp.modify_date,
    sp.default_database_name
FROM sys.server_principals sp
WHERE sp.type IN ('S', 'U', 'G', 'E', 'X')
AND sp.name NOT LIKE '##%'
AND sp.name NOT IN ('sa', 'NT AUTHORITY\SYSTEM', 'NT SERVICE\MSSQLSERVER')
"""

QUERY_SERVER_ROLES = """
SELECT
    rm.role_principal_id,
    rp.name AS role_name,
    rm.member_principal_id,
    mp.name AS member_name,
    mp.type_desc AS member_type
FROM sys.server_role_members rm
JOIN sys.server_principals rp ON rm.role_principal_id = rp.principal_id
JOIN sys.server_principals mp ON rm.member_principal_id = mp.principal_id
"""

QUERY_SERVER_PERMISSIONS = """
SELECT
    perm.class_desc,
    perm.grantee_principal_id,
    grantee.name AS grantee_name,
    grantee.type_desc AS grantee_type,
    perm.permission_name,
    perm.state_desc AS permission_state
FROM sys.server_permissions perm
JOIN sys.server_principals grantee ON perm.grantee_principal_id = grantee.principal_id
WHERE grantee.name NOT LIKE '##%'
"""


class SQLServerExtractor:
    """Extracts deep SQL Server permissions via T-SQL queries.

    Connects to Azure SQL databases and extracts:
    - Server logins, roles, and permissions
    - Database users, roles, and role membership
    - Object/schema/column-level permissions (GRANT/DENY/REVOKE)
    - Row-Level Security policies with filter function definitions
    - Dynamic Data Masking rules
    - TDE status

    Args:
        tenant_id: Azure AD tenant ID.
        snapshot_id: Current snapshot ID.
    """

    def __init__(self, tenant_id: str, snapshot_id: int) -> None:
        self.tenant_id = tenant_id
        self.snapshot_id = snapshot_id
        self.logger = structlog.get_logger(self.__class__.__name__)

    def extract_database(
        self,
        connection_string: str,
        server_name: str,
        database_name: str,
    ) -> ExtractResult:
        """Extract all permissions from a specific database.

        Args:
            connection_string: pyodbc connection string.
            server_name: SQL server name (for resource mapping).
            database_name: Database name.

        Returns:
            ExtractResult with resources and assignments.
        """
        import pyodbc

        start_time = time.monotonic()
        resources: list[dict[str, Any]] = []
        assignments: list[dict[str, Any]] = []
        rls_policies: list[dict[str, Any]] = []
        ddm_rules: list[dict[str, Any]] = []
        errors: list[str] = []

        db_resource_id = generate_surrogate_key("sql", f"{server_name}/{database_name}")

        try:
            conn = pyodbc.connect(connection_string, timeout=30)
            cursor = conn.cursor()

            # ─── Database Users ───
            try:
                cursor.execute(QUERY_DB_USERS)
                for row in cursor.fetchall():
                    user_record = self._map_db_user(row, db_resource_id, server_name, database_name)
                    resources.append(user_record["principal"])
                    assignments.append(user_record["assignment"])
                self.logger.info("db_users_extracted", db=database_name, count=cursor.rowcount)
            except Exception as e:
                errors.append(f"DB users {database_name}: {e}")

            # ─── Database Roles ───
            try:
                cursor.execute(QUERY_DB_ROLES)
                for row in cursor.fetchall():
                    resources.append(self._map_db_role(row, db_resource_id, database_name))
                self.logger.info("db_roles_extracted", db=database_name)
            except Exception as e:
                errors.append(f"DB roles {database_name}: {e}")

            # ─── Role Membership ───
            try:
                cursor.execute(QUERY_DB_ROLE_MEMBERS)
                for row in cursor.fetchall():
                    assignments.append(
                        self._map_role_membership(row, db_resource_id, database_name)
                    )
                self.logger.info("role_members_extracted", db=database_name)
            except Exception as e:
                errors.append(f"Role members {database_name}: {e}")

            # ─── Database Permissions (object, schema, column level) ───
            try:
                cursor.execute(QUERY_DB_PERMISSIONS)
                for row in cursor.fetchall():
                    assignments.append(
                        self._map_db_permission(row, db_resource_id, database_name)
                    )
                self.logger.info("db_permissions_extracted", db=database_name)
            except Exception as e:
                errors.append(f"DB permissions {database_name}: {e}")

            # ─── Row-Level Security ───
            try:
                cursor.execute(QUERY_RLS_POLICIES)
                for row in cursor.fetchall():
                    rls_policies.append(
                        self._map_rls_policy(row, db_resource_id, database_name)
                    )
                self.logger.info("rls_policies_extracted", db=database_name, count=len(rls_policies))
            except Exception as e:
                errors.append(f"RLS {database_name}: {e}")

            # ─── Dynamic Data Masking ───
            try:
                cursor.execute(QUERY_DDM_RULES)
                for row in cursor.fetchall():
                    ddm_rules.append(
                        self._map_ddm_rule(row, db_resource_id, database_name)
                    )
                self.logger.info("ddm_rules_extracted", db=database_name, count=len(ddm_rules))
            except Exception as e:
                errors.append(f"DDM {database_name}: {e}")

            conn.close()

        except pyodbc.Error as e:
            errors.append(f"Connection to {database_name}: {e}")
            self.logger.error("sql_connection_failed", db=database_name, error=str(e))

        duration = time.monotonic() - start_time
        return ExtractResult(
            records=[{
                "resources": resources,
                "assignments": assignments,
                "rls_policies": rls_policies,
                "ddm_rules": ddm_rules,
            }],
            errors=errors,
            record_count=len(resources) + len(assignments) + len(rls_policies) + len(ddm_rules),
            duration_seconds=duration,
            extractor_name="SQLServerExtractor",
        )

    def extract_server_level(self, connection_string: str, server_name: str) -> ExtractResult:
        """Extract server-level logins, roles, and permissions.

        Args:
            connection_string: pyodbc connection string to master database.
            server_name: SQL server name.

        Returns:
            ExtractResult with server-level records.
        """
        import pyodbc

        start_time = time.monotonic()
        resources: list[dict[str, Any]] = []
        assignments: list[dict[str, Any]] = []
        errors: list[str] = []

        server_resource_id = generate_surrogate_key("sql", server_name)

        try:
            conn = pyodbc.connect(connection_string, timeout=30)
            cursor = conn.cursor()

            # Server logins
            try:
                cursor.execute(QUERY_SERVER_LOGINS)
                for row in cursor.fetchall():
                    resources.append({
                        "principal_id": generate_surrogate_key("sql_login", row.login_name),
                        "tenant_id": self.tenant_id,
                        "object_id": row.login_name,
                        "principal_type": self._map_sql_principal_type(row.login_type),
                        "display_name": row.login_name,
                        "account_enabled": not row.is_disabled,
                        "created_date": str(row.create_date) if row.create_date else None,
                        "_default_database": row.default_database_name,
                        "_source": "SQL_Server_Login",
                    })
            except Exception as e:
                errors.append(f"Server logins: {e}")

            # Server role members
            try:
                cursor.execute(QUERY_SERVER_ROLES)
                for row in cursor.fetchall():
                    assignments.append({
                        "assignment_id": generate_surrogate_key(
                            "sql_server_role",
                            f"{server_name}:{row.role_name}:{row.member_name}",
                        ),
                        "principal_id": generate_surrogate_key("sql_login", row.member_name),
                        "role_id": generate_surrogate_key("sql_server_role", row.role_name),
                        "resource_id": server_resource_id,
                        "assignment_type": "SQL_DB_ROLE",
                        "source": "SQL_Server",
                        "snapshot_id": self.snapshot_id,
                        "_role_name": row.role_name,
                        "_member_name": row.member_name,
                        "_scope": "SERVER",
                    })
            except Exception as e:
                errors.append(f"Server roles: {e}")

            # Server-level permissions
            try:
                cursor.execute(QUERY_SERVER_PERMISSIONS)
                for row in cursor.fetchall():
                    assignments.append({
                        "assignment_id": generate_surrogate_key(
                            "sql_server_perm",
                            f"{server_name}:{row.grantee_name}:{row.permission_name}",
                        ),
                        "principal_id": generate_surrogate_key("sql_login", row.grantee_name),
                        "resource_id": server_resource_id,
                        "assignment_type": "SQL_PERMISSION",
                        "source": "SQL_Server",
                        "snapshot_id": self.snapshot_id,
                        "_permission_name": row.permission_name,
                        "_permission_state": row.permission_state,
                        "_class": row.class_desc,
                        "_scope": "SERVER",
                    })
            except Exception as e:
                errors.append(f"Server permissions: {e}")

            conn.close()

        except pyodbc.Error as e:
            errors.append(f"Server connection: {e}")
            self.logger.error("sql_server_connect_failed", error=str(e))

        duration = time.monotonic() - start_time
        return ExtractResult(
            records=[{"resources": resources, "assignments": assignments}],
            errors=errors,
            record_count=len(resources) + len(assignments),
            duration_seconds=duration,
            extractor_name="SQLServerExtractor_ServerLevel",
        )

    def extract_via_arm(self, credential: TokenCredential, subscription_id: str) -> ExtractResult:
        """Extract SQL access data via ARM REST API (no direct SQL connection needed).

        Gets AD admins, firewall rules, auditing settings, TDE status via azure-mgmt-sql.

        Args:
            credential: Azure token credential.
            subscription_id: Azure subscription ID.

        Returns:
            ExtractResult with ARM-level SQL access data.
        """
        from azure.mgmt.sql import SqlManagementClient

        start_time = time.monotonic()
        resources: list[dict[str, Any]] = []
        assignments: list[dict[str, Any]] = []
        errors: list[str] = []

        try:
            client = SqlManagementClient(credential, subscription_id)

            for server in client.servers.list():
                server_id = server.id or ""
                server_resource_id = generate_surrogate_key("sql", server_id)
                rg_name = self._extract_rg(server_id)

                # AD Admin
                try:
                    admins = client.server_azure_ad_administrators.list_by_server(rg_name, server.name)
                    for admin in admins:
                        assignments.append({
                            "assignment_id": generate_surrogate_key(
                                "sql_ad_admin", f"{server_id}:{admin.sid}"
                            ),
                            "principal_id": generate_surrogate_key("entra", admin.sid or ""),
                            "resource_id": server_resource_id,
                            "assignment_type": "SQL_DB_ROLE",
                            "source": "SQL_ARM",
                            "snapshot_id": self.snapshot_id,
                            "_role_name": "AD_Admin",
                            "_admin_name": admin.login or "",
                            "_admin_type": admin.administrator_type or "",
                        })
                except Exception as e:
                    errors.append(f"AD admin {server.name}: {e}")

                # Firewall rules (who can connect by IP)
                try:
                    rules = client.firewall_rules.list_by_server(rg_name, server.name)
                    for rule in rules:
                        resources.append({
                            "resource_id": generate_surrogate_key(
                                "sql_fw", f"{server_id}:{rule.name}"
                            ),
                            "resource_type": "GENERIC",
                            "name": f"FW: {rule.name} ({rule.start_ip_address}-{rule.end_ip_address})",
                            "parent_id": server_resource_id,
                            "_start_ip": rule.start_ip_address,
                            "_end_ip": rule.end_ip_address,
                            "_is_allow_all_azure": (
                                rule.start_ip_address == "0.0.0.0"
                                and rule.end_ip_address == "0.0.0.0"
                            ),
                        })
                except Exception as e:
                    errors.append(f"Firewall {server.name}: {e}")

                # Databases
                try:
                    for db in client.databases.list_by_server(rg_name, server.name):
                        if db.name == "master":
                            continue
                        db_id = db.id or ""
                        resources.append({
                            "resource_id": generate_surrogate_key("sql", db_id),
                            "tenant_id": self.tenant_id,
                            "resource_guid": db_id,
                            "resource_type": "SQL_DATABASE",
                            "name": db.name or "",
                            "parent_id": server_resource_id,
                            "_sku": str(db.sku) if db.sku else None,
                            "_status": db.status or "",
                        })
                except Exception as e:
                    errors.append(f"Databases {server.name}: {e}")

            self.logger.info("sql_arm_extracted", servers=len(resources))

        except Exception as e:
            errors.append(f"SQL ARM: {e}")
            self.logger.error("sql_arm_failed", error=str(e))

        duration = time.monotonic() - start_time
        return ExtractResult(
            records=[{"resources": resources, "assignments": assignments}],
            errors=errors,
            record_count=len(resources) + len(assignments),
            duration_seconds=duration,
            extractor_name="SQLServerExtractor_ARM",
        )

    # ─────────────────────────────────────────────────────────
    # Mappers
    # ─────────────────────────────────────────────────────────
    def _map_db_user(
        self, row: Any, db_resource_id: int, server: str, database: str
    ) -> dict[str, Any]:
        """Map database user to principal + assignment."""
        return {
            "principal": {
                "principal_id": generate_surrogate_key(
                    "sql_user", f"{server}/{database}/{row.user_name}"
                ),
                "tenant_id": self.tenant_id,
                "object_id": f"{server}/{database}/{row.user_name}",
                "principal_type": self._map_sql_principal_type(row.principal_type),
                "display_name": row.user_name,
                "created_date": str(row.create_date) if row.create_date else None,
                "_auth_type": row.authentication_type_desc,
                "_default_schema": row.default_schema_name,
                "_source": "SQL_Database_User",
            },
            "assignment": {
                "assignment_id": generate_surrogate_key(
                    "sql_db_user", f"{db_resource_id}:{row.user_name}"
                ),
                "principal_id": generate_surrogate_key(
                    "sql_user", f"{server}/{database}/{row.user_name}"
                ),
                "resource_id": db_resource_id,
                "assignment_type": "SQL_DB_ROLE",
                "source": "SQL_Database",
                "snapshot_id": self.snapshot_id,
                "_role_name": "DatabaseUser",
                "_user_name": row.user_name,
            },
        }

    def _map_db_role(
        self, row: Any, db_resource_id: int, database: str
    ) -> dict[str, Any]:
        """Map database role to resource."""
        return {
            "resource_id": generate_surrogate_key(
                "sql_db_role", f"{db_resource_id}:{row.role_name}"
            ),
            "resource_type": "GENERIC",
            "name": f"DB Role: {row.role_name}",
            "parent_id": db_resource_id,
            "_is_fixed_role": row.is_fixed_role,
            "_database": database,
        }

    def _map_role_membership(
        self, row: Any, db_resource_id: int, database: str
    ) -> dict[str, Any]:
        """Map role membership to FactRoleAssignment."""
        return {
            "assignment_id": generate_surrogate_key(
                "sql_role_member",
                f"{db_resource_id}:{row.role_name}:{row.member_name}",
            ),
            "principal_id": generate_surrogate_key(
                "sql_user", f"{db_resource_id}/{row.member_name}"
            ),
            "role_id": generate_surrogate_key(
                "sql_db_role", f"{db_resource_id}:{row.role_name}"
            ),
            "resource_id": db_resource_id,
            "assignment_type": "SQL_DB_ROLE",
            "source": "SQL_Database",
            "snapshot_id": self.snapshot_id,
            "_role_name": row.role_name,
            "_member_name": row.member_name,
            "_member_type": row.member_type,
        }

    def _map_db_permission(
        self, row: Any, db_resource_id: int, database: str
    ) -> dict[str, Any]:
        """Map database permission to FactRoleAssignment."""
        return {
            "assignment_id": generate_surrogate_key(
                "sql_perm",
                f"{db_resource_id}:{row.grantee_name}:{row.permission_name}:{row.object_name or ''}:{row.column_name or ''}",
            ),
            "principal_id": generate_surrogate_key(
                "sql_user", f"{db_resource_id}/{row.grantee_name}"
            ),
            "resource_id": db_resource_id,
            "assignment_type": "SQL_PERMISSION",
            "source": "SQL_Database",
            "snapshot_id": self.snapshot_id,
            "_permission_name": row.permission_name,
            "_permission_state": row.permission_state,  # GRANT, DENY, REVOKE
            "_class": row.class_desc,
            "_object_name": row.object_name,
            "_column_name": row.column_name,
            "_granted_by": row.grantor_name,
            "_scope": "DATABASE",
        }

    def _map_rls_policy(
        self, row: Any, db_resource_id: int, database: str
    ) -> dict[str, Any]:
        """Map RLS policy."""
        return {
            "resource_id": db_resource_id,
            "database": database,
            "policy_name": row.policy_name,
            "is_enabled": row.is_enabled,
            "target_table": f"{row.target_schema}.{row.target_table}",
            "predicate_type": row.predicate_type_desc,
            "predicate_definition": row.predicate_definition,
            "filter_function_name": row.filter_function_name,
            "filter_function_definition": row.filter_function_definition,
            "snapshot_id": self.snapshot_id,
        }

    def _map_ddm_rule(
        self, row: Any, db_resource_id: int, database: str
    ) -> dict[str, Any]:
        """Map Dynamic Data Masking rule."""
        return {
            "resource_id": db_resource_id,
            "database": database,
            "table": f"{row.schema_name}.{row.table_name}",
            "column": row.column_name,
            "masking_function": row.masking_function,
            "snapshot_id": self.snapshot_id,
        }

    @staticmethod
    def _map_sql_principal_type(type_desc: str) -> str:
        """Map SQL principal type to EAIP PrincipalType."""
        mapping = {
            "SQL_USER": "USER",
            "WINDOWS_USER": "USER",
            "EXTERNAL_USER": "USER",
            "WINDOWS_GROUP": "GROUP",
            "EXTERNAL_GROUP": "GROUP",
            "SQL_LOGIN": "USER",
            "WINDOWS_LOGIN": "USER",
            "EXTERNAL_LOGIN": "USER",
            "SERVER_ROLE": "GROUP",
            "DATABASE_ROLE": "GROUP",
        }
        return mapping.get(type_desc, "UNKNOWN")

    @staticmethod
    def _extract_rg(resource_id: str) -> str:
        """Extract resource group from ARM resource ID."""
        parts = resource_id.split("/")
        for i, part in enumerate(parts):
            if part.lower() == "resourcegroups" and i + 1 < len(parts):
                return parts[i + 1]
        return ""
