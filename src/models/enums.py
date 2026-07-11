"""
Enterprise Access Intelligence Platform — Enumeration Types.

Defines all domain enumerations used across the EAIP data model,
covering principals, resources, platforms, permissions, assignments,
memberships, and resource-graph relationships.
"""

from enum import Enum


# ──────────────────────────────────────────────────────────────
# Principal types
# ──────────────────────────────────────────────────────────────
class PrincipalType(str, Enum):
    """Kind of security principal in Entra ID / Azure AD."""

    USER = "USER"
    GROUP = "GROUP"
    SERVICE_PRINCIPAL = "SERVICE_PRINCIPAL"
    MANAGED_IDENTITY = "MANAGED_IDENTITY"
    APPLICATION = "APPLICATION"
    DEVICE = "DEVICE"
    UNKNOWN = "UNKNOWN"


# ──────────────────────────────────────────────────────────────
# Resource types
# ──────────────────────────────────────────────────────────────
class ResourceType(str, Enum):
    """Categorises every resource the platform can discover."""

    # Azure hierarchy
    MANAGEMENT_GROUP = "MANAGEMENT_GROUP"
    SUBSCRIPTION = "SUBSCRIPTION"
    RESOURCE_GROUP = "RESOURCE_GROUP"

    # Storage
    STORAGE_ACCOUNT = "STORAGE_ACCOUNT"
    STORAGE_CONTAINER = "STORAGE_CONTAINER"
    ADLS_FILESYSTEM = "ADLS_FILESYSTEM"

    # Data & security
    KEY_VAULT = "KEY_VAULT"
    KEY_VAULT_KEY = "KEY_VAULT_KEY"
    KEY_VAULT_SECRET = "KEY_VAULT_SECRET"
    KEY_VAULT_CERTIFICATE = "KEY_VAULT_CERTIFICATE"
    SQL_SERVER = "SQL_SERVER"
    SQL_DATABASE = "SQL_DATABASE"
    SQL_DB_ROLE = "SQL_DB_ROLE"
    SQL_DB_USER = "SQL_DB_USER"

    # Compute
    VIRTUAL_MACHINE = "VIRTUAL_MACHINE"
    APP_SERVICE = "APP_SERVICE"
    FUNCTION_APP = "FUNCTION_APP"
    AKS_CLUSTER = "AKS_CLUSTER"

    # Fabric / Power BI
    FABRIC_WORKSPACE = "FABRIC_WORKSPACE"
    FABRIC_LAKEHOUSE = "FABRIC_LAKEHOUSE"
    FABRIC_WAREHOUSE = "FABRIC_WAREHOUSE"
    SEMANTIC_MODEL = "SEMANTIC_MODEL"
    REPORT = "REPORT"
    DASHBOARD = "DASHBOARD"
    DATAFLOW = "DATAFLOW"
    PIPELINE = "PIPELINE"
    NOTEBOOK = "NOTEBOOK"
    POWER_BI_APP = "POWER_BI_APP"
    POWER_BI_GATEWAY = "POWER_BI_GATEWAY"
    POWER_BI_DATASOURCE = "POWER_BI_DATASOURCE"
    POWER_BI_CAPACITY = "POWER_BI_CAPACITY"

    # M365
    SHAREPOINT_SITE = "SHAREPOINT_SITE"
    DOCUMENT_LIBRARY = "DOCUMENT_LIBRARY"
    SHAREPOINT_LIST = "SHAREPOINT_LIST"
    SHAREPOINT_ITEM = "SHAREPOINT_ITEM"
    TEAM = "TEAM"
    CHANNEL = "CHANNEL"
    TEAMS_APP = "TEAMS_APP"

    # DevOps
    DEVOPS_PROJECT = "DEVOPS_PROJECT"
    DEVOPS_REPO = "DEVOPS_REPO"
    DEVOPS_PIPELINE = "DEVOPS_PIPELINE"

    # Analytics & misc
    ANALYSIS_SERVICES_MODEL = "ANALYSIS_SERVICES_MODEL"
    ANALYSIS_SERVICES_ROLE = "ANALYSIS_SERVICES_ROLE"
    COSMOS_DB = "COSMOS_DB"
    COSMOS_DB_DATABASE = "COSMOS_DB_DATABASE"
    COSMOS_DB_CONTAINER = "COSMOS_DB_CONTAINER"
    REDIS_CACHE = "REDIS_CACHE"

    # Networking
    VNET = "VNET"
    SUBNET = "SUBNET"
    NSG = "NSG"
    PRIVATE_ENDPOINT = "PRIVATE_ENDPOINT"

    # Catch-all
    GENERIC = "GENERIC"


# ──────────────────────────────────────────────────────────────
# Platform / permission system
# ──────────────────────────────────────────────────────────────
class Platform(str, Enum):
    """Permission system that governs access."""

    AZURE_RBAC = "AZURE_RBAC"
    ENTRA_ID = "ENTRA_ID"
    FABRIC = "FABRIC"
    POWER_BI = "POWER_BI"
    SQL = "SQL"
    ANALYSIS_SERVICES = "ANALYSIS_SERVICES"
    STORAGE_ACL = "STORAGE_ACL"
    KEY_VAULT = "KEY_VAULT"
    DEVOPS = "DEVOPS"
    SHAREPOINT = "SHAREPOINT"
    TEAMS = "TEAMS"
    PURVIEW = "PURVIEW"


# ──────────────────────────────────────────────────────────────
# Permission state
# ──────────────────────────────────────────────────────────────
class PermissionState(str, Enum):
    """Whether a permission entry allows, denies, or is unspecified."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    NOT_SPECIFIED = "NOT_SPECIFIED"


# ──────────────────────────────────────────────────────────────
# Assignment types
# ──────────────────────────────────────────────────────────────
class AssignmentType(str, Enum):
    """Mechanism through which a principal is granted access."""

    AZURE_RBAC = "AZURE_RBAC"
    DIRECTORY_ROLE = "DIRECTORY_ROLE"
    FABRIC_WORKSPACE_ROLE = "FABRIC_WORKSPACE_ROLE"
    FABRIC_ITEM_PERMISSION = "FABRIC_ITEM_PERMISSION"
    ONELAKE_DATA_ACCESS_ROLE = "ONELAKE_DATA_ACCESS_ROLE"
    PBI_APP_AUDIENCE = "PBI_APP_AUDIENCE"
    PBI_DATASET_USER = "PBI_DATASET_USER"
    PBI_REPORT_USER = "PBI_REPORT_USER"
    PBI_DASHBOARD_USER = "PBI_DASHBOARD_USER"
    PBI_DATAFLOW_USER = "PBI_DATAFLOW_USER"
    PBI_GATEWAY_USER = "PBI_GATEWAY_USER"
    PBI_CAPACITY_ADMIN = "PBI_CAPACITY_ADMIN"
    SQL_DB_ROLE = "SQL_DB_ROLE"
    SQL_PERMISSION = "SQL_PERMISSION"
    SQL_RLS = "SQL_RLS"
    SQL_DDM = "SQL_DDM"
    STORAGE_ACL = "STORAGE_ACL"
    KEY_VAULT_POLICY = "KEY_VAULT_POLICY"
    KEY_VAULT_RBAC = "KEY_VAULT_RBAC"
    COSMOS_DATA_PLANE_RBAC = "COSMOS_DATA_PLANE_RBAC"
    DEVOPS_PERMISSION = "DEVOPS_PERMISSION"
    SHAREPOINT_PERMISSION = "SHAREPOINT_PERMISSION"
    SHAREPOINT_SHARING_LINK = "SHAREPOINT_SHARING_LINK"
    TEAM_MEMBERSHIP = "TEAM_MEMBERSHIP"
    TEAM_CHANNEL_MEMBERSHIP = "TEAM_CHANNEL_MEMBERSHIP"
    AAS_ROLE = "AAS_ROLE"
    AAS_RLS = "AAS_RLS"
    NSG_RULE = "NSG_RULE"


# ──────────────────────────────────────────────────────────────
# Membership types
# ──────────────────────────────────────────────────────────────
class MembershipType(str, Enum):
    """Kind of group / role membership relationship."""

    AD_GROUP = "AD_GROUP"
    DIRECTORY_ROLE = "DIRECTORY_ROLE"
    DEVOPS_GROUP = "DEVOPS_GROUP"
    TEAM = "TEAM"
    APP_ROLE = "APP_ROLE"


# ──────────────────────────────────────────────────────────────
# Relationship types (resource graph edges)
# ──────────────────────────────────────────────────────────────
class RelationshipType(str, Enum):
    """Edge label for the resource-hierarchy graph."""

    CONTAINS = "CONTAINS"
    PART_OF = "PART_OF"
    HOSTED_ON = "HOSTED_ON"
    MEMBER_OF = "MEMBER_OF"
