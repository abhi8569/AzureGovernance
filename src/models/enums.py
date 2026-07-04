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
    SQL_SERVER = "SQL_SERVER"
    SQL_DATABASE = "SQL_DATABASE"

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

    # M365
    SHAREPOINT_SITE = "SHAREPOINT_SITE"
    DOCUMENT_LIBRARY = "DOCUMENT_LIBRARY"
    TEAM = "TEAM"
    CHANNEL = "CHANNEL"

    # DevOps
    DEVOPS_PROJECT = "DEVOPS_PROJECT"
    DEVOPS_REPO = "DEVOPS_REPO"
    DEVOPS_PIPELINE = "DEVOPS_PIPELINE"

    # Analytics & misc
    ANALYSIS_SERVICES_MODEL = "ANALYSIS_SERVICES_MODEL"
    COSMOS_DB = "COSMOS_DB"
    REDIS_CACHE = "REDIS_CACHE"

    # Networking
    VNET = "VNET"
    SUBNET = "SUBNET"
    NSG = "NSG"

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
    PBI_APP_AUDIENCE = "PBI_APP_AUDIENCE"
    SQL_DB_ROLE = "SQL_DB_ROLE"
    SQL_PERMISSION = "SQL_PERMISSION"
    STORAGE_ACL = "STORAGE_ACL"
    KEY_VAULT_POLICY = "KEY_VAULT_POLICY"
    KEY_VAULT_RBAC = "KEY_VAULT_RBAC"
    DEVOPS_PERMISSION = "DEVOPS_PERMISSION"
    SHAREPOINT_PERMISSION = "SHAREPOINT_PERMISSION"
    TEAM_MEMBERSHIP = "TEAM_MEMBERSHIP"
    AAS_ROLE = "AAS_ROLE"


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
