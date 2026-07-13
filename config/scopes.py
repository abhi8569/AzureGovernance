"""OAuth 2.0 scope constants for Microsoft cloud services.

Each constant defines the permission scopes required when acquiring tokens
for the corresponding Microsoft API. Delegated scopes are used with
interactive (user-context) authentication; application scopes use the
``/.default`` suffix for client-credential flows.
"""

from typing import Final

GRAPH_SCOPES: Final[list[str]] = ["https://graph.microsoft.com/.default"]
"""Microsoft Graph application-level scopes (client-credential flow)."""

GRAPH_DELEGATED_SCOPES: Final[list[str]] = [
    "User.Read",
    "Directory.Read.All",
    "Group.Read.All",
    "RoleManagement.Read.Directory",
    "Application.Read.All",
]
"""Microsoft Graph delegated scopes for interactive user authentication.

Grants read access to the signed-in user's profile, directory objects,
groups, directory roles, and application registrations.
"""

ARM_SCOPES: Final[list[str]] = [
    "https://management.azure.com/.default",
]
"""Azure Resource Manager scopes for subscription and resource queries."""

FABRIC_SCOPES: Final[list[str]] = [
    "https://api.fabric.microsoft.com/.default",
]
"""Microsoft Fabric API scopes for workspace and capacity queries."""

POWERBI_SCOPES: Final[list[str]] = [
    "https://analysis.windows.net/powerbi/api/.default",
]
"""Power BI REST API scopes for report, dataset, and workspace queries."""

DEVOPS_SCOPES: Final[list[str]] = [
    "499b84ac-1321-427f-aa17-267ca6975798/.default",
]
"""Azure DevOps API scopes (resource ID-based) for project and pipeline queries."""

SHAREPOINT_SCOPES: Final[list[str]] = [
    "https://microsoft.sharepoint-df.com/.default",
]
"""SharePoint Online REST API scopes for site and list queries."""

TEAMS_SCOPES: Final[list[str]] = [
    "https://graph.microsoft.com/.default",
]
"""Microsoft Teams scopes (via Graph API) for team and channel queries."""

KEY_VAULT_SCOPES: Final[list[str]] = [
    "https://vault.azure.net/.default",
]
"""Azure Key Vault scopes for secret, key, and certificate access policies."""

AAS_SCOPES: Final[list[str]] = [
    "https://analysis.windows.net/powerbi/api/.default",
]
"""Azure Analysis Services / Power BI XMLA endpoint scopes."""

COSMOS_SCOPES: Final[list[str]] = [
    "https://cosmos.azure.com/.default",
]
"""Azure Cosmos DB data-plane scopes for RBAC and policy queries."""
