"""EAIP application settings with Pydantic configuration.

Loads configuration from environment variables (prefixed with EAIP_)
and an optional .env file. Provides a cached singleton accessor.
"""

from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings


class EAIPSettings(BaseSettings):
    """Enterprise Access Intelligence Platform configuration.

    All fields can be set via environment variables with the EAIP_ prefix
    (e.g. EAIP_TENANT_ID) or through a .env file in the project root.

    Attributes:
        tenant_id: Azure AD / Entra ID tenant identifier.
        client_id: Application (client) ID registered in Azure AD.
        client_secret: Application client secret. Leave empty for interactive
            browser-based SSO authentication.
        database_path: File path for the embedded DuckDB database.
        parquet_output_dir: Directory for exported Parquet files.
        log_level: Logging verbosity (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        max_retries: Maximum number of retry attempts for transient failures.
        batch_size: Number of items per batch in bulk API operations.
            Capped at 999 for Microsoft Graph batch limits.
        devops_org: Azure DevOps organisation name.
        devops_pat: Azure DevOps personal access token.
        sql_connections: List of pyodbc connection strings for SQL extraction.
        aas_servers: List of AAS/PBI XMLA endpoint URLs.
        extract_sharepoint: Enable or disable the SharePoint extractor.
        extract_teams: Enable or disable the Teams extractor.
        extract_networking: Enable or disable the networking extractor.
        extract_cosmosdb: Enable or disable the Cosmos DB extractor.
    """

    tenant_id: str = Field(
        default="",
        description="Azure AD / Entra ID tenant identifier.",
    )
    client_id: str = Field(
        default="",
        description="Application (client) ID registered in Azure AD.",
    )
    client_secret: SecretStr = Field(
        default=SecretStr(""),
        description=(
            "Application client secret. Leave empty for interactive auth."
        ),
    )
    database_path: str = Field(
        default="./data/eaip.duckdb",
        description="File path for the embedded DuckDB database.",
    )
    parquet_output_dir: str = Field(
        default="./data/parquet",
        description="Directory for exported Parquet files.",
    )
    log_level: str = Field(
        default="INFO",
        description="Logging verbosity.",
    )
    max_retries: int = Field(
        default=5,
        description="Maximum retry attempts for transient failures.",
    )
    batch_size: int = Field(
        default=999,
        description="Items per batch in bulk API operations.",
    )
    devops_org: str = Field(
        default="",
        description="Azure DevOps organisation name.",
    )
    devops_pat: SecretStr = Field(
        default=SecretStr(""),
        description="Azure DevOps personal access token.",
    )
    sql_connections: list[str] = Field(
        default_factory=list,
        description="List of pyodbc connection strings for SQL-based extraction.",
    )
    aas_servers: list[str] = Field(
        default_factory=list,
        description="List of AAS/PBI XMLA endpoint URLs.",
    )
    extract_entra: bool = Field(
        default=True,
        description="Enable or disable the Entra ID extractor.",
    )
    extract_keyvault: bool = Field(
        default=True,
        description="Enable or disable the Key Vault extractor.",
    )
    extract_storage: bool = Field(
        default=True,
        description="Enable or disable the Storage account extractor.",
    )
    extract_sql: bool = Field(
        default=True,
        description="Enable or disable the SQL Server extractor (both ARM and data-plane).",
    )
    extract_fabric: bool = Field(
        default=True,
        description="Enable or disable the Fabric/Power BI extractor.",
    )
    extract_devops: bool = Field(
        default=True,
        description="Enable or disable the DevOps extractor.",
    )
    extract_aas: bool = Field(
        default=True,
        description="Enable or disable the Analysis Services XMLA extractor.",
    )
    extract_sharepoint: bool = Field(
        default=True,
        description="Enable or disable the SharePoint extractor.",
    )
    extract_teams: bool = Field(
        default=True,
        description="Enable or disable the Teams extractor.",
    )
    extract_networking: bool = Field(
        default=True,
        description="Enable or disable the networking extractor.",
    )
    extract_cosmosdb: bool = Field(
        default=True,
        description="Enable or disable the Cosmos DB extractor.",
    )
    subscription_ids: list[str] = Field(
        default_factory=list,
        description=(
            "List of Azure subscription GUIDs to scan. "
            "Used by --scan-subscription mode. Can also be passed via CLI."
        ),
    )

    model_config = {
        "env_prefix": "EAIP_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }

    @property
    def use_interactive_auth(self) -> bool:
        """Determine whether interactive browser SSO should be used.

        Returns:
            True if no client secret is configured, indicating that the
            application should fall back to interactive browser-based
            authentication instead of client-credential flow.
        """
        return self.client_secret.get_secret_value() == ""


@lru_cache(maxsize=1)
def get_settings() -> EAIPSettings:
    """Return a cached singleton instance of EAIPSettings.

    The settings object is created once on first call and reused for the
    lifetime of the process. Call ``get_settings.cache_clear()`` if you
    need to force a reload (e.g. during testing).

    Returns:
        The resolved EAIPSettings instance.
    """
    return EAIPSettings()
