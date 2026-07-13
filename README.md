# EAIP — Enterprise Access Intelligence Platform

![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)
![DuckDB](https://img.shields.io/badge/database-DuckDB-FED100?logo=duckdb&logoColor=black)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

---

## What is EAIP?

EAIP is a **read-only, SSO-enabled** access-intelligence platform for Microsoft environments. It extracts identity, directory, infrastructure, and data-layer permissions from across the Microsoft ecosystem and unifies them into a single graph model stored in an embedded **DuckDB** database.

It answers the question: **"Who has access to this resource, and why?"**

### Key Capabilities

| Feature | Description |
|---------|-------------|
| **Unified identity graph** | Users, groups, service principals, managed identities, and their nested memberships |
| **12-phase extraction** | Covers Entra ID → Azure RBAC → Storage → Key Vault → SQL → Cosmos DB → Fabric/PBI → SharePoint → Teams → AAS → Networking → DevOps |
| **Deep sub-resource permissions** | Goes beyond "what resources exist" to extract who has what access at every level (dataset users, DB role members, RLS policies, sharing links, NSG rules, etc.) |
| **Transitive closure engine** | Resolves nested group memberships and inherited role assignments to compute effective permissions |
| **Local-first** | All data stays on your machine. No cloud storage, no telemetry, no remote deployments |
| **Flexible output** | Hive-partitioned Parquet files + DuckDB for Power BI dashboards |

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| **Python** | 3.11+ | 3.12 also supported |
| **pip** | Latest | `python -m pip install --upgrade pip` |
| **ODBC Driver** | 18+ | Required only for SQL Server deep extraction. [Download](https://learn.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server) |
| **Azure AD App Registration** | — | With `Directory.Read.All`, `Group.Read.All`, `RoleManagement.Read.Directory` API permissions |

### Azure AD App Registration

1. Go to [Azure Portal → App registrations](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
2. Click **New registration**
3. Set name: `EAIP-AccessIntelligence`
4. Set redirect URI: `http://localhost` (for interactive SSO)
5. Note down the **Application (client) ID** and **Directory (tenant) ID**
6. Under **API permissions**, add:
   - `Microsoft Graph` → `Directory.Read.All`, `Group.Read.All`, `User.Read.All`, `RoleManagement.Read.Directory`, `Application.Read.All`
   - `Azure Service Management` → `user_impersonation` (for Azure RBAC)
7. Grant admin consent

---

## Quick Start

### 1. Clone & Install

```bash
# Clone the repository
git clone <repo-url> && cd MicrosoftGovernance

# Option A: Install with pip (recommended)
pip install -r requirements.txt

# Option B: Install in editable mode with dev tools
pip install -e ".[dev]"
```

### 2. Configure

```bash
# Copy the environment template
cp .env.example .env
```

Edit `.env` and fill in your values:

```dotenv
# REQUIRED — Azure AD identity
EAIP_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
EAIP_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# OPTIONAL — leave empty for interactive SSO (browser popup)
EAIP_CLIENT_SECRET=

# OPTIONAL — SQL Server deep extraction
EAIP_SQL_CONNECTIONS=["Driver={ODBC Driver 18 for SQL Server};Server=myserver.database.windows.net;Database=mydb;Authentication=ActiveDirectoryInteractive"]

# OPTIONAL — Analysis Services / PBI Premium XMLA
EAIP_AAS_SERVERS=["powerbi://api.powerbi.com/v1.0/myorg/MyWorkspace"]
```

### 3. Run

#### 🚀 Subscription Scan (Recommended — easiest way to start)

Just provide your subscription ID(s) and EAIP auto-discovers all resources and extracts everything:

```bash
# Scan a single subscription — discovers SQL, Key Vault, Storage, Cosmos, NSGs, etc.
python -m src.orchestrator.pipeline --scan-subscription --subscription-ids YOUR-SUB-GUID

# Scan multiple subscriptions at once
python -m src.orchestrator.pipeline --scan-subscription --subscription-ids SUB-1 SUB-2 SUB-3
```

This mode:
1. Queries **Azure Resource Graph** to discover every resource in the subscription
2. Matches discovered resources to extractors (SQL → SQL deep extractor, Key Vault → KV extractor, etc.)
3. Runs **Entra ID, Azure RBAC, Fabric/PBI, SharePoint, Teams, AAS** automatically
4. Computes transitive closures and effective permissions
5. Exports to DuckDB + Parquet

#### Other Run Modes

```bash
# Full pipeline (uses all configured sources — same as scan but reads from .env)
python -m src.orchestrator.pipeline --full

# Extract only (no ETL processing)
python -m src.orchestrator.pipeline --extract-only

# ETL only (process existing data from a previous extraction)
python -m src.orchestrator.pipeline --etl-only

# ETL on a specific snapshot
python -m src.orchestrator.pipeline --etl-only --snapshot-id 42
```

On first run, a **browser window opens** for interactive SSO authentication. Subsequent runs use cached tokens.

### 4. View Results

After a successful run:

- **DuckDB database**: `./data/eaip.duckdb` — open with [DBeaver](https://dbeaver.io/) or any DuckDB client
- **Parquet files**: `./data/parquet/` — Hive-partitioned, ready for Power BI import
- **Console output**: JSON summary of extraction counts and any errors

```bash
# Quick query against the database
python -c "
import duckdb
con = duckdb.connect('./data/eaip.duckdb')
print(con.sql('SELECT COUNT(*) as principals FROM dim_principal').fetchone())
print(con.sql('SELECT COUNT(*) as assignments FROM fact_role_assignment').fetchone())
print(con.sql('SELECT COUNT(*) as effective FROM fact_effective_permission').fetchone())
"
```

---

## Configuration Reference

All settings are set via environment variables with the `EAIP_` prefix, or in a `.env` file.

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `EAIP_TENANT_ID` | string | *required* | Azure AD / Entra ID tenant GUID |
| `EAIP_CLIENT_ID` | string | *required* | App registration client ID |
| `EAIP_CLIENT_SECRET` | secret | `""` | Client secret. Empty = interactive SSO |
| `EAIP_DATABASE_PATH` | string | `./data/eaip.duckdb` | DuckDB database file path |
| `EAIP_PARQUET_OUTPUT_DIR` | string | `./data/parquet` | Parquet export directory |
| `EAIP_LOG_LEVEL` | string | `INFO` | Logging level (DEBUG/INFO/WARNING/ERROR) |
| `EAIP_MAX_RETRIES` | int | `5` | Max retry attempts for API calls |
| `EAIP_BATCH_SIZE` | int | `999` | Items per API page (max 999 for Graph) |
| `EAIP_DEVOPS_ORG` | string | `""` | Azure DevOps org name |
| `EAIP_DEVOPS_PAT` | secret | `""` | Azure DevOps personal access token |
| `EAIP_SQL_CONNECTIONS` | list | `[]` | pyodbc connection strings for SQL audit |
| `EAIP_AAS_SERVERS` | list | `[]` | AAS/XMLA endpoint URLs |
| `EAIP_EXTRACT_SHAREPOINT` | bool | `true` | Enable SharePoint extraction |
| `EAIP_EXTRACT_TEAMS` | bool | `true` | Enable Teams extraction |
| `EAIP_EXTRACT_NETWORKING` | bool | `true` | Enable networking (NSG/PE) extraction |
| `EAIP_EXTRACT_COSMOSDB` | bool | `true` | Enable Cosmos DB extraction |
| `EAIP_SUBSCRIPTION_IDS` | list | `[]` | Subscription GUIDs for `--scan-subscription` (also configurable via CLI) |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Microsoft APIs                                │
│  Graph · ARM · Fabric · Power BI · SQL · Key Vault · Cosmos · AAS    │
│  SharePoint · Teams · DevOps · Storage · Networking                  │
└──────────────────┬───────────────────────────────────────────────────┘
                   │
                   ▼
        ┌─────────────────────┐
        │     12 Extractors   │   Platform-specific API clients
        │  (src/extractors/)  │   with retry, pagination, rate limiting
        └────────┬────────────┘
                 │
                 ▼
        ┌─────────────────────┐
        │  Normalizer + Load  │   Surrogate keys, deduplication,
        │   (src/etl/)        │   schema mapping into DuckDB
        └────────┬────────────┘
                 │
                 ▼
        ┌─────────────────────┐
        │   Closure Engine    │   Transitive group membership
        │    (src/etl/)       │   and resource hierarchy resolution
        └────────┬────────────┘
                 │
                 ▼
        ┌─────────────────────┐
        │ Effective Perms     │   FactEffectivePermission +
        │ + Access Paths      │   FactAccessPath for explainability
        └────────┬────────────┘
                 │
          ┌──────┴──────┐
          ▼             ▼
   ┌────────────┐ ┌───────────┐
   │   DuckDB   │ │  Parquet  │
   │  (local)   │ │  (Hive)   │
   └────────────┘ └───────────┘
```

---

## What Gets Extracted (12 Phases)

| Phase | Platform | What's extracted |
|-------|----------|-----------------|
| 1 | **Entra ID** | Users, groups, memberships, directory roles, service principals, app registrations |
| 2 | **Azure RBAC** | Subscriptions, resource groups, management groups, role definitions, role assignments, all resources (via Resource Graph) |
| 3 | **Storage** | Storage accounts, ADLS Gen2 containers, POSIX ACLs (user/group/other/named) |
| 4 | **Key Vault** | Vault access policies + individual key/secret/certificate RBAC |
| 5 | **SQL Server** | Server logins, DB users, roles, role membership, object/schema/column GRANT/DENY, RLS policies (with filter function SQL), DDM rules, AD admins, firewall rules |
| 6 | **Cosmos DB** | Data-plane RBAC (invisible to ARM!), custom + built-in role definitions, scoped assignments at account/database/container level |
| 7 | **Fabric / Power BI** | Workspaces, per-dataset/report/dashboard/app/dataflow users, gateway users, capacity admins, Scanner API bulk users, OneLake data access roles |
| 8 | **SharePoint** | Site permissions, list permissions, drive item permissions, sharing links (anonymous/organization/specific people) |
| 9 | **Teams** | Team members/owners/guests, private channel members, shared channel cross-team access, team settings, installed apps |
| 10 | **Analysis Services** | XMLA databases, roles, role members, RLS filter expressions (DAX), model permissions |
| 11 | **Networking** | NSG allow/deny rules, private endpoints, VNet service endpoints |
| 12 | **DevOps** | Projects, repositories, pipelines, build/release permissions |

---

## Data Model (Star Schema)

### Dimension Tables

| Table | Description |
|-------|-------------|
| `dim_principal` | Users, groups, service principals, managed identities |
| `dim_resource` | All Azure/M365 resources (subs, RGs, workspaces, databases, vaults, etc.) |
| `dim_role` | Role definitions across all platforms |
| `dim_permission` | Granular permission definitions |
| `dim_snapshot` | ETL snapshot metadata (for time-travel) |
| `dim_time` | Calendar dimension |

### Fact Tables

| Table | Description |
|-------|-------------|
| `fact_membership` | Direct group/role memberships |
| `fact_membership_closure` | Transitive closure (nested groups resolved) |
| `fact_resource_hierarchy` | Direct resource containment (MG → Sub → RG → Resource) |
| `fact_resource_hierarchy_closure` | Transitive closure of resource hierarchy |
| `fact_role_assignment` | Direct role-to-resource assignments |
| `fact_permission_assignment` | Raw GRANT/DENY permission entries (SQL, ACLs) |
| `fact_effective_permission` | **Computed**: "who can do what, where?" — the final output |
| `fact_access_path` | Step-by-step explainability ("why does Alice have access?") |
| `fact_rls_policy` | Row-Level Security policies (SQL + AAS) |
| `fact_ddm_rule` | Dynamic Data Masking rules |
| `fact_sharing_link` | SharePoint/OneDrive sharing links |
| `fact_nsg_rule` | NSG security rules |
| `fact_private_endpoint` | Private endpoint connections |
| `fact_onelake_role` | OneLake data access roles |

---

## Project Structure

```
MicrosoftGovernance/
├── .env.example                    # Configuration template
├── pyproject.toml                  # Package definition + tool config
├── requirements.txt                # pip dependencies
│
├── config/                         # Settings and constants
│   ├── settings.py                 #   Pydantic settings (env-based)
│   └── scopes.py                   #   OAuth 2.0 scope constants
│
├── src/
│   ├── auth/                       # Authentication
│   │   ├── msal_client.py          #   MSAL token acquisition (SSO + SPN)
│   │   ├── credential_factory.py   #   Azure credential builder
│   │   └── token_cache.py          #   Local token cache
│   │
│   ├── extractors/                 # Platform-specific API extractors
│   │   ├── base.py                 #   BaseExtractor ABC + ExtractResult
│   │   ├── entra/                  #   Users, groups, memberships, roles, SPs
│   │   ├── azure_rbac/             #   Subscriptions, MGs, role defs/assignments, Resource Graph
│   │   ├── storage/                #   Storage accounts, ADLS containers, POSIX ACLs
│   │   ├── keyvault/               #   Vault policies + key/secret/cert RBAC
│   │   ├── sql/                    #   Server logins, DB users/roles/perms, RLS, DDM
│   │   ├── cosmosdb/               #   Data-plane RBAC, scoped assignments
│   │   ├── fabric/                 #   Workspaces, PBI deep perms, Scanner API, OneLake
│   │   ├── sharepoint/             #   Site/list/item perms, sharing links, Teams
│   │   ├── aas/                    #   XMLA databases, roles, RLS DAX
│   │   ├── networking/             #   NSGs, private endpoints, VNet SEs
│   │   └── devops/                 #   Projects, repos, pipelines
│   │
│   ├── models/                     # Pydantic schemas and enums
│   │   ├── enums.py                #   PrincipalType, ResourceType, AssignmentType
│   │   ├── principals.py           #   Principal Pydantic models
│   │   ├── resources.py            #   Resource Pydantic models
│   │   ├── roles.py                #   Role Pydantic models
│   │   └── assignments.py          #   Assignment Pydantic models
│   │
│   ├── etl/                        # Transform and analysis
│   │   ├── normalizer.py           #   Data normalization + deduplication
│   │   ├── closure.py              #   Transitive closure computation
│   │   ├── effective_permissions.py #   Effective permission resolution
│   │   ├── access_paths.py         #   Access path explainability
│   │   ├── snapshot.py             #   Snapshot management (time-travel)
│   │   └── validation.py           #   Data quality checks
│   │
│   ├── storage/                    # Database and export
│   │   ├── schema.py               #   SQLAlchemy ORM (20 tables)
│   │   ├── database.py             #   DuckDB session management
│   │   └── parquet_writer.py       #   Hive-partitioned Parquet export
│   │
│   ├── utils/                      # Shared utilities
│   │   ├── id_generator.py         #   Deterministic surrogate key generation
│   │   ├── pagination.py           #   Graph/REST/Fabric async paginators
│   │   ├── rate_limiter.py         #   Token-bucket rate limiters per API
│   │   ├── retry.py                #   Retry with backoff (429 handling)
│   │   └── logging.py              #   structlog configuration
│   │
│   └── orchestrator/               # Pipeline coordination
│       └── pipeline.py             #   12-phase extraction + ETL + CLI
│
├── sql/ddl/                        # Raw DDL scripts (reference)
│   ├── 001_dimensions.sql
│   ├── 002_facts.sql
│   ├── 003_closure.sql
│   ├── 004_effective.sql
│   └── 005_indexes.sql
│
└── tests/                          # Unit tests (61 tests)
    ├── conftest.py                 #   Shared fixtures (DuckDB test DB)
    ├── etl/
    │   └── test_normalizer.py      #   14 tests: principals, resources, RLS, DDM, NSG
    ├── extractors/
    │   ├── test_powerbi_permissions.py  # 6 tests: workspace/item user mapping
    │   ├── test_sql_permissions.py      # 7 tests: DB users, GRANT/DENY, RLS
    │   ├── test_aas_models.py           # 8 tests: XMLA endpoint, XML parsing
    │   ├── test_teams_permissions.py    # 4 tests: members, channels, errors
    │   └── test_cosmosdb_networking.py  # 7 tests: scope detection, NSG rules
    └── utils/
        └── test_utils.py           #   11 tests: id_generator, rate_limiter
```

---

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ -v --cov=src --cov-report=term-missing

# Run specific test module
python -m pytest tests/etl/test_normalizer.py -v

# Run specific test class
python -m pytest tests/extractors/test_sql_permissions.py::TestMapRlsPolicy -v
```

Current status: **61 tests, all passing** ✅

---

## Example Queries

After extraction, query the DuckDB database to answer governance questions:

```sql
-- Who has Owner access to any subscription?
SELECT p.display_name, p.principal_type, r.role_name, res.name AS resource
FROM fact_role_assignment fa
JOIN dim_principal p ON fa.principal_id = p.principal_id
JOIN dim_role r ON fa.role_id = r.role_id
JOIN dim_resource res ON fa.resource_id = res.resource_id
WHERE r.role_name = 'Owner' AND res.resource_type = 'SUBSCRIPTION';

-- All anonymous sharing links in SharePoint
SELECT item_name, link_url, link_scope, created_by
FROM fact_sharing_link
WHERE link_scope = 'anonymous';

-- RLS policies with their filter definitions
SELECT database, policy_name, target_table, filter_function_definition
FROM fact_rls_policy
WHERE is_enabled = true;

-- NSG rules allowing inbound from Internet
SELECT nsg_name, rule_name, destination_port, access
FROM fact_nsg_rule
WHERE direction = 'Inbound' AND source_address = 'Internet' AND access = 'Allow';

-- Effective permissions: who can access what, traced through group membership
SELECT p.display_name, res.name, perm.permission_name, ep.inheritance_path
FROM fact_effective_permission ep
JOIN dim_principal p ON ep.principal_id = p.principal_id
JOIN dim_resource res ON ep.resource_id = res.resource_id
JOIN dim_permission perm ON ep.permission_id = perm.permission_id
WHERE p.display_name = 'Alice';
```

---

## Resumability

> If the pipeline is interrupted or AI credits run out during development, check `task.md` in the artifacts directory and resume from the first unchecked item.

The pipeline supports incremental operation modes:

- `--extract-only` → run extraction, skip ETL
- `--etl-only` → process existing extracted data
- `--snapshot-id N` → re-process a specific historical snapshot

Data is snapshot-based: each run creates a new `dim_snapshot` entry, so historical comparisons are preserved.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: No module named 'xyz'` | Run `pip install -r requirements.txt` |
| `AADSTS700016: Application not found` | Verify `EAIP_CLIENT_ID` matches your app registration |
| `AADSTS50011: Reply URL mismatch` | Add `http://localhost` as a redirect URI in your app registration |
| Browser doesn't open for SSO | Ensure `EAIP_CLIENT_SECRET` is empty in `.env` |
| `pyodbc.Error: ODBC Driver not found` | Install [ODBC Driver 18 for SQL Server](https://learn.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server) |
| Rate limited (429 errors) | Built-in — the platform auto-retries with exponential backoff |
| DuckDB locked | Only one process can write to DuckDB at a time. Close other connections. |

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.
