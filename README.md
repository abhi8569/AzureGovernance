# EAIP — Enterprise Access Intelligence Platform

![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

---

## Overview

EAIP is a **read-only, SSO-enabled** access-analysis platform for Microsoft environments. It extracts identity, directory, infrastructure, and data-layer permissions from across the Microsoft ecosystem and unifies them into a single graph model stored in an embedded **DuckDB** database.

Key capabilities:

- **Unified identity graph** — users, groups, service principals, managed identities, and their nested memberships.
- **Cross-platform permission analysis** — Entra ID roles, Azure RBAC, Fabric/Power BI workspaces, SQL grants, Key Vault policies, ADLS ACLs, and more.
- **Transitive closure engine** — resolves nested group memberships and inherited role assignments to compute effective permissions.
- **Local-first** — all data stays on your machine. No cloud storage, no telemetry.
- **Flexible output** — Hive-partitioned Parquet files and a Power BI template for interactive dashboards.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Microsoft APIs                                │
│  (Graph · ARM · Fabric · Power BI · SQL · Key Vault · DevOps · …)   │
└──────────────────┬───────────────────────────────────────────────────┘
                   │
                   ▼
        ┌─────────────────────┐
        │     Extractors      │   Platform-specific API clients
        │  (src/extractors/)  │   with retry, pagination, batching
        └────────┬────────────┘
                 │
                 ▼
        ┌─────────────────────┐
        │       DuckDB        │   Embedded analytical database
        │   (src/storage/)    │   Star-schema dimensional model
        └────────┬────────────┘
                 │
                 ▼
        ┌─────────────────────┐
        │   Closure Engine    │   Transitive group-membership
        │    (src/etl/)       │   and role-inheritance resolution
        └────────┬────────────┘
                 │
                 ▼
        ┌─────────────────────┐
        │ Effective Perms     │   FactEffectivePermission —
        │    (src/etl/)       │   "Who can do what, where?"
        └────────┬────────────┘
                 │
          ┌──────┴──────┐
          ▼             ▼
   ┌────────────┐ ┌───────────┐
   │  Parquet   │ │  Power BI │
   │  (Hive)    │ │  Template │
   └────────────┘ └───────────┘
```

---

## Quick Start

```bash
# 1. Clone the repository
git clone <repo-url> && cd MicrosoftGovernance

# 2. Install in editable mode with dev dependencies
pip install -e ".[dev]"

# 3. Configure environment
cp .env.example .env
# Edit .env — fill in EAIP_TENANT_ID and EAIP_CLIENT_ID at minimum.

# 4. Run the full extraction + analysis pipeline
python -m src.orchestrator.pipeline --full
```

On first run, a browser window will open for interactive SSO authentication. Subsequent runs use cached tokens.

---

## Project Structure

```
MicrosoftGovernance/
├── .env.example              # Configuration template
├── README.md
├── pyproject.toml            # Package & dependency definition
├── task.md                   # Development tracker (resumability)
│
├── config/                   # Settings, constants, schema versions
│   └── settings.py
│
├── src/
│   ├── auth/                 # MSAL authentication (SSO + SPN)
│   │   └── msal_auth.py
│   ├── extractors/           # Platform-specific API extractors
│   │   ├── entra.py          #   Entra ID (users, groups, roles)
│   │   ├── azure_rbac.py     #   Azure RBAC assignments
│   │   ├── fabric.py         #   Fabric / Power BI workspaces
│   │   ├── keyvault.py       #   Key Vault access policies
│   │   ├── sql.py            #   Azure SQL / Synapse grants
│   │   ├── adls.py           #   ADLS Gen2 ACLs
│   │   ├── devops.py         #   Azure DevOps permissions
│   │   └── sharepoint.py     #   SharePoint / Teams sites
│   ├── models/               # Pydantic schemas & enums
│   │   └── schemas.py
│   ├── etl/                  # Transform, closure, effective perms
│   │   ├── transform.py
│   │   ├── closure.py
│   │   └── effective.py
│   ├── storage/              # DuckDB + Parquet I/O
│   │   ├── duckdb_store.py
│   │   └── parquet_export.py
│   ├── utils/                # Logging, retry, Graph helpers
│   │   ├── logging.py
│   │   ├── retry.py
│   │   └── graph_helpers.py
│   └── orchestrator/         # Pipeline coordination
│       └── pipeline.py
│
├── sql/                      # DDL & analytical SQL scripts
│   ├── 001_create_dimensions.sql
│   ├── 002_create_facts.sql
│   └── 003_closure.sql
│
├── powerbi/                  # Power BI template & docs
│   └── eaip_template.pbit
│
├── tests/                    # Unit & integration tests
│   ├── test_auth.py
│   ├── test_extractors.py
│   └── test_etl.py
│
└── docs/                     # Additional documentation
    └── data_model.md
```

---

## Supported Platforms

| Platform                | Scope                                     | Extractor            |
| ----------------------- | ----------------------------------------- | -------------------- |
| **Entra ID**            | Users, groups, app registrations, roles    | `entra.py`           |
| **Azure RBAC**          | Role assignments across subscriptions      | `azure_rbac.py`      |
| **Microsoft Fabric**    | Workspace roles, item permissions          | `fabric.py`          |
| **Power BI**            | Workspace access, dataset/report sharing   | `fabric.py`          |
| **Azure SQL / Synapse** | Database principals, role members, grants  | `sql.py`             |
| **Key Vault**           | Access policies and RBAC assignments       | `keyvault.py`        |
| **ADLS Gen2**           | ACLs on containers, directories, files     | `adls.py`            |
| **Azure DevOps**        | Project permissions, repo/pipeline access  | `devops.py`          |
| **SharePoint / Teams**  | Site permissions, team memberships          | `sharepoint.py`      |
| **Analysis Services**   | Model roles and memberships                | *(planned)*          |

---

## Data Model

EAIP uses a **star-schema dimensional model** optimized for analytical queries:

| Table                       | Type      | Description                                         |
| --------------------------- | --------- | --------------------------------------------------- |
| `DimPrincipal`              | Dimension | Users, groups, service principals, managed identities|
| `DimResource`               | Dimension | Subscriptions, workspaces, databases, vaults, etc.  |
| `DimRole`                   | Dimension | Role definitions (RBAC roles, directory roles, etc.)|
| `FactMembership`            | Fact      | Direct group/role memberships                       |
| `FactMembershipClosure`     | Fact      | Transitive closure of nested memberships            |
| `FactRoleAssignment`        | Fact      | Direct role-to-resource assignments                 |
| `FactEffectivePermission`   | Fact      | Computed: "who can do what, where?" (final output)  |

The **closure engine** expands nested group memberships and inherited scopes so that `FactEffectivePermission` gives a complete, flattened view of access.

---

## Resumability

> **Development is tracked in `task.md`.** If the pipeline or development is interrupted, check the completed items and resume from the first unchecked task.

The extraction pipeline also supports incremental runs. Use `--resume` to skip already-completed extraction stages:

```bash
python -m src.orchestrator.pipeline --resume
```

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.
