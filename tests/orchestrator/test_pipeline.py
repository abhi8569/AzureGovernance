"""Tests for the EAIP main pipeline loader."""
from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from config.settings import EAIPSettings
from src.orchestrator.pipeline import Pipeline
from src.storage.schema import DimPrincipal, DimResource, FactMembership, FactRoleAssignment, DimRole
from src.utils.id_generator import generate_surrogate_key
from src.etl.snapshot import SnapshotManager


def test_pipeline_load_to_database(db_session: Session, test_settings: EAIPSettings) -> None:
    """Test that _load_to_database correctly inserts normalized records."""
    pipeline = Pipeline(test_settings)
    
    # Create the snapshot to satisfy the foreign key constraint
    snapshot_id = SnapshotManager.create_snapshot(db_session, description="Test snapshot")

    u_key = generate_surrogate_key("entra", "u-1")
    g_key = generate_surrogate_key("entra", "g-1")
    res_key = generate_surrogate_key("azure", "res-1")
    role_key = generate_surrogate_key("azure", "role-reader")

    # Construct mock extract results matching extractor shapes
    extract_results = {
        "users": {
            "records": [
                {
                    "object_id": "u-1",
                    "principal_type": "User",
                    "displayName": "Alice User",
                    "userPrincipalName": "alice@company.com",
                    "mail": "alice@company.com",
                    "accountEnabled": True,
                }
            ],
            "record_count": 1,
            "errors": [],
            "duration": 0.1,
        },
        "groups": {
            "records": [
                {
                    "object_id": "g-1",
                    "principal_type": "Group",
                    "displayName": "IT Group",
                    "accountEnabled": None,
                }
            ],
            "record_count": 1,
            "errors": [],
            "duration": 0.1,
        },
        "memberships": {
            "records": [
                {
                    "member_id": u_key,
                    "parent_id": g_key,
                    "membership_type": "AD_GROUP",
                    "source": "entra_group_member",
                    "effective_from": None,
                    "effective_to": None,
                    "snapshot_id": snapshot_id,
                }
            ],
            "record_count": 1,
            "errors": [],
            "duration": 0.1,
        },
        "resource_graph": {
            "records": [
                {
                    "resource_guid": "res-1",
                    "resource_type": "MICROSOFT.KEYVAULT/VAULTS",
                    "name": "kv-prod",
                    "location": "eastus",
                }
            ],
            "record_count": 1,
            "errors": [],
            "duration": 0.1,
        },
        "role_definitions": {
            "records": [
                {
                    "role_id": role_key,
                    "role_name": "Reader",
                    "role_type": "BuiltInRole",
                    "description": "Read access",
                    "permissions": "[]",
                    "source": "azure",
                    "snapshot_id": snapshot_id,
                }
            ],
            "record_count": 1,
            "errors": [],
            "duration": 0.1,
        },
        "role_assignments": {
            "records": [
                {
                    "principal_id": u_key,
                    "role_id": role_key,
                    "resource_id": res_key,
                    "assignment_type": "AZURE_RBAC",
                    "snapshot_id": snapshot_id,
                }
            ],
            "record_count": 1,
            "errors": [],
            "duration": 0.1,
        }
    }

    # Run the load function
    counts = pipeline._load_to_database(db_session, extract_results, snapshot_id)

    # Verify return counts
    assert counts.get("dim_principal") == 2
    assert counts.get("fact_membership") == 1
    assert counts.get("dim_resource") == 1
    assert counts.get("dim_role") == 1
    assert counts.get("fact_role_assignment") == 1

    # Query database and verify insertions
    principals = db_session.execute(select(DimPrincipal)).scalars().all()
    assert len(principals) == 2
    names = {p.display_name for p in principals}
    assert "Alice User" in names
    assert "IT Group" in names

    memberships = db_session.execute(select(FactMembership)).scalars().all()
    assert len(memberships) == 1
    assert memberships[0].member_id == u_key
    assert memberships[0].snapshot_id == snapshot_id

    resources = db_session.execute(select(DimResource)).scalars().all()
    assert len(resources) == 1
    assert resources[0].name == "kv-prod"

    assignments = db_session.execute(select(FactRoleAssignment)).scalars().all()
    assert len(assignments) == 1
    assert assignments[0].principal_id == u_key
    assert assignments[0].snapshot_id == snapshot_id


def test_pipeline_resource_group_filtering(test_settings: EAIPSettings) -> None:
    """Test that _filter_records_by_rg correctly drops records from other resource groups."""
    pipeline = Pipeline(test_settings)
    pipeline.settings.resource_groups = ["rg-allowed"]

    records = [
        # Flat dict with resource_group field (allowed)
        {"resource_group": "rg-allowed", "name": "res-1"},
        # Flat dict with resource_group field (disallowed)
        {"resource_group": "rg-disallowed", "name": "res-2"},
        # Flat dict with Azure ID containing resource group (allowed)
        {"resource_guid": "/subscriptions/sub/resourceGroups/rg-allowed/providers/Microsoft.KeyVault/vaults/kv-1"},
        # Flat dict with Azure ID containing resource group (disallowed)
        {"resource_guid": "/subscriptions/sub/resourceGroups/rg-disallowed/providers/Microsoft.KeyVault/vaults/kv-2"},
        # Tenant level object with no RG (should be kept)
        {"object_id": "user-123"},
        # Nested list structure (e.g. storage / keyvault return shape)
        {
            "resources": [
                {"resource_group": "rg-allowed", "name": "res-nested-allowed"},
                {"resource_group": "rg-disallowed", "name": "res-nested-disallowed"}
            ],
            "assignments": [
                {"scope": "/subscriptions/sub/resourceGroups/rg-allowed/providers/kv-1", "role": "Reader"},
                {"scope": "/subscriptions/sub/resourceGroups/rg-disallowed/providers/kv-2", "role": "Reader"}
            ]
        }
    ]

    filtered = pipeline._filter_records_by_rg(records)

    # We expect:
    # 1. {"resource_group": "rg-allowed", "name": "res-1"} -> KEP
    # 2. {"resource_group": "rg-disallowed", "name": "res-2"} -> DROP
    # 3. {"resource_guid": ".../rg-allowed/..."} -> KEP
    # 4. {"resource_guid": ".../rg-disallowed/..."} -> DROP
    # 5. {"object_id": "user-123"} -> KEP
    # 6. Nested dict -> kept, but sub-lists inside are filtered!
    
    assert len(filtered) == 4
    
    # Check flat items
    assert filtered[0]["name"] == "res-1"
    assert "rg-allowed" in filtered[1]["resource_guid"]
    assert filtered[2]["object_id"] == "user-123"
    
    # Check nested item
    nested = filtered[3]
    assert len(nested["resources"]) == 1
    assert nested["resources"][0]["name"] == "res-nested-allowed"
    
    assert len(nested["assignments"]) == 1
    assert "rg-allowed" in nested["assignments"][0]["scope"]

