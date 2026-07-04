"""Shared pytest fixtures for EAIP tests."""
from __future__ import annotations

import os
import pytest
import duckdb
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from src.storage.schema import Base
from config.settings import EAIPSettings


@pytest.fixture(scope="session")
def test_settings() -> EAIPSettings:
    """Create test settings with in-memory DuckDB."""
    return EAIPSettings(
        tenant_id="test-tenant-00000000-0000-0000-0000-000000000000",
        client_id="test-client-00000000-0000-0000-0000-000000000000",
        client_secret="",
        database_path=":memory:",
        parquet_output_dir="./test_data/parquet",
        log_level="DEBUG",
    )


@pytest.fixture(scope="function")
def db_engine():
    """Create a fresh in-memory DuckDB engine for each test."""
    engine = create_engine("duckdb:///:memory:")
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture(scope="function")
def db_session(db_engine) -> Session:
    """Create a database session for each test."""
    session_factory = sessionmaker(bind=db_engine)
    session = session_factory()
    yield session
    session.close()


@pytest.fixture(scope="function")
def duckdb_conn():
    """Create a raw DuckDB in-memory connection for each test."""
    conn = duckdb.connect(":memory:")
    yield conn
    conn.close()


@pytest.fixture(scope="function")
def sample_principals() -> list[dict]:
    """Sample principal data for testing."""
    return [
        {
            "principal_id": 1,
            "tenant_id": "test-tenant",
            "object_id": "00000000-0000-0000-0000-000000000001",
            "principal_type": "User",
            "display_name": "Alice Johnson",
            "user_principal_name": "alice@contoso.com",
            "mail": "alice@contoso.com",
            "account_enabled": True,
            "is_deleted": False,
        },
        {
            "principal_id": 2,
            "tenant_id": "test-tenant",
            "object_id": "00000000-0000-0000-0000-000000000002",
            "principal_type": "User",
            "display_name": "Bob Smith",
            "user_principal_name": "bob@contoso.com",
            "mail": "bob@contoso.com",
            "account_enabled": True,
            "is_deleted": False,
        },
        {
            "principal_id": 3,
            "tenant_id": "test-tenant",
            "object_id": "00000000-0000-0000-0000-000000000003",
            "principal_type": "Group",
            "display_name": "Engineering Team",
            "account_enabled": None,
            "is_deleted": False,
        },
        {
            "principal_id": 4,
            "tenant_id": "test-tenant",
            "object_id": "00000000-0000-0000-0000-000000000004",
            "principal_type": "Group",
            "display_name": "IT Department",
            "account_enabled": None,
            "is_deleted": False,
        },
        {
            "principal_id": 5,
            "tenant_id": "test-tenant",
            "object_id": "00000000-0000-0000-0000-000000000005",
            "principal_type": "ServicePrincipal",
            "display_name": "Data Pipeline SPN",
            "account_enabled": True,
            "is_deleted": False,
        },
    ]


@pytest.fixture(scope="function")
def sample_memberships() -> list[dict]:
    """Sample membership data matching SRS test vector: U1->G1->G2."""
    return [
        {"member_id": 1, "parent_id": 3, "membership_type": "AD_GROUP", "source": "GraphAPI", "snapshot_id": 1},  # Alice -> Engineering
        {"member_id": 2, "parent_id": 3, "membership_type": "AD_GROUP", "source": "GraphAPI", "snapshot_id": 1},  # Bob -> Engineering
        {"member_id": 3, "parent_id": 4, "membership_type": "AD_GROUP", "source": "GraphAPI", "snapshot_id": 1},  # Engineering -> IT Dept
    ]


@pytest.fixture(scope="function")
def sample_resources() -> list[dict]:
    """Sample resource hierarchy data."""
    return [
        {"resource_id": 100, "tenant_id": "test-tenant", "resource_guid": "sub-001", "resource_type": "Subscription", "name": "Production"},
        {"resource_id": 101, "tenant_id": "test-tenant", "resource_guid": "rg-001", "resource_type": "ResourceGroup", "name": "RG-Data", "parent_id": 100},
        {"resource_id": 102, "tenant_id": "test-tenant", "resource_guid": "sa-001", "resource_type": "StorageAccount", "name": "datalakeprod", "parent_id": 101},
    ]


@pytest.fixture(autouse=True)
def clean_test_data():
    """Clean up test data directory after tests."""
    yield
    import shutil
    if os.path.exists("./test_data"):
        shutil.rmtree("./test_data", ignore_errors=True)
