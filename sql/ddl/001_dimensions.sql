-- EAIP Dimension Tables (DuckDB)

CREATE TABLE IF NOT EXISTS dim_principal (
    principal_id        BIGINT PRIMARY KEY,
    tenant_id           VARCHAR(36) NOT NULL,
    object_id           VARCHAR(36) NOT NULL,
    principal_type      VARCHAR(50) NOT NULL,
    display_name        VARCHAR(256),
    user_principal_name VARCHAR(256),
    mail                VARCHAR(256),
    account_enabled     BOOLEAN,
    user_type           VARCHAR(20),
    created_date        TIMESTAMP,
    modified_date       TIMESTAMP,
    is_deleted          BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS dim_resource (
    resource_id         BIGINT PRIMARY KEY,
    tenant_id           VARCHAR(36) NOT NULL,
    resource_guid       VARCHAR(256) NOT NULL,
    resource_type       VARCHAR(100) NOT NULL,
    name                VARCHAR(256),
    parent_id           BIGINT,
    subscription_id     VARCHAR(50),
    resource_group      VARCHAR(100),
    location            VARCHAR(50),
    tags                TEXT,
    created_date        TIMESTAMP,
    deleted_date        TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dim_role (
    role_id             BIGINT PRIMARY KEY,
    role_name           VARCHAR(256),
    platform            VARCHAR(50),
    is_built_in         BOOLEAN,
    description         VARCHAR(500),
    definition_json     TEXT
);

CREATE TABLE IF NOT EXISTS dim_permission (
    permission_id       BIGINT PRIMARY KEY,
    permission_name     VARCHAR(256),
    description         VARCHAR(512),
    permission_category VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS dim_snapshot (
    snapshot_id         BIGINT PRIMARY KEY,
    snapshot_date       DATE NOT NULL,
    description         VARCHAR(200),
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dim_time (
    date_key            INTEGER PRIMARY KEY,
    full_date           DATE NOT NULL,
    year                INTEGER,
    quarter             INTEGER,
    month               INTEGER,
    month_name          VARCHAR(20),
    week                INTEGER,
    day_of_week         INTEGER,
    day_name            VARCHAR(20),
    is_weekend          BOOLEAN
);
