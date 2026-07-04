-- EAIP Effective Permission Tables (DuckDB)

CREATE TABLE IF NOT EXISTS fact_effective_permission (
    effective_id            BIGINT PRIMARY KEY,
    principal_id            BIGINT NOT NULL,
    resource_id             BIGINT NOT NULL,
    permission_id           BIGINT NOT NULL,
    source_assignment_id    BIGINT NOT NULL,
    depth                   INTEGER NOT NULL,
    inheritance_path        TEXT,
    calculated_on           TIMESTAMP,
    snapshot_id             BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS fact_access_path (
    path_id                 BIGINT PRIMARY KEY,
    effective_id            BIGINT NOT NULL,
    step_order              INTEGER NOT NULL,
    node_id                 BIGINT NOT NULL,
    node_type               VARCHAR(50),
    node_name               VARCHAR(256),
    snapshot_id             BIGINT NOT NULL
);
