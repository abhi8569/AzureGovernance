-- EAIP Fact Tables (DuckDB)

CREATE TABLE IF NOT EXISTS fact_membership (
    member_id           BIGINT NOT NULL,
    parent_id           BIGINT NOT NULL,
    membership_type     VARCHAR(50),
    source              VARCHAR(50),
    effective_from      TIMESTAMP,
    effective_to        TIMESTAMP,
    snapshot_id         BIGINT NOT NULL,
    PRIMARY KEY (member_id, parent_id, snapshot_id)
);

CREATE TABLE IF NOT EXISTS fact_resource_hierarchy (
    parent_resource_id  BIGINT NOT NULL,
    child_resource_id   BIGINT NOT NULL,
    relationship_type   VARCHAR(50),
    snapshot_id         BIGINT NOT NULL,
    PRIMARY KEY (parent_resource_id, child_resource_id, snapshot_id)
);

CREATE TABLE IF NOT EXISTS fact_role_assignment (
    assignment_id       BIGINT PRIMARY KEY,
    principal_id        BIGINT NOT NULL,
    role_id             BIGINT,
    resource_id         BIGINT,
    assignment_type     VARCHAR(50),
    start_date          TIMESTAMP,
    end_date            TIMESTAMP,
    granted_by_id       BIGINT,
    inherited           BOOLEAN,
    source              VARCHAR(50),
    snapshot_id         BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS fact_permission_assignment (
    permission_assignment_id BIGINT PRIMARY KEY,
    principal_id        BIGINT NOT NULL,
    resource_id         BIGINT NOT NULL,
    permission_id       BIGINT NOT NULL,
    permission_state    VARCHAR(20) NOT NULL,
    grantor_id          BIGINT,
    inherited           BOOLEAN DEFAULT FALSE,
    source              VARCHAR(50),
    snapshot_id         BIGINT NOT NULL
);
