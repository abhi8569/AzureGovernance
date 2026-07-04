-- EAIP Closure Tables (DuckDB)

CREATE TABLE IF NOT EXISTS fact_membership_closure (
    ancestor_id         BIGINT NOT NULL,
    descendant_id       BIGINT NOT NULL,
    depth               INTEGER NOT NULL,
    path                TEXT,
    snapshot_id         BIGINT NOT NULL,
    PRIMARY KEY (ancestor_id, descendant_id, snapshot_id)
);

CREATE TABLE IF NOT EXISTS fact_resource_hierarchy_closure (
    ancestor_resource_id    BIGINT NOT NULL,
    descendant_resource_id  BIGINT NOT NULL,
    depth                   INTEGER NOT NULL,
    path                    TEXT,
    snapshot_id             BIGINT NOT NULL,
    PRIMARY KEY (ancestor_resource_id, descendant_resource_id, snapshot_id)
);
