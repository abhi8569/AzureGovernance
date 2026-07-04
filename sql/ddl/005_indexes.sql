-- EAIP Indexes (DuckDB)

-- Dimension indexes
CREATE INDEX IF NOT EXISTS idx_principal_object_id ON dim_principal(object_id);
CREATE INDEX IF NOT EXISTS idx_principal_tenant ON dim_principal(tenant_id);
CREATE INDEX IF NOT EXISTS idx_principal_type ON dim_principal(principal_type);

CREATE INDEX IF NOT EXISTS idx_resource_guid ON dim_resource(resource_guid);
CREATE INDEX IF NOT EXISTS idx_resource_tenant ON dim_resource(tenant_id);
CREATE INDEX IF NOT EXISTS idx_resource_type ON dim_resource(resource_type);
CREATE INDEX IF NOT EXISTS idx_resource_parent ON dim_resource(parent_id);

-- Fact membership indexes
CREATE INDEX IF NOT EXISTS idx_membership_parent ON fact_membership(parent_id);
CREATE INDEX IF NOT EXISTS idx_membership_snapshot ON fact_membership(snapshot_id);

-- Closure indexes
CREATE INDEX IF NOT EXISTS idx_closure_descendant ON fact_membership_closure(descendant_id);
CREATE INDEX IF NOT EXISTS idx_closure_snapshot ON fact_membership_closure(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_res_closure_descendant ON fact_resource_hierarchy_closure(descendant_resource_id);
CREATE INDEX IF NOT EXISTS idx_res_closure_snapshot ON fact_resource_hierarchy_closure(snapshot_id);

-- Resource hierarchy indexes
CREATE INDEX IF NOT EXISTS idx_res_hierarchy_child ON fact_resource_hierarchy(child_resource_id);
CREATE INDEX IF NOT EXISTS idx_res_hierarchy_snapshot ON fact_resource_hierarchy(snapshot_id);

-- Role assignment indexes
CREATE INDEX IF NOT EXISTS idx_role_assign_principal ON fact_role_assignment(principal_id);
CREATE INDEX IF NOT EXISTS idx_role_assign_resource ON fact_role_assignment(resource_id);
CREATE INDEX IF NOT EXISTS idx_role_assign_snapshot ON fact_role_assignment(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_role_assign_role ON fact_role_assignment(role_id);

-- Permission assignment indexes
CREATE INDEX IF NOT EXISTS idx_perm_assign_principal ON fact_permission_assignment(principal_id);
CREATE INDEX IF NOT EXISTS idx_perm_assign_resource ON fact_permission_assignment(resource_id);
CREATE INDEX IF NOT EXISTS idx_perm_assign_snapshot ON fact_permission_assignment(snapshot_id);

-- Effective permission indexes
CREATE INDEX IF NOT EXISTS idx_effective_principal ON fact_effective_permission(principal_id);
CREATE INDEX IF NOT EXISTS idx_effective_resource ON fact_effective_permission(resource_id);
CREATE INDEX IF NOT EXISTS idx_effective_snapshot ON fact_effective_permission(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_effective_assignment ON fact_effective_permission(source_assignment_id);

-- Access path indexes
CREATE INDEX IF NOT EXISTS idx_access_path_effective ON fact_access_path(effective_id);
CREATE INDEX IF NOT EXISTS idx_access_path_snapshot ON fact_access_path(snapshot_id);
