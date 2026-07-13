"""SQLAlchemy ORM schema for EAIP data warehouse."""
from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    PrimaryKeyConstraint,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


# ============================================================================
# Dimension Tables
# ============================================================================

class DimPrincipal(Base):
    """Security principals: users, groups, service principals, managed identities."""
    __tablename__ = "dim_principal"

    principal_id = Column(BigInteger, primary_key=True)
    tenant_id = Column(String(36), nullable=False)
    object_id = Column(String(36), nullable=False, index=True)
    principal_type = Column(String(50), nullable=False)
    display_name = Column(String(256))
    user_principal_name = Column(String(256))
    mail = Column(String(256))
    account_enabled = Column(Boolean)
    user_type = Column(String(20))
    created_date = Column(DateTime)
    modified_date = Column(DateTime)
    is_deleted = Column(Boolean, default=False)


class DimResource(Base):
    """Azure and Microsoft service resources."""
    __tablename__ = "dim_resource"

    resource_id = Column(BigInteger, primary_key=True)
    tenant_id = Column(String(36), nullable=False)
    resource_guid = Column(String(256), nullable=False, index=True)
    resource_type = Column(String(100), nullable=False)
    name = Column(String(256))
    parent_id = Column(BigInteger, ForeignKey("dim_resource.resource_id"))
    subscription_id = Column(String(50))
    resource_group = Column(String(100))
    location = Column(String(50))
    tags = Column(Text)
    created_date = Column(DateTime)
    deleted_date = Column(DateTime)

    parent = relationship("DimResource", remote_side=[resource_id])


class DimRole(Base):
    """Role definitions across platforms."""
    __tablename__ = "dim_role"

    role_id = Column(BigInteger, primary_key=True)
    role_name = Column(String(256))
    platform = Column(String(50))
    is_built_in = Column(Boolean)
    description = Column(String(500))
    definition_json = Column(Text)


class DimPermission(Base):
    """Granular permission definitions."""
    __tablename__ = "dim_permission"

    permission_id = Column(BigInteger, primary_key=True)
    permission_name = Column(String(256))
    description = Column(String(512))
    permission_category = Column(String(100))


class DimSnapshot(Base):
    """ETL snapshot metadata."""
    __tablename__ = "dim_snapshot"

    snapshot_id = Column(BigInteger, primary_key=True, autoincrement=True)
    snapshot_date = Column(Date, nullable=False)
    description = Column(String(200))
    created_at = Column(DateTime, server_default=func.now())


class DimTime(Base):
    """Calendar dimension for time-based analysis."""
    __tablename__ = "dim_time"

    date_key = Column(Integer, primary_key=True)
    full_date = Column(Date, nullable=False)
    year = Column(Integer)
    quarter = Column(Integer)
    month = Column(Integer)
    month_name = Column(String(20))
    week = Column(Integer)
    day_of_week = Column(Integer)
    day_name = Column(String(20))
    is_weekend = Column(Boolean)


# ============================================================================
# Fact Tables
# ============================================================================

class FactMembership(Base):
    """Direct membership edges between principals."""
    __tablename__ = "fact_membership"
    __table_args__ = (
        PrimaryKeyConstraint("member_id", "parent_id", "snapshot_id"),
    )

    member_id = Column(BigInteger, ForeignKey("dim_principal.principal_id"), nullable=False)
    parent_id = Column(BigInteger, ForeignKey("dim_principal.principal_id"), nullable=False)
    membership_type = Column(String(50))
    source = Column(String(50))
    effective_from = Column(DateTime)
    effective_to = Column(DateTime)
    snapshot_id = Column(BigInteger, ForeignKey("dim_snapshot.snapshot_id"), nullable=False)


class FactMembershipClosure(Base):
    """Transitive closure of membership relationships."""
    __tablename__ = "fact_membership_closure"
    __table_args__ = (
        PrimaryKeyConstraint("ancestor_id", "descendant_id", "snapshot_id"),
    )

    ancestor_id = Column(BigInteger, nullable=False)
    descendant_id = Column(BigInteger, nullable=False)
    depth = Column(Integer, nullable=False)
    path = Column(Text)
    snapshot_id = Column(BigInteger, nullable=False)


class FactResourceHierarchy(Base):
    """Direct resource containment relationships."""
    __tablename__ = "fact_resource_hierarchy"
    __table_args__ = (
        PrimaryKeyConstraint("parent_resource_id", "child_resource_id", "snapshot_id"),
    )

    parent_resource_id = Column(BigInteger, ForeignKey("dim_resource.resource_id"), nullable=False)
    child_resource_id = Column(BigInteger, ForeignKey("dim_resource.resource_id"), nullable=False)
    relationship_type = Column(String(50))
    snapshot_id = Column(BigInteger, ForeignKey("dim_snapshot.snapshot_id"), nullable=False)


class FactResourceHierarchyClosure(Base):
    """Transitive closure of resource hierarchy."""
    __tablename__ = "fact_resource_hierarchy_closure"
    __table_args__ = (
        PrimaryKeyConstraint("ancestor_resource_id", "descendant_resource_id", "snapshot_id"),
    )

    ancestor_resource_id = Column(BigInteger, nullable=False)
    descendant_resource_id = Column(BigInteger, nullable=False)
    depth = Column(Integer, nullable=False)
    path = Column(Text)
    snapshot_id = Column(BigInteger, nullable=False)


class FactRoleAssignment(Base):
    """Direct role and permission assignments."""
    __tablename__ = "fact_role_assignment"

    assignment_id = Column(BigInteger, primary_key=True)
    principal_id = Column(BigInteger, ForeignKey("dim_principal.principal_id"), nullable=False)
    role_id = Column(BigInteger, ForeignKey("dim_role.role_id"))
    resource_id = Column(BigInteger, ForeignKey("dim_resource.resource_id"))
    assignment_type = Column(String(50))
    start_date = Column(DateTime)
    end_date = Column(DateTime)
    granted_by_id = Column(BigInteger)
    inherited = Column(Boolean)
    source = Column(String(50))
    snapshot_id = Column(BigInteger, ForeignKey("dim_snapshot.snapshot_id"), nullable=False)


class FactPermissionAssignment(Base):
    """Raw permission grants (GRANT/DENY) for SQL/AAS/ACLs."""
    __tablename__ = "fact_permission_assignment"

    permission_assignment_id = Column(BigInteger, primary_key=True)
    principal_id = Column(BigInteger, ForeignKey("dim_principal.principal_id"), nullable=False)
    resource_id = Column(BigInteger, ForeignKey("dim_resource.resource_id"), nullable=False)
    permission_id = Column(BigInteger, ForeignKey("dim_permission.permission_id"), nullable=False)
    permission_state = Column(String(20), nullable=False)
    grantor_id = Column(BigInteger)
    inherited = Column(Boolean, default=False)
    source = Column(String(50))
    snapshot_id = Column(BigInteger, ForeignKey("dim_snapshot.snapshot_id"), nullable=False)


class FactEffectivePermission(Base):
    """Computed effective permissions after inheritance resolution."""
    __tablename__ = "fact_effective_permission"

    effective_id = Column(BigInteger, primary_key=True)
    principal_id = Column(BigInteger, ForeignKey("dim_principal.principal_id"), nullable=False)
    resource_id = Column(BigInteger, ForeignKey("dim_resource.resource_id"), nullable=False)
    permission_id = Column(BigInteger, ForeignKey("dim_permission.permission_id"), nullable=False)
    source_assignment_id = Column(BigInteger, ForeignKey("fact_role_assignment.assignment_id"), nullable=False)
    depth = Column(Integer, nullable=False)
    inheritance_path = Column(Text)
    calculated_on = Column(DateTime)
    snapshot_id = Column(BigInteger, ForeignKey("dim_snapshot.snapshot_id"), nullable=False)


class FactAccessPath(Base):
    """Detailed access path steps for explainability."""
    __tablename__ = "fact_access_path"

    path_id = Column(BigInteger, primary_key=True)
    effective_id = Column(BigInteger, ForeignKey("fact_effective_permission.effective_id"), nullable=False)
    step_order = Column(Integer, nullable=False)
    node_id = Column(BigInteger, nullable=False)
    node_type = Column(String(50))
    node_name = Column(String(256))
    snapshot_id = Column(BigInteger, ForeignKey("dim_snapshot.snapshot_id"), nullable=False)


class FactRLSPolicy(Base):
    """Row-Level Security policies extracted from SQL databases."""
    __tablename__ = "fact_rls_policy"

    rls_id = Column(BigInteger, primary_key=True)
    resource_id = Column(BigInteger, ForeignKey("dim_resource.resource_id"), nullable=False)
    database = Column(String(256), nullable=False)
    policy_name = Column(String(256), nullable=False)
    is_enabled = Column(Boolean)
    target_table = Column(String(256))
    predicate_type = Column(String(50))
    predicate_definition = Column(Text)
    filter_function_name = Column(String(256))
    filter_function_definition = Column(Text)
    role_name = Column(String(256))
    model_permission = Column(String(50))
    snapshot_id = Column(BigInteger, ForeignKey("dim_snapshot.snapshot_id"), nullable=False)


class FactDDMRule(Base):
    """Dynamic Data Masking rules extracted from SQL databases."""
    __tablename__ = "fact_ddm_rule"

    ddm_id = Column(BigInteger, primary_key=True)
    resource_id = Column(BigInteger, ForeignKey("dim_resource.resource_id"), nullable=False)
    database = Column(String(256), nullable=False)
    table_name = Column(String(256), nullable=False)
    column_name = Column(String(256), nullable=False)
    masking_function = Column(String(256))
    snapshot_id = Column(BigInteger, ForeignKey("dim_snapshot.snapshot_id"), nullable=False)


class FactSharingLink(Base):
    """SharePoint / OneDrive sharing links."""
    __tablename__ = "fact_sharing_link"

    link_id = Column(BigInteger, primary_key=True)
    item_name = Column(String(256))
    drive_id = Column(String(256))
    item_id = Column(String(256))
    link_type = Column(String(50))
    link_scope = Column(String(50))
    link_url = Column(Text)
    created_by = Column(Text)
    snapshot_id = Column(BigInteger, ForeignKey("dim_snapshot.snapshot_id"), nullable=False)


class FactNSGRule(Base):
    """Network Security Group rules."""
    __tablename__ = "fact_nsg_rule"

    rule_id = Column(BigInteger, primary_key=True)
    nsg_resource_id = Column(BigInteger, ForeignKey("dim_resource.resource_id"), nullable=False)
    nsg_name = Column(String(256))
    rule_name = Column(String(256), nullable=False)
    priority = Column(Integer)
    direction = Column(String(20))
    access = Column(String(20))
    protocol = Column(String(20))
    source_address = Column(String(256))
    source_port = Column(String(256))
    destination_address = Column(String(256))
    destination_port = Column(String(256))
    description = Column(String(512))
    snapshot_id = Column(BigInteger, ForeignKey("dim_snapshot.snapshot_id"), nullable=False)


class FactPrivateEndpoint(Base):
    """Azure Private Endpoint connections."""
    __tablename__ = "fact_private_endpoint"

    pe_id = Column(BigInteger, primary_key=True)
    resource_id = Column(BigInteger, ForeignKey("dim_resource.resource_id"), nullable=False)
    name = Column(String(256))
    location = Column(String(50))
    subnet_id = Column(String(256))
    target_resource = Column(Text)
    group_ids = Column(Text)
    connection_status = Column(String(50))
    snapshot_id = Column(BigInteger, ForeignKey("dim_snapshot.snapshot_id"), nullable=False)


class FactOneLakeRole(Base):
    """OneLake workspace-level role assignments."""
    __tablename__ = "fact_onelake_role"

    onelake_role_id = Column(BigInteger, primary_key=True)
    workspace_id = Column(String(256))
    item_id = Column(String(256))
    item_type = Column(String(100))
    item_name = Column(String(256))
    role_name = Column(String(256))
    role_definition_id = Column(String(256))
    decision_rules = Column(Text)
    members = Column(Text)
    snapshot_id = Column(BigInteger, ForeignKey("dim_snapshot.snapshot_id"), nullable=False)
