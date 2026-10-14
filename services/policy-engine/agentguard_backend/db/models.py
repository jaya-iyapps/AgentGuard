"""SQLAlchemy tables for trusted facts and authorization evidence."""

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def uuid_string() -> str:
    return str(uuid4())


STATUS_CHECK = "status IN ('ACTIVE', 'INACTIVE', 'REVOKED')"
CLASSIFICATION_CHECK = "classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')"


class Base(DeclarativeBase):
    pass


class Principal(Base):
    __tablename__ = "pdp_principals"
    __table_args__ = (CheckConstraint(STATUS_CHECK, name="ck_principal_status"),)

    id: Mapped[str] = mapped_column(String(160), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class PrincipalBinding(Base):
    __tablename__ = "pdp_principal_bindings"
    __table_args__ = (
        CheckConstraint(STATUS_CHECK, name="ck_binding_status"),
        CheckConstraint("surface IN ('mcp', 'salesforce')", name="ck_binding_surface"),
        CheckConstraint("length(credential_sha256) = 64", name="ck_binding_digest_length"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    principal_id: Mapped[str] = mapped_column(ForeignKey("pdp_principals.id"), nullable=False)
    adapter_id: Mapped[str] = mapped_column(String(160), nullable=False)
    surface: Mapped[str] = mapped_column(String(16), nullable=False)
    credential_sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Resource(Base):
    __tablename__ = "pdp_resources"
    __table_args__ = (
        CheckConstraint(CLASSIFICATION_CHECK, name="ck_resource_classification"),
        CheckConstraint("origin IN ('SOURCE', 'DERIVED')", name="ck_resource_origin"),
    )

    id: Mapped[str] = mapped_column(String(160), primary_key=True)
    type: Mapped[str] = mapped_column(String(80), nullable=False)
    owner_principal_id: Mapped[str] = mapped_column(ForeignKey("pdp_principals.id"), nullable=False)
    classification: Mapped[str] = mapped_column(String(16), nullable=False)
    origin: Mapped[str] = mapped_column(String(16), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class Permission(Base):
    __tablename__ = "pdp_permissions"
    __table_args__ = (
        UniqueConstraint("principal_id", "action", "resource_id", name="uq_permission_scope"),
        CheckConstraint(STATUS_CHECK, name="ck_permission_status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    principal_id: Mapped[str] = mapped_column(ForeignKey("pdp_principals.id"), nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    resource_id: Mapped[str] = mapped_column(ForeignKey("pdp_resources.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)


class ProvenanceEdge(Base):
    __tablename__ = "pdp_provenance_edges"
    __table_args__ = (
        CheckConstraint("parent_id <> child_id", name="ck_provenance_not_self"),
        CheckConstraint("evidence IN ('declared', 'observed')", name="ck_provenance_evidence"),
        CheckConstraint(
            "evidence <> 'observed' OR "
            "(evidence_ref IS NOT NULL AND length(trim(evidence_ref)) > 0)",
            name="ck_provenance_observed_ref",
        ),
    )

    parent_id: Mapped[str] = mapped_column(ForeignKey("pdp_resources.id"), primary_key=True)
    child_id: Mapped[str] = mapped_column(ForeignKey("pdp_resources.id"), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    evidence: Mapped[str] = mapped_column(String(16), default="declared", server_default="declared")
    evidence_ref: Mapped[str | None] = mapped_column(String(256))


class GraphDestination(Base):
    """Curated analysis metadata, NOT the PDP's approved-destination allowlist."""

    __tablename__ = "graph_destinations"
    __table_args__ = (
        CheckConstraint(STATUS_CHECK, name="ck_graph_destination_status"),
        CheckConstraint(
            "location IN ('INTERNAL', 'EXTERNAL', 'UNKNOWN')", name="ck_graph_destination_location"
        ),
    )

    id: Mapped[str] = mapped_column(String(160), primary_key=True)
    address: Mapped[str] = mapped_column(String(254), unique=True, nullable=False)
    location: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ToolDataFlow(Base):
    """Trusted administrative declaration of ONE scoped tool input/output relationship.

    VERIFIED means the tool contract was verified, not that a tool was executed.
    DECLARED requires an explicit assumption; neither form grants permission.
    """

    __tablename__ = "graph_tool_data_flows"
    __table_args__ = (
        CheckConstraint(STATUS_CHECK, name="ck_graph_flow_status"),
        CheckConstraint(
            "verification IN ('DECLARED', 'VERIFIED')", name="ck_graph_flow_verification"
        ),
        CheckConstraint(
            "verification <> 'DECLARED' OR "
            "(assumption IS NOT NULL AND length(trim(assumption)) > 0)",
            name="ck_graph_flow_assumption",
        ),
        CheckConstraint(
            "verification <> 'VERIFIED' OR verified_at IS NOT NULL",
            name="ck_graph_flow_verified_at",
        ),
        CheckConstraint("length(trim(evidence_ref)) > 0", name="ck_graph_flow_evidence_ref"),
    )

    id: Mapped[str] = mapped_column(String(160), primary_key=True)
    permission_id: Mapped[str] = mapped_column(ForeignKey("pdp_permissions.id"), index=True)
    input_resource_id: Mapped[str] = mapped_column(ForeignKey("pdp_resources.id"), nullable=False)
    destination_id: Mapped[str | None] = mapped_column(ForeignKey("graph_destinations.id"))
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    verification: Mapped[str] = mapped_column(String(16), nullable=False)
    assumption: Mapped[str | None] = mapped_column(Text)
    evidence_ref: Mapped[str] = mapped_column(String(256), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Revocation(Base):
    __tablename__ = "pdp_revocations"
    __table_args__ = (
        CheckConstraint(
            "(CASE WHEN principal_id IS NOT NULL THEN 1 ELSE 0 END + "
            "CASE WHEN binding_id IS NOT NULL THEN 1 ELSE 0 END + "
            "CASE WHEN permission_id IS NOT NULL THEN 1 ELSE 0 END) = 1",
            name="ck_revocation_one_target",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    principal_id: Mapped[str | None] = mapped_column(ForeignKey("pdp_principals.id"), index=True)
    binding_id: Mapped[str | None] = mapped_column(
        ForeignKey("pdp_principal_bindings.id"), index=True
    )
    permission_id: Mapped[str | None] = mapped_column(ForeignKey("pdp_permissions.id"), index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ApprovedDestination(Base):
    __tablename__ = "pdp_approved_destinations"

    address: Mapped[str] = mapped_column(String(254), primary_key=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False)


class AuthorizationAudit(Base):
    __tablename__ = "pdp_authorization_audits"
    __table_args__ = (
        CheckConstraint("decision IN ('ALLOW', 'DENY')", name="ck_audit_decision"),
        CheckConstraint("length(request_digest) = 64", name="ck_audit_digest_length"),
    )

    decision_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    request_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    principal_id: Mapped[str | None] = mapped_column(ForeignKey("pdp_principals.id"))
    adapter_id: Mapped[str | None] = mapped_column(String(160))
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    # Unknown resources must still be auditable, so this is intentionally not a foreign key.
    resource_id: Mapped[str] = mapped_column(String(160), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    decision: Mapped[str] = mapped_column(String(8), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(160), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    policy_version: Mapped[str] = mapped_column(String(160), nullable=False)
    resource_classification: Mapped[str | None] = mapped_column(String(16))
    provenance_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    permission_status: Mapped[str | None] = mapped_column(String(16))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
