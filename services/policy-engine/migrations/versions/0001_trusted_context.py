"""Trusted context, provenance, revocations, and decision audit.

Revision ID: 0001_trusted_context
Revises: None
"""

from alembic import op
import sqlalchemy as sa

revision = "0001_trusted_context"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "pdp_principals",
        sa.Column("id", sa.String(160), primary_key=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'INACTIVE', 'REVOKED')", name="ck_principal_status"
        ),
    )
    op.create_table(
        "pdp_principal_bindings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "principal_id", sa.String(160), sa.ForeignKey("pdp_principals.id"), nullable=False
        ),
        sa.Column("adapter_id", sa.String(160), nullable=False),
        sa.Column("surface", sa.String(16), nullable=False),
        sa.Column("credential_sha256", sa.String(64), unique=True, nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("status IN ('ACTIVE', 'INACTIVE', 'REVOKED')", name="ck_binding_status"),
        sa.CheckConstraint("surface IN ('mcp', 'salesforce')", name="ck_binding_surface"),
        sa.CheckConstraint("length(credential_sha256) = 64", name="ck_binding_digest_length"),
    )
    op.create_table(
        "pdp_resources",
        sa.Column("id", sa.String(160), primary_key=True),
        sa.Column("type", sa.String(80), nullable=False),
        sa.Column(
            "owner_principal_id", sa.String(160), sa.ForeignKey("pdp_principals.id"), nullable=False
        ),
        sa.Column("classification", sa.String(16), nullable=False),
        sa.Column("origin", sa.String(16), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')",
            name="ck_resource_classification",
        ),
        sa.CheckConstraint("origin IN ('SOURCE', 'DERIVED')", name="ck_resource_origin"),
    )
    op.create_table(
        "pdp_permissions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "principal_id", sa.String(160), sa.ForeignKey("pdp_principals.id"), nullable=False
        ),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("resource_id", sa.String(160), sa.ForeignKey("pdp_resources.id"), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.UniqueConstraint("principal_id", "action", "resource_id", name="uq_permission_scope"),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'INACTIVE', 'REVOKED')", name="ck_permission_status"
        ),
    )
    op.create_table(
        "pdp_provenance_edges",
        sa.Column("parent_id", sa.String(160), sa.ForeignKey("pdp_resources.id"), primary_key=True),
        sa.Column("child_id", sa.String(160), sa.ForeignKey("pdp_resources.id"), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("parent_id <> child_id", name="ck_provenance_not_self"),
    )
    op.create_table(
        "pdp_revocations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("principal_id", sa.String(160), sa.ForeignKey("pdp_principals.id")),
        sa.Column("binding_id", sa.String(36), sa.ForeignKey("pdp_principal_bindings.id")),
        sa.Column("permission_id", sa.String(36), sa.ForeignKey("pdp_permissions.id")),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "(CASE WHEN principal_id IS NOT NULL THEN 1 ELSE 0 END + "
            "CASE WHEN binding_id IS NOT NULL THEN 1 ELSE 0 END + "
            "CASE WHEN permission_id IS NOT NULL THEN 1 ELSE 0 END) = 1",
            name="ck_revocation_one_target",
        ),
    )
    for column in ("principal_id", "binding_id", "permission_id"):
        op.create_index(f"ix_pdp_revocations_{column}", "pdp_revocations", [column])
    op.create_table(
        "pdp_approved_destinations",
        sa.Column("address", sa.String(254), primary_key=True),
        sa.Column("active", sa.Boolean, nullable=False),
    )
    op.create_table(
        "pdp_authorization_audits",
        sa.Column("decision_id", sa.String(36), primary_key=True),
        sa.Column("request_id", sa.String(128), nullable=False),
        sa.Column("session_id", sa.String(128), nullable=False),
        sa.Column("principal_id", sa.String(160), sa.ForeignKey("pdp_principals.id")),
        sa.Column("adapter_id", sa.String(160)),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("resource_id", sa.String(160), nullable=False),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("decision", sa.String(8), nullable=False),
        sa.Column("reason_code", sa.String(160), nullable=False),
        sa.Column("explanation", sa.Text, nullable=False),
        sa.Column("policy_version", sa.String(160), nullable=False),
        sa.Column("resource_classification", sa.String(16)),
        sa.Column("provenance_refs", sa.JSON, nullable=False),
        sa.Column("permission_status", sa.String(16)),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("decision IN ('ALLOW', 'DENY')", name="ck_audit_decision"),
        sa.CheckConstraint("length(request_digest) = 64", name="ck_audit_digest_length"),
    )
    op.create_index(
        "ix_pdp_authorization_audits_request_id", "pdp_authorization_audits", ["request_id"]
    )


def downgrade() -> None:
    for table in (
        "pdp_authorization_audits",
        "pdp_approved_destinations",
        "pdp_revocations",
        "pdp_provenance_edges",
        "pdp_permissions",
        "pdp_resources",
        "pdp_principal_bindings",
        "pdp_principals",
    ):
        op.drop_table(table)
