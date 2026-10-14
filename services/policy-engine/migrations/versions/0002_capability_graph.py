"""Add curated graph facts; existing provenance remains declared.

Revision ID: 0002_capability_graph
Revises: 0001_trusted_context
"""

from alembic import op
import sqlalchemy as sa

revision = "0002_capability_graph"
down_revision = "0001_trusted_context"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("pdp_provenance_edges") as batch:
        batch.add_column(
            sa.Column("evidence", sa.String(16), nullable=False, server_default="declared")
        )
        batch.add_column(sa.Column("evidence_ref", sa.String(256)))
        batch.create_check_constraint(
            "ck_provenance_evidence", "evidence IN ('declared', 'observed')"
        )
        batch.create_check_constraint(
            "ck_provenance_observed_ref",
            "evidence <> 'observed' OR (evidence_ref IS NOT NULL AND length(trim(evidence_ref)) > 0)",
        )
    op.create_table(
        "graph_destinations",
        sa.Column("id", sa.String(160), primary_key=True),
        sa.Column("address", sa.String(254), nullable=False, unique=True),
        sa.Column("location", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'INACTIVE', 'REVOKED')", name="ck_graph_destination_status"
        ),
        sa.CheckConstraint(
            "location IN ('INTERNAL', 'EXTERNAL', 'UNKNOWN')", name="ck_graph_destination_location"
        ),
    )
    op.create_table(
        "graph_tool_data_flows",
        sa.Column("id", sa.String(160), primary_key=True),
        sa.Column(
            "permission_id", sa.String(36), sa.ForeignKey("pdp_permissions.id"), nullable=False
        ),
        sa.Column(
            "input_resource_id", sa.String(160), sa.ForeignKey("pdp_resources.id"), nullable=False
        ),
        sa.Column("destination_id", sa.String(160), sa.ForeignKey("graph_destinations.id")),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("verification", sa.String(16), nullable=False),
        sa.Column("assumption", sa.Text),
        sa.Column("evidence_ref", sa.String(256), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'INACTIVE', 'REVOKED')", name="ck_graph_flow_status"
        ),
        sa.CheckConstraint(
            "verification IN ('DECLARED', 'VERIFIED')", name="ck_graph_flow_verification"
        ),
        sa.CheckConstraint(
            "verification <> 'DECLARED' OR (assumption IS NOT NULL AND length(trim(assumption)) > 0)",
            name="ck_graph_flow_assumption",
        ),
        sa.CheckConstraint(
            "verification <> 'VERIFIED' OR verified_at IS NOT NULL",
            name="ck_graph_flow_verified_at",
        ),
        sa.CheckConstraint("length(trim(evidence_ref)) > 0", name="ck_graph_flow_evidence_ref"),
    )
    op.create_index(
        "ix_graph_tool_data_flows_permission_id", "graph_tool_data_flows", ["permission_id"]
    )


def downgrade() -> None:
    op.drop_table("graph_tool_data_flows")
    op.drop_table("graph_destinations")
    with op.batch_alter_table("pdp_provenance_edges") as batch:
        batch.drop_constraint("ck_provenance_observed_ref", type_="check")
        batch.drop_constraint("ck_provenance_evidence", type_="check")
        batch.drop_column("evidence_ref")
        batch.drop_column("evidence")
