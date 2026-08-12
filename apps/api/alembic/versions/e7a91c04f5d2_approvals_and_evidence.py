"""approvals and evidence: approvals table, correlators, redaction fields

Revision ID: e7a91c04f5d2
Revises: c41f8a72d3be
Create Date: 2026-08-12 18:00:00.000000

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "e7a91c04f5d2"
down_revision = "c41f8a72d3be"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("role", sa.String(length=50), nullable=True))
    op.add_column(
        "tools",
        sa.Column(
            "sensitive_fields",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )

    op.add_column("action_requests", sa.Column("trace_id", sa.Uuid(), nullable=True))
    op.create_index(
        op.f("ix_action_requests_trace_id"), "action_requests", ["trace_id"], unique=False
    )
    op.add_column(
        "action_requests",
        sa.Column(
            "content_mode",
            sa.String(length=20),
            nullable=False,
            server_default="metadata_only",
        ),
    )
    op.add_column(
        "action_requests",
        sa.Column(
            "redacted_fields",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )

    # Lifecycle events (approval, execution) carry no verdict.
    op.alter_column("events", "verdict", existing_type=sa.String(length=20), nullable=True)
    op.add_column(
        "events", sa.Column("detail", postgresql.JSONB(astext_type=sa.Text()), nullable=True)
    )

    op.create_table(
        "approvals",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("action_request_id", sa.Uuid(), nullable=False),
        sa.Column("request_id", sa.Uuid(), nullable=False),
        sa.Column("trace_id", sa.Uuid(), nullable=True),
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("canonical_hash", sa.String(length=64), nullable=False),
        sa.Column("tool_name", sa.String(length=200), nullable=False),
        sa.Column("environment", sa.String(length=50), nullable=False),
        sa.Column("agent_version", sa.String(length=100), nullable=False),
        sa.Column("policy_version", sa.String(length=100), nullable=False),
        sa.Column("approver_role", sa.String(length=50), nullable=False),
        sa.Column("requester_user_id", sa.Uuid(), nullable=True),
        sa.Column("args_preview", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("redacted_fields", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("reason_codes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("matched_rules", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_by", sa.Uuid(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "state IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'CONSUMED', 'VOIDED')",
            name=op.f("ck_approvals_state"),
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], name=op.f("fk_approvals_org_id_organizations")
        ),
        sa.ForeignKeyConstraint(
            ["action_request_id"],
            ["action_requests.id"],
            name=op.f("fk_approvals_action_request_id_action_requests"),
        ),
        sa.ForeignKeyConstraint(
            ["session_id"], ["sessions.id"], name=op.f("fk_approvals_session_id_sessions")
        ),
        sa.ForeignKeyConstraint(
            ["requester_user_id"],
            ["users.id"],
            name=op.f("fk_approvals_requester_user_id_users"),
        ),
        sa.ForeignKeyConstraint(
            ["decided_by"], ["users.id"], name=op.f("fk_approvals_decided_by_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_approvals")),
    )
    op.create_index(
        op.f("ix_approvals_canonical_hash"), "approvals", ["canonical_hash"], unique=False
    )
    # At most one live PENDING approval per exact request binding — the
    # database enforces it even under concurrent resolve calls.
    op.create_index(
        "uq_approvals_one_pending",
        "approvals",
        ["org_id", "canonical_hash", "session_id"],
        unique=True,
        postgresql_where=sa.text("state = 'PENDING'"),
    )


def downgrade() -> None:
    op.drop_index("uq_approvals_one_pending", table_name="approvals")
    op.drop_index(op.f("ix_approvals_canonical_hash"), table_name="approvals")
    op.drop_table("approvals")
    op.drop_column("events", "detail")
    op.execute("DELETE FROM events WHERE verdict IS NULL")
    op.alter_column("events", "verdict", existing_type=sa.String(length=20), nullable=False)
    op.drop_column("action_requests", "redacted_fields")
    op.drop_column("action_requests", "content_mode")
    op.drop_index(op.f("ix_action_requests_trace_id"), table_name="action_requests")
    op.drop_column("action_requests", "trace_id")
    op.drop_column("tools", "sensitive_fields")
    op.drop_column("users", "role")
