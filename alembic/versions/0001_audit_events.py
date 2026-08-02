"""create audit_events table

PR4.2: durable persistence for the audit pipeline. event_id is the primary
key (not a surrogate id) so a duplicate insert -- e.g. a worker re-processing
an unacked Redis message after a crash -- fails on the PK constraint instead
of silently creating a second row for the same event. See
consumers/sink.py for how the worker relies on that.

Revision ID: 0001_audit_events
Revises:
Create Date: 2026-08-01

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0001_audit_events"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("event_id", sa.String(length=64), primary_key=True),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("service", sa.String(length=255), nullable=False),
        sa.Column("event_type", sa.String(length=255), nullable=False),
        sa.Column("user_id", sa.String(length=255), nullable=True),
        sa.Column("action", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("resource", sa.String(length=255), nullable=True),
        sa.Column("decision", sa.String(length=64), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("trace_id", sa.String(length=255), nullable=True),
        sa.Column("context", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("audit_events")
