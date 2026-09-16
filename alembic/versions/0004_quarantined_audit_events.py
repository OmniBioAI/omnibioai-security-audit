"""add quarantined_audit_events table (HIPAA-V2-002 durable poison handling)

Track E2: previously, a Redis Streams entry that exceeded
AuditConfig.PEL_MAX_DELIVERIES was ACKed and discarded with only a
print() (StreamReader.claim_stale -> worker/main.py::sweep_pending) --
no durable evidence of the loss. This table gives poison entries a
durable home, written BEFORE the original stream entry is acked (see
worker/main.py::quarantine_and_ack), so a persistence failure during
quarantine itself leaves the original message pending/retryable rather
than silently gone.

Revision ID: 0004_quarantined_audit_events
Revises: 0003_tenant_contract
Create Date: 2026-09-16

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0004_quarantined_audit_events"
down_revision: str | None = "0003_tenant_contract"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "quarantined_audit_events",
        sa.Column("stream_message_id", sa.String(length=64), primary_key=True),
        sa.Column("raw_data", sa.Text(), nullable=True),
        sa.Column("raw_signature", sa.Text(), nullable=True),
        sa.Column("service", sa.String(length=255), nullable=True),
        sa.Column("failure_category", sa.String(length=32), nullable=False),
        sa.Column("failure_detail", sa.String(length=255), nullable=True),
        sa.Column("delivery_attempts", sa.Integer(), nullable=False),
        sa.Column("quarantined_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("quarantined_audit_events")
