"""add integrity_status to audit_events

PR2 of the audit:events integrity remediation (see audit/signing.py, PR1;
consumers/processor.py::classify_event_integrity, this PR). Adds one
column recording whether the worker was able to cryptographically verify
each event at ingest time: "valid", "invalid", or "unsigned".

server_default="unsigned" back-fills every existing row automatically on
this ALTER -- no manual UPDATE, no backfill script. That default is
correct for pre-existing rows: they predate signing entirely, so
"unsigned" is not a guess, it's simply true.

Revision ID: 0002_integrity_status
Revises: 0001_audit_events
Create Date: 2026-08-14

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0002_integrity_status"
down_revision: Union[str, None] = "0001_audit_events"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "audit_events",
        sa.Column(
            "integrity_status",
            sa.String(length=16),
            nullable=False,
            server_default="unsigned",
        ),
    )


def downgrade() -> None:
    op.drop_column("audit_events", "integrity_status")
