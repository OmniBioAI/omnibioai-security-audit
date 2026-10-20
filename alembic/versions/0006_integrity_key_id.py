"""Persist the key identifier used for stored-record integrity HMACs.

Revision ID: 0006_integrity_key_id
Revises: 0005_retention_immutability

The nullable columns are additive. Existing rows remain byte-for-byte
unchanged; NULL explicitly means legacy key selection, never "verified".
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_integrity_key_id"
down_revision: str | None = "0005_retention_immutability"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("audit_events", sa.Column("integrity_key_id", sa.String(length=64), nullable=True))
    op.add_column(
        "quarantined_audit_events",
        sa.Column("integrity_key_id", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    # Preserve verifiability: refuse to discard key IDs once any v2 row exists.
    bind = op.get_bind()
    for table in ("audit_events", "quarantined_audit_events"):
        present = bind.execute(
            sa.text(f"SELECT 1 FROM {table} WHERE integrity_key_id IS NOT NULL LIMIT 1")
        ).first()
        if present:
            raise RuntimeError(f"cannot downgrade while {table} contains versioned integrity records")
    op.drop_column("quarantined_audit_events", "integrity_key_id")
    op.drop_column("audit_events", "integrity_key_id")
