"""Add immutable Skills durable receipts and idempotency evidence.

Revision ID: 0007_skills_audit_receipts
Revises: 0006_integrity_key_id
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0007_skills_audit_receipts"
down_revision: str | None = "0006_integrity_key_id"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "skills_audit_receipts",
        sa.Column("event_id", sa.String(length=64), primary_key=True),
        sa.Column("receipt_id", sa.String(length=80), nullable=False, unique=True),
        sa.Column("schema_version", sa.String(length=32), nullable=False),
        sa.Column("organization_id", sa.String(length=255), nullable=False),
        sa.Column("event_digest", sa.String(length=64), nullable=False),
        sa.Column("durable_at", sa.DateTime(), nullable=False),
        sa.Column("sink_partition", sa.String(length=320), nullable=False),
        sa.Column("key_id", sa.String(length=64), nullable=False),
        sa.Column("signature", sa.String(length=128), nullable=False),
    )
    op.create_index(
        "ix_skills_audit_receipts_org_durable_event",
        "skills_audit_receipts",
        ["organization_id", "durable_at", "event_id"],
    )
    if op.get_bind().dialect.name == "mysql":
        op.execute(
            """
            CREATE TRIGGER trg_skills_audit_receipts_no_update
            BEFORE UPDATE ON skills_audit_receipts
            FOR EACH ROW
            BEGIN
                SIGNAL SQLSTATE '45000'
                    SET MESSAGE_TEXT = 'skills_audit_receipts is append-only: UPDATE denied';
            END
            """
        )
        op.execute(
            """
            CREATE TRIGGER trg_skills_audit_receipts_no_delete
            BEFORE DELETE ON skills_audit_receipts
            FOR EACH ROW
            BEGIN
                IF SUBSTRING_INDEX(USER(), '@', 1) != 'audit_maintenance' THEN
                    SIGNAL SQLSTATE '45000'
                        SET MESSAGE_TEXT = 'skills_audit_receipts retention requires audit_maintenance';
                END IF;
                IF EXISTS (
                    SELECT 1 FROM audit_legal_holds h
                    WHERE h.record_key = OLD.event_id
                      AND h.record_table IN ('audit_events', 'skills_audit_receipts')
                ) THEN
                    SIGNAL SQLSTATE '45000'
                        SET MESSAGE_TEXT = 'skills_audit_receipts legal hold prevents DELETE';
                END IF;
            END
            """
        )


def downgrade() -> None:
    bind = op.get_bind()
    present = bind.execute(
        sa.text("SELECT 1 FROM skills_audit_receipts LIMIT 1")
    ).first()
    if present:
        raise RuntimeError("cannot downgrade while durable Skills receipts exist")
    if bind.dialect.name == "mysql":
        op.execute("DROP TRIGGER IF EXISTS trg_skills_audit_receipts_no_delete")
        op.execute("DROP TRIGGER IF EXISTS trg_skills_audit_receipts_no_update")
    op.drop_index(
        "ix_skills_audit_receipts_org_durable_event",
        table_name="skills_audit_receipts",
    )
    op.drop_table("skills_audit_receipts")
