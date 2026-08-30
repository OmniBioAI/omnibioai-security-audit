"""add first-class tenant provenance to audit_events

SAT-1: organization_id is nullable for backward compatibility. Existing
rows are explicitly classified as unknown, never global. Producers may mark
an event organization-scoped or explicitly global in tenant_scope.
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0003_tenant_contract"
down_revision: str | None = "0002_integrity_status"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("audit_events", sa.Column("organization_id", sa.String(length=255), nullable=True))
    op.add_column(
        "audit_events",
        sa.Column("tenant_scope", sa.String(length=16), nullable=False, server_default="unknown"),
    )
    op.create_index(
        "ix_audit_events_org_timestamp_event",
        "audit_events",
        ["organization_id", "timestamp", "event_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_audit_events_org_timestamp_event", table_name="audit_events")
    op.drop_column("audit_events", "tenant_scope")
    op.drop_column("audit_events", "organization_id")
