"""V2-003 (Track E3): retention/immutability foundation

Adds:
  - audit_events.record_integrity_hash
  - quarantined_audit_events.record_integrity_hash
  - audit_legal_holds (new table -- see db/models.py::AuditLegalHold)
  - trg_audit_events_no_update / trg_audit_events_no_delete
  - trg_quarantined_audit_events_no_update / trg_quarantined_audit_events_no_delete
  - trg_audit_legal_holds_no_update

Triggers implement database-level append-only enforcement:

  - audit_events / quarantined_audit_events: UPDATE is rejected for
    EVERY identity, no exceptions -- these tables never carry a mutable
    "held" flag (legal hold is a separate, existence-based reference
    table instead, so no UPDATE exception was ever needed on the
    canonical/quarantine tables themselves). DELETE is rejected unless
    the connecting identity's username (not full account) is exactly
    'audit_maintenance' (the restricted role
    scripts/provision_audit_db_users.py creates for retention cleanup),
    AND is rejected even for that identity if a matching row exists in
    audit_legal_holds.

    Identity is checked via `SUBSTRING_INDEX(USER(), '@', 1)`, NOT
    `CURRENT_USER()` -- verified empirically (not just assumed) against
    a real MySQL 8.0 server before shipping this: MySQL triggers always
    execute in the trigger's DEFINER security context (there is no `SQL
    SECURITY INVOKER` option for triggers, unlike stored
    procedures/functions/views), so `CURRENT_USER()` inside a trigger
    body returns the trigger's DEFINER (root, since these are created
    by whatever ran this migration) on every single invocation,
    regardless of who actually issued the DELETE. A first draft of this
    migration used `CURRENT_USER() != 'audit_maintenance@%'` and it
    silently made deletion impossible for EVERYONE, including the
    legitimate audit_maintenance identity -- caught only by actually
    connecting as that user and confirming a real DELETE was rejected,
    not by reading the trigger body. `USER()`, by contrast, reflects
    the actual connecting/invoking account even inside a DEFINER-
    context trigger; only its host portion varies with the client's
    network path (e.g. a Docker bridge IP), which is why only the
    username portion is compared, not the full `user@host` string.

  - audit_legal_holds: UPDATE is always rejected (a hold record's
    identity/reason should never be silently altered -- release a hold
    by deleting the row, not editing it). INSERT is unrestricted at the
    trigger level (privilege-gated instead -- see
    scripts/provision_audit_db_users.py: only audit_maintenance is
    granted INSERT on this table). DELETE (releasing a hold) is
    likewise privilege-gated, not trigger-gated, since releasing a hold
    is itself meant to be an ordinary, if privileged, maintenance
    action, not something requiring a second layer of trigger logic.

This intentionally does NOT exempt root/administrative connections from
the DELETE-identity check -- an ordinary or accidental root DELETE is
stopped by the trigger; only a deliberate `DROP TRIGGER` first can
bypass it, a materially different and much harder-to-do-by-accident
action. See
omnibioai-docs/security/hipaa_v2_003_audit_retention_immutability_evidence.md
for the full threat model, including the honest limit: a fully
privileged DBA who deliberately drops these triggers is not stopped by
anything in this migration -- that is a higher threat tier
database-internal controls cannot fully close, only raise the bar
against.

Trigger bodies are plain SQL (op.execute), not something Alembic's
declarative helpers model -- MySQL trigger DDL has no portable
SQLAlchemy Core construct.

Revision ID: 0005_retention_immutability
Revises: 0004_quarantined_audit_events
Create Date: 2026-09-16

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0005_retention_immutability"
down_revision: str | None = "0004_quarantined_audit_events"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_MAINTENANCE_USER = "audit_maintenance"


def upgrade() -> None:
    op.add_column("audit_events", sa.Column("record_integrity_hash", sa.String(length=64), nullable=True))
    op.add_column(
        "quarantined_audit_events", sa.Column("record_integrity_hash", sa.String(length=64), nullable=True),
    )

    op.create_table(
        "audit_legal_holds",
        sa.Column("record_table", sa.String(length=32), primary_key=True),
        sa.Column("record_key", sa.String(length=64), primary_key=True),
        sa.Column("held_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("held_by", sa.String(length=255), nullable=True),
        sa.Column("reason", sa.String(length=255), nullable=True),
    )

    # MySQL-only from here: SIGNAL/SQLSTATE/CURRENT_USER() trigger
    # bodies have no SQLite equivalent, and this repo's own migration
    # tests (tests/test_migrations.py) deliberately run against a
    # throwaway SQLite database to exercise portable schema mechanics
    # quickly, "never against a real MySQL instance" (that file's own
    # docstring) -- so this step must be skipped there, not fail there.
    # Production/dev/CI-integration all run real MySQL, where these
    # triggers are the actual point of this migration.
    if op.get_bind().dialect.name != "mysql":
        return

    op.execute("""
        CREATE TRIGGER trg_audit_events_no_update
        BEFORE UPDATE ON audit_events
        FOR EACH ROW
        BEGIN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'audit_events is append-only: UPDATE denied by trigger';
        END
    """)
    op.execute(f"""
        CREATE TRIGGER trg_audit_events_no_delete
        BEFORE DELETE ON audit_events
        FOR EACH ROW
        BEGIN
            IF SUBSTRING_INDEX(USER(), '@', 1) != '{_MAINTENANCE_USER}' THEN
                SIGNAL SQLSTATE '45000'
                    SET MESSAGE_TEXT = 'audit_events delete requires the audit_maintenance identity';
            END IF;
            IF EXISTS (
                SELECT 1 FROM audit_legal_holds
                WHERE record_table = 'audit_events' AND record_key = OLD.event_id
            ) THEN
                SIGNAL SQLSTATE '45000'
                    SET MESSAGE_TEXT = 'audit_events row is under legal hold, delete denied';
            END IF;
        END
    """)
    op.execute("""
        CREATE TRIGGER trg_quarantined_audit_events_no_update
        BEFORE UPDATE ON quarantined_audit_events
        FOR EACH ROW
        BEGIN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'quarantined_audit_events is append-only: UPDATE denied by trigger';
        END
    """)
    op.execute(f"""
        CREATE TRIGGER trg_quarantined_audit_events_no_delete
        BEFORE DELETE ON quarantined_audit_events
        FOR EACH ROW
        BEGIN
            IF SUBSTRING_INDEX(USER(), '@', 1) != '{_MAINTENANCE_USER}' THEN
                SIGNAL SQLSTATE '45000'
                    SET MESSAGE_TEXT = 'quarantined_audit_events delete requires the audit_maintenance identity';
            END IF;
            IF EXISTS (
                SELECT 1 FROM audit_legal_holds
                WHERE record_table = 'quarantined_audit_events' AND record_key = OLD.stream_message_id
            ) THEN
                SIGNAL SQLSTATE '45000'
                    SET MESSAGE_TEXT = 'quarantined_audit_events row is under legal hold, delete denied';
            END IF;
        END
    """)
    op.execute("""
        CREATE TRIGGER trg_audit_legal_holds_no_update
        BEFORE UPDATE ON audit_legal_holds
        FOR EACH ROW
        BEGIN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'audit_legal_holds is append-only: UPDATE denied by trigger -- delete and re-insert instead';
        END
    """)


def downgrade() -> None:
    if op.get_bind().dialect.name == "mysql":
        op.execute("DROP TRIGGER IF EXISTS trg_audit_legal_holds_no_update")
        op.execute("DROP TRIGGER IF EXISTS trg_quarantined_audit_events_no_delete")
        op.execute("DROP TRIGGER IF EXISTS trg_quarantined_audit_events_no_update")
        op.execute("DROP TRIGGER IF EXISTS trg_audit_events_no_delete")
        op.execute("DROP TRIGGER IF EXISTS trg_audit_events_no_update")
    op.drop_table("audit_legal_holds")
    op.drop_column("quarantined_audit_events", "record_integrity_hash")
    op.drop_column("audit_events", "record_integrity_hash")
