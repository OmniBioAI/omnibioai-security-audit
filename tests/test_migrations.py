"""PR4.2: Alembic migration mechanics for the audit_events table, exercised
against an isolated throwaway SQLite database -- never against a real
MySQL instance. Mirrors omnibioai-auth/tests/test_migrations.py's pattern.
"""
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

REPO_ROOT = Path(__file__).resolve().parent.parent

EXPECTED_COLUMNS = {
    "event_id", "timestamp", "service", "event_type", "user_id", "action",
    "resource", "decision", "reason", "trace_id", "context", "created_at",
    "integrity_status",
    "organization_id", "tenant_scope",
}


def _alembic_config(db_url: str) -> Config:
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    # env.py only falls back to AuditConfig.DATABASE_URL when this is unset
    # -- setting it here points migrations at the throwaway test DB instead
    # of whatever AUDIT_DATABASE_URL resolves to in this environment.
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def test_upgrade_head_creates_audit_events_table(tmp_path):
    db_file = tmp_path / "migration_test.db"
    db_url = f"sqlite:///{db_file}"

    cfg = _alembic_config(db_url)
    command.upgrade(cfg, "head")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    assert "audit_events" in inspector.get_table_names()

    columns = {c["name"] for c in inspector.get_columns("audit_events")}
    assert EXPECTED_COLUMNS <= columns


def test_audit_events_event_id_is_primary_key(tmp_path):
    db_file = tmp_path / "migration_test.db"
    db_url = f"sqlite:///{db_file}"

    cfg = _alembic_config(db_url)
    command.upgrade(cfg, "head")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    pk = inspector.get_pk_constraint("audit_events")
    assert pk["constrained_columns"] == ["event_id"]


def test_downgrade_drops_audit_events_table(tmp_path):
    db_file = tmp_path / "migration_test.db"
    db_url = f"sqlite:///{db_file}"

    cfg = _alembic_config(db_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    assert "audit_events" not in inspector.get_table_names()


# ---------------------------------------------------------------------------
# PR2: 0002_integrity_status
# ---------------------------------------------------------------------------

def test_integrity_status_column_exists_after_upgrade(tmp_path):
    db_file = tmp_path / "migration_test.db"
    db_url = f"sqlite:///{db_file}"

    cfg = _alembic_config(db_url)
    command.upgrade(cfg, "head")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    columns = {c["name"]: c for c in inspector.get_columns("audit_events")}
    assert "integrity_status" in columns
    assert columns["integrity_status"]["nullable"] is False


def test_tenant_columns_and_query_index_exist_after_upgrade(tmp_path):
    db_file = tmp_path / "migration_test.db"
    cfg = _alembic_config(f"sqlite:///{db_file}")
    command.upgrade(cfg, "head")
    engine = create_engine(f"sqlite:///{db_file}")
    inspector = inspect(engine)
    columns = {c["name"]: c for c in inspector.get_columns("audit_events")}
    assert columns["organization_id"]["nullable"] is True
    assert columns["tenant_scope"]["nullable"] is False
    indexes = {i["name"] for i in inspector.get_indexes("audit_events")}
    assert "ix_audit_events_org_timestamp_event" in indexes


def test_legacy_rows_are_unknown_after_tenant_migration(tmp_path):
    db_file = tmp_path / "migration_test.db"
    cfg = _alembic_config(f"sqlite:///{db_file}")
    command.upgrade(cfg, "0002_integrity_status")
    engine = create_engine(f"sqlite:///{db_file}")
    with engine.begin() as conn:
        from sqlalchemy import text
        conn.execute(text("INSERT INTO audit_events (event_id, timestamp, service, event_type, action, context) VALUES ('legacy', '2026-01-01 00:00:00', 'svc', 'test', '', '{}')"))
    command.upgrade(cfg, "head")
    with engine.begin() as conn:
        from sqlalchemy import text
        row = conn.execute(text("SELECT organization_id, tenant_scope FROM audit_events WHERE event_id='legacy'")).fetchone()
    assert row == (None, "unknown")


def test_existing_rows_backfill_to_unsigned_on_upgrade(tmp_path):
    """The exact PR2 migration guarantee: a row written under 0001 (before
    integrity_status existed at all) must read back as "unsigned" after
    upgrading to head -- via the column's own server_default, not a
    manual backfill script."""
    db_file = tmp_path / "migration_test.db"
    db_url = f"sqlite:///{db_file}"

    cfg = _alembic_config(db_url)
    command.upgrade(cfg, "0001_audit_events")

    engine = create_engine(db_url)
    with engine.begin() as conn:
        from sqlalchemy import text

        conn.execute(
            text(
                "INSERT INTO audit_events "
                "(event_id, timestamp, service, event_type, action, context) "
                "VALUES ('pre-0002-evt', '2026-01-01 00:00:00', 'svc', 'test', '', '{}')"
            )
        )

    command.upgrade(cfg, "head")

    with engine.begin() as conn:
        from sqlalchemy import text

        row = conn.execute(
            text("SELECT integrity_status FROM audit_events WHERE event_id = 'pre-0002-evt'")
        ).fetchone()
    assert row is not None
    assert row[0] == "unsigned"


def test_downgrade_to_0001_removes_integrity_status_column_only(tmp_path):
    """Distinct from test_downgrade_drops_audit_events_table above (which
    downgrades all the way to "base", dropping the whole table) -- this
    downgrades exactly one revision, proving 0002's own downgrade() drops
    only the column it added, leaving the table and 0001's columns intact."""
    db_file = tmp_path / "migration_test.db"
    db_url = f"sqlite:///{db_file}"

    cfg = _alembic_config(db_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "0001_audit_events")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    assert "audit_events" in inspector.get_table_names()
    columns = {c["name"] for c in inspector.get_columns("audit_events")}
    assert "integrity_status" not in columns
    assert "event_id" in columns  # 0001's own columns untouched
