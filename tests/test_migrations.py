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
