"""Unit tests for scripts/audit_retention_cleanup.py -- V2-003 (Track E3)
authorized retention cleanup. _count_eligible/_delete_eligible and the
end-to-end main() flow are exercised against a real (SQLite) engine,
same "real DB over mocks where practical" convention as
tests/test_audit_query_service.py -- the raw text() SQL this script
uses is portable to SQLite (confirmed: NOT EXISTS correlated subqueries
work identically). A "partial delete" (expected != actual) is the one
case a real DB can't produce on demand (it would need a genuinely
concurrent writer); that single scenario monkeypatches _delete_eligible
instead.

Developer: Manish Kumar <manish@omnibioai.org>
"""
from __future__ import annotations

import runpy
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text

import db.models  # noqa: F401 -- registers audit_events/quarantined_audit_events/audit_legal_holds on Base.metadata
import scripts.audit_retention_cleanup as arc
from db.base import Base


@pytest.fixture
def sqlite_url(monkeypatch, tmp_path):
    """A file-backed SQLite DB (not :memory:) so every `engine.connect()` in main() sees the same
    schema/data -- an in-memory SQLite DB is per-connection and would look empty on the second
    connection main() opens."""
    db_path = tmp_path / "retention_test.db"
    url = f"sqlite:///{db_path}"
    engine = create_engine(url)
    Base.metadata.create_all(bind=engine)
    engine.dispose()
    return url


def _insert_audit_event(engine, event_id, days_old):
    ts = datetime.now(timezone.utc) - timedelta(days=days_old)
    with engine.connect() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_events (event_id, timestamp, service, event_type, action, "
                "tenant_scope, context, integrity_status) VALUES "
                "(:e, :t, 's', 'et', 'a', 'unknown', '{}', 'unsigned')"
            ),
            {"e": event_id, "t": ts},
        )
        conn.commit()


def _insert_quarantine_event(engine, message_id, days_old):
    ts = datetime.now(timezone.utc) - timedelta(days=days_old)
    with engine.connect() as conn:
        conn.execute(
            text(
                "INSERT INTO quarantined_audit_events (stream_message_id, failure_category, "
                "delivery_attempts, quarantined_at) VALUES (:m, 'malformed', 1, :t)"
            ),
            {"m": message_id, "t": ts},
        )
        conn.commit()


def _add_legal_hold(engine, table, key):
    with engine.connect() as conn:
        conn.execute(
            text("INSERT INTO audit_legal_holds (record_table, record_key) VALUES (:t, :k)"),
            {"t": table, "k": key},
        )
        conn.commit()


# ---------------------------------------------------------------------------
# _cutoff
# ---------------------------------------------------------------------------


def test_cutoff_is_retention_days_before_now():
    """Compute a cutoff exactly retention_days in the past."""
    before = datetime.now(timezone.utc) - timedelta(days=90)
    cutoff = arc._cutoff(90)
    after = datetime.now(timezone.utc) - timedelta(days=90)
    assert before <= cutoff <= after


# ---------------------------------------------------------------------------
# _count_eligible / _delete_eligible
# ---------------------------------------------------------------------------


def test_count_eligible_excludes_rows_under_a_legal_hold(sqlite_url):
    """Exclude a row from the eligible count when it has a matching legal hold, even though it's
    past the cutoff."""
    engine = create_engine(sqlite_url)
    _insert_audit_event(engine, "e-old", days_old=200)
    _insert_audit_event(engine, "e-held", days_old=200)
    _add_legal_hold(engine, "audit_events", "e-held")
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)

    with engine.connect() as conn:
        count = arc._count_eligible(conn, "audit_events", "event_id", "timestamp", cutoff)

    assert count == 1


def test_delete_eligible_deletes_only_unheld_rows_past_cutoff(sqlite_url):
    """Delete only the rows past cutoff without a legal hold, leaving recent and held rows intact."""
    engine = create_engine(sqlite_url)
    _insert_audit_event(engine, "e-old", days_old=200)
    _insert_audit_event(engine, "e-held", days_old=200)
    _insert_audit_event(engine, "e-recent", days_old=1)
    _add_legal_hold(engine, "audit_events", "e-held")
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)

    with engine.connect() as conn:
        deleted = arc._delete_eligible(conn, "audit_events", "event_id", "timestamp", cutoff)
        conn.commit()

    assert deleted == 1
    with engine.connect() as conn:
        remaining = {row[0] for row in conn.execute(text("SELECT event_id FROM audit_events"))}
    assert remaining == {"e-held", "e-recent"}


# ---------------------------------------------------------------------------
# _write_status_file
# ---------------------------------------------------------------------------


def test_write_status_file_is_a_no_op_when_unconfigured(monkeypatch, tmp_path):
    """Write nothing when AUDIT_HEALTH_STATUS_DIR is unset."""
    monkeypatch.delenv("AUDIT_HEALTH_STATUS_DIR", raising=False)
    arc._write_status_file("dry_run", True, {})
    assert list(tmp_path.iterdir()) == []


def test_write_status_file_sums_only_successful_deletions(monkeypatch, tmp_path):
    """Sum only tables with status 'success' into the total-deleted figure, ignoring dry_run/failed/
    partial entries."""
    monkeypatch.setenv("AUDIT_HEALTH_STATUS_DIR", str(tmp_path))
    results = {
        "audit_events": {"status": "success", "count": 7},
        "quarantined_audit_events": {"status": "dry_run", "count": 999},
    }

    arc._write_status_file("execute", True, results)

    content = (tmp_path / "audit-retention-run.env").read_text()
    assert "LAST_RETENTION_RUN_MODE=execute" in content
    assert "LAST_RETENTION_RUN_RESULT=success" in content
    assert "LAST_RETENTION_RUN_DELETED_TOTAL=7" in content


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


def test_main_rejects_dry_run_and_execute_together(capsys):
    """Exit 2 (argparse usage error) when --dry-run and --execute are both given."""
    with pytest.raises(SystemExit) as exc_info:
        arc.main(["--dry-run", "--execute"])
    assert exc_info.value.code == 2
    assert "mutually exclusive" in capsys.readouterr().err


def test_main_is_a_successful_noop_when_retention_days_unset(monkeypatch, capsys):
    """Exit 0 and do nothing when AUDIT_RETENTION_DAYS is not configured."""
    monkeypatch.delenv("AUDIT_RETENTION_DAYS", raising=False)
    exit_code = arc.main([])
    assert exit_code == 0
    assert "retention is not yet configured" in capsys.readouterr().out


@pytest.mark.parametrize("bad_value", ["not-a-number", "0", "-5"])
def test_main_rejects_invalid_retention_days(monkeypatch, capsys, bad_value):
    """Exit 1 for a non-positive-integer AUDIT_RETENTION_DAYS."""
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", bad_value)
    exit_code = arc.main([])
    assert exit_code == 1
    assert "must be a positive integer" in capsys.readouterr().err


def test_main_requires_maintenance_database_url(monkeypatch, capsys):
    """Exit 1 when AUDIT_MAINTENANCE_DATABASE_URL is unset, even with a valid retention period."""
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "90")
    monkeypatch.delenv("AUDIT_MAINTENANCE_DATABASE_URL", raising=False)
    exit_code = arc.main([])
    assert exit_code == 1
    assert "AUDIT_MAINTENANCE_DATABASE_URL must be set" in capsys.readouterr().err


def test_main_dry_run_reports_without_deleting(monkeypatch, sqlite_url, capsys):
    """Report eligible counts and delete nothing in dry-run (default) mode."""
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "90")
    monkeypatch.setenv("AUDIT_MAINTENANCE_DATABASE_URL", sqlite_url)
    engine = create_engine(sqlite_url)
    _insert_audit_event(engine, "e-old", days_old=200)

    exit_code = arc.main([])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "DRY-RUN" in out
    assert "1 row(s) would be deleted" in out
    with engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM audit_events")).scalar() == 1


def test_main_execute_deletes_eligible_rows_from_both_tables(monkeypatch, sqlite_url, capsys):
    """Delete eligible rows from both tables and report success when --execute is passed."""
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "90")
    monkeypatch.setenv("AUDIT_MAINTENANCE_DATABASE_URL", sqlite_url)
    engine = create_engine(sqlite_url)
    _insert_audit_event(engine, "e-old", days_old=200)
    _insert_quarantine_event(engine, "q-old", days_old=200)

    exit_code = arc.main(["--execute"])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "audit_events: deleted 1 row(s)" in out
    assert "quarantined_audit_events: deleted 1 row(s)" in out
    with engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM audit_events")).scalar() == 0
        assert conn.execute(text("SELECT COUNT(*) FROM quarantined_audit_events")).scalar() == 0


def test_main_execute_with_nothing_eligible_reports_zero_deleted(monkeypatch, sqlite_url, capsys):
    """Report a clean zero-deleted success when nothing is past the cutoff."""
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "90")
    monkeypatch.setenv("AUDIT_MAINTENANCE_DATABASE_URL", sqlite_url)
    create_engine(sqlite_url)  # ensures schema exists via the sqlite_url fixture

    exit_code = arc.main(["--execute"])

    assert exit_code == 0
    assert "0 rows eligible, nothing to delete" in capsys.readouterr().out


def test_main_explicit_dry_run_flag_behaves_like_the_default(monkeypatch, sqlite_url):
    """Behave identically whether --dry-run is passed explicitly or omitted."""
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "90")
    monkeypatch.setenv("AUDIT_MAINTENANCE_DATABASE_URL", sqlite_url)
    assert arc.main(["--dry-run"]) == 0


def test_main_reports_partial_result_and_emits_warning_alert_on_mismatch(monkeypatch, sqlite_url, capsys):
    """Treat a deleted-count that doesn't match the eligible-count as a partial result: overall
    failure, warning-severity alert (no table outright failed), never silently upgraded to
    success."""
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "90")
    monkeypatch.setenv("AUDIT_MAINTENANCE_DATABASE_URL", sqlite_url)
    engine = create_engine(sqlite_url)
    _insert_audit_event(engine, "e-old", days_old=200)
    alerts = []
    monkeypatch.setattr(arc, "emit_security_alert", lambda **kwargs: alerts.append(kwargs))
    monkeypatch.setattr(arc, "_delete_eligible", lambda *a, **k: 0)  # claims to delete 0 of the 1 eligible row

    exit_code = arc.main(["--execute"])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "treat as a partial result" in captured.out
    assert "[FAIL] retention run completed with partial/failed results" in captured.err
    assert len(alerts) == 1
    assert alerts[0]["condition"] == "retention_cleanup_failed"
    assert alerts[0]["severity"] == "warning"


def test_main_reports_failed_table_and_emits_critical_alert_on_exception(monkeypatch, capsys):
    """Report a table as failed (not partial) and emit a critical alert when the table's operation
    raises outright, e.g. an unreachable/misconfigured database."""
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "90")
    monkeypatch.setenv("AUDIT_MAINTENANCE_DATABASE_URL", "sqlite:////nonexistent-dir/does-not-exist.db")
    alerts = []
    monkeypatch.setattr(arc, "emit_security_alert", lambda **kwargs: alerts.append(kwargs))

    exit_code = arc.main(["--execute"])

    assert exit_code == 1
    err = capsys.readouterr().err
    assert "retention operation failed" in err
    assert len(alerts) == 1
    assert alerts[0]["condition"] == "retention_cleanup_failed"
    assert alerts[0]["severity"] == "critical"


def test_main_writes_status_file_when_configured(monkeypatch, sqlite_url, tmp_path):
    """Write the operational status file as part of a normal main() run when AUDIT_HEALTH_STATUS_DIR
    is configured."""
    status_dir = tmp_path / "status"
    status_dir.mkdir()
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "90")
    monkeypatch.setenv("AUDIT_MAINTENANCE_DATABASE_URL", sqlite_url)
    monkeypatch.setenv("AUDIT_HEALTH_STATUS_DIR", str(status_dir))

    exit_code = arc.main(["--execute"])

    assert exit_code == 0
    assert (status_dir / "audit-retention-run.env").exists()


# ---------------------------------------------------------------------------
# __main__ guard
# ---------------------------------------------------------------------------


def test_dunder_main_exits_with_mains_return_code(monkeypatch):
    """Exit with main()'s own return code when run as a script."""
    import sys

    monkeypatch.setattr(sys, "argv", ["audit_retention_cleanup.py"])
    monkeypatch.delenv("AUDIT_RETENTION_DAYS", raising=False)  # cheapest deterministic path: the no-op-return-0 branch

    with pytest.raises(SystemExit) as exc_info:
        runpy.run_path(arc.__file__, run_name="__main__")

    assert exc_info.value.code == 0
