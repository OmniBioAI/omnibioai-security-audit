"""Unit tests for scripts/verify_audit_integrity.py -- V2-003 (Track E3)
read-only stored-record integrity verification.

verify_audit_events/verify_quarantine_records/_report/_write_status_file
are exercised against a real (SQLite) db_session, same convention as
tests/test_audit_query_service.py. Duplicate-primary-key detection is the
one case a real DB can never produce (event_id/stream_message_id are
literal primary keys) -- those two tests use a minimal fake session
whose `.query(Model).yield_per(n)` returns hand-built rows instead.

Developer: Manish Kumar <manish@omnibioai.org>
"""
from __future__ import annotations

import runpy
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import scripts.verify_audit_integrity as vai
from audit.record_integrity import (
    compute_audit_event_hash,
    compute_quarantine_record_hash,
)
from db.models import AuditEventRecord, QuarantinedAuditEvent

SECRET = "test-secret-value"


def _audit_fields(**overrides):
    fields = {
        "event_id": "evt-1",
        "timestamp": datetime(2026, 9, 16, 12, 0, 0),  # noqa: DTZ001 -- naive column, matches AuditEventRecord.timestamp convention
        "service": "test",
        "event_type": "test",
        "user_id": None,
        "organization_id": None,
        "tenant_scope": "unknown",
        "action": "login",
        "resource": None,
        "decision": None,
        "reason": None,
        "trace_id": None,
        "context": {},
        "integrity_status": "unsigned",
    }
    fields.update(overrides)
    return fields


def _add_audit_row(db_session, hash_mode="valid", **overrides):
    """Insert an AuditEventRecord. hash_mode is 'valid' (correct hash), 'tampered' (wrong hash), or
    'none' (no baseline hash at all)."""
    fields = _audit_fields(**overrides)
    if hash_mode == "valid":
        record_integrity_hash = compute_audit_event_hash(fields, SECRET)
    elif hash_mode == "tampered":
        record_integrity_hash = "0" * 64
    else:
        record_integrity_hash = None
    row = AuditEventRecord(**fields, record_integrity_hash=record_integrity_hash)
    db_session.add(row)
    return row


def _quarantine_fields(**overrides):
    fields = {
        "stream_message_id": "1-0",
        "raw_data": '{"service":"test"}',
        "raw_signature": None,
        "service": "test",
        "failure_category": "malformed",
        "failure_detail": "JSONDecodeError",
        "delivery_attempts": 5,
    }
    fields.update(overrides)
    return fields


def _add_quarantine_row(db_session, hash_mode="valid", **overrides):
    fields = _quarantine_fields(**overrides)
    if hash_mode == "valid":
        record_integrity_hash = compute_quarantine_record_hash(fields, SECRET)
    elif hash_mode == "tampered":
        record_integrity_hash = "0" * 64
    else:
        record_integrity_hash = None
    row = QuarantinedAuditEvent(**fields, record_integrity_hash=record_integrity_hash)
    db_session.add(row)
    return row


# ---------------------------------------------------------------------------
# _resolve_secret / _resolve_session
# ---------------------------------------------------------------------------


def test_resolve_secret_returns_configured_value(monkeypatch):
    """Return the configured JWT_SECRET value."""
    monkeypatch.setenv("JWT_SECRET", "a-real-secret")
    assert vai._resolve_secret() == "a-real-secret"


def test_resolve_secret_exits_when_unset(monkeypatch, capsys):
    """Exit 1 with a [FAIL] message when JWT_SECRET is unset."""
    monkeypatch.delenv("JWT_SECRET", raising=False)
    with pytest.raises(SystemExit) as exc_info:
        vai._resolve_secret()
    assert exc_info.value.code == 1
    assert "JWT_SECRET must be set" in capsys.readouterr().err


def test_resolve_session_exits_when_no_url_configured(monkeypatch, capsys):
    """Exit 1 when neither AUDIT_READER_DATABASE_URL nor AUDIT_DATABASE_URL is set."""
    monkeypatch.delenv("AUDIT_READER_DATABASE_URL", raising=False)
    monkeypatch.delenv("AUDIT_DATABASE_URL", raising=False)
    with pytest.raises(SystemExit) as exc_info:
        vai._resolve_session()
    assert exc_info.value.code == 1
    assert "AUDIT_READER_DATABASE_URL" in capsys.readouterr().err


def test_resolve_session_uses_reader_url(monkeypatch):
    """Build a working session from AUDIT_READER_DATABASE_URL when set."""
    monkeypatch.setenv("AUDIT_READER_DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.delenv("AUDIT_DATABASE_URL", raising=False)
    session = vai._resolve_session()
    try:
        assert session.execute(__import__("sqlalchemy").text("SELECT 1")).scalar() == 1
    finally:
        session.close()


def test_resolve_session_falls_back_to_audit_database_url(monkeypatch):
    """Fall back to AUDIT_DATABASE_URL when AUDIT_READER_DATABASE_URL is unset."""
    monkeypatch.delenv("AUDIT_READER_DATABASE_URL", raising=False)
    monkeypatch.setenv("AUDIT_DATABASE_URL", "sqlite:///:memory:")
    session = vai._resolve_session()
    session.close()


# ---------------------------------------------------------------------------
# verify_audit_events
# ---------------------------------------------------------------------------


def test_verify_audit_events_counts_valid_tampered_and_no_baseline(db_session):
    """Classify a correctly-hashed row as valid, a wrong-hash row as invalid, and a hash-less row
    as no_baseline."""
    _add_audit_row(db_session, hash_mode="valid", event_id="e-valid")
    _add_audit_row(db_session, hash_mode="tampered", event_id="e-tampered")
    _add_audit_row(db_session, hash_mode="none", event_id="e-no-baseline")
    db_session.commit()

    stats = vai.verify_audit_events(db_session, SECRET)

    assert stats["checked"] == 3
    assert stats["valid"] == 1
    assert stats["invalid"] == ["e-tampered"]
    assert stats["no_baseline"] == 1
    assert stats["structural"] == []


def test_verify_audit_events_flags_empty_required_field_as_structural():
    """Flag a row whose required field is an empty string as a structural problem, via a fake
    session (avoids the DB's own NOT NULL constraint semantics)."""
    row = SimpleNamespace(**_audit_fields(action=""), record_integrity_hash=None)
    fake_session = MagicMock()
    fake_session.query.return_value.yield_per.return_value = [row]

    stats = vai.verify_audit_events(fake_session, SECRET)

    assert stats["checked"] == 1
    assert any("action" in s for s in stats["structural"])


def test_verify_audit_events_flags_duplicate_event_id_as_structural():
    """Flag a second row sharing an event_id already seen as a structural duplicate."""
    row_a = SimpleNamespace(**_audit_fields(event_id="dup-1"), record_integrity_hash=None)
    row_b = SimpleNamespace(**_audit_fields(event_id="dup-1"), record_integrity_hash=None)
    fake_session = MagicMock()
    fake_session.query.return_value.yield_per.return_value = [row_a, row_b]

    stats = vai.verify_audit_events(fake_session, SECRET)

    assert stats["checked"] == 2
    assert any("duplicate event_id" in s for s in stats["structural"])


# ---------------------------------------------------------------------------
# verify_quarantine_records
# ---------------------------------------------------------------------------


def test_verify_quarantine_records_counts_valid_tampered_and_no_baseline(db_session):
    """Classify quarantine rows the same way verify_audit_events classifies audit-event rows."""
    _add_quarantine_row(db_session, hash_mode="valid", stream_message_id="q-valid")
    _add_quarantine_row(db_session, hash_mode="tampered", stream_message_id="q-tampered")
    _add_quarantine_row(db_session, hash_mode="none", stream_message_id="q-no-baseline")
    db_session.commit()

    stats = vai.verify_quarantine_records(db_session, SECRET)

    assert stats["checked"] == 3
    assert stats["valid"] == 1
    assert stats["invalid"] == ["q-tampered"]
    assert stats["no_baseline"] == 1
    assert stats["structural"] == []


def test_verify_quarantine_records_flags_empty_required_field_as_structural():
    """Flag a quarantine row whose required field is an empty string as structural."""
    row = SimpleNamespace(**_quarantine_fields(failure_category=""), record_integrity_hash=None)
    fake_session = MagicMock()
    fake_session.query.return_value.yield_per.return_value = [row]

    stats = vai.verify_quarantine_records(fake_session, SECRET)

    assert any("failure_category" in s for s in stats["structural"])


def test_verify_quarantine_records_flags_duplicate_stream_message_id_as_structural():
    """Flag a second row sharing a stream_message_id already seen as a structural duplicate."""
    row_a = SimpleNamespace(**_quarantine_fields(stream_message_id="dup-1"), record_integrity_hash=None)
    row_b = SimpleNamespace(**_quarantine_fields(stream_message_id="dup-1"), record_integrity_hash=None)
    fake_session = MagicMock()
    fake_session.query.return_value.yield_per.return_value = [row_a, row_b]

    stats = vai.verify_quarantine_records(fake_session, SECRET)

    assert any("duplicate stream_message_id" in s for s in stats["structural"])


# ---------------------------------------------------------------------------
# _report
# ---------------------------------------------------------------------------


def test_report_all_clear_prints_ok_and_returns_true(capsys):
    """Print an [OK] summary and return True when nothing is wrong."""
    stats = {"checked": 5, "valid": 5, "no_baseline": 0, "invalid": [], "structural": []}
    assert vai._report("audit_events", stats) is True
    out = capsys.readouterr().out
    assert "[OK] audit_events: no integrity or structural problems found" in out


def test_report_invalid_records_prints_fail_and_returns_false(capsys):
    """Print [FAIL] lines naming each tampered record and return False."""
    stats = {"checked": 2, "valid": 1, "no_baseline": 0, "invalid": ["evt-1"], "structural": []}
    assert vai._report("audit_events", stats) is False
    err = capsys.readouterr().err
    assert "1 record(s) failed integrity verification" in err
    assert "TAMPERED OR CORRUPTED: evt-1" in err


def test_report_structural_problems_prints_fail_and_returns_false(capsys):
    """Print [FAIL] lines naming each structural problem and return False."""
    stats = {"checked": 1, "valid": 0, "no_baseline": 0, "invalid": [], "structural": ["evt-1: missing required field 'action'"]}
    assert vai._report("audit_events", stats) is False
    err = capsys.readouterr().err
    assert "1 structural problem(s)" in err
    assert "evt-1: missing required field 'action'" in err


# ---------------------------------------------------------------------------
# _write_status_file
# ---------------------------------------------------------------------------


def test_write_status_file_is_a_no_op_when_unconfigured(monkeypatch, tmp_path):
    """Write nothing when AUDIT_HEALTH_STATUS_DIR is unset."""
    monkeypatch.delenv("AUDIT_HEALTH_STATUS_DIR", raising=False)
    vai._write_status_file(True, {"checked": 0, "invalid": []}, {"checked": 0, "invalid": []})
    assert list(tmp_path.iterdir()) == []


def test_write_status_file_writes_expected_fields(monkeypatch, tmp_path):
    """Write every expected KEY=VALUE line when AUDIT_HEALTH_STATUS_DIR is set."""
    monkeypatch.setenv("AUDIT_HEALTH_STATUS_DIR", str(tmp_path))
    events_stats = {"checked": 10, "invalid": ["e1"]}
    quarantine_stats = {"checked": 2, "invalid": []}

    vai._write_status_file(False, events_stats, quarantine_stats)

    content = (tmp_path / "audit-integrity-verification.env").read_text()
    assert "LAST_VERIFICATION_RESULT=fail" in content
    assert "LAST_VERIFICATION_EVENTS_CHECKED=10" in content
    assert "LAST_VERIFICATION_EVENTS_INVALID=1" in content
    assert "LAST_VERIFICATION_QUARANTINE_CHECKED=2" in content
    assert "LAST_VERIFICATION_QUARANTINE_INVALID=0" in content


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


def test_main_passes_and_exits_zero_with_no_alert(monkeypatch, db_session, capsys):
    """Exit 0, print [OK], and never emit a security alert when everything verifies clean."""
    monkeypatch.setenv("JWT_SECRET", SECRET)
    monkeypatch.delenv("AUDIT_HEALTH_STATUS_DIR", raising=False)
    monkeypatch.setattr(vai, "_resolve_secret", lambda: SECRET)
    monkeypatch.setattr(vai, "_resolve_session", lambda: db_session)
    alerts = []
    monkeypatch.setattr(vai, "emit_security_alert", lambda **kwargs: alerts.append(kwargs))
    _add_audit_row(db_session, hash_mode="valid", event_id="e1")
    _add_quarantine_row(db_session, hash_mode="valid", stream_message_id="q1")
    db_session.commit()

    exit_code = vai.main()

    assert exit_code == 0
    assert "[OK] integrity verification passed" in capsys.readouterr().out
    assert alerts == []


def test_main_fails_exits_one_and_emits_alert(monkeypatch, db_session, capsys):
    """Exit 1, print [FAIL], and emit a critical security alert when a tampered record is found."""
    monkeypatch.setenv("JWT_SECRET", SECRET)
    monkeypatch.delenv("AUDIT_HEALTH_STATUS_DIR", raising=False)
    monkeypatch.setattr(vai, "_resolve_secret", lambda: SECRET)
    monkeypatch.setattr(vai, "_resolve_session", lambda: db_session)
    alerts = []
    monkeypatch.setattr(vai, "emit_security_alert", lambda **kwargs: alerts.append(kwargs))
    _add_audit_row(db_session, hash_mode="tampered", event_id="e-bad")
    db_session.commit()

    exit_code = vai.main()

    assert exit_code == 1
    assert "[FAIL] integrity verification found problems" in capsys.readouterr().err
    assert len(alerts) == 1
    assert alerts[0]["condition"] == "integrity_verification_failed"
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["metadata"]["events_invalid"] == 1


def test_main_closes_the_session_even_when_verification_raises(monkeypatch):
    """Close the resolved session in a finally block, even when verification itself raises."""
    monkeypatch.setattr(vai, "_resolve_secret", lambda: SECRET)
    broken_session = MagicMock()
    broken_session.query.side_effect = RuntimeError("db exploded")
    monkeypatch.setattr(vai, "_resolve_session", lambda: broken_session)

    with pytest.raises(RuntimeError):
        vai.main()

    broken_session.close.assert_called_once()


def test_main_writes_status_file_when_configured(monkeypatch, db_session, tmp_path):
    """Write the operational status file as part of main()'s run when AUDIT_HEALTH_STATUS_DIR is
    configured."""
    monkeypatch.setenv("JWT_SECRET", SECRET)
    monkeypatch.setenv("AUDIT_HEALTH_STATUS_DIR", str(tmp_path))
    monkeypatch.setattr(vai, "_resolve_secret", lambda: SECRET)
    monkeypatch.setattr(vai, "_resolve_session", lambda: db_session)
    _add_audit_row(db_session, hash_mode="valid", event_id="e1")
    db_session.commit()

    exit_code = vai.main()

    assert exit_code == 0
    assert (tmp_path / "audit-integrity-verification.env").exists()


# ---------------------------------------------------------------------------
# __main__ guard
# ---------------------------------------------------------------------------


def test_dunder_main_exits_with_mains_return_code(monkeypatch):
    """Exit with main()'s own return code when run as a script."""
    monkeypatch.delenv("JWT_SECRET", raising=False)  # cheapest deterministic path: _resolve_secret's own sys.exit(1)

    with pytest.raises(SystemExit) as exc_info:
        runpy.run_path(vai.__file__, run_name="__main__")

    assert exc_info.value.code == 1
