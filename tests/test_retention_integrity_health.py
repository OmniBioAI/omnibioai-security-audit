"""V2-003 (Track E3) Phase 18: RetentionIntegrityHealth -- the optional
status-file bridge between scripts/verify_audit_integrity.py /
scripts/audit_retention_cleanup.py (external script runs) and
GET /audit/pipeline-health. Same "unknown is never fabricated" and
opt-in-via-env-var discipline as the rest of audit_health_service.py.
"""
from services.audit_health_service import get_retention_integrity_health


def test_not_configured_when_status_dir_unset(monkeypatch):
    monkeypatch.delenv("AUDIT_HEALTH_STATUS_DIR", raising=False)

    health = get_retention_integrity_health()

    assert health.status_source == "not_configured"
    assert health.last_integrity_verification_ts is None
    assert health.last_retention_run_ts is None


def test_configured_but_never_run_reports_none_fields(monkeypatch, tmp_path):
    monkeypatch.setenv("AUDIT_HEALTH_STATUS_DIR", str(tmp_path))

    health = get_retention_integrity_health()

    assert health.status_source == "configured"
    assert health.last_integrity_verification_ts is None  # no file written yet -- never fabricated
    assert health.last_retention_run_ts is None


def test_reads_a_real_verification_status_file(monkeypatch, tmp_path):
    monkeypatch.setenv("AUDIT_HEALTH_STATUS_DIR", str(tmp_path))
    (tmp_path / "audit-integrity-verification.env").write_text(
        "LAST_VERIFICATION_TS=2026-09-16T12:00:00+00:00\n"
        "LAST_VERIFICATION_RESULT=pass\n"
        "LAST_VERIFICATION_EVENTS_CHECKED=42\n"
        "LAST_VERIFICATION_EVENTS_INVALID=0\n"
        "LAST_VERIFICATION_QUARANTINE_CHECKED=1\n"
        "LAST_VERIFICATION_QUARANTINE_INVALID=0\n"
    )

    health = get_retention_integrity_health()

    assert health.last_integrity_verification_ts == "2026-09-16T12:00:00+00:00"
    assert health.last_integrity_verification_result == "pass"
    assert health.last_integrity_events_invalid == 0


def test_reads_a_real_retention_status_file(monkeypatch, tmp_path):
    monkeypatch.setenv("AUDIT_HEALTH_STATUS_DIR", str(tmp_path))
    (tmp_path / "audit-retention-run.env").write_text(
        "LAST_RETENTION_RUN_TS=2026-09-16T04:00:00+00:00\n"
        "LAST_RETENTION_RUN_MODE=execute\n"
        "LAST_RETENTION_RUN_RESULT=success\n"
        "LAST_RETENTION_RUN_DELETED_TOTAL=3\n"
    )

    health = get_retention_integrity_health()

    assert health.last_retention_run_ts == "2026-09-16T04:00:00+00:00"
    assert health.last_retention_run_result == "success"
    assert health.last_retention_deleted_total == 3


def test_malformed_integer_field_does_not_crash(monkeypatch, tmp_path):
    """A hand-edited or corrupted status file must degrade gracefully,
    not raise -- this is observability, it must never itself become a
    new failure mode."""
    monkeypatch.setenv("AUDIT_HEALTH_STATUS_DIR", str(tmp_path))
    (tmp_path / "audit-integrity-verification.env").write_text(
        "LAST_VERIFICATION_TS=2026-09-16T12:00:00+00:00\n"
        "LAST_VERIFICATION_RESULT=pass\n"
        "LAST_VERIFICATION_EVENTS_INVALID=not-a-number\n"
    )

    health = get_retention_integrity_health()  # must not raise

    assert health.last_integrity_verification_result == "pass"
    assert health.last_integrity_events_invalid is None  # unparseable -- None, not fabricated as 0


def test_real_verify_script_writes_a_status_file_when_configured(tmp_path, monkeypatch):
    """Real end-to-end: run verify_audit_integrity.py's status-writing
    function directly (not the whole script -- that needs a real DB,
    covered elsewhere) and confirm the file the health service reads is
    exactly the file this script writes."""
    import sys
    sys.path.insert(0, ".")
    from scripts.verify_audit_integrity import _write_status_file

    monkeypatch.setenv("AUDIT_HEALTH_STATUS_DIR", str(tmp_path))
    _write_status_file(
        passed=False,
        events_stats={"checked": 10, "invalid": ["evt-1", "evt-2"]},
        quarantine_stats={"checked": 2, "invalid": []},
    )

    health = get_retention_integrity_health()
    assert health.last_integrity_verification_result == "fail"
    assert health.last_integrity_events_invalid == 2


def test_real_retention_script_writes_a_status_file_when_configured(tmp_path, monkeypatch):
    import sys
    sys.path.insert(0, ".")
    from scripts.audit_retention_cleanup import _write_status_file

    monkeypatch.setenv("AUDIT_HEALTH_STATUS_DIR", str(tmp_path))
    _write_status_file(
        mode="execute", overall_ok=True,
        results={"audit_events": {"status": "success", "count": 5}, "quarantined_audit_events": {"status": "success", "count": 0}},
    )

    health = get_retention_integrity_health()
    assert health.last_retention_run_result == "success"
    assert health.last_retention_deleted_total == 5
