"""PR4.2 regression tests: Sink now persists to audit_events instead of
printing (consumers/sink.py). Supersedes the print-based Sink tests that
used to live in tests/test_processor.py.

Developer: Manish Kumar <manish@omnibioai.org>
"""
from datetime import datetime, timezone

from consumers.sink import Sink
from db.models import AuditEventRecord


def _event(event_id="evt-1", **overrides):
    """Build a parsed AuditEvent for the sink tests, applying any field overrides."""
    payload = {
        "event_id": event_id,
        "timestamp": datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        "service": "auth",
        "event_type": "auth_login",
        "user_id": "u1",
        "action": "login",
        "resource": None,
        "decision": "success",
        "reason": None,
        "trace_id": "trace-1",
        "context": {"ip": "1.2.3.4"},
    }
    payload.update(overrides)
    return payload


def test_sink_write_persists_event(db_session):
    """Persist an event with its service and user_id intact."""
    sink = Sink(db_session)
    result = sink.write(_event())

    assert result is True
    fetched = db_session.get(AuditEventRecord, "evt-1")
    assert fetched is not None
    assert fetched.service == "auth"
    assert fetched.user_id == "u1"


def test_sink_write_persists_first_class_tenant(db_session):
    """Persist organization_id and tenant_scope as first-class columns."""
    Sink(db_session).write(_event(organization_id="org-7", tenant_scope="organization"))
    fetched = db_session.get(AuditEventRecord, "evt-1")
    assert fetched.organization_id == "org-7"
    assert fetched.tenant_scope == "organization"


def test_sink_legacy_event_defaults_to_unknown_tenant(db_session):
    """Default a legacy event with no tenant fields to organization_id=None and
    tenant_scope=unknown."""
    Sink(db_session).write(_event())
    fetched = db_session.get(AuditEventRecord, "evt-1")
    assert fetched.organization_id is None
    assert fetched.tenant_scope == "unknown"


def test_sink_write_preserves_context(db_session):
    """Persist a nested context object unchanged."""
    sink = Sink(db_session)
    sink.write(_event(context={"a": 1, "b": {"c": 2}}))

    fetched = db_session.get(AuditEventRecord, "evt-1")
    assert fetched.context == {"a": 1, "b": {"c": 2}}


def test_sink_write_duplicate_event_id_is_safe_noop(db_session):
    """Writing the same event_id twice must not raise and must not create
    a second row -- this is what lets the worker treat 'already persisted'
    as a safe outcome to ACK rather than a failure to retry."""
    sink = Sink(db_session)

    first = sink.write(_event())
    second = sink.write(_event())  # same event_id, e.g. redelivered message

    assert first is True
    assert second is True
    count = db_session.query(AuditEventRecord).filter_by(event_id="evt-1").count()
    assert count == 1


def test_sink_write_handles_optional_fields_missing(db_session):
    """A minimal event dict (only required AuditEvent fields) must not
    raise -- optional fields fall back to sensible defaults."""
    sink = Sink(db_session)
    minimal = {
        "event_id": "evt-minimal",
        "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "service": "svc",
        "event_type": "test",
    }
    result = sink.write(minimal)

    assert result is True
    fetched = db_session.get(AuditEventRecord, "evt-minimal")
    assert fetched.user_id is None
    assert fetched.context == {}


# ---------------------------------------------------------------------------
# PR2: integrity_status -- additive, existing callers above are unaffected
# and unmodified (none of them pass this key).
# ---------------------------------------------------------------------------

def test_sink_write_persists_explicit_valid_status(db_session):
    """Persist an explicit valid integrity_status."""
    sink = Sink(db_session)
    sink.write(_event(integrity_status="valid"))

    fetched = db_session.get(AuditEventRecord, "evt-1")
    assert fetched.integrity_status == "valid"


def test_sink_write_persists_explicit_invalid_status(db_session):
    """Persist an explicit invalid integrity_status."""
    sink = Sink(db_session)
    sink.write(_event(integrity_status="invalid"))

    fetched = db_session.get(AuditEventRecord, "evt-1")
    assert fetched.integrity_status == "invalid"


def test_sink_write_persists_explicit_unsigned_status(db_session):
    """Persist an explicit unsigned integrity_status."""
    sink = Sink(db_session)
    sink.write(_event(integrity_status="unsigned"))

    fetched = db_session.get(AuditEventRecord, "evt-1")
    assert fetched.integrity_status == "unsigned"


def test_sink_write_omitted_status_defaults_to_unsigned(db_session):
    """No existing caller (this file's own earlier tests, worker/main.py
    before PR2, test_producer_contract_reconciliation.py) passes this key
    -- must default safely rather than KeyError or persist None."""
    sink = Sink(db_session)
    sink.write(_event())  # no integrity_status key at all

    fetched = db_session.get(AuditEventRecord, "evt-1")
    assert fetched.integrity_status == "unsigned"


def test_sink_stores_aware_timestamp_as_naive_utc_and_the_stored_row_verifies(db_session, monkeypatch):
    """2026-09-24 live finding: rows written from aware producer timestamps
    failed integrity verification on read-back. Sink must hash and store
    the same naive-UTC value, including for a non-UTC offset."""
    from datetime import timedelta

    from audit.config import AuditConfig
    from audit.record_integrity import verify_audit_event_hash

    monkeypatch.setattr(AuditConfig, "EVENT_SIGNING_SECRET", "sink-tz-test-secret")
    chicago = timezone(timedelta(hours=-5))
    Sink(db_session).write(_event(event_id="evt-tz", timestamp=datetime(2026, 1, 1, 7, 0, 0, 600000, tzinfo=chicago)))

    fetched = db_session.get(AuditEventRecord, "evt-tz")
    assert fetched.timestamp.replace(microsecond=0) in (
        datetime(2026, 1, 1, 12, 0, 0),  # noqa: DTZ001 -- backend kept microseconds (SQLite)
        datetime(2026, 1, 1, 12, 0, 1),  # noqa: DTZ001 -- backend rounded (MySQL DATETIME)
    )
    assert fetched.timestamp.tzinfo is None

    columns = (
        "event_id", "timestamp", "service", "event_type", "user_id", "organization_id",
        "tenant_scope", "action", "resource", "decision", "reason", "trace_id", "context",
        "integrity_status", "record_integrity_hash",
    )
    row = {col: getattr(fetched, col) for col in columns}
    assert verify_audit_event_hash(row, "sink-tz-test-secret") is True
