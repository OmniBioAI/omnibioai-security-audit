"""PR4.2 regression tests: Sink now persists to audit_events instead of
printing (consumers/sink.py). Supersedes the print-based Sink tests that
used to live in tests/test_processor.py."""
from datetime import datetime

from db.models import AuditEventRecord
from consumers.sink import Sink


def _event(event_id="evt-1", **overrides):
    payload = {
        "event_id": event_id,
        "timestamp": datetime(2026, 1, 1, 12, 0, 0),
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
    sink = Sink(db_session)
    result = sink.write(_event())

    assert result is True
    fetched = db_session.get(AuditEventRecord, "evt-1")
    assert fetched is not None
    assert fetched.service == "auth"
    assert fetched.user_id == "u1"


def test_sink_write_preserves_context(db_session):
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
        "timestamp": datetime(2026, 1, 1),
        "service": "svc",
        "event_type": "test",
    }
    result = sink.write(minimal)

    assert result is True
    fetched = db_session.get(AuditEventRecord, "evt-minimal")
    assert fetched.user_id is None
    assert fetched.context == {}
