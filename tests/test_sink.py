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


def test_sink_write_persists_first_class_tenant(db_session):
    Sink(db_session).write(_event(organization_id="org-7", tenant_scope="organization"))
    fetched = db_session.get(AuditEventRecord, "evt-1")
    assert fetched.organization_id == "org-7"
    assert fetched.tenant_scope == "organization"


def test_sink_legacy_event_defaults_to_unknown_tenant(db_session):
    Sink(db_session).write(_event())
    fetched = db_session.get(AuditEventRecord, "evt-1")
    assert fetched.organization_id is None
    assert fetched.tenant_scope == "unknown"


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


# ---------------------------------------------------------------------------
# PR2: integrity_status -- additive, existing callers above are unaffected
# and unmodified (none of them pass this key).
# ---------------------------------------------------------------------------

def test_sink_write_persists_explicit_valid_status(db_session):
    sink = Sink(db_session)
    sink.write(_event(integrity_status="valid"))

    fetched = db_session.get(AuditEventRecord, "evt-1")
    assert fetched.integrity_status == "valid"


def test_sink_write_persists_explicit_invalid_status(db_session):
    sink = Sink(db_session)
    sink.write(_event(integrity_status="invalid"))

    fetched = db_session.get(AuditEventRecord, "evt-1")
    assert fetched.integrity_status == "invalid"


def test_sink_write_persists_explicit_unsigned_status(db_session):
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
