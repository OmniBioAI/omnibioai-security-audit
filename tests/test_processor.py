import json
import pytest
from datetime import datetime

from audit.models import AuditEvent
from consumers.processor import process_event, parse_audit_event


# ---------------------------------------------------------------------------
# process_event
# ---------------------------------------------------------------------------

def test_process_event_extracts_user_id():
    raw = json.dumps({"user_id": "u1", "event_type": "auth_login", "decision": "allow"})
    result = process_event(raw)
    assert result["user"] == "u1"


def test_process_event_extracts_event_type():
    raw = json.dumps({"user_id": "u1", "event_type": "policy_decision", "decision": "deny"})
    result = process_event(raw)
    assert result["event"] == "policy_decision"


def test_process_event_extracts_decision():
    raw = json.dumps({"user_id": "u1", "event_type": "test", "decision": "success"})
    result = process_event(raw)
    assert result["decision"] == "success"


def test_process_event_missing_fields_return_none():
    raw = json.dumps({})
    result = process_event(raw)
    assert result["user"] is None
    assert result["event"] is None
    assert result["decision"] is None


def test_process_event_partial_fields():
    raw = json.dumps({"user_id": "u2"})
    result = process_event(raw)
    assert result["user"] == "u2"
    assert result["event"] is None


def test_process_event_raises_on_invalid_json():
    with pytest.raises(json.JSONDecodeError):
        process_event("not-json")


def test_process_event_returns_dict():
    raw = json.dumps({"user_id": "u3", "event_type": "test", "decision": "ok"})
    result = process_event(raw)
    assert isinstance(result, dict)
    assert set(result.keys()) == {"user", "event", "decision"}


# ---------------------------------------------------------------------------
# parse_audit_event (PR4.2: full-fidelity parse for durable persistence,
# unlike process_event's lossy user/event/decision summary above)
# ---------------------------------------------------------------------------

def test_parse_audit_event_returns_audit_event():
    raw = json.dumps({
        "event_id": "evt-1",
        "timestamp": "2026-01-01T12:00:00",
        "service": "auth",
        "event_type": "auth_login",
        "user_id": "u1",
        "action": "login",
        "decision": "success",
        "context": {"ip": "1.2.3.4"},
    })
    event = parse_audit_event(raw)

    assert isinstance(event, AuditEvent)
    assert event.event_id == "evt-1"
    assert event.service == "auth"
    assert event.context == {"ip": "1.2.3.4"}


def test_parse_audit_event_preserves_all_fields():
    raw = json.dumps({
        "event_id": "evt-2",
        "timestamp": "2026-01-01T12:00:00",
        "service": "policy",
        "event_type": "policy_decision",
        "user_id": "u2",
        "action": "evaluate",
        "resource": "job_queue",
        "decision": "deny",
        "reason": "rbac failed",
        "trace_id": "trace-xyz",
        "context": {"env": "prod"},
    })
    event = parse_audit_event(raw)

    assert event.resource == "job_queue"
    assert event.reason == "rbac failed"
    assert event.trace_id == "trace-xyz"
    assert isinstance(event.timestamp, datetime)


def test_parse_audit_event_preserves_first_class_tenant():
    event = parse_audit_event(json.dumps({
        "event_id": "tenant-1", "timestamp": "2026-01-01T12:00:00",
        "service": "tes", "event_type": "run", "organization_id": "org-7",
        "tenant_scope": "organization", "context": {"organization_id": "wrong"},
    }))
    assert event.organization_id == "org-7"
    assert event.tenant_scope == "organization"


def test_legacy_event_without_tenant_is_unknown_not_global():
    event = parse_audit_event(json.dumps({"service": "svc", "event_type": "test"}))
    assert event.organization_id is None
    assert event.tenant_scope == "unknown"


def test_tenant_is_never_inferred_from_context():
    event = parse_audit_event(json.dumps({
        "service": "svc", "event_type": "test",
        "context": {"organization_id": "org-context-only"},
    }))
    assert event.organization_id is None
    assert event.tenant_scope == "unknown"


def test_parse_audit_event_raises_on_invalid_json():
    with pytest.raises(json.JSONDecodeError):
        parse_audit_event("not-json")


def test_parse_audit_event_raises_on_missing_required_fields():
    raw = json.dumps({"user_id": "u1"})  # missing service/event_type
    with pytest.raises(Exception):
        parse_audit_event(raw)
