import pytest
from datetime import datetime
from audit.models import AuditEvent
from audit.events import AuditEvents


# ---------------------------------------------------------------------------
# AuditEvent model
# ---------------------------------------------------------------------------

def test_audit_event_required_fields():
    event = AuditEvent(service="auth", event_type="auth_login")
    assert event.service == "auth"
    assert event.event_type == "auth_login"


def test_audit_event_has_uuid_event_id():
    # Phase 3 PR4.1: event_id is generated per-instance via Field(default_factory=...)
    # -- see test_models.py for the regression test proving two instances differ.
    event = AuditEvent(service="auth", event_type="test")
    assert isinstance(event.event_id, str)
    assert len(event.event_id) == 36  # UUID4 string: 8-4-4-4-12 format


def test_audit_event_auto_generates_timestamp():
    event = AuditEvent(service="auth", event_type="test")
    assert isinstance(event.timestamp, datetime)


def test_audit_event_optional_fields_default_none():
    event = AuditEvent(service="svc", event_type="type")
    assert event.user_id is None
    assert event.resource is None
    assert event.decision is None
    assert event.reason is None
    assert event.trace_id is None


def test_audit_event_action_defaults_empty_string():
    event = AuditEvent(service="svc", event_type="type")
    assert event.action == ""


def test_audit_event_context_defaults_empty_dict():
    event = AuditEvent(service="svc", event_type="type")
    assert event.context == {}


def test_audit_event_full_construction():
    event = AuditEvent(
        service="policy-engine",
        event_type="policy_decision",
        user_id="u1",
        action="tes.submit",
        resource="job_queue",
        decision="allow",
        reason="rbac passed",
        trace_id="trace-123",
        context={"env": "prod"},
    )
    assert event.user_id == "u1"
    assert event.decision == "allow"
    assert event.context == {"env": "prod"}


def test_audit_event_serialization():
    event = AuditEvent(
        service="svc",
        event_type="test",
        user_id="u1",
        action="do_thing",
        decision="success",
    )
    data = event.dict()
    assert data["service"] == "svc"
    assert data["user_id"] == "u1"
    assert data["decision"] == "success"


# ---------------------------------------------------------------------------
# AuditEvents constants
# ---------------------------------------------------------------------------

def test_audit_events_auth_constants():
    assert AuditEvents.AUTH_LOGIN == "auth_login"
    assert AuditEvents.AUTH_FAILED == "auth_failed"


def test_audit_events_iam_constants():
    assert AuditEvents.IAM_CACHE_HIT == "iam_cache_hit"
    assert AuditEvents.IAM_CACHE_MISS == "iam_cache_miss"


def test_audit_events_policy_constants():
    assert AuditEvents.POLICY_DECISION == "policy_decision"


def test_audit_events_tes_constants():
    assert AuditEvents.TES_SUBMIT == "tes_submit"
    assert AuditEvents.TES_COMPLETE == "tes_complete"
