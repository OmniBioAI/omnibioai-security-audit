"""Validate the AuditEvent model's field defaults, auto-generated event_id and timestamp, full
construction, and serialization, plus the AuditEvents constant groups.

Developer: Manish Kumar <manish@omnibioai.org>
"""

import pytest
from datetime import datetime
from audit.models import AuditEvent
from audit.events import AuditEvents


# ---------------------------------------------------------------------------
# AuditEvent model
# ---------------------------------------------------------------------------

def test_audit_event_required_fields():
    """Construct an AuditEvent from its required service and event_type fields."""
    event = AuditEvent(service="auth", event_type="auth_login")
    assert event.service == "auth"
    assert event.event_type == "auth_login"


def test_audit_event_has_uuid_event_id():
    """Auto-generate a 36-character UUID4-format event_id."""
    # Phase 3 PR4.1: event_id is generated per-instance via Field(default_factory=...)
    # -- see test_models.py for the regression test proving two instances differ.
    event = AuditEvent(service="auth", event_type="test")
    assert isinstance(event.event_id, str)
    assert len(event.event_id) == 36  # UUID4 string: 8-4-4-4-12 format


def test_audit_event_auto_generates_timestamp():
    """Auto-generate a datetime timestamp when none is supplied."""
    event = AuditEvent(service="auth", event_type="test")
    assert isinstance(event.timestamp, datetime)


def test_audit_event_optional_fields_default_none():
    """Default user_id, resource, decision, reason, and trace_id to None."""
    event = AuditEvent(service="svc", event_type="type")
    assert event.user_id is None
    assert event.resource is None
    assert event.decision is None
    assert event.reason is None
    assert event.trace_id is None


def test_audit_event_action_defaults_empty_string():
    """Default action to an empty string."""
    event = AuditEvent(service="svc", event_type="type")
    assert event.action == ""


def test_audit_event_context_defaults_empty_dict():
    """Default context to an empty dict."""
    event = AuditEvent(service="svc", event_type="type")
    assert event.context == {}


def test_audit_event_full_construction():
    """Construct an AuditEvent with every field supplied and preserve each value."""
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
    """Serialize an AuditEvent to a dict carrying its service, user_id, and decision."""
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
    """Pin the AUTH_LOGIN and AUTH_FAILED event-type constants."""
    assert AuditEvents.AUTH_LOGIN == "auth_login"
    assert AuditEvents.AUTH_FAILED == "auth_failed"


def test_audit_events_iam_constants():
    """Pin the IAM_CACHE_HIT and IAM_CACHE_MISS event-type constants."""
    assert AuditEvents.IAM_CACHE_HIT == "iam_cache_hit"
    assert AuditEvents.IAM_CACHE_MISS == "iam_cache_miss"


def test_audit_events_policy_constants():
    """Pin the POLICY_DECISION event-type constant."""
    assert AuditEvents.POLICY_DECISION == "policy_decision"


def test_audit_events_tes_constants():
    """Pin the TES_SUBMIT and TES_COMPLETE event-type constants."""
    assert AuditEvents.TES_SUBMIT == "tes_submit"
    assert AuditEvents.TES_COMPLETE == "tes_complete"
