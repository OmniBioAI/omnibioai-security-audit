"""
Phase 3 PR4.1 regression tests: AuditEvent.event_id/timestamp must be
generated per-instance, not once at class-definition time.

Before this fix, both fields were assigned as plain expressions
(`= str(uuid.uuid4())`, `= datetime.utcnow()`), which Pydantic evaluates
once when the class body executes -- every instance that didn't explicitly
override these fields shared the exact same event_id and the exact same,
permanently frozen timestamp for the life of the process. These tests
construct two separate instances (with a real delay for the timestamp
case) and assert they differ -- the check that would have caught the bug.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import time
from datetime import datetime, timezone

import pytest

from audit.models import AuditEvent


def test_event_id_differs_across_instances():
    """Assign a distinct event_id to each AuditEvent instance."""
    e1 = AuditEvent(service="svc", event_type="test")
    e2 = AuditEvent(service="svc", event_type="test")
    assert e1.event_id != e2.event_id


def test_timestamp_differs_across_instances():
    """Advance the timestamp for each AuditEvent constructed later."""
    e1 = AuditEvent(service="svc", event_type="test")
    time.sleep(0.05)
    e2 = AuditEvent(service="svc", event_type="test")
    assert e1.timestamp != e2.timestamp
    assert e2.timestamp > e1.timestamp


def test_explicitly_supplied_event_id_is_respected():
    """Preserve an explicitly supplied event_id instead of generating one."""
    event = AuditEvent(service="svc", event_type="test", event_id="fixed-id-123")
    assert event.event_id == "fixed-id-123"


def test_organization_tenant_scope_requires_first_class_id():
    """Reject tenant_scope=organization when no organization_id is supplied."""
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        AuditEvent(service="svc", event_type="test", tenant_scope="organization")


def test_global_and_unknown_are_distinct():
    """Distinguish an explicit global tenant_scope from the default unknown scope."""
    global_event = AuditEvent(service="svc", event_type="maintenance", tenant_scope="global")
    unknown_event = AuditEvent(service="svc", event_type="test")
    assert global_event.tenant_scope == "global"
    assert unknown_event.tenant_scope == "unknown"


def test_organization_id_alone_promotes_scope_to_organization():
    """A first-class organization_id is itself an authoritative
    organization-scoped declaration -- tenant_scope need not be passed
    explicitly and is auto-promoted from its "unknown" default."""
    event = AuditEvent(service="svc", event_type="test", organization_id="org-1")
    assert event.tenant_scope == "organization"


def test_organization_id_with_explicit_non_organization_scope_is_rejected():
    """Reject an organization_id paired with a tenant_scope other than organization."""
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        AuditEvent(
            service="svc", event_type="test",
            organization_id="org-1", tenant_scope="global",
        )


def test_explicitly_supplied_timestamp_is_respected():
    """Preserve an explicitly supplied timestamp instead of generating one."""
    fixed = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    event = AuditEvent(service="svc", event_type="test", timestamp=fixed)
    assert event.timestamp == fixed
