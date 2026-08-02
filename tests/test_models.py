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
"""
import time
from datetime import datetime

from audit.models import AuditEvent


def test_event_id_differs_across_instances():
    e1 = AuditEvent(service="svc", event_type="test")
    e2 = AuditEvent(service="svc", event_type="test")
    assert e1.event_id != e2.event_id


def test_timestamp_differs_across_instances():
    e1 = AuditEvent(service="svc", event_type="test")
    time.sleep(0.05)
    e2 = AuditEvent(service="svc", event_type="test")
    assert e1.timestamp != e2.timestamp
    assert e2.timestamp > e1.timestamp


def test_explicitly_supplied_event_id_is_respected():
    event = AuditEvent(service="svc", event_type="test", event_id="fixed-id-123")
    assert event.event_id == "fixed-id-123"


def test_explicitly_supplied_timestamp_is_respected():
    fixed = datetime(2024, 1, 1, 0, 0, 0)
    event = AuditEvent(service="svc", event_type="test", timestamp=fixed)
    assert event.timestamp == fixed
