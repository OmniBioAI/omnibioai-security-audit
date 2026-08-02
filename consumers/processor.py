import json

from audit.models import AuditEvent


def process_event(raw_event: str):
    event = json.loads(raw_event)

    # future:
    # - anomaly detection
    # - security alerts
    # - metrics aggregation

    return {
        "user": event.get("user_id"),
        "event": event.get("event_type"),
        "decision": event.get("decision"),
    }


def parse_audit_event(raw_event: str) -> AuditEvent:
    """PR4.2: deserialize + validate a raw stream payload into a full
    AuditEvent, for durable persistence. Unlike process_event() above (a
    lossy summary used nowhere in production today), this preserves every
    field the worker needs to write to audit_events, including context.

    Raises json.JSONDecodeError / pydantic.ValidationError on a malformed
    payload -- the caller (worker/main.py) decides what to do with that.
    """
    payload = json.loads(raw_event)
    return AuditEvent(**payload)