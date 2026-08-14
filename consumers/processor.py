from __future__ import annotations

import json

from audit.models import AuditEvent
from audit.signing import verify_audit_event


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


def classify_event_integrity(
    service: str, signature: str | None, data: str, secret: str
) -> str:
    """PR2: the worker's answer to "should this event be trusted as
    signed?" -- deliberately a separate function from parse_audit_event()
    (which has other callers, see this PR's report) rather than a change
    to its signature.

    `data` must be the exact raw stream string (fields["data"]), never a
    re-serialization -- audit.signing's own MAC covers the exact
    transmitted bytes, see its module docstring. `signature` is
    fields.get("sig"), which is None for every event today (no producer
    signs yet); this is not folded into verify_audit_event() itself
    because that function already collapses "missing" and "invalid" into
    the same False (correctly -- that distinction is this consumer's
    business, not the signing module's), so the emptiness check has to
    happen here, before delegating.

    Returns exactly one of "valid" / "invalid" / "unsigned" -- never
    raises (verify_audit_event() already never raises; the emptiness
    check above it can't either).
    """
    if not signature:
        return "unsigned"
    return "valid" if verify_audit_event(service, data, signature, secret) else "invalid"