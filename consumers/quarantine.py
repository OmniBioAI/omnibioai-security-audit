"""V2-002: durable poison-message quarantine.

See db/models.py::QuarantinedAuditEvent for the schema rationale and
worker/main.py::quarantine_and_ack for the ACK-ordering contract this
module exists to support (quarantine write must succeed BEFORE the
original stream entry is acked).
"""
from __future__ import annotations

import json

from sqlalchemy.exc import IntegrityError

from audit.config import AuditConfig
from audit.record_integrity import compute_quarantine_record_hash
from db.models import QuarantinedAuditEvent


def classify_poison_reason(raw_data: str | None) -> tuple[str, str | None, str | None]:
    """Best-effort diagnosis of *why* an entry became poison, without
    trusting or fully re-validating the payload.

    Returns (failure_category, service_if_parseable, failure_detail).
    failure_detail is deliberately just an exception *type* name, never
    the exception's full message -- a JSONDecodeError's message can
    include a fragment of the offending (possibly attacker-controlled or
    PHI-bearing) input, and raw_data already preserves the full original
    content once; echoing part of it a second time into a field meant to
    be safe to browse would add nothing but risk.
    """
    if raw_data is None:
        return "malformed", None, "MissingDataField"
    try:
        payload = json.loads(raw_data)
    except Exception as e:  # noqa: BLE001 -- any parse failure means "malformed", the exact exception type is all we record
        return "malformed", None, type(e).__name__

    if not isinstance(payload, dict):
        return "malformed", None, "NotAJsonObject"

    service = payload.get("service") if isinstance(payload.get("service"), str) else None
    # Parses as a JSON object but was still never successfully persisted
    # after PEL_MAX_DELIVERIES attempts -- the payload itself isn't the
    # (only) problem; every attempt to reach MySQL failed.
    return "persistence_exhausted", service, None


class QuarantineSink:
    """Persists one poison Redis Streams entry to QuarantinedAuditEvent.

    Mirrors consumers/sink.py::Sink exactly: same idempotent-insert
    pattern (stream_message_id is the PK, a duplicate insert is treated
    as a successful no-op via IntegrityError, not an error), same
    "any other DB error propagates uncaught" contract so the caller
    knows not to ack.
    """

    def __init__(self, db_session):
        self.db_session = db_session

    def write(self, message_id: str, fields: dict, delivery_attempts: int) -> bool:
        raw_data = fields.get("data")
        raw_signature = fields.get("sig")
        failure_category, service, failure_detail = classify_poison_reason(raw_data)

        # V2-003: same stored-record tamper-detection model as
        # consumers/sink.py -- poison evidence must not be easier to
        # alter undetected than canonical evidence.
        record_integrity_hash = compute_quarantine_record_hash(
            {
                "stream_message_id": message_id,
                "raw_data": raw_data,
                "raw_signature": raw_signature,
                "service": service,
                "failure_category": failure_category,
                "failure_detail": failure_detail,
                "delivery_attempts": delivery_attempts,
            },
            AuditConfig.EVENT_SIGNING_SECRET,
        )
        record = QuarantinedAuditEvent(
            stream_message_id=message_id,
            raw_data=raw_data,
            raw_signature=raw_signature,
            service=service,
            failure_category=failure_category,
            failure_detail=failure_detail,
            delivery_attempts=delivery_attempts,
            record_integrity_hash=record_integrity_hash,
        )
        self.db_session.add(record)
        try:
            self.db_session.commit()
        except IntegrityError:
            # Already quarantined (e.g. the previous attempt's write
            # succeeded but the process crashed before the follow-up
            # XACK) -- durable evidence already exists, safe to proceed
            # to ack.
            self.db_session.rollback()
        return True
