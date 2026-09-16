from sqlalchemy.exc import IntegrityError

from audit.config import AuditConfig
from audit.record_integrity import compute_audit_event_hash
from db.models import AuditEventRecord


class Sink:
    """PR4.2: persists audit events to the audit_events table.

    Previously this printed the event and discarded it. The consumer
    worker now owns the Redis-reading/ack lifecycle; this class only knows
    how to durably store one event given a DB session.
    """

    def __init__(self, db_session):
        self.db_session = db_session

    def write(self, event: dict) -> bool:
        """Insert `event` (an AuditEvent.model_dump()-shaped dict) as a row.

        Returns True whether the row was newly inserted or already existed
        (duplicate event_id) -- both are a successful, durable outcome from
        the caller's point of view, safe to ACK. Any other database error
        propagates uncaught so the worker knows NOT to ack and can retry.
        """
        integrity_status = event.get("integrity_status", "unsigned")
        # V2-003: computed once, here, at insert time, by the one
        # trusted writer -- see audit/record_integrity.py's module
        # docstring for why this is a separate mechanism from producer
        # signing, and why it must never be recomputed after insert.
        record_integrity_hash = compute_audit_event_hash(
            {
                "event_id": event["event_id"],
                "timestamp": event["timestamp"],
                "service": event["service"],
                "event_type": event["event_type"],
                "user_id": event.get("user_id"),
                "organization_id": event.get("organization_id"),
                "tenant_scope": event.get("tenant_scope", "unknown"),
                "action": event.get("action", ""),
                "resource": event.get("resource"),
                "decision": event.get("decision"),
                "reason": event.get("reason"),
                "trace_id": event.get("trace_id"),
                "context": event.get("context", {}),
                "integrity_status": integrity_status,
            },
            AuditConfig.EVENT_SIGNING_SECRET,
        )
        record = AuditEventRecord(
            event_id=event["event_id"],
            timestamp=event["timestamp"],
            service=event["service"],
            event_type=event["event_type"],
            user_id=event.get("user_id"),
            organization_id=event.get("organization_id"),
            tenant_scope=event.get("tenant_scope", "unknown"),
            action=event.get("action", ""),
            resource=event.get("resource"),
            decision=event.get("decision"),
            reason=event.get("reason"),
            trace_id=event.get("trace_id"),
            context=event.get("context", {}),
            # PR2: additive -- callers that never pass this key (every
            # existing caller as of this PR) get the same "unsigned"
            # default the column's own server_default applies at the DB
            # level, so omitting it is indistinguishable from a genuinely
            # unsigned event, not an error.
            integrity_status=integrity_status,
            record_integrity_hash=record_integrity_hash,
        )
        self.db_session.add(record)
        try:
            self.db_session.commit()
        except IntegrityError:
            # event_id already present -- a durable copy already exists
            # (e.g. re-processing a message that was persisted but never
            # acked before a worker crash). Treat as success, not a failure
            # to retry.
            self.db_session.rollback()
        return True
