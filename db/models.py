from sqlalchemy import JSON, Column, DateTime, Index, Integer, String, Text
from sqlalchemy.sql import func

from db.base import Base


class AuditEventRecord(Base):
    """Durable copy of an AuditEvent (audit/models.py), written by the
    consumer worker after it reads the event back off the Redis stream.

    event_id is the primary key (not a surrogate int id) so that inserting
    the same event twice -- e.g. a worker crash/restart re-delivering an
    unacked message -- is a natural, safe no-op via the PK's uniqueness
    constraint rather than something the application has to de-duplicate
    itself. See consumers/sink.py for how that constraint is used.
    """

    __tablename__ = "audit_events"

    event_id = Column(String(64), primary_key=True)
    timestamp = Column(DateTime, nullable=False)
    service = Column(String(255), nullable=False)
    event_type = Column(String(255), nullable=False)
    user_id = Column(String(255), nullable=True)
    organization_id = Column(String(255), nullable=True)
    # Legacy rows and events without an authoritative tenant are UNKNOWN.
    # GLOBAL is only valid when a producer explicitly declares it.
    tenant_scope = Column(String(16), nullable=False, server_default="unknown")
    action = Column(String(255), nullable=False, default="")
    resource = Column(String(255), nullable=True)
    decision = Column(String(64), nullable=True)
    reason = Column(Text, nullable=True)
    trace_id = Column(String(255), nullable=True)
    context = Column(JSON, nullable=False, default=dict)
    # PR2 of the audit:events integrity remediation: one of "valid" /
    # "invalid" / "unsigned", set by the worker (consumers/processor.py::
    # classify_event_integrity) at ingest time -- never supplied by a
    # producer. server_default="unsigned" back-fills every pre-existing
    # row on migration with no manual UPDATE, and matches what an event
    # missing a signature already classifies as going forward, so old and
    # new "no signature" rows read identically.
    integrity_status = Column(String(16), nullable=False, server_default="unsigned")
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    # V2-003 (Track E3): stored-record tamper detection. Computed once by
    # the trusted worker at insert time over this row's own decomposed
    # column values (audit/record_integrity.py) -- NOT a re-verification
    # of the producer's original HMAC (audit/signing.py), which only
    # proves the wire payload was validly signed, not that the stored
    # row hasn't since been altered by direct SQL. NULL for any row
    # inserted before this column existed -- those rows have no
    # retroactive integrity baseline and are honestly reported as such
    # by the verification tool, never silently treated as verified.
    record_integrity_hash = Column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_audit_events_org_timestamp_event", "organization_id", "timestamp", "event_id"),
    )


class QuarantinedAuditEvent(Base):
    """V2-002 (durable audit delivery): a Redis Streams entry that could
    not be durably persisted to AuditEventRecord after
    AuditConfig.PEL_MAX_DELIVERIES attempts, saved here BEFORE it is
    acked out of the stream -- see worker/main.py::quarantine_and_ack.

    stream_message_id (the Redis Streams entry ID, e.g. "169...-0") is
    the primary key so re-quarantining the same entry (the write
    succeeds but the process crashes before the follow-up XACK, and a
    later sweep reclaims and re-quarantines it) is a safe idempotent
    no-op via the PK's uniqueness constraint -- identical pattern to
    AuditEventRecord.event_id in consumers/sink.py.

    raw_data/raw_signature intentionally preserve the exact original
    payload: for a "persistence_exhausted" entry this is a perfectly
    legitimate audit event that just couldn't reach MySQL in time, and
    without the raw bytes here it could never be manually recovered.
    This is not a new PHI/secret exposure -- it is the same content a
    successful delivery would have written into audit_events' own
    columns, just not yet decomposed into them.
    """

    __tablename__ = "quarantined_audit_events"

    stream_message_id = Column(String(64), primary_key=True)
    raw_data = Column(Text, nullable=True)
    raw_signature = Column(Text, nullable=True)
    # Best-effort -- parsed loosely from raw_data without full schema
    # validation (which is exactly what failed for a malformed event),
    # so this may be None.
    service = Column(String(255), nullable=True)
    # "malformed" (payload doesn't even parse) vs "persistence_exhausted"
    # (payload is valid, every delivery attempt failed to reach MySQL) --
    # see worker/main.py::_classify_poison_reason. Never a raw exception
    # message: that could echo attacker-controlled or PHI-bearing payload
    # content back into a field meant to be safe to browse.
    failure_category = Column(String(32), nullable=False)
    failure_detail = Column(String(255), nullable=True)
    delivery_attempts = Column(Integer, nullable=False)
    quarantined_at = Column(DateTime, server_default=func.now(), nullable=False)
    # V2-003 (Track E3): same tamper-detection model as AuditEventRecord
    # above -- poison evidence must not be easier to alter undetected
    # than canonical evidence.
    record_integrity_hash = Column(String(64), nullable=True)


class AuditLegalHold(Base):
    """V2-003 (Track E3): a minimal, policy-neutral legal-hold
    mechanism. Deliberately a separate, append-only reference table --
    NOT a mutable flag column on audit_events/quarantined_audit_events
    -- so those two tables never need an UPDATE exception carved out of
    their own append-only triggers at all (a flag column would have
    required exactly that: something able to flip legal_hold from 0 to
    1 later). "Is this record held?" is answered by row existence here,
    not by a mutable bit on the record itself.

    This provides the technical CAPABILITY only. It does not invent who
    is authorized to declare a hold, what qualifies, or how long one
    lasts -- that is an organizational/legal policy decision this
    repository cannot make. See the governing evidence document's
    "Legal Hold" section for the explicit scope boundary.
    """

    __tablename__ = "audit_legal_holds"

    # 'audit_events' | 'quarantined_audit_events' -- not a real foreign
    # key (deliberately: a hold table FK-referencing an append-only
    # table would need ON DELETE semantics that can never actually
    # fire, since blocking deletion is the whole point; a plain string
    # discriminator + composite PK is simpler and equally sufficient
    # for an existence check).
    record_table = Column(String(32), primary_key=True)
    record_key = Column(String(64), primary_key=True)  # event_id or stream_message_id
    held_at = Column(DateTime, server_default=func.now(), nullable=False)
    held_by = Column(String(255), nullable=True)  # operational identifier (e.g. a case/ticket reference) -- never PHI
    reason = Column(String(255), nullable=True)  # short, safe description only
