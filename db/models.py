from sqlalchemy import JSON, Column, DateTime, Index, String, Text
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

    __table_args__ = (
        Index("ix_audit_events_org_timestamp_event", "organization_id", "timestamp", "event_id"),
    )
