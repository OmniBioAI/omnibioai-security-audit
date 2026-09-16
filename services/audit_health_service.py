"""V2-002 (Track E2): operational observability for the audit delivery
pipeline -- Redis Stream -> consumer group -> worker -> MySQL.

Same "unknown evidence is never fabricated as health" discipline as
audit/source_semantics.py: every field that can't be honestly derived
from live Redis/MySQL state is None, not a guessed or zero-defaulted
value. Computed live on each call (no new persistent counters/state) --
Redis and MySQL already durably track everything this needs (XPENDING,
XINFO GROUPS/CONSUMERS, and the audit_events/quarantined_audit_events
tables themselves), so a separate metrics store would just be a second,
driftable copy of the same facts.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from audit.config import AuditConfig
from db.models import AuditEventRecord, QuarantinedAuditEvent


@dataclass(frozen=True)
class RedisPipelineHealth:
    available: bool
    pending_count: int | None = None
    oldest_pending_age_seconds: float | None = None
    retry_in_progress_count: int | None = None
    consumer_lag: int | None = None
    consumer_lag_source: str | None = None  # "xinfo_groups" | "unsupported_redis_version" | None
    stream_length: int | None = None
    # Worker health proxy: how many consumer identities the group has
    # actually seen recently, and the least-idle one's idle time -- a
    # single live worker actively looping shows up here even with zero
    # pending entries; a worker that stopped looping entirely shows a
    # growing idle time on its own consumer identity.
    active_consumer_count: int | None = None
    least_idle_consumer_ms: int | None = None
    error: str | None = None


@dataclass(frozen=True)
class PersistencePipelineHealth:
    available: bool
    last_successful_persistence_at: datetime | None = None
    quarantine_count: int | None = None
    last_quarantine_at: datetime | None = None
    error: str | None = None


@dataclass(frozen=True)
class AuditPipelineHealth:
    generated_at: datetime
    redis: RedisPipelineHealth
    persistence: PersistencePipelineHealth


def get_redis_pipeline_health(reader) -> RedisPipelineHealth:
    """`reader` is a consumers.stream_reader.StreamReader (or anything
    exposing the same `.redis`/`.stream` attributes) -- callers pass the
    real one; tests can pass a fake with a mocked `.redis` client.
    """
    try:
        stream = reader.stream
        group = AuditConfig.CONSUMER_GROUP
        r = reader.redis

        stream_length = r.xlen(stream)

        summary = r.xpending(stream, group)
        pending_count = summary["pending"] if summary else 0

        oldest_pending_age_seconds = None
        retry_in_progress_count = None
        if pending_count:
            # Oldest-by-ID pending entry -- xpending_range with min="-"
            # returns entries in stream order (oldest first).
            oldest = r.xpending_range(stream, group, min="-", max="+", count=1)
            if oldest:
                oldest_pending_age_seconds = oldest[0]["time_since_delivered"] / 1000.0

            # Bounded scan (same PEL_SWEEP_BATCH cap the worker's own
            # sweep uses) rather than an unbounded XPENDING RANGE call --
            # a health check must never itself become a slow/expensive
            # operation on a large backlog.
            sample = r.xpending_range(
                stream, group, min="-", max="+", count=AuditConfig.PEL_SWEEP_BATCH,
            )
            retry_in_progress_count = sum(1 for e in sample if e["times_delivered"] > 1)

        consumer_lag = None
        consumer_lag_source = None
        try:
            groups_info = r.xinfo_groups(stream)
            for g in groups_info:
                if g.get("name") == group and "lag" in g:
                    consumer_lag = g["lag"]
                    consumer_lag_source = "xinfo_groups"
                    break
            if consumer_lag is None:
                consumer_lag_source = "unsupported_redis_version"
        except Exception:  # noqa: BLE001 -- XINFO GROUPS lag support varies by Redis version; absence is not a health-check failure
            consumer_lag_source = "unsupported_redis_version"

        active_consumer_count = None
        least_idle_consumer_ms = None
        try:
            consumers_info = r.xinfo_consumers(stream, group)
            active_consumer_count = len(consumers_info)
            if consumers_info:
                least_idle_consumer_ms = min(c["idle"] for c in consumers_info)
        except Exception:  # noqa: BLE001, S110 -- absence of consumer info (e.g. group never had a consumer yet) is not a health-check failure; nothing to log beyond what the caller already sees as active_consumer_count=None
            pass

        return RedisPipelineHealth(
            available=True,
            pending_count=pending_count,
            oldest_pending_age_seconds=oldest_pending_age_seconds,
            retry_in_progress_count=retry_in_progress_count,
            consumer_lag=consumer_lag,
            consumer_lag_source=consumer_lag_source,
            stream_length=stream_length,
            active_consumer_count=active_consumer_count,
            least_idle_consumer_ms=least_idle_consumer_ms,
        )
    except Exception as e:  # noqa: BLE001 -- a health check must degrade to "unavailable", never raise/crash its caller
        return RedisPipelineHealth(available=False, error=type(e).__name__)


def get_persistence_pipeline_health(db: Session) -> PersistencePipelineHealth:
    try:
        last_success = db.query(func.max(AuditEventRecord.created_at)).scalar()
        quarantine_count = db.query(func.count(QuarantinedAuditEvent.stream_message_id)).scalar()
        last_quarantine = db.query(func.max(QuarantinedAuditEvent.quarantined_at)).scalar()
        return PersistencePipelineHealth(
            available=True,
            last_successful_persistence_at=last_success,
            quarantine_count=quarantine_count or 0,
            last_quarantine_at=last_quarantine,
        )
    except Exception as e:  # noqa: BLE001 -- same degrade-not-crash contract as the Redis side
        return PersistencePipelineHealth(available=False, error=type(e).__name__)


def get_pipeline_health(reader, db: Session) -> AuditPipelineHealth:
    return AuditPipelineHealth(
        generated_at=datetime.now(timezone.utc),
        redis=get_redis_pipeline_health(reader),
        persistence=get_persistence_pipeline_health(db),
    )
