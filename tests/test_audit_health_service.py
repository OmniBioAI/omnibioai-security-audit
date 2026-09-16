"""V2-002 (Track E2): services/audit_health_service.py -- pipeline
observability, computed live from Redis + MySQL state. Same "unknown is
never fabricated as health" discipline as audit/source_semantics.py's
own existing tests.
"""
from datetime import datetime

from db.models import AuditEventRecord, QuarantinedAuditEvent
from services.audit_health_service import (
    get_persistence_pipeline_health,
    get_pipeline_health,
    get_redis_pipeline_health,
)

# ---------------------------------------------------------------------------
# Redis side
# ---------------------------------------------------------------------------

def test_redis_health_reports_zero_pending_cleanly(stream_reader):
    reader, mock_redis = stream_reader
    mock_redis.xlen.return_value = 0
    mock_redis.xpending.return_value = {"pending": 0}
    mock_redis.xinfo_groups.return_value = [{"name": "audit-workers", "lag": 0}]
    mock_redis.xinfo_consumers.return_value = []

    health = get_redis_pipeline_health(reader)

    assert health.available is True
    assert health.pending_count == 0
    assert health.oldest_pending_age_seconds is None  # nothing pending -- no age to report
    assert health.retry_in_progress_count is None
    assert health.consumer_lag == 0
    assert health.consumer_lag_source == "xinfo_groups"


def test_redis_health_reports_pending_backlog_and_oldest_age(stream_reader):
    reader, mock_redis = stream_reader
    mock_redis.xlen.return_value = 42
    mock_redis.xpending.return_value = {"pending": 3}
    mock_redis.xpending_range.return_value = [
        {"message_id": "1-0", "consumer": "w1", "time_since_delivered": 120000, "times_delivered": 2},
    ]
    mock_redis.xinfo_groups.return_value = []
    mock_redis.xinfo_consumers.return_value = [{"name": "worker-1", "pending": 3, "idle": 500}]

    health = get_redis_pipeline_health(reader)

    assert health.pending_count == 3
    assert health.oldest_pending_age_seconds == 120.0
    assert health.retry_in_progress_count == 1  # times_delivered > 1
    assert health.consumer_lag is None
    assert health.consumer_lag_source == "unsupported_redis_version"
    assert health.active_consumer_count == 1
    assert health.least_idle_consumer_ms == 500
    assert health.stream_length == 42


def test_redis_health_degrades_gracefully_on_connection_failure(stream_reader):
    reader, mock_redis = stream_reader
    mock_redis.xlen.side_effect = ConnectionError("redis unreachable")

    health = get_redis_pipeline_health(reader)

    assert health.available is False
    assert health.error == "ConnectionError"
    assert health.pending_count is None  # never fabricated


def test_redis_health_missing_xinfo_groups_support_is_not_a_failure(stream_reader):
    """Older Redis (<7.0) doesn't expose per-group `lag` -- must degrade
    that one field, not the whole health check."""
    reader, mock_redis = stream_reader
    mock_redis.xlen.return_value = 0
    mock_redis.xpending.return_value = {"pending": 0}
    mock_redis.xinfo_groups.side_effect = Exception("unknown command XINFO")
    mock_redis.xinfo_consumers.return_value = []

    health = get_redis_pipeline_health(reader)

    assert health.available is True
    assert health.consumer_lag is None
    assert health.consumer_lag_source == "unsupported_redis_version"


# ---------------------------------------------------------------------------
# Persistence (MySQL) side
# ---------------------------------------------------------------------------

def test_persistence_health_with_empty_tables(db_session):
    health = get_persistence_pipeline_health(db_session)

    assert health.available is True
    assert health.last_successful_persistence_at is None
    assert health.quarantine_count == 0
    assert health.last_quarantine_at is None


def test_persistence_health_reports_last_success_and_quarantine_count(db_session):
    db_session.add(AuditEventRecord(
        event_id="evt-1", timestamp=datetime(2026, 1, 1, 12, 0, 0),  # noqa: DTZ001 -- naive column, matches AuditEventRecord convention
        service="auth", event_type="login", action="login",
    ))
    db_session.add(QuarantinedAuditEvent(
        stream_message_id="1-0", raw_data="{}", failure_category="malformed",
        delivery_attempts=5,
    ))
    db_session.add(QuarantinedAuditEvent(
        stream_message_id="2-0", raw_data="{}", failure_category="persistence_exhausted",
        delivery_attempts=5,
    ))
    db_session.commit()

    health = get_persistence_pipeline_health(db_session)

    assert health.available is True
    assert health.last_successful_persistence_at is not None
    assert health.quarantine_count == 2
    assert health.last_quarantine_at is not None


def test_persistence_health_degrades_gracefully_on_db_failure():
    from unittest.mock import MagicMock

    broken_db = MagicMock()
    broken_db.query.side_effect = Exception("simulated MySQL outage")

    health = get_persistence_pipeline_health(broken_db)

    assert health.available is False
    assert health.error is not None
    assert health.quarantine_count is None  # never fabricated


# ---------------------------------------------------------------------------
# Combined
# ---------------------------------------------------------------------------

def test_get_pipeline_health_combines_both_sides(stream_reader, db_session):
    reader, mock_redis = stream_reader
    mock_redis.xlen.return_value = 0
    mock_redis.xpending.return_value = {"pending": 0}
    mock_redis.xinfo_groups.return_value = []
    mock_redis.xinfo_consumers.return_value = []

    health = get_pipeline_health(reader, db_session)

    assert isinstance(health.generated_at, datetime)
    assert health.generated_at.tzinfo is not None
    assert health.redis.available is True
    assert health.persistence.available is True
