"""V2-002 (Track E2): services/audit_health_service.py -- pipeline
observability, computed live from Redis + MySQL state. Same "unknown is
never fabricated as health" discipline as audit/source_semantics.py's
own existing tests.

Track E4 (breadth pass) added: _evaluate_health_alerts(), called from
get_pipeline_health() after both sides are computed. Tests below
monkeypatch services.audit_health_service.emit_security_alert with a
recording stub -- this checks WHICH conditions get wired with WHAT
metadata, independent of security_alerts.py's own dedup/sink behavior
(already covered by tests/test_security_alerts.py).

Developer: Manish Kumar <manish@omnibioai.org>
"""
from datetime import datetime

import pytest

from db.models import AuditEventRecord, QuarantinedAuditEvent
from services import audit_health_service
from services.audit_health_service import (
    get_persistence_pipeline_health,
    get_pipeline_health,
    get_redis_pipeline_health,
)

# ---------------------------------------------------------------------------
# Redis side
# ---------------------------------------------------------------------------

def test_redis_health_reports_zero_pending_cleanly(stream_reader):
    """Report Redis as available with zero pending, no oldest-pending age, and the consumer lag
    sourced from xinfo_groups."""
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
    """Report the pending count, oldest pending age, retry-in-progress count, and active/idle
    consumer stats from a real backlog."""
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
    """Report Redis as unavailable with the error name, and never fabricate a pending count, when
    the connection fails."""
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


def test_redis_health_missing_xinfo_consumers_support_is_not_a_failure(stream_reader):
    """A Redis version/state where XINFO CONSUMERS itself fails (e.g. the
    consumer group has never had a consumer) must degrade only the
    consumer-stat fields, not the whole health check."""
    reader, mock_redis = stream_reader
    mock_redis.xlen.return_value = 0
    mock_redis.xpending.return_value = {"pending": 0}
    mock_redis.xinfo_groups.return_value = [{"name": "audit-workers", "lag": 0}]
    mock_redis.xinfo_consumers.side_effect = Exception("NOGROUP")

    health = get_redis_pipeline_health(reader)

    assert health.available is True
    assert health.active_consumer_count is None
    assert health.least_idle_consumer_ms is None


# ---------------------------------------------------------------------------
# Persistence (MySQL) side
# ---------------------------------------------------------------------------

def test_persistence_health_with_empty_tables(db_session):
    """Report persistence as available with no last-success time and zero quarantine when both
    tables are empty."""
    health = get_persistence_pipeline_health(db_session)

    assert health.available is True
    assert health.last_successful_persistence_at is None
    assert health.quarantine_count == 0
    assert health.last_quarantine_at is None


def test_persistence_health_reports_last_success_and_quarantine_count(db_session):
    """Report the last successful persistence time and the quarantine count from seeded rows."""
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
    """Report persistence as unavailable with the error set, and never fabricate a quarantine count,
    when the database query fails."""
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

def test_get_pipeline_health_combines_both_sides(stream_reader, db_session, recording_alerts):
    """Combine Redis and persistence health under one timezone-aware generated_at timestamp."""
    reader, mock_redis = stream_reader
    mock_redis.xlen.return_value = 0
    mock_redis.xpending.return_value = {"pending": 0}
    mock_redis.xinfo_groups.return_value = []
    mock_redis.xinfo_consumers.return_value = [{"name": "worker-1", "pending": 0, "idle": 100}]

    health = get_pipeline_health(reader, db_session)

    assert isinstance(health.generated_at, datetime)
    assert health.generated_at.tzinfo is not None
    assert health.redis.available is True
    assert health.persistence.available is True


# ---------------------------------------------------------------------------
# Track E4 (breadth pass): alert wiring
# ---------------------------------------------------------------------------

class _RecordedCall:
    """Capture the keyword arguments of one emit_security_alert call for assertion."""

    def __init__(self, kwargs):
        self.condition = kwargs.get("condition")
        self.severity = kwargs.get("severity")
        self.component = kwargs.get("component")
        self.metadata = kwargs.get("metadata")


@pytest.fixture
def recording_alerts(monkeypatch):
    """Replace emit_security_alert with a recorder so tests can assert on which alerts fired."""
    calls = []

    def _fake_emit(**kwargs):
        calls.append(_RecordedCall(kwargs))

    monkeypatch.setattr(audit_health_service, "emit_security_alert", _fake_emit)
    return calls


def _consumers(idle_ms=100):
    """Build a single-consumer xinfo_consumers-style response with the given idle time."""
    return [{"name": "worker-1", "pending": 0, "idle": idle_ms}]


def test_redis_unavailable_fires_critical_alert(stream_reader, db_session, recording_alerts):
    """Fire a critical redis_stream_unavailable alert when the Redis connection fails."""
    reader, mock_redis = stream_reader
    mock_redis.xlen.side_effect = ConnectionError("redis unreachable")

    get_pipeline_health(reader, db_session)

    conditions = [c.condition for c in recording_alerts]
    assert "redis_stream_unavailable" in conditions
    fired = next(c for c in recording_alerts if c.condition == "redis_stream_unavailable")
    assert fired.severity == "critical"
    assert fired.component == "audit-delivery"


def test_no_consumer_ever_registered_fires_critical_alert(stream_reader, db_session, recording_alerts):
    """Fire a critical audit_worker_never_registered alert, but not a Redis-unavailable one, when no
    consumer has ever registered."""
    reader, mock_redis = stream_reader
    mock_redis.xlen.return_value = 0
    mock_redis.xpending.return_value = {"pending": 0}
    mock_redis.xinfo_groups.return_value = []
    mock_redis.xinfo_consumers.return_value = []  # nobody has ever registered

    get_pipeline_health(reader, db_session)

    conditions = [c.condition for c in recording_alerts]
    assert "audit_worker_never_registered" in conditions
    assert "redis_stream_unavailable" not in conditions  # redis itself is fine


def test_healthy_redis_with_a_registered_consumer_fires_no_availability_alerts(stream_reader, db_session, recording_alerts):
    """Fire no availability alerts when Redis is healthy and a consumer is registered."""
    reader, mock_redis = stream_reader
    mock_redis.xlen.return_value = 0
    mock_redis.xpending.return_value = {"pending": 0}
    mock_redis.xinfo_groups.return_value = []
    mock_redis.xinfo_consumers.return_value = _consumers()

    get_pipeline_health(reader, db_session)

    conditions = [c.condition for c in recording_alerts]
    assert "redis_stream_unavailable" not in conditions
    assert "audit_worker_never_registered" not in conditions


def test_pel_pending_threshold_unconfigured_fires_nothing(stream_reader, db_session, recording_alerts, monkeypatch):
    """Fire no PEL backlog alert when the pending-count threshold is not configured, however large
    the backlog."""
    monkeypatch.delenv("AUDIT_ALERT_PEL_PENDING_THRESHOLD", raising=False)
    reader, mock_redis = stream_reader
    mock_redis.xlen.return_value = 100
    mock_redis.xpending.return_value = {"pending": 99999}  # would be "abnormal" by any reasonable guess
    mock_redis.xpending_range.return_value = []
    mock_redis.xinfo_groups.return_value = []
    mock_redis.xinfo_consumers.return_value = _consumers()

    get_pipeline_health(reader, db_session)

    assert "pel_backlog_threshold_exceeded" not in [c.condition for c in recording_alerts], \
        "must never fabricate a threshold that was never configured"


def test_pel_pending_threshold_configured_as_non_integer_fires_nothing(stream_reader, db_session, recording_alerts, monkeypatch):
    """Treat an unparseable threshold value the same as an unconfigured one -- evaluate nothing,
    never guess or crash."""
    monkeypatch.setenv("AUDIT_ALERT_PEL_PENDING_THRESHOLD", "not-a-number")
    reader, mock_redis = stream_reader
    mock_redis.xlen.return_value = 100
    mock_redis.xpending.return_value = {"pending": 99999}
    mock_redis.xpending_range.return_value = []
    mock_redis.xinfo_groups.return_value = []
    mock_redis.xinfo_consumers.return_value = _consumers()

    get_pipeline_health(reader, db_session)

    assert "pel_backlog_threshold_exceeded" not in [c.condition for c in recording_alerts]


def test_pel_pending_threshold_configured_and_exceeded_fires_warning(stream_reader, db_session, recording_alerts, monkeypatch):
    """Fire a warning PEL backlog alert, carrying the pending count and threshold, once the
    configured threshold is exceeded."""
    monkeypatch.setenv("AUDIT_ALERT_PEL_PENDING_THRESHOLD", "10")
    reader, mock_redis = stream_reader
    mock_redis.xlen.return_value = 100
    mock_redis.xpending.return_value = {"pending": 50}
    mock_redis.xpending_range.return_value = [
        {"message_id": "1-0", "consumer": "w1", "time_since_delivered": 1000, "times_delivered": 1},
    ]
    mock_redis.xinfo_groups.return_value = []
    mock_redis.xinfo_consumers.return_value = _consumers()

    get_pipeline_health(reader, db_session)

    fired = next(c for c in recording_alerts if c.condition == "pel_backlog_threshold_exceeded")
    assert fired.severity == "warning"
    assert fired.metadata["pending_count"] == 50
    assert fired.metadata["threshold"] == 10


def test_pel_pending_threshold_configured_but_not_exceeded_fires_nothing(stream_reader, db_session, recording_alerts, monkeypatch):
    """Fire no PEL backlog alert while the pending count stays under the configured threshold."""
    monkeypatch.setenv("AUDIT_ALERT_PEL_PENDING_THRESHOLD", "1000")
    reader, mock_redis = stream_reader
    mock_redis.xlen.return_value = 100
    mock_redis.xpending.return_value = {"pending": 5}
    mock_redis.xpending_range.return_value = [
        {"message_id": "1-0", "consumer": "w1", "time_since_delivered": 100, "times_delivered": 1},
    ]
    mock_redis.xinfo_groups.return_value = []
    mock_redis.xinfo_consumers.return_value = _consumers()

    get_pipeline_health(reader, db_session)

    assert "pel_backlog_threshold_exceeded" not in [c.condition for c in recording_alerts]


def test_pel_age_threshold_configured_and_exceeded_fires_warning(stream_reader, db_session, recording_alerts, monkeypatch):
    """Fire a warning alert carrying the oldest pending age once the configured age threshold is
    exceeded."""
    monkeypatch.setenv("AUDIT_ALERT_PEL_AGE_THRESHOLD_SECONDS", "60")
    reader, mock_redis = stream_reader
    mock_redis.xlen.return_value = 10
    mock_redis.xpending.return_value = {"pending": 1}
    mock_redis.xpending_range.return_value = [
        {"message_id": "1-0", "consumer": "w1", "time_since_delivered": 120000, "times_delivered": 1},  # 120s
    ]
    mock_redis.xinfo_groups.return_value = []
    mock_redis.xinfo_consumers.return_value = _consumers()

    get_pipeline_health(reader, db_session)

    fired = next(c for c in recording_alerts if c.condition == "pel_entry_age_threshold_exceeded")
    assert fired.severity == "warning"
    assert fired.metadata["oldest_pending_age_seconds"] == 120.0


def test_worker_stall_threshold_configured_and_exceeded_fires_warning(stream_reader, db_session, recording_alerts, monkeypatch):
    """Fire a warning alert carrying the least-idle consumer's idle time once the configured stall
    threshold is exceeded."""
    monkeypatch.setenv("AUDIT_ALERT_WORKER_STALL_THRESHOLD_MS", "5000")
    reader, mock_redis = stream_reader
    mock_redis.xlen.return_value = 0
    mock_redis.xpending.return_value = {"pending": 0}
    mock_redis.xinfo_groups.return_value = []
    mock_redis.xinfo_consumers.return_value = _consumers(idle_ms=999999)

    get_pipeline_health(reader, db_session)

    fired = next(c for c in recording_alerts if c.condition == "audit_worker_stalled")
    assert fired.severity == "warning"
    assert fired.metadata["least_idle_consumer_ms"] == 999999


def test_audit_database_unavailable_fires_critical_alert(stream_reader, recording_alerts):
    """Fire a critical alert on the audit-persistence component when the database is unavailable."""
    from unittest.mock import MagicMock

    reader, mock_redis = stream_reader
    mock_redis.xlen.return_value = 0
    mock_redis.xpending.return_value = {"pending": 0}
    mock_redis.xinfo_groups.return_value = []
    mock_redis.xinfo_consumers.return_value = _consumers()

    broken_db = MagicMock()
    broken_db.query.side_effect = Exception("simulated MySQL outage")

    get_pipeline_health(reader, broken_db)

    fired = next(c for c in recording_alerts if c.condition == "audit_database_unavailable")
    assert fired.severity == "critical"
    assert fired.component == "audit-persistence"


def test_quarantine_count_threshold_unconfigured_fires_nothing(stream_reader, db_session, recording_alerts, monkeypatch):
    """Fire no quarantine-count alert when its threshold is not configured."""
    monkeypatch.delenv("AUDIT_ALERT_QUARANTINE_COUNT_THRESHOLD", raising=False)
    db_session.add(QuarantinedAuditEvent(stream_message_id="1-0", raw_data="{}", failure_category="malformed", delivery_attempts=5))
    db_session.commit()
    reader, mock_redis = stream_reader
    mock_redis.xlen.return_value = 0
    mock_redis.xpending.return_value = {"pending": 0}
    mock_redis.xinfo_groups.return_value = []
    mock_redis.xinfo_consumers.return_value = _consumers()

    get_pipeline_health(reader, db_session)

    assert "quarantine_count_threshold_exceeded" not in [c.condition for c in recording_alerts]


def test_quarantine_count_threshold_configured_and_exceeded_fires_warning(stream_reader, db_session, recording_alerts, monkeypatch):
    """Fire a warning alert carrying the quarantine count and threshold once the configured
    threshold is exceeded."""
    monkeypatch.setenv("AUDIT_ALERT_QUARANTINE_COUNT_THRESHOLD", "1")
    db_session.add(QuarantinedAuditEvent(stream_message_id="1-0", raw_data="{}", failure_category="malformed", delivery_attempts=5))
    db_session.add(QuarantinedAuditEvent(stream_message_id="2-0", raw_data="{}", failure_category="malformed", delivery_attempts=5))
    db_session.commit()
    reader, mock_redis = stream_reader
    mock_redis.xlen.return_value = 0
    mock_redis.xpending.return_value = {"pending": 0}
    mock_redis.xinfo_groups.return_value = []
    mock_redis.xinfo_consumers.return_value = _consumers()

    get_pipeline_health(reader, db_session)

    fired = next(c for c in recording_alerts if c.condition == "quarantine_count_threshold_exceeded")
    assert fired.severity == "warning"
    assert fired.metadata["quarantine_count"] == 2
    assert fired.metadata["threshold"] == 1


def test_alert_evaluation_never_raises_even_if_emit_itself_is_broken(stream_reader, db_session, monkeypatch):
    """The blanket try/except in _evaluate_health_alerts must protect the
    health response even from a bug in the alerting call itself -- not
    just from a working-but-unavailable sink (already covered in
    test_security_alerts.py)."""
    reader, mock_redis = stream_reader
    mock_redis.xlen.side_effect = ConnectionError("redis unreachable")  # triggers an alert condition

    def _broken_emit(**kwargs):
        raise RuntimeError("simulated bug in alert emission itself")

    monkeypatch.setattr(audit_health_service, "emit_security_alert", _broken_emit)

    health = get_pipeline_health(reader, db_session)  # must not raise

    assert health.redis.available is False  # the underlying health fact is still correctly reported
