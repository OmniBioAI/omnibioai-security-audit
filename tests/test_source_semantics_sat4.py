from datetime import timezone

from audit.source_semantics import (
    FreshnessStatus,
    RetentionStatus,
    SourceAvailability,
    available_query_evidence,
)


def test_available_evidence_keeps_unknown_dimensions_unknown():
    evidence = available_query_evidence()
    assert evidence.availability is SourceAvailability.AVAILABLE
    assert evidence.freshness.status is FreshnessStatus.UNKNOWN
    assert evidence.retention.status is RetentionStatus.UNKNOWN
    assert evidence.retention.retention_days is None
    assert evidence.retention.oldest_available_event_at is None
    assert evidence.freshness.ingestion_lag_seconds is None
    assert evidence.generated_at.tzinfo == timezone.utc
    assert evidence.source_checked_at.tzinfo == timezone.utc
