"""Explicit source evidence semantics; unknown evidence is never health."""
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum


class SourceAvailability(StrEnum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


class FreshnessStatus(StrEnum):
    CURRENT = "CURRENT"
    STALE = "STALE"
    UNKNOWN = "UNKNOWN"


class RetentionStatus(StrEnum):
    KNOWN = "KNOWN"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class RetentionEvidence:
    status: RetentionStatus = RetentionStatus.UNKNOWN
    retention_days: int | None = None
    oldest_available_event_at: datetime | None = None


@dataclass(frozen=True)
class FreshnessEvidence:
    status: FreshnessStatus = FreshnessStatus.UNKNOWN
    last_persisted_event_at: datetime | None = None
    ingestion_lag_seconds: float | None = None


@dataclass(frozen=True)
class SourceEvidence:
    availability: SourceAvailability
    generated_at: datetime
    source_checked_at: datetime
    freshness: FreshnessEvidence
    retention: RetentionEvidence
    warnings: tuple[str, ...] = ()


def _evidence(availability: SourceAvailability, warnings: tuple[str, ...]) -> SourceEvidence:
    now = datetime.now(timezone.utc)
    return SourceEvidence(availability, now, now, FreshnessEvidence(), RetentionEvidence(), warnings)


def available_query_evidence() -> SourceEvidence:
    return _evidence(SourceAvailability.AVAILABLE, ("freshness_unknown", "retention_unknown", "ingestion_lag_unknown"))


def unavailable_query_evidence() -> SourceEvidence:
    return _evidence(SourceAvailability.UNAVAILABLE, ("durable_query_unavailable",))
