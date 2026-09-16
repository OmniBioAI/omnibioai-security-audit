"""V2-002 (Track E2): GET /audit/pipeline-health -- machine-readable
delivery-pipeline observability (pending count, oldest pending age,
consumer lag, quarantine count, last successful persistence, worker
liveness proxy). Platform-admin gated, same convention as
routes_audit_events.py -- this exposes operational facts about the
security audit trail itself, not appropriate for general/org-scoped
access.

No monitoring/alerting platform is wired to this endpoint's output as
of Track E2 -- it is machine-readable evidence for one to consume, not
alerting infrastructure itself (see the Track E2 report's Observability
section for what remains a deployment prerequisite).
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.deps import require_platform_admin
from audit.config import AuditConfig
from consumers.stream_reader import StreamReader
from db.session import get_db
from services.audit_health_service import get_pipeline_health

router = APIRouter()


@router.get("/audit/pipeline-health")
def pipeline_health(
    db: Session = Depends(get_db),  # noqa: B008 -- FastAPI's own documented dependency-injection pattern
    _admin: dict = Depends(require_platform_admin),  # noqa: B008 -- same as above
):
    reader = StreamReader()
    health = get_pipeline_health(reader, db)
    return {
        "generated_at": health.generated_at.isoformat(),
        "stream": AuditConfig.STREAM_NAME,
        "consumer_group": AuditConfig.CONSUMER_GROUP,
        "redis": {
            "available": health.redis.available,
            "pending_count": health.redis.pending_count,
            "oldest_pending_age_seconds": health.redis.oldest_pending_age_seconds,
            "retry_in_progress_count": health.redis.retry_in_progress_count,
            "consumer_lag": health.redis.consumer_lag,
            "consumer_lag_source": health.redis.consumer_lag_source,
            "stream_length": health.redis.stream_length,
            "active_consumer_count": health.redis.active_consumer_count,
            "least_idle_consumer_ms": health.redis.least_idle_consumer_ms,
            "error": health.redis.error,
        },
        "persistence": {
            "available": health.persistence.available,
            "last_successful_persistence_at": (
                health.persistence.last_successful_persistence_at.isoformat()
                if health.persistence.last_successful_persistence_at else None
            ),
            "quarantine_count": health.persistence.quarantine_count,
            "last_quarantine_at": (
                health.persistence.last_quarantine_at.isoformat()
                if health.persistence.last_quarantine_at else None
            ),
            "error": health.persistence.error,
        },
        # V2-003 (Track E3) Phase 18: only populated if
        # AUDIT_HEALTH_STATUS_DIR is configured -- see
        # services/audit_health_service.py::RetentionIntegrityHealth's
        # own docstring for why this can't be computed live the way the
        # sections above are (retention/verification are external
        # script runs, not this process's own runtime state).
        "retention_integrity": {
            "status_source": health.retention_integrity.status_source,
            "last_integrity_verification_ts": health.retention_integrity.last_integrity_verification_ts,
            "last_integrity_verification_result": health.retention_integrity.last_integrity_verification_result,
            "last_integrity_events_invalid": health.retention_integrity.last_integrity_events_invalid,
            "last_retention_run_ts": health.retention_integrity.last_retention_run_ts,
            "last_retention_run_result": health.retention_integrity.last_retention_run_result,
            "last_retention_deleted_total": health.retention_integrity.last_retention_deleted_total,
        },
    }
