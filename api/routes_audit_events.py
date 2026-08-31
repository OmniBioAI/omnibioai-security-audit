from datetime import datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from api.deps import require_platform_admin
from audit.source_semantics import available_query_evidence, unavailable_query_evidence
from db.session import get_db
from schemas.audit import (
    AuditEventListResponse,
    AuditEventOut,
    FreshnessOut,
    RetentionOut,
)
from services import audit_query_service

# Deliberately a separate router/module from routes_audit.py (/health,
# /audit/test -- the write-side ingestion smoke-test route): this is the
# read-side query API added in PR4.2's follow-up, PR4.3, and platform-admin
# gated, unlike /audit/test which has no auth at all today.
router = APIRouter()


@router.get("/audit/events", response_model=AuditEventListResponse)
def list_audit_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user_id: str | None = Query(None),
    service: str | None = Query(None),
    event_type: str | None = Query(None),
    decision: str | None = Query(None),
    from_timestamp: datetime | None = Query(None),  # noqa: B008 -- FastAPI's own documented query-param pattern, not a mutable-default bug
    to_timestamp: datetime | None = Query(None),  # noqa: B008 -- FastAPI's own documented query-param pattern, not a mutable-default bug
    # HIPAA audit-integrity rollout: lets a platform_admin ask "show me
    # every event that failed signature verification" (integrity_status=
    # invalid) or isolate the still-unsigned backlog -- not just see the
    # field per-row. No validation beyond `str | None`: the DB column
    # itself is the source of truth for what values exist ("valid"/
    # "invalid"/"unsigned" today, see audit/config.py's classifier), and
    # an unrecognized value here just filters to zero rows, not an error.
    integrity_status: str | None = Query(None),
    db: Session = Depends(get_db),  # noqa: B008 -- FastAPI's own documented dependency-injection pattern, not a mutable-default bug
    _admin: dict = Depends(require_platform_admin),  # noqa: B008 -- FastAPI's own documented dependency-injection pattern, not a mutable-default bug
) -> AuditEventListResponse:
    try:
        rows, total = audit_query_service.list_audit_events(
            db, page=page, page_size=page_size, user_id=user_id, service=service,
            event_type=event_type, decision=decision, from_timestamp=from_timestamp,
            to_timestamp=to_timestamp, integrity_status=integrity_status,
        )
    except SQLAlchemyError:
        evidence = unavailable_query_evidence()
        return JSONResponse(status_code=503, content={
            "error": "AUDIT_SOURCE_UNAVAILABLE", "source": "security_audit",
            "source_availability": evidence.availability.value,
            "generated_at": evidence.generated_at.isoformat(),
            "source_checked_at": evidence.source_checked_at.isoformat(),
            "warnings": list(evidence.warnings),
        })
    total_pages = (total + page_size - 1) // page_size if total else 0
    evidence = available_query_evidence()
    items = []
    for row in rows:
        item = AuditEventOut.model_validate(row)
        item.context = audit_query_service.project_safe_metadata(row)
        items.append(item)
    return AuditEventListResponse(
        source="security_audit",
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        source_availability=evidence.availability,
        generated_at=evidence.generated_at,
        source_checked_at=evidence.source_checked_at,
        freshness=FreshnessOut(status=evidence.freshness.status),
        retention=RetentionOut(status=evidence.retention.status),
        warnings=list(evidence.warnings),
    )
