from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from api.deps_audit import AuditAccess, require_audit_read_access
from audit.source_semantics import available_query_evidence, unavailable_query_evidence
from db.session import get_db
from schemas.audit import (
    FreshnessOut,
    RetentionOut,
    SafeAuditEventListResponse,
    SafeAuditEventOut,
)
from services import audit_query_service

router = APIRouter()


@router.get("/audit/events/safe", response_model=SafeAuditEventListResponse)
def list_safe_audit_events(
    page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
    user_id: str | None = Query(None, max_length=255), service: str | None = Query(None, max_length=255),
    event_type: str | None = Query(None, max_length=255), decision: str | None = Query(None, max_length=64),
    from_timestamp: datetime | None = Query(None),  # noqa: B008
    to_timestamp: datetime | None = Query(None),  # noqa: B008
    integrity_status: Literal["valid", "invalid", "unsigned", "unknown"] | None = Query(None),
    organization_id: str | None = Query(None, max_length=255),
    access: AuditAccess = Depends(require_audit_read_access),  # noqa: B008
    db: Session = Depends(get_db),  # noqa: B008
) -> SafeAuditEventListResponse | JSONResponse:
    if from_timestamp and to_timestamp and from_timestamp > to_timestamp:
        raise HTTPException(422, "from_timestamp must not be after to_timestamp")
    if not access.platform_wide and organization_id not in (None, access.organization_id):
        raise HTTPException(403, "organization_id is outside verified scope")
    effective_org = organization_id if access.platform_wide else access.organization_id
    try:
        rows, total = audit_query_service.list_safe_audit_events(
            db, page=page, page_size=page_size, organization_id=effective_org,
            platform_wide=access.platform_wide, user_id=user_id, service=service,
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
    evidence = available_query_evidence()
    items = [SafeAuditEventOut(
        event_id=row.event_id, timestamp=row.timestamp, organization_id=row.organization_id,
        tenant_scope=row.tenant_scope or "unknown", actor=row.user_id, event_type=row.event_type,
        action=row.action, decision=row.decision,
        integrity=row.integrity_status if row.integrity_status in {"valid", "invalid", "unsigned", "unknown"} else "unknown",
        metadata=audit_query_service.project_safe_metadata(row),
    ) for row in rows]
    return SafeAuditEventListResponse(
        source="security_audit", items=items, total=total, page=page, page_size=page_size,
        total_pages=(total + page_size - 1) // page_size if total else 0,
        source_availability=evidence.availability, generated_at=evidence.generated_at,
        source_checked_at=evidence.source_checked_at,
        freshness=FreshnessOut(**evidence.freshness.__dict__),
        retention=RetentionOut(**evidence.retention.__dict__),
        warnings=list(evidence.warnings),
    )
