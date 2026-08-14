from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from api.deps import require_platform_admin
from db.session import get_db
from schemas.audit import AuditEventListResponse
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
    user_id: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    decision: Optional[str] = Query(None),
    from_timestamp: Optional[datetime] = Query(None),
    to_timestamp: Optional[datetime] = Query(None),
    # HIPAA audit-integrity rollout: lets a platform_admin ask "show me
    # every event that failed signature verification" (integrity_status=
    # invalid) or isolate the still-unsigned backlog -- not just see the
    # field per-row. No validation beyond Optional[str]: the DB column
    # itself is the source of truth for what values exist ("valid"/
    # "invalid"/"unsigned" today, see audit/config.py's classifier), and
    # an unrecognized value here just filters to zero rows, not an error.
    integrity_status: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    _admin: dict = Depends(require_platform_admin),
) -> AuditEventListResponse:
    rows, total = audit_query_service.list_audit_events(
        db,
        page=page,
        page_size=page_size,
        user_id=user_id,
        service=service,
        event_type=event_type,
        decision=decision,
        from_timestamp=from_timestamp,
        to_timestamp=to_timestamp,
        integrity_status=integrity_status,
    )
    total_pages = (total + page_size - 1) // page_size if total else 0
    return AuditEventListResponse(
        items=rows,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )
