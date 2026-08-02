from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from db.models import AuditEventRecord


def list_audit_events(
    db: Session,
    page: int,
    page_size: int,
    user_id: Optional[str] = None,
    service: Optional[str] = None,
    event_type: Optional[str] = None,
    decision: Optional[str] = None,
    from_timestamp: Optional[datetime] = None,
    to_timestamp: Optional[datetime] = None,
) -> tuple[list[AuditEventRecord], int]:
    """Returns (page of AuditEventRecord rows, total matching rows).

    All filtering happens in SQL (no in-memory scan of the table), and
    pagination is applied after the count so `total` reflects every
    matching row, not just the current page. page/page_size are assumed
    already validated by the route layer (FastAPI Query(ge=..., le=...)).

    Ordering is deterministic -- timestamp DESC, event_id DESC as a
    tiebreaker for events sharing a timestamp -- so page boundaries don't
    shift between requests.
    """
    query = db.query(AuditEventRecord)

    if user_id is not None:
        query = query.filter(AuditEventRecord.user_id == user_id)
    if service is not None:
        query = query.filter(AuditEventRecord.service == service)
    if event_type is not None:
        query = query.filter(AuditEventRecord.event_type == event_type)
    if decision is not None:
        query = query.filter(AuditEventRecord.decision == decision)
    if from_timestamp is not None:
        query = query.filter(AuditEventRecord.timestamp >= from_timestamp)
    if to_timestamp is not None:
        query = query.filter(AuditEventRecord.timestamp <= to_timestamp)

    total = query.count()

    rows = (
        query.order_by(
            AuditEventRecord.timestamp.desc(), AuditEventRecord.event_id.desc()
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return rows, total
