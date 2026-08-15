from datetime import datetime

from sqlalchemy.orm import Session

from db.models import AuditEventRecord


def list_audit_events(
    db: Session,
    page: int,
    page_size: int,
    user_id: str | None = None,
    service: str | None = None,
    event_type: str | None = None,
    decision: str | None = None,
    from_timestamp: datetime | None = None,
    to_timestamp: datetime | None = None,
    integrity_status: str | None = None,
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
    if integrity_status is not None:
        query = query.filter(AuditEventRecord.integrity_status == integrity_status)

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
