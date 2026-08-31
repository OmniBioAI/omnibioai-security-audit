from datetime import datetime

from sqlalchemy.orm import Session

from db.models import AuditEventRecord


def list_audit_events(
    db: Session,
    page: int,
    page_size: int,
    user_id: str | None = None,
    organization_id: str | None = None,
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
    if organization_id is not None:
        query = query.filter(AuditEventRecord.organization_id == organization_id)
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


SAFE_METADATA_KEYS = frozenset({"trace_id", "request_id", "workflow_id", "run_id", "resource_type", "resource_id", "backend"})


def project_safe_metadata(row: AuditEventRecord) -> dict[str, object]:
    context = row.context if isinstance(row.context, dict) else {}
    return {key: context[key] for key in SAFE_METADATA_KEYS if key in context}


def list_safe_audit_events(
    db: Session, *, page: int, page_size: int, organization_id: str | None,
    platform_wide: bool, user_id: str | None = None, service: str | None = None,
    event_type: str | None = None, decision: str | None = None,
    from_timestamp: datetime | None = None, to_timestamp: datetime | None = None,
    integrity_status: str | None = None,
) -> tuple[list[AuditEventRecord], int]:
    """Tenant-safe SQL query; scope is applied before count and pagination."""
    query = db.query(AuditEventRecord)
    if not platform_wide:
        query = query.filter(
            AuditEventRecord.organization_id == organization_id,
            AuditEventRecord.tenant_scope == "organization",
        )
    elif organization_id is not None:
        query = query.filter(AuditEventRecord.organization_id == organization_id)
    for column, value in (
        (AuditEventRecord.user_id, user_id), (AuditEventRecord.service, service),
        (AuditEventRecord.event_type, event_type), (AuditEventRecord.decision, decision),
        (AuditEventRecord.integrity_status, integrity_status),
    ):
        if value is not None:
            query = query.filter(column == value)
    if from_timestamp is not None:
        query = query.filter(AuditEventRecord.timestamp >= from_timestamp)
    if to_timestamp is not None:
        query = query.filter(AuditEventRecord.timestamp <= to_timestamp)
    total = query.count()
    rows = query.order_by(
        AuditEventRecord.timestamp.desc(), AuditEventRecord.event_id.desc()
    ).offset((page - 1) * page_size).limit(page_size).all()
    return rows, total
