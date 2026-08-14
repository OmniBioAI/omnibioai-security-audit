from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict


class AuditEventOut(BaseModel):
    """Read-model for one audit_events row (db/models.py::AuditEventRecord).
    Field names mirror AuditEvent (audit/models.py) exactly -- this is a
    read view of the same durable data, not a new shape."""

    model_config = ConfigDict(from_attributes=True)

    event_id: str
    timestamp: datetime
    service: str
    event_type: str
    user_id: Optional[str] = None
    action: str
    resource: Optional[str] = None
    decision: Optional[str] = None
    reason: Optional[str] = None
    trace_id: Optional[str] = None
    context: dict[str, Any]
    created_at: datetime
    # HIPAA audit-integrity rollout: PR2/PR#5 added this column and the
    # worker has classified every event ("valid"/"invalid"/"unsigned")
    # since PR3a's deployment, but nothing surfaced it through this read
    # API until now -- a platform_admin querying /audit/events had no way
    # to see whether any event was ever actually verified. Always present
    # (DB column is NOT NULL with server_default="unsigned"), never
    # Optional -- matches AuditEventRecord.integrity_status exactly.
    integrity_status: str


class AuditEventListResponse(BaseModel):
    """Pagination shape matches omnibioai-auth's existing platform-admin
    list responses (app/schemas/platform_admin.py::PlatformOrgListOut) --
    items/total/page/page_size/total_pages, the established convention
    across the platform's paginated platform-admin endpoints."""

    items: list[AuditEventOut]
    total: int
    page: int
    page_size: int
    total_pages: int
