import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class AuditEvent(BaseModel):
    # default_factory ensures a new value is generated per instance --
    # `= str(uuid.uuid4())` / `= datetime.utcnow()` would evaluate once at
    # class-definition time, making every event share the same id/timestamp.
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    service: str
    event_type: str   # auth, iam, policy, tes

    user_id: str | None = None
    # First-class tenant provenance. This is intentionally separate from the
    # arbitrary context object: context is never an authority for tenant
    # isolation. Legacy payloads default to UNKNOWN, not GLOBAL.
    organization_id: str | None = None
    tenant_scope: Literal["organization", "global", "unknown"] = "unknown"
    action: str = ""
    resource: str | None = None

    decision: str | None = None  # allow / deny / success / fail
    reason: str | None = None

    trace_id: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_tenant_scope(self) -> "AuditEvent":
        # Supplying a first-class organization ID is itself an authoritative
        # organization-scoped declaration. The explicit discriminator is
        # still emitted so readers can distinguish legacy UNKNOWN from GLOBAL.
        if self.organization_id is not None and self.tenant_scope == "unknown":
            self.tenant_scope = "organization"
        if self.tenant_scope == "organization" and self.organization_id is None:
            raise ValueError("organization tenant scope requires organization_id")
        if self.tenant_scope != "organization" and self.organization_id is not None:
            raise ValueError("organization_id requires organization tenant scope")
        return self
