from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime
import uuid


class AuditEvent(BaseModel):
    # default_factory ensures a new value is generated per instance --
    # `= str(uuid.uuid4())` / `= datetime.utcnow()` would evaluate once at
    # class-definition time, making every event share the same id/timestamp.
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    service: str
    event_type: str   # auth, iam, policy, tes

    user_id: Optional[str] = None
    action: str = ""
    resource: Optional[str] = None

    decision: Optional[str] = None  # allow / deny / success / fail
    reason: Optional[str] = None

    trace_id: Optional[str] = None
    context: Dict[str, Any] = {}