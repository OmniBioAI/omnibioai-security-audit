"""
OmniBioAI api.routes_audit.

Purpose:
    Defines HTTP route handlers for api.routes_audit, including health and test_log.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

from fastapi import APIRouter
from audit.logger import AuditLogger

router = APIRouter()
logger = AuditLogger()


@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/audit/test")
async def test_log():
    from audit.models import AuditEvent
    from audit.config import AuditConfig

    await logger.log(
        AuditEvent(
            service=AuditConfig.SERVICE_NAME,
            event_type="test",
            action="health_check",
            decision="success",
        )
    )

    return {"logged": True}