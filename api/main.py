from fastapi import FastAPI

from api.routes_audit import router
from api.routes_audit_events import router as audit_events_router
from audit.config import AuditConfig

app = FastAPI(title=f"OmniBioAI Security Audit — {AuditConfig.SERVICE_NAME}")

app.include_router(router)
app.include_router(audit_events_router)
