"""Opt-in Skills audit receipt and durable health API."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import ValidationError
from sqlalchemy.orm import Session

from api.deps_skills_audit import (
    require_skills_audit_reader,
    require_skills_audit_writer,
)
from audit.skills_contract import (
    PolicyAuditEventV1,
    SkillsAuditEventV1,
)
from db.session import get_db, get_writer_db
from services.skills_audit_receipts import (
    AuditIdempotencyConflict,
    AuditTenantMismatch,
    DurableReceiptService,
    ReceiptIntegrityError,
    SkillsAuditDisabled,
    SkillsAuditSettings,
    SQLReceiptStore,
)

router = APIRouter(prefix="/audit/receipts", tags=["skills-audit"])


def _service(request: Request, db: Session) -> DurableReceiptService:
    settings = SkillsAuditSettings.from_env()
    try:
        signer = settings.build_signer()
    except SkillsAuditDisabled as exc:
        raise HTTPException(
            status_code=503, detail="Skills durable audit is disabled"
        ) from exc
    verifiers = getattr(request.app.state, "skills_receipt_verifiers", None)
    if verifiers is None:
        verifiers = {signer.key_id: signer}
    return DurableReceiptService(
        store=SQLReceiptStore(
            db,
            principal_key=settings.principal_pseudonymization_key or "",
        ),
        signer=signer,
        verifiers=verifiers,
    )


def get_live_receipt_service(
    request: Request,
    db: Session = Depends(get_writer_db),  # noqa: B008 - FastAPI dependency injection
) -> DurableReceiptService:
    return _service(request, db)


def get_live_receipt_reader_service(
    request: Request,
    db: Session = Depends(get_db),  # noqa: B008 - FastAPI dependency injection
) -> DurableReceiptService:
    return _service(request, db)


def _event(payload: dict[str, Any]) -> SkillsAuditEventV1 | PolicyAuditEventV1:
    if len(json.dumps(payload, separators=(",", ":")).encode()) > 16 * 1024:
        raise HTTPException(status_code=413, detail="Audit event exceeds size limit")
    try:
        if payload.get("schema_version") == "skills-audit/v1":
            return SkillsAuditEventV1.model_validate(payload)
        return PolicyAuditEventV1.model_validate(payload)
    except ValidationError as exc:
        raise HTTPException(
            status_code=422, detail="Audit event schema rejected"
        ) from exc


def _translate_service_error(exc: Exception) -> HTTPException:
    if isinstance(exc, AuditTenantMismatch):
        return HTTPException(status_code=403, detail="Audit tenant binding rejected")
    if isinstance(exc, AuditIdempotencyConflict):
        return HTTPException(status_code=409, detail="Audit idempotency conflict")
    if isinstance(exc, ReceiptIntegrityError):
        return HTTPException(status_code=503, detail="Durable receipt integrity failed")
    if isinstance(exc, SkillsAuditDisabled):
        return HTTPException(status_code=503, detail="Skills durable audit is disabled")
    return HTTPException(status_code=503, detail="Durable audit service unavailable")


@router.get("/health")
def receipt_health(
    tenant_id: str = Depends(require_skills_audit_writer),
    service: DurableReceiptService = Depends(get_live_receipt_service),  # noqa: B008
) -> dict[str, object]:
    del tenant_id
    try:
        if not service.health(require_durable=True):
            raise SkillsAuditDisabled("durable receipt store is unavailable")
    except Exception as exc:
        raise _translate_service_error(exc) from exc
    return {"durable": True, "source": "security-audit"}


@router.post("")
def create_receipt(
    payload: dict[str, Any],
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    tenant_id: str = Depends(require_skills_audit_writer),
    service: DurableReceiptService = Depends(get_live_receipt_service),  # noqa: B008
) -> dict[str, Any]:
    event = _event(payload)
    try:
        receipt = service.emit(
            event,
            idempotency_key=idempotency_key or event.event_id,
            verified_tenant=tenant_id,
        )
    except Exception as exc:
        raise _translate_service_error(exc) from exc
    return receipt.model_dump(mode="json")


@router.get("/{event_id}")
def get_receipt(
    event_id: str,
    tenant_id: str = Depends(require_skills_audit_reader),
    service: DurableReceiptService = Depends(get_live_receipt_reader_service),  # noqa: B008
) -> dict[str, Any]:
    try:
        receipt = service.get(event_id=event_id, verified_tenant=tenant_id)
    except Exception as exc:
        raise _translate_service_error(exc) from exc
    if receipt is None:
        raise HTTPException(status_code=404, detail="Audit receipt not found")
    return receipt.model_dump(mode="json")
