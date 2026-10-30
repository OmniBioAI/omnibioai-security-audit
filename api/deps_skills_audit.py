"""Fail-closed workload identity port for the opt-in Skills audit API."""

from __future__ import annotations

from typing import Protocol

from fastapi import Header, HTTPException, Request

SKILLS_AUDIT_WRITE_SCOPE = "audit.events.write:skills"
SKILLS_AUDIT_READ_SCOPE = "audit.receipts.read:skills"


class SkillsWorkloadVerifier(Protocol):
    def verify(self, token: str, *, required_scope: str) -> str: ...


def _verified_tenant(
    request: Request,
    authorization: str | None,
    *,
    scope: str,
) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Workload bearer token required")
    token = authorization[7:].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Workload bearer token required")
    verifier: SkillsWorkloadVerifier | None = getattr(
        request.app.state, "skills_workload_verifier", None
    )
    if verifier is None:
        raise HTTPException(
            status_code=503, detail="Workload identity verifier unavailable"
        )
    try:
        tenant_id = verifier.verify(token, required_scope=scope)
    except Exception as exc:
        raise HTTPException(
            status_code=403, detail="Workload identity rejected"
        ) from exc
    if (
        not isinstance(tenant_id, str)
        or not tenant_id
        or len(tenant_id) > 255
        or not tenant_id.isascii()
        or not tenant_id.isdecimal()
        or (tenant_id != "0" and tenant_id.startswith("0"))
    ):
        raise HTTPException(status_code=403, detail="Verified tenant is invalid")
    return tenant_id


def require_skills_audit_writer(
    request: Request,
    authorization: str | None = Header(default=None),
) -> str:
    return _verified_tenant(request, authorization, scope=SKILLS_AUDIT_WRITE_SCOPE)


def require_skills_audit_reader(
    request: Request,
    authorization: str | None = Header(default=None),
) -> str:
    return _verified_tenant(request, authorization, scope=SKILLS_AUDIT_READ_SCOPE)
