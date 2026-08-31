"""Authorization context for tenant-safe audit reads."""
from dataclasses import dataclass

from fastapi import Header, HTTPException

from audit.jwt_verify import TokenInvalid, verify_token

PLATFORM_WIDE_PERMISSION = "manage_all_orgs"
ORGANIZATION_READ_ROLE = "org_admin"


@dataclass(frozen=True)
class AuditAccess:
    platform_wide: bool
    organization_id: str | None


def require_audit_read_access(authorization: str | None = Header(default=None)) -> AuditAccess:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Missing or malformed Authorization header")
    try:
        payload = verify_token(authorization.split(" ", 1)[1].strip())
    except TokenInvalid as exc:
        raise HTTPException(401, str(exc)) from exc
    if PLATFORM_WIDE_PERMISSION in (payload.get("permissions") or []):
        return AuditAccess(platform_wide=True, organization_id=None)
    if ORGANIZATION_READ_ROLE not in (payload.get("org_role") or []):
        raise HTTPException(403, "Audit read permission required")
    org_id = payload.get("org_id")
    if isinstance(org_id, (dict, list, tuple, set)) or org_id in (None, ""):
        raise HTTPException(403, "Verified organization scope required")
    return AuditAccess(platform_wide=False, organization_id=str(org_id))
