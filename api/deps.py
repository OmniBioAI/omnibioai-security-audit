from __future__ import annotations

from fastapi import Header, HTTPException

from audit.jwt_verify import TokenInvalid, verify_token

# omnibioai-auth's own authorization code deliberately checks the
# manage_all_orgs *permission*, never a role name, so the permission can
# move to a different role without breaking callers (see
# omnibioai-auth/app/rbac.py). This service has no database access to
# resolve permissions from role names, though -- the JWT only carries role
# names -- so, like control-center's require_admin does for "admin", this
# checks for the seeded "platform_admin" role by name instead.
PLATFORM_ADMIN_ROLE = "platform_admin"


def require_platform_admin(authorization: str | None = Header(default=None)) -> dict:
    """FastAPI dependency: 401 on missing/invalid/expired/revoked token, 403
    if the token is valid but lacks the platform_admin role. Returns the
    decoded payload.

    Signature/expiry/type/required-claims/revocation checking is delegated
    to audit.jwt_verify.verify_token (SSO Phase 2 PR3) -- this function
    only owns the Authorization-header parsing and the role-based
    authorization decision.

    Audit records are platform-admin only, never exposed to organization
    admins -- they contain security-sensitive administrative activity
    across the whole platform, not scoped to any one org.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Missing or malformed Authorization header")

    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = verify_token(token)
    except TokenInvalid as e:
        raise HTTPException(401, str(e))

    if PLATFORM_ADMIN_ROLE not in (payload.get("roles") or []):
        raise HTTPException(403, "Platform admin role required")

    return payload
