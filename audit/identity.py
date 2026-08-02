"""PR4.4: validates identity tokens for in-process audit event producers
(audit/contexts.py::inject_context, consumed by audit/decorators.py).

Before this, inject_context(user_id=...) accepted a bare string with zero
verification -- any caller could attribute an audit event to any user_id.
This validates a real access token issued by omnibioai-auth and derives
identity fields from its signed claims instead.

Deliberately not a FastAPI dependency: audit producers call inject_context
directly from arbitrary in-process code, not from inside a request/response
cycle where Header()/HTTPException apply. SSO Phase 2 PR3: signature/
expiry/type/required-claims/revocation checking now lives in
audit/jwt_verify.py, shared with api/deps.py::require_platform_admin --
both this module and api/deps.py sit inside the `audit`-adjacent package
tree, so importing jwt_verify here pulls in no FastAPI dependency (unlike
importing api.deps directly would have, which is why PR4.4 originally kept
a separate decode call here instead of sharing api/deps.py's).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from audit.jwt_verify import TokenInvalid, verify_token


@dataclass(frozen=True)
class VerifiedIdentity:
    """Identity claims from a signature- and expiry-verified access token.
    Field names mirror omnibioai-auth's own token payload
    (app/services/auth_service.py::build_user_claims) so this stays a
    direct read of those claims, not a reinterpretation of them.
    """

    sub: str
    email: Optional[str] = None
    roles: list[str] = field(default_factory=list)
    org_id: Optional[int] = None
    org_role: list[str] = field(default_factory=list)

    def as_context(self) -> dict[str, Any]:
        """Shape stashed into AuditEvent.context (audit/decorators.py) --
        deliberately not new top-level AuditEvent/audit_events columns, so
        PR4.1-PR4.3's schema (Pydantic model, DB table, migrations, query
        API) needs zero changes for this PR."""
        return {
            "identity": {
                "sub": self.sub,
                "email": self.email,
                "roles": self.roles,
                "org_id": self.org_id,
                "org_role": self.org_role,
                "verified": True,
            }
        }


def validate_identity_token(token: Optional[str]) -> Optional[VerifiedIdentity]:
    """Returns a VerifiedIdentity for a token that passes verify_token()
    (signature, expiry, token type, required claims, not revoked); None
    for anything else.

    Never raises -- audit identity verification must never be able to
    break the calling service, the same fire-and-forget guarantee
    AuditLogger.log() already makes for the persistence side (PR4.1.5).
    A None return means "log the event without a verified identity," not
    "fail the caller's request."
    """
    try:
        payload = verify_token(token)
    except TokenInvalid:
        return None

    return VerifiedIdentity(
        sub=str(payload["sub"]),
        email=payload.get("email"),
        roles=payload.get("roles") or [],
        org_id=payload.get("org_id"),
        org_role=payload.get("org_role") or [],
    )
