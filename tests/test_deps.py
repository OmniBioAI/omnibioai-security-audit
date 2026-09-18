"""PR4.3: api/deps.py::require_platform_admin -- the platform-admin gate for
GET /audit/events. Mirrors the coverage of
omnibioai-control-center/backend/tests/test_core_auth.py::TestRequireAdmin,
adapted to this repo's plain-pytest style and the platform_admin role.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import datetime as dt

import jwt
import pytest
from fastapi import HTTPException

from api import deps as deps_module
from audit import jwt_verify as jwt_verify_module

SECRET = "test-secret"


def _token(**claims):
    """Sign an HS256 test token with the shared test secret, applying any extra claims."""
    return jwt.encode(claims, SECRET, algorithm="HS256")


@pytest.fixture(autouse=True)
def _patch_secret(monkeypatch):
    """Point the JWT verifier at the shared test secret for every test in this module."""
    # SSO Phase 2 PR3: decoding now happens in audit.jwt_verify, not here
    # -- deps_module no longer has its own JWT_SECRET to patch.
    monkeypatch.setattr(jwt_verify_module, "JWT_SECRET", SECRET)


def test_missing_header_raises_401():
    """Reject a missing Authorization header with 401."""
    with pytest.raises(HTTPException) as exc:
        deps_module.require_platform_admin(None)
    assert exc.value.status_code == 401


def test_non_bearer_header_raises_401():
    """Reject a non-Bearer Authorization scheme with 401."""
    with pytest.raises(HTTPException) as exc:
        deps_module.require_platform_admin("Basic abc123")
    assert exc.value.status_code == 401


def test_invalid_token_raises_401():
    """Reject an undecodable token with 401."""
    with pytest.raises(HTTPException) as exc:
        deps_module.require_platform_admin("Bearer not-a-real-token")
    assert exc.value.status_code == 401


def test_expired_token_raises_401():
    """Reject an expired token with 401."""
    token = jwt.encode(
        {
            "sub": "1",
            "roles": ["platform_admin"],
            "exp": dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1),
        },
        SECRET,
        algorithm="HS256",
    )
    with pytest.raises(HTTPException) as exc:
        deps_module.require_platform_admin(f"Bearer {token}")
    assert exc.value.status_code == 401


def test_valid_token_without_platform_admin_role_raises_403():
    """An org_admin token must not pass -- audit logs are platform-admin
    only, never exposed to organization admins."""
    token = _token(sub="1", roles=["org_admin"])
    with pytest.raises(HTTPException) as exc:
        deps_module.require_platform_admin(f"Bearer {token}")
    assert exc.value.status_code == 403


def test_valid_token_missing_roles_claim_raises_403():
    """Reject a valid token that carries no roles claim with 403."""
    token = _token(sub="1")
    with pytest.raises(HTTPException) as exc:
        deps_module.require_platform_admin(f"Bearer {token}")
    assert exc.value.status_code == 403


def test_org_admin_with_multiple_roles_still_denied():
    """Deny a token whose roles include org_admin but not platform_admin."""
    token = _token(sub="1", roles=["org_admin", "team_lead"])
    with pytest.raises(HTTPException) as exc:
        deps_module.require_platform_admin(f"Bearer {token}")
    assert exc.value.status_code == 403


def test_valid_platform_admin_token_returns_payload():
    """Return the decoded payload for a token carrying the platform_admin role."""
    token = _token(sub="1", roles=["platform_admin"])
    payload = deps_module.require_platform_admin(f"Bearer {token}")
    assert payload["sub"] == "1"
    assert "platform_admin" in payload["roles"]


def test_bearer_prefix_case_insensitive():
    """Accept a lowercase bearer scheme prefix."""
    token = _token(sub="1", roles=["platform_admin"])
    payload = deps_module.require_platform_admin(f"bearer {token}")
    assert "platform_admin" in payload["roles"]
