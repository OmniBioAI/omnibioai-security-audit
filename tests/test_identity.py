"""PR4.4: audit/identity.py -- validates access tokens for audit event
producers and derives verified identity claims from them."""
import datetime as dt

import jwt
import pytest

from audit import jwt_verify as jwt_verify_module
from audit.identity import VerifiedIdentity, validate_identity_token

SECRET = "test-secret"


def _token(**claims):
    return jwt.encode(claims, SECRET, algorithm="HS256")


@pytest.fixture(autouse=True)
def _patch_secret(monkeypatch):
    # SSO Phase 2 PR3: decoding now happens in audit.jwt_verify, not here
    # -- identity_module no longer has its own JWT_SECRET to patch.
    monkeypatch.setattr(jwt_verify_module, "JWT_SECRET", SECRET)


def test_none_token_returns_none():
    assert validate_identity_token(None) is None


def test_empty_token_returns_none():
    assert validate_identity_token("") is None


def test_malformed_token_returns_none():
    assert validate_identity_token("not-a-real-token") is None


def test_wrong_signature_returns_none():
    token = jwt.encode({"sub": "1"}, "a-different-secret", algorithm="HS256")
    assert validate_identity_token(token) is None


def test_expired_token_returns_none():
    token = jwt.encode(
        {
            "sub": "1",
            "exp": dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1),
        },
        SECRET,
        algorithm="HS256",
    )
    assert validate_identity_token(token) is None


def test_missing_sub_claim_returns_none():
    token = _token(email="nosub@omnibioai.test")
    assert validate_identity_token(token) is None


def test_valid_token_returns_verified_identity():
    token = _token(
        sub="42",
        email="alice@omnibioai.test",
        roles=["org_admin"],
        org_id=7,
        org_role=["admin"],
    )
    result = validate_identity_token(token)

    assert isinstance(result, VerifiedIdentity)
    assert result.sub == "42"
    assert result.email == "alice@omnibioai.test"
    assert result.roles == ["org_admin"]
    assert result.org_id == 7
    assert result.org_role == ["admin"]


def test_valid_token_minimal_claims_defaults_gracefully():
    """Only `sub` is required -- a token with no email/roles/org_id (e.g. a
    service token) must not raise, and must default to empty/None rather
    than sharing mutable state across instances (the PR4.1 mutable-default
    lesson -- see VerifiedIdentity's field(default_factory=list))."""
    token = _token(sub="99")
    result = validate_identity_token(token)

    assert result.sub == "99"
    assert result.email is None
    assert result.roles == []
    assert result.org_id is None
    assert result.org_role == []


def test_verified_identity_instances_do_not_share_mutable_defaults():
    a = VerifiedIdentity(sub="a")
    b = VerifiedIdentity(sub="b")
    a.roles.append("should-not-leak")
    assert b.roles == []


def test_non_string_sub_claim_returns_none():
    """PyJWT enforces RFC 7519's `sub` must be a string at decode time
    (raises InvalidSubjectError, a subclass of InvalidTokenError) --
    omnibioai-auth always signs sub as str(user.id), so this never fires
    against a real token, but it's still routed through the same
    catch-all InvalidTokenError handling as every other malformed case."""
    token = jwt.encode({"sub": 42}, SECRET, algorithm="HS256")
    assert validate_identity_token(token) is None


def test_as_context_shape():
    identity = VerifiedIdentity(
        sub="1", email="a@b.com", roles=["r1"], org_id=1, org_role=["r2"]
    )
    ctx = identity.as_context()
    assert ctx == {
        "identity": {
            "sub": "1",
            "email": "a@b.com",
            "roles": ["r1"],
            "org_id": 1,
            "org_role": ["r2"],
            "verified": True,
        }
    }
