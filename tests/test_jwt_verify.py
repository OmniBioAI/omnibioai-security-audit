"""SSO Phase 2 PR3: audit/jwt_verify.py -- the shared local JWT verifier
(signature, expiry, token type, required claims, Redis jti-blacklist
revocation) both api/deps.py and audit/identity.py now delegate to.
"""
import datetime as dt
from unittest.mock import MagicMock

import jwt
import pytest

from audit import jwt_verify as jwt_verify_module
from audit.jwt_verify import TokenInvalid, verify_token

SECRET = "test-secret"


def _token(**claims):
    return jwt.encode(claims, SECRET, algorithm="HS256")


@pytest.fixture(autouse=True)
def _patch_secret(monkeypatch):
    monkeypatch.setattr(jwt_verify_module, "JWT_SECRET", SECRET)


@pytest.fixture(autouse=True)
def mock_blacklist(monkeypatch):
    """Every test in this file gets a blacklist that reports 'not
    revoked' by default -- tests that specifically exercise revocation
    override .exists.return_value themselves."""
    mock = MagicMock()
    mock.exists.return_value = False
    monkeypatch.setattr(jwt_verify_module, "_blacklist", mock)
    return mock


# ---------------------------------------------------------------------------
# Success path
# ---------------------------------------------------------------------------

def test_valid_token_succeeds():
    token = _token(sub="1", roles=["platform_admin"], type="access")
    payload = verify_token(token)
    assert payload["sub"] == "1"
    assert payload["roles"] == ["platform_admin"]


def test_valid_token_without_type_claim_succeeds():
    """Every pre-PR3 test fixture in this repo omits `type` entirely --
    must keep working unmodified."""
    token = _token(sub="1")
    payload = verify_token(token)
    assert payload["sub"] == "1"


# ---------------------------------------------------------------------------
# Failure paths
# ---------------------------------------------------------------------------

def test_missing_token_raises():
    with pytest.raises(TokenInvalid):
        verify_token(None)
    with pytest.raises(TokenInvalid):
        verify_token("")


def test_invalid_signature_raises():
    token = jwt.encode({"sub": "1"}, "wrong-secret", algorithm="HS256")
    with pytest.raises(TokenInvalid):
        verify_token(token)


def test_malformed_token_raises():
    with pytest.raises(TokenInvalid):
        verify_token("not-a-real-token")


def test_expired_token_raises():
    token = jwt.encode(
        {"sub": "1", "exp": dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)},
        SECRET,
        algorithm="HS256",
    )
    with pytest.raises(TokenInvalid):
        verify_token(token)


def test_missing_sub_claim_raises():
    token = _token(email="x@y.com")
    with pytest.raises(TokenInvalid):
        verify_token(token)


def test_wrong_token_type_raises():
    """omnibioai-auth signs refresh tokens with the SAME claim set as
    access tokens (build_user_claims) -- differing only in `type` and TTL
    (7 days vs 15 minutes). Before this check, a leaked refresh token
    granted the same access as a stolen access token, for up to 7 days
    instead of 15 minutes."""
    token = _token(sub="1", roles=["platform_admin"], type="refresh")
    with pytest.raises(TokenInvalid):
        verify_token(token)


def test_other_token_types_also_rejected():
    for bad_type in ("oauth_state", "sso_state", "oauth_link"):
        token = _token(sub="1", type=bad_type)
        with pytest.raises(TokenInvalid):
            verify_token(token)


# ---------------------------------------------------------------------------
# Revocation (Redis jti blacklist)
# ---------------------------------------------------------------------------

def test_blacklisted_jti_raises(mock_blacklist):
    mock_blacklist.exists.return_value = True
    token = _token(sub="1", jti="revoked-jti-123")
    with pytest.raises(TokenInvalid):
        verify_token(token)
    mock_blacklist.exists.assert_called_once_with("blacklist:jti:revoked-jti-123")


def test_non_blacklisted_jti_succeeds(mock_blacklist):
    mock_blacklist.exists.return_value = False
    token = _token(sub="1", jti="fine-jti-456")
    payload = verify_token(token)
    assert payload["sub"] == "1"


def test_token_without_jti_skips_blacklist_check(mock_blacklist):
    token = _token(sub="1")  # no jti claim at all
    payload = verify_token(token)
    assert payload["sub"] == "1"
    mock_blacklist.exists.assert_not_called()


def test_blacklist_redis_error_fails_open(monkeypatch):
    """Matches omnibioai-auth/app/core/token_revocation.py's own
    documented tradeoff: a Redis outage must not 401 every request in
    this service either."""
    mock = MagicMock()
    mock.exists.side_effect = Exception("redis down")
    monkeypatch.setattr(jwt_verify_module, "_blacklist", mock)

    token = _token(sub="1", jti="some-jti")
    payload = verify_token(token)  # must not raise
    assert payload["sub"] == "1"
