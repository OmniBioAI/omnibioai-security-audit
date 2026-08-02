"""SSO Phase 2 PR3: audit/jwt_verify.py -- the shared local JWT verifier
(signature, expiry, token type, required claims, Redis jti-blacklist
revocation) both api/deps.py and audit/identity.py now delegate to.

SSO Phase 2 PR16: adds coverage for the RS256/JWKS verification path
added alongside the existing HS256 path.
"""
import datetime as dt
from unittest.mock import MagicMock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWKClient
from jwt.algorithms import RSAAlgorithm

from audit import jwt_verify as jwt_verify_module
from audit.jwt_verify import TokenInvalid, verify_token

SECRET = "test-secret"

KID = "test-kid-1"
_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_KEY = _PRIVATE_KEY.public_key()

OTHER_KID = "test-kid-2"
_OTHER_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER_PUBLIC_KEY = _OTHER_PRIVATE_KEY.public_key()


def _token(**claims):
    return jwt.encode(claims, SECRET, algorithm="HS256")


def _rs256_token(private_key, kid, **claims):
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": kid})


def _jwk(public_key, kid: str) -> dict:
    jwk = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return jwk


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


@pytest.fixture(autouse=True)
def _reset_jwks_client(monkeypatch):
    """Every test starts with no cached JWKS client -- RS256 tests install
    their own fake via install_jwks(); tests that never touch RS256 never
    trigger a real network fetch."""
    monkeypatch.setattr(jwt_verify_module, "_jwks_client", None)


def install_jwks(*jwks_responses: dict) -> MagicMock:
    """Wires a real PyJWKClient (so get_signing_key's actual match/
    refresh-on-miss logic runs) whose network fetch is replaced by a
    canned sequence of JWKS responses -- one per expected fetch_data()
    call."""
    client = PyJWKClient(jwt_verify_module.JWKS_URL)
    fetch = MagicMock(side_effect=list(jwks_responses))
    client.fetch_data = fetch
    jwt_verify_module._jwks_client = client
    return fetch


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


# ---------------------------------------------------------------------------
# RS256 / JWKS (PR16)
# ---------------------------------------------------------------------------

def test_valid_rs256_token_succeeds():
    install_jwks({"keys": [_jwk(_PUBLIC_KEY, KID)]})
    token = _rs256_token(_PRIVATE_KEY, KID, sub="1", roles=["platform_admin"], type="access")
    payload = verify_token(token)
    assert payload["sub"] == "1"
    assert payload["roles"] == ["platform_admin"]


def test_invalid_rs256_signature_raises():
    """Token claims kid=KID in its header but was actually signed by a
    different key -- JWKS lookup resolves KID's real public key, so the
    signature check must fail rather than trusting the header."""
    install_jwks({"keys": [_jwk(_PUBLIC_KEY, KID)]})
    forged = _rs256_token(_OTHER_PRIVATE_KEY, KID, sub="1")
    with pytest.raises(TokenInvalid):
        verify_token(forged)


def test_unknown_kid_rejected():
    """Neither the initial fetch nor the refresh-on-miss fetch ever
    contains the token's kid -- must fail closed, not fall back to any
    other verification path."""
    fetch = install_jwks(
        {"keys": [_jwk(_PUBLIC_KEY, KID)]},
        {"keys": [_jwk(_PUBLIC_KEY, KID)]},
    )
    token = _rs256_token(_OTHER_PRIVATE_KEY, "no-such-kid", sub="1")
    with pytest.raises(TokenInvalid):
        verify_token(token)
    assert fetch.call_count == 2


def test_jwks_refresh_finds_rotated_key():
    """Simulates key rotation: the token's kid isn't in the JWKS response
    cached at the time verification starts, but is present once
    PyJWKClient refetches after the initial miss."""
    fetch = install_jwks(
        {"keys": [_jwk(_PUBLIC_KEY, KID)]},
        {"keys": [_jwk(_PUBLIC_KEY, KID), _jwk(_OTHER_PUBLIC_KEY, OTHER_KID)]},
    )
    token = _rs256_token(_OTHER_PRIVATE_KEY, OTHER_KID, sub="1")
    payload = verify_token(token)
    assert payload["sub"] == "1"
    assert fetch.call_count == 2


def test_jwks_fetch_failure_fails_closed():
    """A network/timeout error while fetching the JWKS must reject the
    token, never fall back to an unverified accept."""
    client = PyJWKClient(jwt_verify_module.JWKS_URL)
    client.fetch_data = MagicMock(side_effect=TimeoutError("jwks unreachable"))
    jwt_verify_module._jwks_client = client
    token = _rs256_token(_PRIVATE_KEY, KID, sub="1")
    with pytest.raises(TokenInvalid):
        verify_token(token)


def test_rs256_token_missing_kid_raises():
    token = jwt.encode({"sub": "1"}, _PRIVATE_KEY, algorithm="RS256")
    with pytest.raises(TokenInvalid):
        verify_token(token)


def test_expired_rs256_token_raises():
    install_jwks({"keys": [_jwk(_PUBLIC_KEY, KID)]})
    token = _rs256_token(
        _PRIVATE_KEY,
        KID,
        sub="1",
        exp=dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1),
    )
    with pytest.raises(TokenInvalid):
        verify_token(token)


def test_get_jwks_client_lazily_builds_real_client():
    """_jwks_client starts as None (fixture) -- the first RS256
    verification must build a real PyJWKClient pointed at JWKS_URL, not
    require a test to have pre-installed one."""
    client = jwt_verify_module._get_jwks_client()
    assert isinstance(client, PyJWKClient)
    assert client.uri == jwt_verify_module.JWKS_URL
    assert jwt_verify_module._get_jwks_client() is client


def test_unsigned_token_rejected():
    """alg=none tokens must never be accepted, regardless of JWKS or
    HS256 secret state."""
    token = jwt.encode({"sub": "1"}, key=None, algorithm="none")
    with pytest.raises(TokenInvalid):
        verify_token(token)


def test_hs256_token_unaffected_by_rs256_path():
    """Old, already-issued HS256 tokens must keep validating exactly as
    before even with a JWKS client installed -- alg dispatch must never
    route an HS256 token through the RS256/JWKS path."""
    install_jwks({"keys": [_jwk(_PUBLIC_KEY, KID)]})
    token = _token(sub="1", roles=["platform_admin"], type="access")
    payload = verify_token(token)
    assert payload["sub"] == "1"
