"""SSO Phase 2 PR3: the single place in this repo that decodes and fully
verifies an omnibioai-auth-issued JWT -- signature, expiry, token type,
required claims, and Redis jti-blacklist revocation state.

api/deps.py::require_platform_admin (PR4.3) and
audit/identity.py::validate_identity_token (PR4.4) previously each did
their own partial jwt.decode() (signature + exp only, via PyJWT's
defaults) with no revocation check at all -- a logged-out or suspended
user's still-unexpired access token stayed valid against this service
until natural expiry. Both now delegate here.

Not shared across repos: omnibioai-control-center has its own, separately
maintained but structurally identical module
(core/jwt_verify.py). Two existing candidate shared packages
(omnibioai-iam-client, omnibioai-security-sdk) were inspected first and
found unsuitable -- neither is imported by any live service today, and
neither implements local-decode-plus-jti-blacklist verification (one does
remote-validate-with-cache, the other does bare decode with no revocation
check at all). See this PR's report for detail. A future PR may extract a
true shared package once this pattern has proven itself in both repos.

SSO Phase 2 PR16: adds RS256/JWKS verification alongside the existing
HS256 shared-secret path, dispatched by the token's own `alg` header --
the same "verify by declared alg, not by config" approach
omnibioai-auth/app/core/jwt.py::decode_token already uses so a token
issued today (HS256) and one issued after a future RS256 cutover both
keep validating here without a coordinated flag flip. JWT_ALGORITHM=RS256
is NOT enabled anywhere yet -- this PR only prepares this service to
verify RS256 tokens once that switch is made in a later, separate change.
"""
from __future__ import annotations

import os
from typing import Any

import jwt
import redis
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientError

from audit.config import AuditConfig

JWT_SECRET = os.environ.get("JWT_SECRET", "change-me")
JWT_ISSUER = os.environ.get("JWT_ISSUER", "omnibioai-auth")
JWT_AUDIENCE = os.environ.get("JWT_AUDIENCE", "omnibioai-platform")

# omnibioai-auth's JWKS endpoint (app/api/routes_jwks.py) -- publishes the
# public half of whatever key app/core/rsa_keys.py loaded/generated, keyed
# by `kid`. Only ever consulted for a token whose header already declares
# alg=RS256; an HS256 token never triggers a fetch.
JWKS_URL = os.environ.get(
    "JWKS_URL", "https://auth.omnibioai.org/.well-known/jwks.json"
)
JWKS_TIMEOUT_SECONDS = int(os.environ.get("JWKS_TIMEOUT_SECONDS", "5"))
# How long a fetched key set is trusted before the next RS256 verification
# re-fetches it. Independent of the "unknown kid -> refresh immediately"
# path in _decode(), which ignores this TTL entirely.
JWKS_CACHE_TTL_SECONDS = int(os.environ.get("JWKS_CACHE_TTL_SECONDS", "300"))

# Same Redis instance and key convention as omnibioai-auth's own
# token_revocation.py::_blacklist ("blacklist:jti:{jti}", checked via
# .exists(), fail-open on Redis errors) -- deliberately matching that
# service's own documented tradeoff: a Redis blip must not 401 every
# request in this service either.
_blacklist = redis.from_url(AuditConfig.REDIS_URL, decode_responses=True)

# Lazy singleton: importing this module must never make a network call --
# only the first RS256 token that actually arrives pays for the initial
# JWKS fetch. PyJWKClient itself caches the fetched key set for
# JWKS_CACHE_TTL_SECONDS and transparently refetches once if a requested
# kid isn't in the cached set (see its get_signing_key()), which is the
# "refresh cache on unknown kid" behavior this PR requires.
_jwks_client: PyJWKClient | None = None


def _get_jwks_client() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = PyJWKClient(
            JWKS_URL, timeout=JWKS_TIMEOUT_SECONDS, lifespan=JWKS_CACHE_TTL_SECONDS
        )
    return _jwks_client


class TokenInvalid(Exception):
    """Raised by verify_token() for any invalid, expired, wrong-type,
    missing-required-claim, or revoked token. Callers decide how to
    surface this (HTTPException, a None return, ...) -- this module only
    verifies, it never decides what an invalid token means to its caller.
    """


def _decode(token: str) -> dict[str, Any]:
    """Verifies signature + expiry, dispatched by the token's own `alg`
    header rather than by any local config -- mirrors omnibioai-auth's own
    decode_token(). Every exit that doesn't return a signature-verified
    payload raises TokenInvalid: unknown/missing alg, unresolvable kid,
    unreachable JWKS endpoint, and bad signature all fail closed. There is
    no path that returns a payload without a verified signature."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as e:
        raise TokenInvalid(f"invalid token: {e}")

    alg = header.get("alg")

    if alg == "RS256":
        kid = header.get("kid")
        if not kid:
            raise TokenInvalid("RS256 token missing kid header")
        try:
            signing_key = _get_jwks_client().get_signing_key(kid).key
        except PyJWKClientError as e:
            raise TokenInvalid(f"unable to resolve signing key: {e}")
        except Exception as e:
            # Covers JWKS-endpoint timeouts/connection errors and any
            # other fetch failure -- fail closed rather than falling back
            # to an unverified path.
            raise TokenInvalid(f"jwks fetch failed: {e}")
        try:
            payload = jwt.decode(
                token, signing_key, algorithms=["RS256"],
                options={"verify_aud": False},
            )
            return _validate_platform_claims(payload)
        except jwt.ExpiredSignatureError:
            raise TokenInvalid("expired")
        except jwt.InvalidTokenError as e:
            raise TokenInvalid(f"invalid token: {e}")

    if alg == "HS256":
        try:
            payload = jwt.decode(
                token, JWT_SECRET, algorithms=["HS256"],
                options={"verify_aud": False},
            )
            return _validate_platform_claims(payload)
        except jwt.ExpiredSignatureError:
            raise TokenInvalid("expired")
        except jwt.InvalidTokenError as e:
            raise TokenInvalid(f"invalid token: {e}")

    raise TokenInvalid(f"unsupported alg: {alg!r}")


def _validate_platform_claims(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate Auth's platform issuer/audience contract.

    Claims remain optional for the documented rolling-deploy compatibility
    window, but a present issuer or audience must match the platform values.
    Manual audience validation preserves that compatibility because PyJWT's
    ``audience=`` argument rejects tokens that predate these claims.
    """
    if payload.get("iss") is not None and payload["iss"] != JWT_ISSUER:
        raise TokenInvalid("invalid issuer")
    audience = payload.get("aud")
    if audience is not None:
        values = audience if isinstance(audience, list) else [audience]
        if JWT_AUDIENCE not in values:
            raise TokenInvalid("invalid audience")
    return payload


def verify_token(token: str | None) -> dict[str, Any]:
    """Decodes and verifies `token`. Returns the decoded payload on
    success; raises TokenInvalid on any failure."""
    if not token:
        raise TokenInvalid("missing token")

    payload = _decode(token)

    # Permissive by design: omnibioai-auth's refresh tokens carry the same
    # claim set as access tokens (build_user_claims), differing only in
    # `type` and TTL (7 days vs 15 minutes) -- without this check, a
    # leaked refresh token grants the same access as an access token, for
    # up to 7 days instead of 15 minutes. Only reject a *known-wrong*
    # type; a token with no `type` claim at all (every pre-existing test
    # fixture in this repo) still passes, so this closes the real gap
    # without requiring a claim that wasn't part of the original contract
    # these callers were built against.
    token_type = payload.get("type")
    if token_type is not None and token_type != "access":
        raise TokenInvalid(f"wrong token type: {token_type!r}")

    if not payload.get("sub"):
        raise TokenInvalid("missing required claim: sub")

    jti = payload.get("jti")
    if jti:
        try:
            revoked = bool(_blacklist.exists(f"blacklist:jti:{jti}"))
        except Exception:
            # Fail open on Redis specifically -- matches
            # omnibioai-auth/app/core/token_revocation.py's own documented
            # "never block on a Redis blip" philosophy for this exact
            # blacklist.
            revoked = False
        if revoked:
            raise TokenInvalid("revoked")

    return payload
