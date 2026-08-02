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
"""
from __future__ import annotations

import os
from typing import Any

import jwt
import redis

from audit.config import AuditConfig

JWT_SECRET = os.environ.get("JWT_SECRET", "change-me")

# Same Redis instance and key convention as omnibioai-auth's own
# token_revocation.py::_blacklist ("blacklist:jti:{jti}", checked via
# .exists(), fail-open on Redis errors) -- deliberately matching that
# service's own documented tradeoff: a Redis blip must not 401 every
# request in this service either.
_blacklist = redis.from_url(AuditConfig.REDIS_URL, decode_responses=True)


class TokenInvalid(Exception):
    """Raised by verify_token() for any invalid, expired, wrong-type,
    missing-required-claim, or revoked token. Callers decide how to
    surface this (HTTPException, a None return, ...) -- this module only
    verifies, it never decides what an invalid token means to its caller.
    """


def verify_token(token: str | None) -> dict[str, Any]:
    """Decodes and verifies `token`. Returns the decoded payload on
    success; raises TokenInvalid on any failure."""
    if not token:
        raise TokenInvalid("missing token")

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise TokenInvalid("expired")
    except jwt.InvalidTokenError as e:
        raise TokenInvalid(f"invalid token: {e}")

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
