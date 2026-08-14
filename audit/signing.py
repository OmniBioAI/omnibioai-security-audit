"""HIPAA audit remediation, PR1: sign/verify helper for the `audit:events`
Redis stream (see docs -- TES `docs/security/iam-cache-integrity.md` and its
companion architecture-investigation report for the full trust-boundary
analysis this PR1 implements the first step of).

This module is a pure, standalone helper: it derives no secret of its own
and reads no configuration. `secret` is always an explicit argument, the
same shape `IAMClient`'s cache-signing helpers in omnibioai-tes (PR #22,
`service/security/iam.py::_sign_cache_entry`) already established for the
platform's one other HMAC construction. Nothing in this repository imports
this module yet -- wiring it into the real producer/consumer path is PR2+,
by design (see this PR's own report for the approved phased sequence).

Envelope: a signed event is transmitted as two sibling Redis stream
fields, `data` (the existing, unchanged JSON payload every producer already
writes) and `sig` (new, this PR's addition):

    XADD audit:events * data <json-string> sig v1:<hex-hmac>

Deliberately NOT re-serializing `data` before signing: the MAC covers the
*exact transmitted string*, sidestepping JSON key-ordering, float-repr, and
whitespace ambiguity between what a producer signed and what a consumer
would re-derive by re-encoding a parsed dict. Callers must pass the same
`data` string used in the XADD call, not `json.dumps(json.loads(data))`.

The producer's own service identity (`service`, e.g. "tes", "gateway") is
bound directly into the signed message -- not left to be read back out of
the JSON body -- so a valid signature cannot be relabeled onto a different
`service` value by copying the `sig` field alone.
"""
from __future__ import annotations

import hashlib
import hmac

# Domain-separated sub-key derivation, deliberately mirroring
# omnibioai-tes's own PR #22 construction (`_cache_mac_key()` /
# `_sign_cache_entry()` in service/security/iam.py) rather than a fresh
# invention: `SHA256(domain_label + ":" + secret)` as the HMAC key,
# `HMAC-SHA256(that key, message)` over the signed content. The domain
# label here is distinct from PR #22's `"tes-iam-cache-mac"` specifically
# so that a derived audit-signing key is not reusable against the IAM
# cache's construction even when both ultimately trace back to the same
# platform JWT_SECRET value -- see test_domain_separation_from_iam_cache_mac
# below for an explicit, non-cross-repo-importing proof of this.
_DOMAIN_LABEL = "omnibioai-audit-events"

# Explicit version tag, carried in both the wire format (`v1:<mac>`) and
# the signed message itself (see _signing_message) -- future envelope or
# key-derivation changes get a new version rather than silently reusing
# "v1" for an incompatible construction, and binding it into the signed
# message means a "v1" signature can never be reinterpreted as valid for
# a hypothetical future "v2" verifier or vice versa.
SUPPORTED_VERSION = "v1"


def _signing_key(secret: str) -> bytes:
    return hashlib.sha256(f"{_DOMAIN_LABEL}:{secret}".encode()).digest()


def _signing_message(version: str, service: str, data: str) -> bytes:
    # "\n"-joined, not concatenated bare: without a separator,
    # service="ab" + data="cd" and service="a" + data="bcd" would hash
    # identically. "\n" is safe here because `service` is a short,
    # producer-controlled identifier (never itself derived from `data`),
    # so this is not the general unsafe-delimiter case where an attacker
    # controls both fields being joined.
    return f"{version}\n{service}\n{data}".encode()


def sign_audit_event(service: str, data: str, secret: str) -> str:
    """Returns the `sig` field value for one audit event: `"v1:<hex-hmac>"`.

    `service` must be the producer's own identity (never taken from
    inside `data`) and non-empty -- signing without a real service label
    would silently produce a signature that can never be told apart from
    one for a different (also-empty) service, so this raises rather than
    doing that quietly. `data` must be the exact string that will be (or
    was) written to the stream's `data` field, not a re-serialization.
    """
    if not service:
        raise ValueError("service must be a non-empty string")
    if data is None:
        raise ValueError("data must not be None")
    mac = hmac.new(
        _signing_key(secret), _signing_message(SUPPORTED_VERSION, service, data), hashlib.sha256
    ).hexdigest()
    return f"{SUPPORTED_VERSION}:{mac}"


def verify_audit_event(service: str, data: str, signature: str, secret: str) -> bool:
    """True only if `signature` is a valid, current-version signature over
    exactly this `(service, data)` pair under `secret`.

    Never raises: `signature` (and, in a future consumer, `service`/`data`
    themselves) come off the wire from a Redis stream any network peer can
    write to (see this PR's report -- that is the exact threat this
    signing scheme exists to address), so any malformed, wrong-type, or
    adversarially-crafted input must fail closed as `False`, the same
    fail-closed contract `IAMClient._get_cached` (PR #22) already
    established for this platform's other HMAC construction, never as an
    uncaught exception that could crash or wedge a consumer.
    """
    try:
        if not signature or not isinstance(signature, str):
            return False
        if not service or not isinstance(service, str):
            return False
        if data is None:
            return False

        version, sep, mac_hex = signature.partition(":")
        if not sep or version != SUPPORTED_VERSION:
            return False

        expected = hmac.new(
            _signing_key(secret), _signing_message(version, service, data), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(mac_hex, expected)
    except Exception:
        return False
