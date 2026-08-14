"""PR1 of the audit:events integrity remediation: sign/verify helper tests.

Synthetic secrets only -- never a real deployment JWT_SECRET. This module
is not yet wired into any producer or consumer (that's PR2+), so these
tests exercise audit.signing directly.
"""
import hashlib
import hmac

import pytest

from audit.signing import sign_audit_event, verify_audit_event

SECRET = "synthetic-test-secret-do-not-use-in-prod"
SERVICE = "tes"
DATA = '{"event_id":"e1","service":"tes","action":"submit"}'


# ---------------------------------------------------------------------------
# 1. valid signature verifies
# ---------------------------------------------------------------------------

def test_valid_signature_verifies():
    sig = sign_audit_event(SERVICE, DATA, SECRET)
    assert verify_audit_event(SERVICE, DATA, sig, SECRET) is True


# ---------------------------------------------------------------------------
# 2. modified data fails
# ---------------------------------------------------------------------------

def test_modified_data_fails():
    sig = sign_audit_event(SERVICE, DATA, SECRET)
    tampered = DATA.replace("submit", "delete_all")
    assert verify_audit_event(SERVICE, tampered, sig, SECRET) is False


def test_even_one_byte_of_modified_data_fails():
    sig = sign_audit_event(SERVICE, DATA, SECRET)
    tampered = DATA[:-1] + ("0" if DATA[-1] != "0" else "1")
    assert verify_audit_event(SERVICE, tampered, sig, SECRET) is False


# ---------------------------------------------------------------------------
# 3. modified service identity fails (a valid sig can't be relabeled)
# ---------------------------------------------------------------------------

def test_modified_service_identity_fails():
    sig = sign_audit_event(SERVICE, DATA, SECRET)
    assert verify_audit_event("gateway", DATA, sig, SECRET) is False


def test_relabeling_a_valid_signature_onto_a_different_service_fails():
    """The exact forgery this binding exists to stop: attacker observes a
    genuine (service="tes", data, sig) triple and tries to claim the same
    sig for a different, more-trusted-looking service identity."""
    sig = sign_audit_event("workflow-bundles", DATA, SECRET)
    assert verify_audit_event("auth-service", DATA, sig, SECRET) is False


# ---------------------------------------------------------------------------
# 4. wrong secret fails
# ---------------------------------------------------------------------------

def test_wrong_secret_fails():
    sig = sign_audit_event(SERVICE, DATA, SECRET)
    assert verify_audit_event(SERVICE, DATA, sig, "a-different-synthetic-secret") is False


# ---------------------------------------------------------------------------
# 5. malformed signature fails
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "malformed",
    [
        "",
        "not-a-valid-signature-at-all",
        "v1",  # no colon separator
        "v1:",  # empty mac
        "v1:not-hex-garbage",
        ":abc123",  # empty version
        "v1:abc:def",  # extra colon -- partition still isolates version correctly, mac just won't match
        123,  # wrong type entirely
        None,
    ],
)
def test_malformed_signature_fails(malformed):
    assert verify_audit_event(SERVICE, DATA, malformed, SECRET) is False


# ---------------------------------------------------------------------------
# 6. missing signature fails
# ---------------------------------------------------------------------------

def test_missing_signature_fails():
    assert verify_audit_event(SERVICE, DATA, "", SECRET) is False
    assert verify_audit_event(SERVICE, DATA, None, SECRET) is False


# ---------------------------------------------------------------------------
# 7. unsupported version fails
# ---------------------------------------------------------------------------

def test_unsupported_version_fails():
    sig = sign_audit_event(SERVICE, DATA, SECRET)
    _, _, mac_hex = sig.partition(":")
    future_version_sig = f"v2:{mac_hex}"
    assert verify_audit_event(SERVICE, DATA, future_version_sig, SECRET) is False


def test_unsupported_version_fails_even_with_a_correctly_recomputed_mac():
    """Not just a string-prefix check: recompute the MAC as if "v2" were a
    real, valid version (mirroring what a genuine v2 signer would produce)
    and confirm a v1-only verifier still rejects it -- proves the version
    is actually load-bearing, not decorative."""
    key = hashlib.sha256(f"omnibioai-audit-events:{SECRET}".encode()).digest()
    mac = hmac.new(key, f"v2\n{SERVICE}\n{DATA}".encode(), hashlib.sha256).hexdigest()
    assert verify_audit_event(SERVICE, DATA, f"v2:{mac}", SECRET) is False


# ---------------------------------------------------------------------------
# 8. deterministic signing for identical inputs
# ---------------------------------------------------------------------------

def test_signing_is_deterministic():
    sig1 = sign_audit_event(SERVICE, DATA, SECRET)
    sig2 = sign_audit_event(SERVICE, DATA, SECRET)
    assert sig1 == sig2


def test_different_data_produces_different_signature():
    sig1 = sign_audit_event(SERVICE, DATA, SECRET)
    sig2 = sign_audit_event(SERVICE, DATA + "x", SECRET)
    assert sig1 != sig2


# ---------------------------------------------------------------------------
# 9. domain separation prevents reuse with the TES IAM-cache signing
#    construction (omnibioai-tes PR #22, service/security/iam.py). No
#    cross-repo import -- hand-mirrored, same convention
#    test_producer_contract_reconciliation.py already uses in this repo
#    for the gateway producer's payload shape.
# ---------------------------------------------------------------------------

def _tes_iam_cache_mac_key(secret: str) -> bytes:
    return hashlib.sha256(f"tes-iam-cache-mac:{secret}".encode()).digest()


def _tes_iam_cache_sign(token: str, body: str, secret: str) -> str:
    return hmac.new(_tes_iam_cache_mac_key(secret), f"{token}\n{body}".encode(), hashlib.sha256).hexdigest()


def test_domain_separation_from_iam_cache_mac():
    """Same underlying secret, structurally analogous inputs (service~token,
    data~body) -- the two constructions must not collide."""
    shared_secret = SECRET
    token_like = SERVICE
    body_like = DATA

    audit_sig = sign_audit_event(SERVICE, DATA, shared_secret)
    _, _, audit_mac_hex = audit_sig.partition(":")

    iam_cache_mac_hex = _tes_iam_cache_sign(token_like, body_like, shared_secret)

    assert audit_mac_hex != iam_cache_mac_hex


def test_domain_separation_keys_themselves_differ():
    """More directly: the two derived sub-keys must differ even though
    both are derived from the identical shared secret."""
    from audit.signing import _signing_key as audit_signing_key

    assert audit_signing_key(SECRET) != _tes_iam_cache_mac_key(SECRET)


# ---------------------------------------------------------------------------
# 10. exact raw `data` string is what gets authenticated (not a
#     re-serialization of the parsed JSON)
# ---------------------------------------------------------------------------

def test_reserialized_json_with_different_key_order_fails_verification():
    """Same logical JSON object, different on-the-wire byte string (key
    order swapped) -- must NOT verify, proving the MAC covers the exact
    transmitted string rather than a semantic/parsed equivalence."""
    original = '{"a": 1, "b": 2}'
    reordered = '{"b": 2, "a": 1}'
    sig = sign_audit_event(SERVICE, original, SECRET)
    assert verify_audit_event(SERVICE, reordered, sig, SECRET) is False


def test_whitespace_only_difference_in_data_fails_verification():
    compact = '{"a":1}'
    spaced = '{"a": 1}'
    sig = sign_audit_event(SERVICE, compact, SECRET)
    assert verify_audit_event(SERVICE, spaced, sig, SECRET) is False


# ---------------------------------------------------------------------------
# Additional: sign_audit_event's own input validation (fail loud at sign
# time -- unlike verify, which must always fail closed/return False since
# its inputs are attacker-reachable off the wire).
# ---------------------------------------------------------------------------

def test_sign_rejects_empty_service():
    with pytest.raises(ValueError):
        sign_audit_event("", DATA, SECRET)


def test_sign_rejects_none_data():
    with pytest.raises(ValueError):
        sign_audit_event(SERVICE, None, SECRET)


def test_signature_format_has_version_prefix():
    sig = sign_audit_event(SERVICE, DATA, SECRET)
    assert sig.startswith("v1:")
    version, _, mac_hex = sig.partition(":")
    assert version == "v1"
    assert len(mac_hex) == 64  # sha256 hexdigest
    int(mac_hex, 16)  # must actually be hex


def test_verify_never_raises_on_adversarial_input():
    """Every field in a real consumer's future call to verify_audit_event
    (PR2+) comes off a Redis stream any network peer can XADD to -- this
    must never crash the consumer regardless of what garbage arrives."""
    garbage_inputs = [
        (None, None, None, None),
        (123, [], {}, object()),
        ("svc", "data", "v1:" + "z" * 64, "secret"),
        ("", "", "", ""),
        ("svc", "data", "v1:" + "a" * 1000, "secret"),
    ]
    for service, data, sig, secret in garbage_inputs:
        assert verify_audit_event(service, data, sig, secret) is False
