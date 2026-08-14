"""PR2 of the audit:events integrity remediation: classify_event_integrity()
(consumers/processor.py) -- the worker-side glue between PR1's sign/verify
helper (audit/signing.py, untouched by this PR) and the new integrity_status
persisted on each AuditEventRecord.

Synthetic secrets only, matching tests/test_signing.py's own convention --
never a real deployment JWT_SECRET.
"""
from audit.signing import sign_audit_event
from consumers.processor import classify_event_integrity

SECRET = "synthetic-test-secret-do-not-use-in-prod"
OTHER_SECRET = "a-different-synthetic-secret"
SERVICE = "tes"
DATA = '{"event_id":"e1","service":"tes","action":"submit"}'


# ---------------------------------------------------------------------------
# valid / wrong / malformed / missing / empty
# ---------------------------------------------------------------------------

def test_valid_signature_classifies_as_valid():
    sig = sign_audit_event(SERVICE, DATA, SECRET)
    assert classify_event_integrity(SERVICE, sig, DATA, SECRET) == "valid"


def test_wrong_secret_classifies_as_invalid():
    sig = sign_audit_event(SERVICE, DATA, SECRET)
    assert classify_event_integrity(SERVICE, sig, DATA, OTHER_SECRET) == "invalid"


def test_tampered_data_classifies_as_invalid():
    sig = sign_audit_event(SERVICE, DATA, SECRET)
    tampered = DATA.replace("submit", "delete_all")
    assert classify_event_integrity(SERVICE, sig, tampered, SECRET) == "invalid"


def test_malformed_signature_classifies_as_invalid():
    assert classify_event_integrity(SERVICE, "not-a-real-signature", DATA, SECRET) == "invalid"


def test_missing_signature_classifies_as_unsigned():
    assert classify_event_integrity(SERVICE, None, DATA, SECRET) == "unsigned"


def test_empty_signature_classifies_as_unsigned():
    assert classify_event_integrity(SERVICE, "", DATA, SECRET) == "unsigned"


# ---------------------------------------------------------------------------
# The missing-signature check happens BEFORE verify_audit_event() -- proven,
# not just asserted, by using a secret that would make ANY real verification
# fail (including of a well-formed-but-absent signature check), yet the
# missing/empty cases above still return "unsigned", never "invalid".
# Explicit ordering check: a None/"" signature must short-circuit even when
# it could theoretically have been run through verify_audit_event() and
# returned False (which would have produced the wrong classification,
# "invalid" instead of "unsigned").
# ---------------------------------------------------------------------------

def test_missing_signature_is_unsigned_not_invalid_even_with_wrong_secret():
    assert classify_event_integrity(SERVICE, None, DATA, OTHER_SECRET) == "unsigned"


# ---------------------------------------------------------------------------
# service/signature/data mismatch combinations
# ---------------------------------------------------------------------------

def test_signature_for_different_service_classifies_as_invalid():
    sig = sign_audit_event("workflow-bundles", DATA, SECRET)
    assert classify_event_integrity("auth-service", sig, DATA, SECRET) == "invalid"


def test_signature_for_different_data_classifies_as_invalid():
    other_data = '{"event_id":"e2","service":"tes","action":"delete"}'
    sig = sign_audit_event(SERVICE, other_data, SECRET)
    assert classify_event_integrity(SERVICE, sig, DATA, SECRET) == "invalid"


# ---------------------------------------------------------------------------
# exact raw JSON string passed through without reserialization -- reordered
# keys (same logical content, different on-the-wire bytes) must invalidate
# a signature made for the original ordering. This is the property that
# makes "verify fields['data'] directly, never event.model_dump()" load-
# bearing rather than incidental.
# ---------------------------------------------------------------------------

def test_reordered_json_keys_invalidate_the_original_signature():
    original = '{"a": 1, "b": 2}'
    reordered = '{"b": 2, "a": 1}'
    sig = sign_audit_event(SERVICE, original, SECRET)
    assert classify_event_integrity(SERVICE, sig, reordered, SECRET) == "invalid"


def test_exact_original_string_still_classifies_as_valid():
    """Sanity companion to the reordering test above -- confirms the
    invalidation is specifically about the byte-level change, not some
    unrelated break."""
    sig = sign_audit_event(SERVICE, DATA, SECRET)
    assert classify_event_integrity(SERVICE, sig, DATA, SECRET) == "valid"


# ---------------------------------------------------------------------------
# Return type/value contract: exactly one of the three strings, nothing else
# ---------------------------------------------------------------------------

def test_return_value_is_always_one_of_the_three_literal_strings():
    sig = sign_audit_event(SERVICE, DATA, SECRET)
    for signature, secret, expected in [
        (sig, SECRET, "valid"),
        (sig, OTHER_SECRET, "invalid"),
        (None, SECRET, "unsigned"),
    ]:
        result = classify_event_integrity(SERVICE, signature, DATA, secret)
        assert result in {"valid", "invalid", "unsigned"}
        assert result == expected
