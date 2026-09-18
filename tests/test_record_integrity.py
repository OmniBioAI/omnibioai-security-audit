"""V2-003 (Track E3): audit/record_integrity.py -- stored-record tamper
detection. Pure unit tests, no database needed.

Three real bugs were found and fixed via actual end-to-end testing
against MySQL before/while this test file existed (not caught by
inspection alone, and in bug #3's case, not even caught by this file's
own first version of the relevant unit tests -- see below):

1. audit_events.context (a JSON column) comes back from a raw/text() SQL
   read as a literal JSON string, not a parsed dict, while the in-memory
   write-time value is always a dict -- these must canonicalize
   identically or every untampered row fails verification. See
   test_context_as_dict_and_as_equivalent_json_string_hash_identically.

2. audit_events.timestamp is a plain MySQL DATETIME (no fractional-
   second precision) -- a Python datetime with microseconds has its
   fractional part collapsed by MySQL on INSERT, so hashing the
   pre-collapse value makes the hash unverifiable unless the
   canonicalization collapses it the identical way.

3. That collapse is ROUNDING (round-half-up: .500000 and above rounds
   up to the next second), not truncation/flooring -- verified directly
   against a real MySQL 8.0 server. An earlier version of both
   record_integrity.py and this test file assumed truncation, and the
   test self-consistently "passed" because it only used microsecond
   values below the .5 boundary, sharing the same wrong assumption as
   the code it was testing. It only surfaced as an intermittent
   (~50% of random datetime.now() values) failure in a real end-to-end
   integration test run. See
   test_timestamp_at_or_above_rounding_boundary_rounds_up_to_the_next_second.

Developer: Manish Kumar <manish@omnibioai.org>
"""
from datetime import datetime

from audit.record_integrity import (
    compute_audit_event_hash,
    compute_quarantine_record_hash,
    verify_audit_event_hash,
    verify_quarantine_record_hash,
)


def _base_audit_event(**overrides):
    """Build a valid base audit-event record dict for hashing, applying any field overrides."""
    record = {
        "event_id": "evt-1",
        "timestamp": datetime(2026, 9, 16, 12, 0, 0),  # noqa: DTZ001 -- naive column, matches AuditEventRecord.timestamp convention
        "service": "test",
        "event_type": "test",
        "user_id": None,
        "organization_id": None,
        "tenant_scope": "unknown",
        "action": "test_action",
        "resource": None,
        "decision": None,
        "reason": None,
        "trace_id": None,
        "context": {},
        "integrity_status": "unsigned",
    }
    record.update(overrides)
    return record


def _base_quarantine_record(**overrides):
    """Build a valid base quarantine-record dict for hashing, applying any field overrides."""
    record = {
        "stream_message_id": "1-0",
        "raw_data": '{"service":"test"}',
        "raw_signature": None,
        "service": "test",
        "failure_category": "malformed",
        "failure_detail": "JSONDecodeError",
        "delivery_attempts": 5,
    }
    record.update(overrides)
    return record


SECRET = "test-secret-value"


# ---------------------------------------------------------------------------
# Basic compute/verify round trip
# ---------------------------------------------------------------------------

def test_audit_event_hash_verifies_for_unmodified_record():
    """Verify an audit event's hash against its own unmodified record."""
    record = _base_audit_event()
    record["record_integrity_hash"] = compute_audit_event_hash(record, SECRET)
    assert verify_audit_event_hash(record, SECRET) is True


def test_quarantine_record_hash_verifies_for_unmodified_record():
    """Verify a quarantine record's hash against its own unmodified record."""
    record = _base_quarantine_record()
    record["record_integrity_hash"] = compute_quarantine_record_hash(record, SECRET)
    assert verify_quarantine_record_hash(record, SECRET) is True


def test_audit_event_hash_fails_when_any_covered_field_changes():
    """Fail verification once a hash-covered audit-event field is changed."""
    record = _base_audit_event()
    record["record_integrity_hash"] = compute_audit_event_hash(record, SECRET)
    record["action"] = "TAMPERED"
    assert verify_audit_event_hash(record, SECRET) is False


def test_quarantine_record_hash_fails_when_any_covered_field_changes():
    """Fail verification once a hash-covered quarantine-record field is changed."""
    record = _base_quarantine_record()
    record["record_integrity_hash"] = compute_quarantine_record_hash(record, SECRET)
    record["failure_category"] = "TAMPERED"
    assert verify_quarantine_record_hash(record, SECRET) is False


def test_verify_fails_closed_when_hash_is_missing():
    """Fail verification, not raise, when the stored hash is missing."""
    record = _base_audit_event()
    record["record_integrity_hash"] = None
    assert verify_audit_event_hash(record, SECRET) is False


def test_verify_fails_closed_with_wrong_secret():
    """Fail record-hash verification when checked against the wrong secret."""
    record = _base_audit_event()
    record["record_integrity_hash"] = compute_audit_event_hash(record, SECRET)
    assert verify_audit_event_hash(record, "a-different-secret") is False


def test_verify_never_raises_on_malformed_record():
    """Return False instead of raising for a completely empty record."""
    assert verify_audit_event_hash({}, SECRET) is False
    assert verify_quarantine_record_hash({}, SECRET) is False


# ---------------------------------------------------------------------------
# Bug #1: context dict vs. equivalent JSON string must canonicalize
# identically -- caught via a real raw-SQL read returning a string where
# the write path had a dict.
# ---------------------------------------------------------------------------

def test_context_as_dict_and_as_equivalent_json_string_hash_identically():
    """Hash an equivalent context identically whether it is given as a dict or as its JSON string."""
    as_dict = _base_audit_event(context={"a": 1, "b": [1, 2, 3]})
    as_json_string = _base_audit_event(context='{"a": 1, "b": [1, 2, 3]}')

    hash_from_dict = compute_audit_event_hash(as_dict, SECRET)
    hash_from_string = compute_audit_event_hash(as_json_string, SECRET)

    assert hash_from_dict == hash_from_string


def test_context_key_order_does_not_affect_the_hash():
    """Hash a context dict identically regardless of key order."""
    record_a = _base_audit_event(context={"a": 1, "b": 2})
    record_b = _base_audit_event(context={"b": 2, "a": 1})

    assert compute_audit_event_hash(record_a, SECRET) == compute_audit_event_hash(record_b, SECRET)


def test_a_hash_computed_from_a_dict_verifies_against_a_row_shaped_as_json_string():
    """Simulates the exact real bug: hash computed at write time (dict),
    verified later against a row shape that came back as a string."""
    write_time = _base_audit_event(context={"k": "v"})
    stored_hash = compute_audit_event_hash(write_time, SECRET)

    read_time = _base_audit_event(context='{"k": "v"}')
    read_time["record_integrity_hash"] = stored_hash
    assert verify_audit_event_hash(read_time, SECRET) is True


# ---------------------------------------------------------------------------
# Bug #2: timestamp microsecond handling -- MySQL's plain DATETIME column
# has no fractional-second precision, and collapses an inserted value by
# ROUNDING to the nearest second (round-half-up: .500000 and above rounds
# UP), never by truncating/flooring. Verified directly against a real
# MySQL 8.0 server: INSERT '...12:00:00.500000' reads back as
# '...12:00:01'. An EARLIER version of both record_integrity.py and this
# test file assumed floor-truncation -- self-consistently "passing" while
# encoding the wrong assumption, since the test was written against the
# same incorrect mental model as the code. It only surfaced as an
# intermittent (~50% of random datetime.now() microsecond values fail)
# failure in a real end-to-end integration test run, never in isolated
# unit tests, because this file's own fixtures never exercised a value at
# or above the .5-second rounding boundary. These tests now pin the
# actual, server-verified behavior.
# ---------------------------------------------------------------------------

def test_timestamp_below_rounding_boundary_truncates_down():
    """Hash a sub-half-second timestamp the same as its truncated whole second."""
    below_half = _base_audit_event(timestamp=datetime(2026, 9, 16, 12, 0, 0, 499999))  # noqa: DTZ001 -- naive column, matches AuditEventRecord.timestamp convention
    whole_second = _base_audit_event(timestamp=datetime(2026, 9, 16, 12, 0, 0, 0))  # noqa: DTZ001 -- same as above

    assert compute_audit_event_hash(below_half, SECRET) == compute_audit_event_hash(whole_second, SECRET)


def test_timestamp_at_or_above_rounding_boundary_rounds_up_to_the_next_second():
    """The exact case the earlier (buggy) truncation-only implementation
    got wrong: MySQL rounds .500000 and above UP to the next second."""
    at_half = _base_audit_event(timestamp=datetime(2026, 9, 16, 12, 0, 0, 500000))  # noqa: DTZ001 -- same as above
    above_half = _base_audit_event(timestamp=datetime(2026, 9, 16, 12, 0, 0, 999999))  # noqa: DTZ001 -- same as above
    next_second = _base_audit_event(timestamp=datetime(2026, 9, 16, 12, 0, 1, 0))  # noqa: DTZ001 -- same as above

    assert compute_audit_event_hash(at_half, SECRET) == compute_audit_event_hash(next_second, SECRET)
    assert compute_audit_event_hash(above_half, SECRET) == compute_audit_event_hash(next_second, SECRET)


def test_a_hash_computed_from_a_microsecond_precision_datetime_verifies_against_the_rounded_stored_value():
    """Simulates the exact real bug: Sink.write() computes the hash from
    an in-memory datetime.now()-shaped value (microseconds included)
    before MySQL rounds it on storage; a later read-back has
    microsecond=0 at the ROUNDED second, not the floored one. Both must
    verify against the same stored hash."""
    write_time = _base_audit_event(timestamp=datetime(2026, 9, 16, 12, 0, 0, 999999))  # noqa: DTZ001 -- same as above
    stored_hash = compute_audit_event_hash(write_time, SECRET)

    read_time = _base_audit_event(timestamp=datetime(2026, 9, 16, 12, 0, 1, 0))  # noqa: DTZ001 -- MySQL rounded up to this
    read_time["record_integrity_hash"] = stored_hash
    assert verify_audit_event_hash(read_time, SECRET) is True


def test_different_whole_second_timestamps_still_produce_different_hashes():
    """Guards against the rounding fix accidentally making the hash
    insensitive to real timestamp changes, not just sub-second noise."""
    record_a = _base_audit_event(timestamp=datetime(2026, 9, 16, 12, 0, 0))  # noqa: DTZ001 -- same as above
    record_b = _base_audit_event(timestamp=datetime(2026, 9, 16, 12, 0, 1))  # noqa: DTZ001 -- same as above

    assert compute_audit_event_hash(record_a, SECRET) != compute_audit_event_hash(record_b, SECRET)


# ---------------------------------------------------------------------------
# Field coverage sanity -- every AUDIT_EVENT_FIELDS/QUARANTINE_RECORD_FIELDS
# entry actually affects the hash (a field silently excluded from coverage
# would mean tampering with it goes undetected).
# ---------------------------------------------------------------------------

def test_every_audit_event_field_affects_the_hash():
    """Change the hash when any single audit-event field is mutated."""
    from audit.record_integrity import AUDIT_EVENT_FIELDS

    base = _base_audit_event()
    base_hash = compute_audit_event_hash(base, SECRET)
    overrides = {
        "event_id": "different", "service": "different", "event_type": "different",
        "user_id": "different", "organization_id": "different", "tenant_scope": "global",
        "action": "different", "resource": "different", "decision": "different",
        "reason": "different", "trace_id": "different", "context": {"different": True},
        "integrity_status": "invalid",
    }
    for field in AUDIT_EVENT_FIELDS:
        if field == "timestamp":
            continue  # covered by its own dedicated tests above
        mutated = dict(base, **{field: overrides[field]})
        assert compute_audit_event_hash(mutated, SECRET) != base_hash, f"field {field!r} does not affect the hash"


def test_every_quarantine_field_affects_the_hash():
    """Change the hash when any single quarantine-record field is mutated."""
    from audit.record_integrity import QUARANTINE_RECORD_FIELDS

    base = _base_quarantine_record()
    base_hash = compute_quarantine_record_hash(base, SECRET)
    overrides = {
        "stream_message_id": "2-0", "raw_data": "different", "raw_signature": "different",
        "service": "different", "failure_category": "persistence_exhausted",
        "failure_detail": "different", "delivery_attempts": 99,
    }
    for field in QUARANTINE_RECORD_FIELDS:
        mutated = dict(base, **{field: overrides[field]})
        assert compute_quarantine_record_hash(mutated, SECRET) != base_hash, f"field {field!r} does not affect the hash"


# ---------------------------------------------------------------------------
# Domain separation -- must never collide with the producer-signing
# construction (audit/signing.py) or other established constructions in
# this codebase, even though they may share the same underlying secret.
# ---------------------------------------------------------------------------

def test_record_integrity_hash_differs_from_producer_signature_for_equivalent_content():
    """Produce a record-integrity hash that never collides with the producer's own signature for the
    same content."""
    from audit.signing import sign_audit_event

    record = _base_audit_event()
    record_hash = compute_audit_event_hash(record, SECRET)
    producer_sig = sign_audit_event("test", "event_id=evt-1", SECRET)

    assert record_hash not in producer_sig
    assert producer_sig not in record_hash
