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
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

from audit.record_integrity import (
    audit_event_hash_matches_legacy_utc_form,
    compute_audit_event_hash,
    compute_quarantine_record_hash,
    to_naive_utc,
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


# ---------------------------------------------------------------------------
# Timezone-aware write-time timestamps (found 2026-09-24 against the live
# ledger: 2,856 of 3,070 hashed rows failed verification). Producers send
# ISO-8601 strings with "Z"/"+00:00", pydantic parses them to aware
# datetimes, and the hash covered "...+00:00" while MySQL's DATETIME
# returns the same instant naive on read.
# ---------------------------------------------------------------------------

def _pre_fix_audit_event_hash(record: dict, secret: str) -> str:
    """Independent re-implementation of the pre-2026-09-24 canonical form
    for an aware UTC timestamp: round, keep tzinfo, isoformat. Written out
    here rather than calling the module's legacy helper, so the test does
    not just confirm the code against itself."""
    ts = record["timestamp"]
    micro = ts.microsecond
    ts = ts.replace(microsecond=0) + (timedelta(seconds=1) if micro >= 500_000 else timedelta(0))
    fields = (
        "event_id", "timestamp", "service", "event_type", "user_id",
        "organization_id", "tenant_scope", "action", "resource", "decision",
        "reason", "trace_id", "context", "integrity_status",
    )
    parts = []
    for field in fields:
        value = record.get(field)
        if field == "context":
            value = json.dumps(value or {}, sort_keys=True, default=str, separators=(",", ":"))
        elif field == "timestamp":
            value = ts.isoformat()
        parts.append(f"{field}={value!s}")
    key = hashlib.sha256(f"omnibioai-audit-record-integrity:{secret}".encode()).digest()
    return hmac.new(key, "\n".join(parts).encode(), hashlib.sha256).hexdigest()


def test_aware_utc_write_time_timestamp_verifies_against_naive_stored_value():
    """The live bug: hash computed from an aware UTC value at insert time
    must verify against the naive value MySQL returns on read."""
    write_time = _base_audit_event(timestamp=datetime(2026, 9, 16, 12, 0, 0, 700000, tzinfo=timezone.utc))
    stored_hash = compute_audit_event_hash(write_time, SECRET)

    read_time = _base_audit_event(timestamp=datetime(2026, 9, 16, 12, 0, 1))  # noqa: DTZ001 -- naive, as MySQL returns it
    read_time["record_integrity_hash"] = stored_hash
    assert verify_audit_event_hash(read_time, SECRET) is True


def test_aware_non_utc_write_time_timestamp_verifies_against_utc_stored_value():
    """A non-UTC offset is the same instant; Sink stores it as naive UTC,
    so the hash must canonicalize it to UTC too."""
    chicago = timezone(timedelta(hours=-5))
    write_time = _base_audit_event(timestamp=datetime(2026, 9, 16, 7, 0, 0, tzinfo=chicago))
    stored_hash = compute_audit_event_hash(write_time, SECRET)

    read_time = _base_audit_event(timestamp=datetime(2026, 9, 16, 12, 0, 0))  # noqa: DTZ001 -- naive UTC
    read_time["record_integrity_hash"] = stored_hash
    assert verify_audit_event_hash(read_time, SECRET) is True


def test_row_hashed_with_the_pre_fix_utc_suffix_form_still_verifies():
    """Rows already in the ledger were hashed with a "+00:00" suffix; the
    append-only triggers mean they can never be re-hashed, so verification
    must accept that form for the same instant."""
    write_time = _base_audit_event(timestamp=datetime(2026, 9, 16, 12, 0, 0, 200000, tzinfo=timezone.utc))
    legacy_hash = _pre_fix_audit_event_hash(write_time, SECRET)

    read_time = _base_audit_event(timestamp=datetime(2026, 9, 16, 12, 0, 0))  # noqa: DTZ001 -- naive, as stored
    read_time["record_integrity_hash"] = legacy_hash
    assert verify_audit_event_hash(read_time, SECRET) is True
    assert audit_event_hash_matches_legacy_utc_form(read_time, SECRET) is True


def test_legacy_form_fallback_still_detects_a_changed_field():
    """Accepting the legacy timestamp representation must not weaken
    tamper detection for any other field."""
    write_time = _base_audit_event(timestamp=datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc))
    legacy_hash = _pre_fix_audit_event_hash(write_time, SECRET)

    tampered = _base_audit_event(timestamp=datetime(2026, 9, 16, 12, 0, 0), decision="allow")  # noqa: DTZ001
    tampered["record_integrity_hash"] = legacy_hash
    assert verify_audit_event_hash(tampered, SECRET) is False
    assert audit_event_hash_matches_legacy_utc_form(tampered, SECRET) is False


def test_legacy_form_fallback_still_rejects_the_wrong_secret():
    """A row hashed under a different key (e.g. the public "change-me"
    fallback) must fail under both canonical forms."""
    write_time = _base_audit_event(timestamp=datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc))
    foreign_hash = _pre_fix_audit_event_hash(write_time, "change-me")

    read_time = _base_audit_event(timestamp=datetime(2026, 9, 16, 12, 0, 0))  # noqa: DTZ001
    read_time["record_integrity_hash"] = foreign_hash
    assert verify_audit_event_hash(read_time, SECRET) is False


def test_new_rows_do_not_rely_on_the_legacy_form():
    """A hash computed by the current code verifies on the primary form,
    so the legacy count in the verifier only ever reflects old rows."""
    write_time = _base_audit_event(timestamp=datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc))
    read_time = _base_audit_event(timestamp=datetime(2026, 9, 16, 12, 0, 0))  # noqa: DTZ001
    read_time["record_integrity_hash"] = compute_audit_event_hash(write_time, SECRET)
    assert verify_audit_event_hash(read_time, SECRET) is True
    assert audit_event_hash_matches_legacy_utc_form(read_time, SECRET) is False


def test_to_naive_utc_converts_aware_and_passes_through_naive():
    """Normalization helper shared by Sink and the canonical form."""
    naive = datetime(2026, 9, 16, 12, 0, 0)  # noqa: DTZ001
    assert to_naive_utc(naive) is naive
    assert to_naive_utc(datetime(2026, 9, 16, 7, 0, 0, tzinfo=timezone(timedelta(hours=-5)))) == naive
    assert to_naive_utc(None) is None
    assert to_naive_utc("2026-09-16T12:00:00") == "2026-09-16T12:00:00"


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

# ---------------------------------------------------------------------------
# Defensive branches: a context value that looks like a string but isn't
# actually JSON, and the fail-closed `except Exception` wrapper in both
# verify_*_hash functions (triggered via a record whose value can't be
# formatted into the canonical message at all).
# ---------------------------------------------------------------------------

def test_context_as_a_non_json_string_is_hashed_as_the_literal_string():
    """A context value that is a string but not valid JSON falls through
    _canonical_json's except branch and is hashed as-is, rather than raising."""
    record = _base_audit_event(context="not valid json {")
    record_hash = compute_audit_event_hash(record, SECRET)
    # Hashing must succeed and be stable/deterministic for the same input.
    assert record_hash == compute_audit_event_hash(_base_audit_event(context="not valid json {"), SECRET)
    # And must differ from the same field hashed as an empty context.
    assert record_hash != compute_audit_event_hash(_base_audit_event(context="{}"), SECRET)


class _RaisesOnFormat:
    """A value whose __format__ raises -- used to force compute_*_hash to
    raise inside _canonical_message's f-string formatting, so
    verify_*_hash's fail-closed `except Exception` branch is exercised."""

    def __format__(self, format_spec):
        raise RuntimeError("boom")

    def __str__(self):
        raise RuntimeError("boom")


def test_verify_audit_event_hash_fails_closed_when_computing_the_hash_raises():
    """Return False, not raise, when compute_audit_event_hash itself raises."""
    record = _base_audit_event(action=_RaisesOnFormat())
    record["record_integrity_hash"] = "irrelevant"
    assert verify_audit_event_hash(record, SECRET) is False


def test_verify_quarantine_record_hash_fails_closed_when_computing_the_hash_raises():
    """Return False, not raise, when compute_quarantine_record_hash itself raises."""
    record = _base_quarantine_record(failure_category=_RaisesOnFormat())
    record["record_integrity_hash"] = "irrelevant"
    assert verify_quarantine_record_hash(record, SECRET) is False


def test_record_integrity_hash_differs_from_producer_signature_for_equivalent_content():
    """Produce a record-integrity hash that never collides with the producer's own signature for the
    same content."""
    from audit.signing import sign_audit_event

    record = _base_audit_event()
    record_hash = compute_audit_event_hash(record, SECRET)
    producer_sig = sign_audit_event("test", "event_id=evt-1", SECRET)

    assert record_hash not in producer_sig
    assert producer_sig not in record_hash
