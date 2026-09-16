"""V2-003 (Track E3): stored-record tamper detection.

Distinct from audit/signing.py's producer-side HMAC (which proves a
*wire payload* was validly signed by whoever holds JWT_SECRET) -- this
module proves a *stored database row's decomposed column values* have
not changed since the trusted worker inserted them. A producer's
signature can never re-verify against a row's current column values
even in the untampered case (the DB never stores the raw signed bytes
for audit_events -- see db/models.py's own comment), so this is a
necessary, separate mechanism, not a duplicate of producer signing.

Same domain-separation pattern already established across this
platform (audit/signing.py, TES's IAM-cache MAC, etc.): one label per
use case, same underlying JWT_SECRET, so a hash computed here can never
be replayed as valid under a different construction even if the secret
is shared.

Computed ONCE, at insert time, by consumers/sink.py and
consumers/quarantine.py -- never recomputed or updated afterward. This
is enforced two ways: by convention (nothing in this codebase calls
these functions except at insert time) and, more robustly, by the
database itself (trg_audit_events_no_update / trg_quarantined_audit_
events_no_update reject UPDATE for any identity other than
audit_maintenance, and that identity's own grants -- see
scripts/provision_audit_db_users.py -- never include UPDATE at all).
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import timedelta

_DOMAIN_LABEL = "omnibioai-audit-record-integrity"


def _integrity_key(secret: str) -> bytes:
    return hashlib.sha256(f"{_DOMAIN_LABEL}:{secret}".encode()).digest()


def _canonical_json(value) -> str:
    """Deterministic serialization for the one JSON-typed field
    (audit_events.context) -- sort_keys so insertion order never
    affects the hash, default=str so any datetime/Decimal-shaped value
    that slipped into context serializes the same way every time.

    `value` may arrive as an already-parsed dict (the normal case: a
    fresh in-memory event about to be inserted, or an ORM-mapped row,
    since SQLAlchemy's JSON column type deserializes on read) OR as a
    raw JSON string (a row fetched via a raw/`text()` SQL query, which
    bypasses ORM-level type deserialization and returns the driver's
    literal string for a JSON column). Both must canonicalize to the
    same bytes for the same logical content, or verification would
    spuriously fail for every row read a different way than it was
    written -- confirmed to actually happen before this fix, via a real
    end-to-end test against MySQL, not just reasoned about.
    """
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            pass  # not actually JSON text -- fall through, hash it as the literal string it is
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


# Explicit, ordered field lists -- NOT `sorted(dict.keys())` over
# whatever a caller happens to pass, so an accidental extra/missing key
# in a caller's dict can never silently change what's covered. Excludes
# server-generated metadata (created_at/quarantined_at) and the hash/
# legal_hold columns themselves (self-referential).
AUDIT_EVENT_FIELDS = (
    "event_id", "timestamp", "service", "event_type", "user_id",
    "organization_id", "tenant_scope", "action", "resource", "decision",
    "reason", "trace_id", "context", "integrity_status",
)

QUARANTINE_RECORD_FIELDS = (
    "stream_message_id", "raw_data", "raw_signature", "service",
    "failure_category", "failure_detail", "delivery_attempts",
)


def _canonical_message(record: dict, fields: tuple[str, ...]) -> bytes:
    parts = []
    for field in fields:
        value = record.get(field)
        if field == "context":
            value = _canonical_json(value if value is not None else {})
        elif field == "timestamp" and value is not None and hasattr(value, "isoformat"):
            # audit_events.timestamp is a plain MySQL DATETIME column --
            # no fractional-second precision. A Python datetime with
            # microseconds (e.g. datetime.now()) has its fractional part
            # collapsed by MySQL on INSERT -- but by ROUNDING to the
            # nearest second (standard round-half-up: .500000 and above
            # rounds up), NOT by truncating/flooring. This was verified
            # empirically against a real MySQL 8.0 server (INSERT
            # '...12:00:00.500000' reads back as '...12:00:01') after an
            # earlier version of this function used floor-truncation
            # instead and produced an intermittent, microsecond-value-
            # dependent hash mismatch for genuinely untampered rows --
            # roughly half of random datetime.now() values have
            # microsecond >= 500000 and round up, silently disagreeing
            # with a floor-based canonical form. Reproduced via a real
            # end-to-end test suite run (not a unit test in isolation)
            # before this fix; see tests/test_record_integrity.py's
            # rounding-boundary tests for the pinned regression.
            microsecond = value.microsecond
            value = value.replace(microsecond=0)
            if microsecond >= 500_000:
                value = value + timedelta(seconds=1)
            value = value.isoformat()
        parts.append(f"{field}={value!s}")
    return "\n".join(parts).encode()


def compute_audit_event_hash(record: dict, secret: str) -> str:
    """`record` is a dict with (at least) AUDIT_EVENT_FIELDS' keys --
    either the dict about to be inserted, or an ORM row's __dict__-like
    mapping when re-verifying. Returns a hex-encoded HMAC-SHA256."""
    mac = hmac.new(_integrity_key(secret), _canonical_message(record, AUDIT_EVENT_FIELDS), hashlib.sha256)
    return mac.hexdigest()


def compute_quarantine_record_hash(record: dict, secret: str) -> str:
    mac = hmac.new(_integrity_key(secret), _canonical_message(record, QUARANTINE_RECORD_FIELDS), hashlib.sha256)
    return mac.hexdigest()


def verify_audit_event_hash(record: dict, secret: str) -> bool:
    """False for a tampered row, a wrong secret, AND a row with no
    stored hash (record_integrity_hash is None -- pre-existing rows
    from before this column existed, or a row that was never through
    the trusted write path at all). Never raises."""
    stored = record.get("record_integrity_hash")
    if not stored:
        return False
    try:
        expected = compute_audit_event_hash(record, secret)
    except Exception:  # noqa: BLE001 -- a malformed record fails verification, it does not crash the verifier
        return False
    return hmac.compare_digest(stored, expected)


def verify_quarantine_record_hash(record: dict, secret: str) -> bool:
    stored = record.get("record_integrity_hash")
    if not stored:
        return False
    try:
        expected = compute_quarantine_record_hash(record, secret)
    except Exception:  # noqa: BLE001 -- same as above
        return False
    return hmac.compare_digest(stored, expected)
