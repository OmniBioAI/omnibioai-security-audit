#!/usr/bin/env python3
"""V2-003 (Track E3): safe, read-only stored-record integrity
verification for audit_events and quarantined_audit_events.

Recomputes each row's record_integrity_hash from its CURRENT column
values (audit/record_integrity.py) and compares against what was
stored at insert time. A mismatch means the row's columns have changed
since it was written through the trusted worker path -- detected
tampering, not proven-safe data.

Never prints row content (context, reason, raw_data, etc.) -- only
counts and structural identifiers (event_id / stream_message_id, which
are producer-generated UUIDs / Redis stream IDs, not PHI).

Exit code is unmistakable for automation: 0 only if zero invalid
records and zero structural problems were found. Any invalid record,
any duplicate PK-shaped anomaly, or a connection failure is a non-zero
exit -- this script fails loudly, never silently reports "clean" when
it couldn't actually check.

Usage:
    AUDIT_READER_DATABASE_URL=mysql+pymysql://audit_reader:...@host/db \\
    python3 scripts/verify_audit_integrity.py
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from audit.record_integrity import (
    verify_audit_event_hash,
    verify_quarantine_record_hash,
)
from db.models import (
    AuditEventRecord,
    QuarantinedAuditEvent,
)

_AUDIT_EVENT_REQUIRED = ("event_id", "timestamp", "service", "event_type", "action")
_QUARANTINE_REQUIRED = ("stream_message_id", "failure_category", "delivery_attempts")


def _resolve_secret() -> str:
    secret = os.environ.get("JWT_SECRET")
    if not secret:
        print(
            "[FAIL] JWT_SECRET must be set -- verification cannot proceed without "
            "the same secret record_integrity_hash was computed with",
            file=sys.stderr,
        )
        sys.exit(1)
    return secret


def _resolve_session():
    db_url = os.environ.get("AUDIT_READER_DATABASE_URL") or os.environ.get("AUDIT_DATABASE_URL")
    if not db_url:
        print("[FAIL] AUDIT_READER_DATABASE_URL (or AUDIT_DATABASE_URL) must be set", file=sys.stderr)
        sys.exit(1)
    engine = create_engine(db_url)
    return sessionmaker(bind=engine)()


def _to_dict(orm_row, columns: tuple[str, ...]) -> dict:
    # Deliberately via the ORM (session.query(Model)), not a raw/text()
    # SQL SELECT -- confirmed by a real end-to-end test that a raw-SQL
    # read returns a JSON column (context) as a literal string rather
    # than a parsed dict, which does not canonicalize identically to
    # the in-memory dict Sink.write()/QuarantineSink.write() hashed at
    # insert time, causing every untampered row to spuriously fail
    # verification. The ORM's JSON column type deserializes on read,
    # matching the write side's shape exactly. audit/record_integrity.py's
    # _canonical_json() is *also* hardened to accept either shape as a
    # second, independent layer of defense -- this comment documents
    # why both fixes exist rather than just one.
    return {col: getattr(orm_row, col) for col in columns}


def verify_audit_events(session, secret: str) -> dict:
    stats = {"checked": 0, "valid": 0, "invalid": [], "no_baseline": 0, "structural": []}
    columns = (
        "event_id", "timestamp", "service", "event_type", "user_id", "organization_id",
        "tenant_scope", "action", "resource", "decision", "reason", "trace_id", "context",
        "integrity_status", "record_integrity_hash",
    )
    seen_ids = set()
    for orm_row in session.query(AuditEventRecord).yield_per(500):
        row = _to_dict(orm_row, columns)
        stats["checked"] += 1
        if row["event_id"] in seen_ids:
            stats["structural"].append(f"duplicate event_id: {row['event_id']}")
        seen_ids.add(row["event_id"])

        for field in _AUDIT_EVENT_REQUIRED:
            if row[field] is None or row[field] == "":
                stats["structural"].append(f"{row['event_id']}: missing required field {field!r}")

        if not row["record_integrity_hash"]:
            stats["no_baseline"] += 1
            continue

        record = row
        if verify_audit_event_hash(record, secret):
            stats["valid"] += 1
        else:
            stats["invalid"].append(row["event_id"])
    return stats


def verify_quarantine_records(session, secret: str) -> dict:
    stats = {"checked": 0, "valid": 0, "invalid": [], "no_baseline": 0, "structural": []}
    columns = (
        "stream_message_id", "raw_data", "raw_signature", "service", "failure_category",
        "failure_detail", "delivery_attempts", "record_integrity_hash",
    )
    seen_ids = set()
    for orm_row in session.query(QuarantinedAuditEvent).yield_per(500):
        row = _to_dict(orm_row, columns)
        stats["checked"] += 1
        if row["stream_message_id"] in seen_ids:
            stats["structural"].append(f"duplicate stream_message_id: {row['stream_message_id']}")
        seen_ids.add(row["stream_message_id"])

        for field in _QUARANTINE_REQUIRED:
            if row[field] is None or row[field] == "":
                stats["structural"].append(f"{row['stream_message_id']}: missing required field {field!r}")

        if not row["record_integrity_hash"]:
            stats["no_baseline"] += 1
            continue

        record = row
        if verify_quarantine_record_hash(record, secret):
            stats["valid"] += 1
        else:
            stats["invalid"].append(row["stream_message_id"])
    return stats


def _report(name: str, stats: dict) -> bool:
    """Returns True if this table's verification found no problems."""
    print(f"[INFO] {name}: {stats['checked']} record(s) checked")
    print(f"[INFO] {name}: {stats['valid']} valid, {stats['no_baseline']} no-baseline (pre-dates this feature)")
    ok = True
    if stats["invalid"]:
        ok = False
        print(f"[FAIL] {name}: {len(stats['invalid'])} record(s) failed integrity verification:", file=sys.stderr)
        for identifier in stats["invalid"]:
            print(f"[FAIL] {name}: TAMPERED OR CORRUPTED: {identifier}", file=sys.stderr)
    if stats["structural"]:
        ok = False
        print(f"[FAIL] {name}: {len(stats['structural'])} structural problem(s):", file=sys.stderr)
        for problem in stats["structural"]:
            print(f"[FAIL] {name}: {problem}", file=sys.stderr)
    if ok:
        print(f"[OK] {name}: no integrity or structural problems found")
    return ok


def _write_status_file(passed: bool, events_stats: dict, quarantine_stats: dict) -> None:
    """V2-003 Phase 18: optional, non-breaking operational evidence --
    only written when AUDIT_HEALTH_STATUS_DIR is set (same opt-in
    pattern as the writer/reader DB URL split in audit/config.py: an
    unconfigured deployment behaves exactly as before). Read by
    services/audit_health_service.py if present, matching Track E1's
    mysql-backup-health.env convention -- a small KEY=VALUE file, not a
    new database table, so this remains a pure add-on with no schema
    dependency for a signal that's inherently produced by an external
    script run, not the API/worker's own runtime.
    """
    status_dir = os.environ.get("AUDIT_HEALTH_STATUS_DIR")
    if not status_dir:
        return
    path = Path(status_dir) / "audit-integrity-verification.env"
    now = datetime.now(timezone.utc).isoformat()
    lines = [
        f"LAST_VERIFICATION_TS={now}",
        f"LAST_VERIFICATION_RESULT={'pass' if passed else 'fail'}",
        f"LAST_VERIFICATION_EVENTS_CHECKED={events_stats['checked']}",
        f"LAST_VERIFICATION_EVENTS_INVALID={len(events_stats['invalid'])}",
        f"LAST_VERIFICATION_QUARANTINE_CHECKED={quarantine_stats['checked']}",
        f"LAST_VERIFICATION_QUARANTINE_INVALID={len(quarantine_stats['invalid'])}",
    ]
    tmp_path = path.with_suffix(".tmp")
    tmp_path.write_text("\n".join(lines) + "\n")
    tmp_path.replace(path)


def main() -> int:
    secret = _resolve_secret()
    session = _resolve_session()

    try:
        events_stats = verify_audit_events(session, secret)
        quarantine_stats = verify_quarantine_records(session, secret)
        events_ok = _report("audit_events", events_stats)
        quarantine_ok = _report("quarantined_audit_events", quarantine_stats)
    finally:
        session.close()

    passed = events_ok and quarantine_ok
    _write_status_file(passed, events_stats, quarantine_stats)

    if passed:
        print("[OK] integrity verification passed")
        return 0
    print("[FAIL] integrity verification found problems -- see above", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
