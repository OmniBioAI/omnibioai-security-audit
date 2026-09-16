#!/usr/bin/env python3
"""V2-003 (Track E3): authorized retention cleanup for audit_events and
quarantined_audit_events.

Two independent gates must both be satisfied before this script deletes
anything, by design:

  1. AUDIT_RETENTION_DAYS must be explicitly set. There is no default
     duration -- this repository does not invent a legal retention
     period. Unset means "retention is not yet configured": the script
     reports that and exits 0 (a successful no-op, not an error).

  2. The connecting identity must be the restricted `audit_maintenance`
     MySQL user (scripts/provision_audit_db_users.py). This script
     never uses AUDIT_WRITER_DATABASE_URL or plain DATABASE_URL/root --
     it requires AUDIT_MAINTENANCE_DATABASE_URL to be explicitly set,
     with NO fallback, so a misconfigured deployment fails closed
     (refuses to run) rather than silently deleting with an
     overprivileged credential. Even if this script's own logic were
     bypassed entirely, the database's own trg_audit_events_no_delete /
     trg_quarantined_audit_events_no_delete triggers independently
     reject any DELETE from a non-audit_maintenance identity -- this is
     defense in depth, not the only control.

Legal hold is honored twice for the same reason: this script's own
query excludes held rows (audit_legal_holds), AND the database trigger
independently rejects deleting a held row even if this script's query
had a bug. Neither layer alone is trusted to be sufficient.

Defaults to --dry-run (report what WOULD be deleted, delete nothing).
Requires the explicit --execute flag to actually delete. A partial
failure (one table's DELETE succeeds, the other's fails) is reported
as a partial result, never silently upgraded to "complete success" --
see main()'s explicit per-table result tracking.

Usage:
    AUDIT_MAINTENANCE_DATABASE_URL=mysql+pymysql://audit_maintenance:...@host/db \\
    AUDIT_RETENTION_DAYS=90 \\
    python3 scripts/audit_retention_cleanup.py --dry-run

    # after reviewing the dry-run output:
    AUDIT_MAINTENANCE_DATABASE_URL=... AUDIT_RETENTION_DAYS=90 \\
    python3 scripts/audit_retention_cleanup.py --execute
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine, text

from audit.security_alerts import emit_security_alert

_TABLES = (
    ("audit_events", "event_id", "timestamp"),
    ("quarantined_audit_events", "stream_message_id", "quarantined_at"),
)


def _cutoff(retention_days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=retention_days)


def _write_status_file(mode: str, overall_ok: bool, results: dict) -> None:
    """V2-003 Phase 18: optional operational evidence, same opt-in
    convention as verify_audit_integrity.py's own status file -- only
    written when AUDIT_HEALTH_STATUS_DIR is set."""
    status_dir = os.environ.get("AUDIT_HEALTH_STATUS_DIR")
    if not status_dir:
        return
    path = Path(status_dir) / "audit-retention-run.env"
    now = datetime.now(timezone.utc).isoformat()
    total_deleted = sum(r.get("count", 0) for r in results.values() if r.get("status") == "success")
    lines = [
        f"LAST_RETENTION_RUN_TS={now}",
        f"LAST_RETENTION_RUN_MODE={mode}",
        f"LAST_RETENTION_RUN_RESULT={'success' if overall_ok else 'failed_or_partial'}",
        f"LAST_RETENTION_RUN_DELETED_TOTAL={total_deleted}",
    ]
    tmp_path = path.with_suffix(".tmp")
    tmp_path.write_text("\n".join(lines) + "\n")
    tmp_path.replace(path)


def _count_eligible(conn, table: str, key_col: str, date_col: str, cutoff: datetime) -> int:
    result = conn.execute(
        text(f"""
            SELECT COUNT(*) FROM {table} t
            WHERE t.{date_col} < :cutoff
              AND NOT EXISTS (
                  SELECT 1 FROM audit_legal_holds h
                  WHERE h.record_table = :table_name AND h.record_key = t.{key_col}
              )
        """),
        {"cutoff": cutoff, "table_name": table},
    )
    return result.scalar_one()


def _delete_eligible(conn, table: str, key_col: str, date_col: str, cutoff: datetime) -> int:
    result = conn.execute(
        text(f"""
            DELETE FROM {table}
            WHERE {date_col} < :cutoff
              AND NOT EXISTS (
                  SELECT 1 FROM audit_legal_holds h
                  WHERE h.record_table = :table_name AND h.record_key = {table}.{key_col}
              )
        """),
        {"cutoff": cutoff, "table_name": table},
    )
    return result.rowcount


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="actually delete (default: dry-run only)")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="explicit no-op flag matching the default behavior (report only, delete nothing) -- for clarity in scripts/cron entries that want to say so explicitly",
    )
    args = parser.parse_args(argv)
    if args.dry_run and args.execute:
        parser.error("--dry-run and --execute are mutually exclusive")

    retention_days_raw = os.environ.get("AUDIT_RETENTION_DAYS")
    if not retention_days_raw:
        print(
            "[OK] AUDIT_RETENTION_DAYS is not set -- retention is not yet "
            "configured for this deployment (governance prerequisite, see "
            "hipaa_v2_003_audit_retention_immutability_evidence.md). Nothing to do."
        )
        return 0
    try:
        retention_days = int(retention_days_raw)
        if retention_days <= 0:
            raise ValueError
    except ValueError:
        print(f"[FAIL] AUDIT_RETENTION_DAYS must be a positive integer, got {retention_days_raw!r}", file=sys.stderr)
        return 1

    maintenance_url = os.environ.get("AUDIT_MAINTENANCE_DATABASE_URL")
    if not maintenance_url:
        print(
            "[FAIL] AUDIT_MAINTENANCE_DATABASE_URL must be set -- this script "
            "never falls back to a writer/admin connection for retention "
            "deletion. Provision the audit_maintenance identity first "
            "(scripts/provision_audit_db_users.py).",
            file=sys.stderr,
        )
        return 1

    cutoff = _cutoff(retention_days)
    engine = create_engine(maintenance_url)

    print(f"[INFO] retention cutoff: {cutoff.isoformat()} ({retention_days} days)")
    print(f"[INFO] mode: {'EXECUTE' if args.execute else 'DRY-RUN (pass --execute to actually delete)'}")

    results: dict[str, dict] = {}
    overall_ok = True

    for table, key_col, date_col in _TABLES:
        # A fresh connection (and therefore transaction) per table --
        # deliberately not one shared connection across both tables'
        # work, so one table's transaction state/failure can never leak
        # into the other's, and each table's result is independently
        # commit-or-rollback complete before moving to the next.
        try:
            with engine.connect() as conn:
                eligible = _count_eligible(conn, table, key_col, date_col, cutoff)
                if not args.execute:
                    print(f"[DRY-RUN] {table}: {eligible} row(s) would be deleted (excluding legal holds)")
                    results[table] = {"status": "dry_run", "count": eligible}
                    continue

                if eligible == 0:
                    print(f"[OK] {table}: 0 rows eligible, nothing to delete")
                    results[table] = {"status": "success", "count": 0}
                    continue

                deleted = _delete_eligible(conn, table, key_col, date_col, cutoff)
                conn.commit()
                if deleted != eligible:
                    # Genuinely unexpected (a legal hold was added concurrently,
                    # or a trigger silently rejected a subset). Report the
                    # actual number, never silently report the *planned*
                    # count as the result.
                    print(
                        f"[WARN] {table}: expected to delete {eligible}, actually deleted {deleted} "
                        f"-- treat as a partial result, investigate the discrepancy",
                    )
                    results[table] = {"status": "partial", "expected": eligible, "actual": deleted}
                    overall_ok = False
                else:
                    print(f"[OK] {table}: deleted {deleted} row(s)")
                    results[table] = {"status": "success", "count": deleted}
        except Exception as e:  # noqa: BLE001 -- one table's failure must be reported, not silently swallow the other table's result
            print(f"[FAIL] {table}: retention operation failed: {type(e).__name__}: {e}", file=sys.stderr)
            results[table] = {"status": "failed", "error": type(e).__name__}
            overall_ok = False

    mode = "execute" if args.execute else "dry_run"
    _write_status_file(mode, overall_ok, results)

    if not overall_ok:
        # Track E4: a failed/partial retention run is a security-relevant
        # operational condition (could mean legal-hold enforcement or the
        # audit_maintenance credential itself is misbehaving) -- surface it
        # through the same alert channel as integrity-verification failures,
        # not just this script's own exit code.
        failed_tables = [t for t, r in results.items() if r.get("status") == "failed"]
        emit_security_alert(
            condition="retention_cleanup_failed",
            severity="critical" if failed_tables else "warning",
            component="retention-cleanup",
            message="Audit retention cleanup completed with partial or failed results",
            metadata={"mode": mode, "results": {t: r.get("status") for t, r in results.items()}},
        )
        print("[FAIL] retention run completed with partial/failed results -- see above", file=sys.stderr)
        return 1

    print("[OK] retention run completed" + (" (dry-run, nothing deleted)" if not args.execute else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
