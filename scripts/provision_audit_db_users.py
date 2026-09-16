#!/usr/bin/env python3
"""V2-003 (Track E3): provisions least-privilege MySQL users for the
audit pipeline. Deliberately NOT an Alembic migration -- migrations are
schema-management concerns re-run per environment; user/password
provisioning is a one-time-per-environment operational step that must
never have a password embedded in a file checked into git.

Creates three restricted MySQL users, idempotently:

  audit_writer      -- SELECT, INSERT only on audit_events and
                        quarantined_audit_events. Used by the consumer
                        worker (the only runtime path that ever
                        INSERTs). No UPDATE/DELETE/DROP grant at all --
                        TRUNCATE requires the DROP privilege in MySQL,
                        so this user structurally cannot TRUNCATE
                        either, without needing a trigger for that.

  audit_reader       -- SELECT only on both tables. Used by the
                        read-only API routes (GET /audit/events,
                        GET /audit/events/safe, GET /audit/pipeline-health).

  audit_maintenance  -- SELECT, DELETE on both tables (retention
                        cleanup, gated further by
                        trg_*_no_delete's identity+legal-hold checks --
                        see alembic/versions/0005_retention_immutability.py)
                        plus SELECT, INSERT, DELETE on audit_legal_holds
                        (declaring/releasing holds). No UPDATE grant
                        anywhere for this user either.

Root/admin credentials (used only to run this script, never by the
application at runtime) come from AUDIT_DB_ADMIN_URL, defaulting to
AuditConfig.DATABASE_URL -- the same connection migrations already use.
Target passwords come from three required env vars with NO fallback
default (fail closed, matching the lesson from the Track E1 MySQL
backup incident: a default/fallback password is exactly the kind of
gap that goes unnoticed until it's exploited).

After running, point the application at the restricted users by
setting AUDIT_WRITER_DATABASE_URL / AUDIT_READER_DATABASE_URL (see
audit/config.py) -- deliberately NOT done automatically by this script,
since assembling and storing those connection strings is itself a
secret-handling step for the operator's own secret-management tooling,
not something to print or write to a file here.

Usage:
    AUDIT_DB_ADMIN_URL=mysql+pymysql://root:root@localhost:3306/omnibioai_audit \\
    AUDIT_WRITER_DB_PASSWORD=... \\
    AUDIT_READER_DB_PASSWORD=... \\
    AUDIT_MAINTENANCE_DB_PASSWORD=... \\
    python3 scripts/provision_audit_db_users.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pymysql
from sqlalchemy.engine.url import make_url

# Run directly (not `python -m`) per this file's own Usage example --
# put the repo root on sys.path so `from audit.config import
# AuditConfig` (below, inside _connect_admin) resolves the same way it
# does for worker/main.py (invoked via `python -m worker.main` from
# WORKDIR /app in Dockerfile.worker, which already has the repo root as
# sys.path[0]).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_TABLES = ("audit_events", "quarantined_audit_events")


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"[FAIL] {name} must be set -- refusing to provision with a default/fallback password", file=sys.stderr)
        sys.exit(1)
    return value


def _connect_admin():
    from audit.config import AuditConfig

    admin_url_str = os.environ.get("AUDIT_DB_ADMIN_URL", AuditConfig.DATABASE_URL)
    url = make_url(admin_url_str)
    return pymysql.connect(
        host=url.host, port=url.port or 3306, user=url.username, password=url.password or "",
        database=url.database, autocommit=True,
    ), url.database


def _create_user_and_grants(cur, database: str, user: str, password: str, grants: dict[str, tuple[str, ...]]):
    # CREATE USER passes `password` as a bound parameter, so pymysql
    # applies %-style substitution to this query string -- the literal
    # host wildcard must be escaped as %% here. The GRANT statements
    # below pass no parameters at all, so pymysql does NOT substitute
    # them; a literal single % is correct there, and %% would (and, in
    # an earlier draft of this script, empirically did) grant to the
    # wrong, nonexistent account pattern '...'@'%%' -- caught only by
    # actually running this against a real server, not by inspection.
    cur.execute(f"CREATE USER IF NOT EXISTS '{user}'@'%%' IDENTIFIED BY %s", (password,))
    for table, privileges in grants.items():
        priv_list = ", ".join(privileges)
        cur.execute(f"GRANT {priv_list} ON `{database}`.`{table}` TO '{user}'@'%'")
    print(f"[OK] provisioned '{user}'@'%' with: " + ", ".join(f"{t}({','.join(p)})" for t, p in grants.items()))


def main() -> int:
    writer_pw = _required_env("AUDIT_WRITER_DB_PASSWORD")
    reader_pw = _required_env("AUDIT_READER_DB_PASSWORD")
    maintenance_pw = _required_env("AUDIT_MAINTENANCE_DB_PASSWORD")

    conn, database = _connect_admin()
    try:
        cur = conn.cursor()

        _create_user_and_grants(
            cur, database, "audit_writer", writer_pw,
            {t: ("SELECT", "INSERT") for t in _TABLES},
        )
        _create_user_and_grants(
            cur, database, "audit_reader", reader_pw,
            {t: ("SELECT",) for t in _TABLES},
        )
        _create_user_and_grants(
            cur, database, "audit_maintenance", maintenance_pw,
            {
                "audit_events": ("SELECT", "DELETE"),
                "quarantined_audit_events": ("SELECT", "DELETE"),
                "audit_legal_holds": ("SELECT", "INSERT", "DELETE"),
            },
        )

        cur.execute("FLUSH PRIVILEGES")
        print("[OK] privileges flushed")
        print(
            "[NEXT STEP] set AUDIT_WRITER_DATABASE_URL / AUDIT_READER_DATABASE_URL "
            "(and point your retention maintenance process's own connection at "
            "audit_maintenance) using the passwords you just supplied -- this "
            "script does not print or store connection strings containing them."
        )
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
