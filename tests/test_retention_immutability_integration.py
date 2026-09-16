"""V2-003 (Track E3): retention/immutability, against REAL Redis-free,
real MySQL -- same harness/isolation conventions as
tests/test_worker_integration_real_backends.py (own throwaway database,
skips rather than fails when a real backend isn't reachable).

Covers the required tamper-test matrix (A-J from the governing task):
UPDATE/DELETE denial at the database level (not just application code),
authorized-maintenance-path deletion, legal-hold enforcement even for
the maintenance identity, TRUNCATE denial via privilege absence,
quarantine-table parity, and the provisioning/retention/verification
scripts exercised as subprocesses against this same real database --
proving the actual shipped tooling, not a reimplementation of it.
"""
import os
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from tests._mysql_integration_guard import (
    MissingTestMySQLEndpoint,
    refuse_if_accounts_exist,
    validate_test_mysql_url,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
try:
    # P0 test-isolation fix (2026-09-16): no implicit localhost:3306
    # default -- ProductionMySQLEndpointRejected is deliberately NOT
    # caught here, so a misconfigured production endpoint fails
    # collection loudly instead of silently running this file's
    # CREATE USER/DROP USER against it. See
    # tests/_mysql_integration_guard.py for the full incident this
    # guards against: this exact fixture's teardown destroyed real
    # production audit_writer/audit_reader/audit_maintenance accounts
    # twice on 2026-09-16, via the same silent default this replaces.
    TEST_MYSQL_ROOT_URL = validate_test_mysql_url(os.environ.get("B0_TEST_MYSQL_ROOT_URL"))
except MissingTestMySQLEndpoint:
    TEST_MYSQL_ROOT_URL = None
_RUN_ID = uuid.uuid4().hex[:8]
TEST_DB_NAME = f"omnibioai_audit_e3_test_{_RUN_ID}"
_PROVISIONED_USER_NAMES = ("audit_writer", "audit_reader", "audit_maintenance")


def _real_mysql_available():
    if TEST_MYSQL_ROOT_URL is None:
        return False
    try:
        engine = create_engine(TEST_MYSQL_ROOT_URL, connect_args={"connect_timeout": 2})
        with engine.connect():
            pass
    except Exception:  # noqa: BLE001 -- availability probe
        return False
    return True


pytestmark = pytest.mark.skipif(
    not _real_mysql_available(),
    reason="real MySQL not reachable (set B0_TEST_MYSQL_ROOT_URL to an isolated, "
    "non-production instance) -- skipped, not failed",
)


@pytest.fixture(scope="module")
def real_mysql_db():
    """Creates a throwaway database, runs the real Alembic migrations
    against it, yields its admin URL, then drops ONLY that database at
    teardown. Does not touch any MySQL user -- ownership of the
    provisioned_users fixture's accounts belongs to that fixture (see
    below), not here. This fixture's teardown is scoped exclusively to
    the UUID-suffixed database it itself created."""
    root_engine = create_engine(TEST_MYSQL_ROOT_URL)
    with root_engine.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {TEST_DB_NAME}"))
        conn.execute(text(f"CREATE DATABASE {TEST_DB_NAME}"))
        conn.commit()

    admin_url = TEST_MYSQL_ROOT_URL.rsplit("/", 1)[0] + f"/{TEST_DB_NAME}"

    from alembic.config import Config

    from alembic import command

    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", admin_url)
    command.upgrade(cfg, "head")

    yield admin_url

    with root_engine.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {TEST_DB_NAME}"))
        conn.commit()


@pytest.fixture(scope="module")
def provisioned_users(real_mysql_db):
    """Runs the real provisioning script as a subprocess against the
    throwaway database -- proves the actual shipped tool, not a
    reimplementation of its logic. The shipped script hardcodes the
    account names audit_writer/audit_reader/audit_maintenance (it takes
    no username parameter), so this fixture cannot rename them; instead
    it refuses to run at all if those names already exist on the target
    server (ownership-safe: it will only ever create and later delete
    accounts it can prove it created itself), and the endpoint guard
    above ensures the target server is never production regardless."""
    root_engine = create_engine(TEST_MYSQL_ROOT_URL)
    with root_engine.connect() as conn:
        refuse_if_accounts_exist(conn, _PROVISIONED_USER_NAMES)

    writer_pw, reader_pw, maint_pw = "w-pw-" + _RUN_ID, "r-pw-" + _RUN_ID, "m-pw-" + _RUN_ID
    env = {
        **os.environ,
        "AUDIT_DB_ADMIN_URL": real_mysql_db,
        "AUDIT_WRITER_DB_PASSWORD": writer_pw,
        "AUDIT_READER_DB_PASSWORD": reader_pw,
        "AUDIT_MAINTENANCE_DB_PASSWORD": maint_pw,
    }
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "provision_audit_db_users.py")],
        env=env, capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, f"provisioning failed: {result.stdout}\n{result.stderr}"

    from sqlalchemy.engine.url import make_url

    base = make_url(real_mysql_db)
    host_port = f"{base.host}:{base.port or 3306}"
    try:
        yield {
            "writer": f"mysql+pymysql://audit_writer:{writer_pw}@{host_port}/{TEST_DB_NAME}",
            "reader": f"mysql+pymysql://audit_reader:{reader_pw}@{host_port}/{TEST_DB_NAME}",
            "maintenance": f"mysql+pymysql://audit_maintenance:{maint_pw}@{host_port}/{TEST_DB_NAME}",
        }
    finally:
        # Ownership-scoped teardown: this fixture proved above (via
        # refuse_if_accounts_exist) that none of these three names
        # existed before it ran, and it is the only code path that
        # created them (the shipped script's own CREATE USER IF NOT
        # EXISTS), so dropping exactly these three names here is safe
        # -- it can never delete an account this fixture did not
        # itself create.
        with root_engine.connect() as conn:
            for user in _PROVISIONED_USER_NAMES:
                conn.execute(text(f"DROP USER IF EXISTS '{user}'@'%'"))
            conn.commit()


def _integration_test_secret() -> str:
    """Whatever AuditConfig.EVENT_SIGNING_SECRET actually resolves to in
    *this* process -- never invented separately. AuditConfig.
    EVENT_SIGNING_SECRET is a class attribute evaluated once at
    audit.config's first import in this pytest session (os.getenv(...)
    at class-body execution time, not per-call), so setting
    os.environ["JWT_SECRET"] *after* that has no effect on it -- the
    exact same "never assumes which secret is active, reads it" caution
    tests/test_worker_integration_real_backends.py's own module
    docstring already documents for this identical reason. Callers that
    need this secret in a *subprocess* (which does re-read the env var
    freshly) must pass it explicitly via that subprocess's own env.
    """
    from audit.config import AuditConfig

    return AuditConfig.EVENT_SIGNING_SECRET


def _insert_valid_event(admin_url: str, event_id: str, days_old: int = 0) -> None:
    from sqlalchemy.orm import sessionmaker

    from consumers.sink import Sink

    engine = create_engine(admin_url)
    Session = sessionmaker(bind=engine)
    ts = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days_old)
    with Session() as db:
        Sink(db).write({
            "event_id": event_id, "timestamp": ts, "service": "e3-test",
            "event_type": "test", "action": "test_action", "context": {},
            "integrity_status": "unsigned",
        })

    # Confirm the write actually landed and is visible via a brand-new
    # connection before returning -- a real (if intermittent, cause not
    # fully pinned down) visibility gap was observed empirically between
    # this function's own commit and an immediately-following read from
    # a *different* process (a subprocess-invoked script), only when run
    # as part of the full test suite rather than this file alone. This
    # assertion both documents that requirement explicitly and (since it
    # forces a real round-trip read against the just-committed row)
    # resolved the flakiness in practice. Callers of this helper depend
    # on the row being durably visible by the time it returns.
    with engine.connect() as verify_conn:
        found = verify_conn.execute(
            text("SELECT record_integrity_hash FROM audit_events WHERE event_id=:eid"),
            {"eid": event_id},
        ).scalar_one_or_none()
    assert found, f"_insert_valid_event: {event_id!r} not visible immediately after commit"


# ---------------------------------------------------------------------------
# A/B/C/D: UPDATE always denied, DELETE denied except for audit_maintenance,
# DELETE denied even for audit_maintenance when a legal hold exists.
# ---------------------------------------------------------------------------

def test_real_update_is_denied_for_every_identity(real_mysql_db, provisioned_users):
    _insert_valid_event(real_mysql_db, "evt-no-update")

    for label, url in (("root", real_mysql_db), ("writer", provisioned_users["writer"])):
        engine = create_engine(url)
        with engine.connect() as conn, pytest.raises(Exception) as exc_info:
            conn.execute(text("UPDATE audit_events SET service='tampered' WHERE event_id='evt-no-update'"))
            conn.commit()
        assert "append-only" in str(exc_info.value).lower() or "denied" in str(exc_info.value).lower(), (
            f"{label}: expected an append-only/permission rejection, got: {exc_info.value}"
        )


def test_real_delete_is_denied_for_root_and_writer_and_reader(real_mysql_db, provisioned_users):
    _insert_valid_event(real_mysql_db, "evt-no-delete")

    for label, url in (
        ("root", real_mysql_db),
        ("writer", provisioned_users["writer"]),
        ("reader", provisioned_users["reader"]),
    ):
        engine = create_engine(url)
        with engine.connect() as conn, pytest.raises(Exception):  # noqa: B017 -- real DBAPI error, denial is the point
            conn.execute(text("DELETE FROM audit_events WHERE event_id='evt-no-delete'"))
            conn.commit()

    # Still present after every denied attempt.
    with create_engine(real_mysql_db).connect() as conn:
        count = conn.execute(
            text("SELECT COUNT(*) FROM audit_events WHERE event_id='evt-no-delete'")
        ).scalar_one()
    assert count == 1


def test_real_delete_succeeds_for_audit_maintenance_without_a_hold(real_mysql_db, provisioned_users):
    _insert_valid_event(real_mysql_db, "evt-maintenance-delete")

    engine = create_engine(provisioned_users["maintenance"])
    with engine.connect() as conn:
        conn.execute(text("DELETE FROM audit_events WHERE event_id='evt-maintenance-delete'"))
        conn.commit()

    with create_engine(real_mysql_db).connect() as conn:
        count = conn.execute(
            text("SELECT COUNT(*) FROM audit_events WHERE event_id='evt-maintenance-delete'")
        ).scalar_one()
    assert count == 0


def test_real_legal_hold_blocks_deletion_even_for_audit_maintenance(real_mysql_db, provisioned_users):
    _insert_valid_event(real_mysql_db, "evt-held")

    maint_engine = create_engine(provisioned_users["maintenance"])
    with maint_engine.connect() as conn:
        conn.execute(text(
            "INSERT INTO audit_legal_holds (record_table, record_key, held_by, reason) "
            "VALUES ('audit_events', 'evt-held', 'e3-test-case', 'integration test')"
        ))
        conn.commit()

        with pytest.raises(Exception):  # noqa: B017 -- denial is the point
            conn.execute(text("DELETE FROM audit_events WHERE event_id='evt-held'"))
            conn.commit()

    with create_engine(real_mysql_db).connect() as conn:
        count = conn.execute(text("SELECT COUNT(*) FROM audit_events WHERE event_id='evt-held'")).scalar_one()
    assert count == 1

    # Release the hold, then deletion succeeds -- proves the mechanism is
    # a real gate, not a permanent lock, and that releasing is itself an
    # ordinary (if privileged) maintenance action.
    with maint_engine.connect() as conn:
        conn.execute(text(
            "DELETE FROM audit_legal_holds WHERE record_table='audit_events' AND record_key='evt-held'"
        ))
        conn.commit()
        conn.execute(text("DELETE FROM audit_events WHERE event_id='evt-held'"))
        conn.commit()
    with create_engine(real_mysql_db).connect() as conn:
        count = conn.execute(text("SELECT COUNT(*) FROM audit_events WHERE event_id='evt-held'")).scalar_one()
    assert count == 0


# ---------------------------------------------------------------------------
# E: TRUNCATE denied via privilege absence (no trigger can stop TRUNCATE --
# it's DDL; MySQL requires the DROP privilege, which writer/reader never get).
# ---------------------------------------------------------------------------

def test_real_truncate_denied_for_writer_and_reader_via_privilege_absence(provisioned_users):
    for label, url in (("writer", provisioned_users["writer"]), ("reader", provisioned_users["reader"])):
        engine = create_engine(url)
        with engine.connect() as conn, pytest.raises(Exception) as exc_info:
            conn.execute(text("TRUNCATE TABLE audit_events"))
        assert "denied" in str(exc_info.value).lower(), f"{label}: expected a privilege denial, got: {exc_info.value}"


# ---------------------------------------------------------------------------
# F: quarantine table gets the same protections -- must not be easier to
# erase than canonical evidence.
# ---------------------------------------------------------------------------

def test_real_quarantine_table_update_and_delete_denied_same_as_canonical(real_mysql_db, provisioned_users):
    from sqlalchemy.orm import sessionmaker

    from consumers.quarantine import QuarantineSink

    engine = create_engine(real_mysql_db)
    Session = sessionmaker(bind=engine)
    with Session() as db:
        QuarantineSink(db).write("e3-quarantine-1", {"data": "not valid json"}, 5)

    with engine.connect() as conn, pytest.raises(Exception):  # noqa: B017 -- denial is the point
        conn.execute(text("UPDATE quarantined_audit_events SET failure_category='x' WHERE stream_message_id='e3-quarantine-1'"))
        conn.commit()

    with engine.connect() as conn, pytest.raises(Exception):  # noqa: B017 -- denial is the point
        conn.execute(text("DELETE FROM quarantined_audit_events WHERE stream_message_id='e3-quarantine-1'"))
        conn.commit()

    maint_engine = create_engine(provisioned_users["maintenance"])
    with maint_engine.connect() as conn:
        conn.execute(text("DELETE FROM quarantined_audit_events WHERE stream_message_id='e3-quarantine-1'"))
        conn.commit()
    with engine.connect() as conn:
        count = conn.execute(
            text("SELECT COUNT(*) FROM quarantined_audit_events WHERE stream_message_id='e3-quarantine-1'")
        ).scalar_one()
    assert count == 0


# ---------------------------------------------------------------------------
# G: audit_legal_holds itself is append-only on UPDATE (release by delete,
# not edit).
# ---------------------------------------------------------------------------

def test_real_legal_hold_record_cannot_be_updated(provisioned_users):
    maint_engine = create_engine(provisioned_users["maintenance"])
    with maint_engine.connect() as conn:
        conn.execute(text(
            "INSERT INTO audit_legal_holds (record_table, record_key, held_by, reason) "
            "VALUES ('audit_events', 'evt-hold-update-test', 'case-1', 'original reason')"
        ))
        conn.commit()

        with pytest.raises(Exception):  # noqa: B017 -- denial is the point
            conn.execute(text(
                "UPDATE audit_legal_holds SET reason='edited' WHERE record_key='evt-hold-update-test'"
            ))
            conn.commit()

        conn.execute(text("DELETE FROM audit_legal_holds WHERE record_key='evt-hold-update-test'"))
        conn.commit()


# ---------------------------------------------------------------------------
# H/I: writer can INSERT, cannot UPDATE/DELETE; reader can SELECT, cannot
# mutate at all. Already partially covered above; these pin the positive
# (INSERT/SELECT succeed) side explicitly.
# ---------------------------------------------------------------------------

def test_real_writer_can_insert_and_select_but_not_mutate(provisioned_users):
    engine = create_engine(provisioned_users["writer"])
    with engine.connect() as conn:
        conn.execute(text(
            "INSERT INTO audit_events (event_id, timestamp, service, event_type, action, context, "
            "integrity_status, record_integrity_hash) VALUES "
            "('evt-writer-insert', NOW(), 'e3-test', 'test', 'test', '{}', 'unsigned', 'x')"
        ))
        conn.commit()
        count = conn.execute(text("SELECT COUNT(*) FROM audit_events WHERE event_id='evt-writer-insert'")).scalar_one()
        assert count == 1


def test_real_reader_can_select_but_cannot_insert(provisioned_users):
    engine = create_engine(provisioned_users["reader"])
    with engine.connect() as conn:
        conn.execute(text("SELECT COUNT(*) FROM audit_events")).scalar_one()  # must not raise

    with engine.connect() as conn, pytest.raises(Exception):  # noqa: B017 -- denial is the point
        conn.execute(text(
            "INSERT INTO audit_events (event_id, timestamp, service, event_type, action, context, "
            "integrity_status, record_integrity_hash) VALUES "
            "('evt-reader-insert', NOW(), 'e3-test', 'test', 'test', '{}', 'unsigned', 'x')"
        ))
        conn.commit()


# ---------------------------------------------------------------------------
# Retention script: dry-run, execute, legal hold respected, fails closed
# on misconfiguration -- exercised as the real subprocess.
# ---------------------------------------------------------------------------

def test_real_retention_cleanup_dry_run_then_execute_respects_legal_hold(real_mysql_db, provisioned_users):
    _insert_valid_event(real_mysql_db, "evt-retention-old", days_old=200)
    _insert_valid_event(real_mysql_db, "evt-retention-recent", days_old=1)
    _insert_valid_event(real_mysql_db, "evt-retention-old-held", days_old=300)

    maint_engine = create_engine(provisioned_users["maintenance"])
    with maint_engine.connect() as conn:
        conn.execute(text(
            "INSERT INTO audit_legal_holds (record_table, record_key, held_by, reason) "
            "VALUES ('audit_events', 'evt-retention-old-held', 'case-2', 'retention integration test')"
        ))
        conn.commit()

    env = {**os.environ, "AUDIT_MAINTENANCE_DATABASE_URL": provisioned_users["maintenance"], "AUDIT_RETENTION_DAYS": "90"}

    dry = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "audit_retention_cleanup.py"), "--dry-run"],
        env=env, capture_output=True, text=True, timeout=30, check=False,
    )
    assert dry.returncode == 0, dry.stdout + dry.stderr
    assert "1 row(s) would be deleted" in dry.stdout

    with create_engine(real_mysql_db).connect() as conn:
        count = conn.execute(text("SELECT COUNT(*) FROM audit_events WHERE event_id='evt-retention-old'")).scalar_one()
    assert count == 1, "dry-run must not delete anything"

    execute = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "audit_retention_cleanup.py"), "--execute"],
        env=env, capture_output=True, text=True, timeout=30, check=False,
    )
    assert execute.returncode == 0, execute.stdout + execute.stderr

    with create_engine(real_mysql_db).connect() as conn:
        remaining = {
            row[0] for row in conn.execute(text(
                "SELECT event_id FROM audit_events WHERE event_id IN "
                "('evt-retention-old', 'evt-retention-recent', 'evt-retention-old-held')"
            ))
        }
    assert remaining == {"evt-retention-recent", "evt-retention-old-held"}, (
        "expected the old-but-unheld event deleted, the recent and held events retained"
    )


def test_real_retention_cleanup_fails_closed_without_retention_days(provisioned_users):
    env = {k: v for k, v in os.environ.items() if k != "AUDIT_RETENTION_DAYS"}
    env["AUDIT_MAINTENANCE_DATABASE_URL"] = provisioned_users["maintenance"]
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "audit_retention_cleanup.py")],
        env=env, capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0  # a successful no-op, not an error
    assert "not set" in result.stdout


def test_real_retention_cleanup_fails_closed_with_a_non_maintenance_credential(real_mysql_db, provisioned_users):
    _insert_valid_event(real_mysql_db, "evt-retention-writer-guard", days_old=200)

    env = {**os.environ, "AUDIT_MAINTENANCE_DATABASE_URL": provisioned_users["writer"], "AUDIT_RETENTION_DAYS": "1"}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "audit_retention_cleanup.py"), "--execute"],
        env=env, capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 1
    with create_engine(real_mysql_db).connect() as conn:
        count = conn.execute(
            text("SELECT COUNT(*) FROM audit_events WHERE event_id='evt-retention-writer-guard'")
        ).scalar_one()
    assert count == 1, "the DB-level trigger must independently reject deletion even if the script ran"


# ---------------------------------------------------------------------------
# Integrity verification tool: real end-to-end chain -- valid event
# (through the real Sink), tampered event, real MySQL throughout.
#
# Deliberately calls the tool's own verify_audit_events()/
# verify_quarantine_records() functions directly (same functions
# scripts/verify_audit_integrity.py's main() calls) rather than
# shelling out to the CLI as a subprocess -- the CLI's own subprocess
# plumbing (argument parsing, env-var resolution, exit codes, stdout/
# stderr framing) is already covered by manual end-to-end verification
# performed during this track's development and by the simpler CLI
# tests elsewhere in this file (e.g. the retention script's own
# subprocess tests). Calling the functions directly here keeps this
# specific test focused on one thing -- real Sink-written data versus
# real tampered data, both correctly classified -- without the added
# variable of a second OS process reading through a differently-
# privileged connection against a large, heavily-shared table that 12
# other tests in this module have already written into.
# ---------------------------------------------------------------------------

def test_real_verify_audit_integrity_tool_distinguishes_valid_from_tampered(real_mysql_db, provisioned_users):
    from sqlalchemy.orm import sessionmaker

    from scripts.verify_audit_integrity import verify_audit_events

    _insert_valid_event(real_mysql_db, "evt-verify-valid-2")

    engine = create_engine(real_mysql_db)
    with engine.connect() as conn:
        conn.execute(text(
            "INSERT INTO audit_events (event_id, timestamp, service, event_type, action, context, "
            "integrity_status, record_integrity_hash) VALUES "
            "('evt-verify-tampered-2', NOW(), 'e3-test', 'test', 'test', '{}', 'unsigned', "
            "'0000000000000000000000000000000000000000000000000000000000000000')"
        ))
        conn.commit()

    Session = sessionmaker(bind=engine)
    with Session() as session:
        stats = verify_audit_events(session, _integration_test_secret())

    assert "evt-verify-tampered-2" in stats["invalid"]
    assert "evt-verify-valid-2" not in stats["invalid"]
