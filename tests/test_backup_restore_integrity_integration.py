"""V2-003 (Track E3): backup/restore interaction with the retention/
immutability schema. Deliberately uses two throwaway databases and a
local `mysqldump`/`mysql` round-trip (never the live omnibioai_audit
database, never Docker container spin-up) -- same isolation discipline
as every other real-backend test in this suite.

Verifies the specific things Phase 13/14 of this track's governing task
asked for:
  - a backup (mysqldump --all-databases-equivalent single-DB dump, same
    flags omnibioai-studio/scripts/backup-mysql.sh actually uses) covers
    audit_events, quarantined_audit_events, and audit_legal_holds
  - event IDs / stream_message_ids survive the round trip unchanged
  - record_integrity_hash values survive byte-for-byte (the whole point
    of the hash is defeated if a backup/restore cycle itself alters the
    bytes it's supposed to protect)
  - the integrity verification tool reports 100% valid on the restored
    copy -- the round trip itself introduces no false "tampering"
  - triggers/append-only enforcement are recreated on the restored copy
    too (a restore must not silently produce a less-protected database)

Does not touch the append-only triggers' CURRENT_USER-vs-USER() behavior
or the provisioning script -- those are covered in
test_retention_immutability_integration.py. This file is scoped to the
backup/restore round trip specifically.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from tests._mysql_integration_guard import (
    MissingTestMySQLEndpoint,
    validate_test_mysql_url,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
try:
    # P0 test-isolation fix (2026-09-16): no implicit localhost:3306
    # default -- ProductionMySQLEndpointRejected is deliberately NOT
    # caught here, so a misconfigured production endpoint fails
    # collection loudly instead of silently running destructive SQL
    # against it. See tests/_mysql_integration_guard.py.
    TEST_MYSQL_ROOT_URL = validate_test_mysql_url(os.environ.get("B0_TEST_MYSQL_ROOT_URL"))
except MissingTestMySQLEndpoint:
    TEST_MYSQL_ROOT_URL = None
_RUN_ID = uuid.uuid4().hex[:8]
SOURCE_DB = f"omnibioai_audit_e3_backup_src_{_RUN_ID}"
RESTORED_DB = f"omnibioai_audit_e3_backup_dst_{_RUN_ID}"


def _real_mysql_available():
    """Report whether the configured test-MySQL root URL is reachable, returning False when
    unconfigured or unreachable."""
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
    reason="real MySQL not reachable (set B0_TEST_MYSQL_ROOT_URL) -- skipped, not failed",
)


@pytest.fixture(scope="module")
def source_db_with_data():
    """Fresh throwaway DB, migrated to head, seeded with real audit
    events (via Sink), a quarantine record (via QuarantineSink), and a
    legal hold -- one of each kind of evidence this schema protects."""
    root_engine = create_engine(TEST_MYSQL_ROOT_URL)
    with root_engine.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {SOURCE_DB}"))
        conn.execute(text(f"CREATE DATABASE {SOURCE_DB}"))
        conn.commit()

    admin_url = TEST_MYSQL_ROOT_URL.rsplit("/", 1)[0] + f"/{SOURCE_DB}"

    from alembic.config import Config

    from alembic import command

    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", admin_url)
    command.upgrade(cfg, "head")

    from sqlalchemy.orm import sessionmaker

    from consumers.quarantine import QuarantineSink
    from consumers.sink import Sink

    engine = create_engine(admin_url)
    Session = sessionmaker(bind=engine)
    with Session() as db:
        Sink(db).write({
            "event_id": "evt-backup-roundtrip", "timestamp": datetime.now(timezone.utc).replace(tzinfo=None),
            "service": "e3-backup-test", "event_type": "test", "action": "test_action",
            "context": {"nested": {"k": "v"}, "list": [1, 2, 3]}, "integrity_status": "unsigned",
        })
    with Session() as db:
        QuarantineSink(db).write("bk-1-0", {"data": json.dumps({"service": "e3-backup-test"})}, 5)

    with engine.connect() as conn:
        conn.execute(text(
            "INSERT INTO audit_legal_holds (record_table, record_key, held_by, reason) "
            "VALUES ('audit_events', 'evt-backup-roundtrip', 'case-backup-test', 'backup round-trip test')"
        ))
        conn.commit()

    yield admin_url

    with root_engine.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {SOURCE_DB}"))
        conn.execute(text(f"DROP DATABASE IF EXISTS {RESTORED_DB}"))
        conn.commit()


@pytest.fixture(scope="module")
def restored_db(source_db_with_data, tmp_path_factory):
    """Real mysqldump -> real mysql restore into a second throwaway DB,
    using the same flags omnibioai-studio/scripts/backup-mysql.sh uses
    for a single database (that script uses --all-databases; a
    single-DB dump with the same --single-transaction --quick
    --lock-tables=false flags is the equivalent unit for this test)."""
    dump_dir = tmp_path_factory.mktemp("e3-backup-dump")
    dump_file = dump_dir / "dump.sql"

    # P0 test-isolation fix (2026-09-16): the mysqldump/mysql CLIs below
    # used to hardcode -h 127.0.0.1 -uroot -proot with no -P at all,
    # which means they always targeted the MySQL client's default port
    # 3306 -- production, on this host -- regardless of what
    # B0_TEST_MYSQL_ROOT_URL's port said. Deriving host/port/user/
    # password from the already-guarded TEST_MYSQL_ROOT_URL instead
    # closes that gap: it can never point at port 3306, because
    # validate_test_mysql_url() already refused that when this module
    # was imported.
    from sqlalchemy.engine.url import make_url

    _admin = make_url(TEST_MYSQL_ROOT_URL)
    _host, _port = _admin.host, str(_admin.port)
    _user, _password = _admin.username, _admin.password or ""

    subprocess.run(
        [
            "mysqldump", "-h", _host, "-P", _port, "-u", _user, f"-p{_password}",
            "--single-transaction", "--quick", "--lock-tables=false",
            "--routines", "--triggers", "--events",
            SOURCE_DB,
        ],
        stdout=dump_file.open("w"), check=True, timeout=30,
    )
    assert dump_file.stat().st_size > 0

    root_engine = create_engine(TEST_MYSQL_ROOT_URL)
    with root_engine.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {RESTORED_DB}"))
        conn.execute(text(f"CREATE DATABASE {RESTORED_DB}"))
        conn.commit()

    subprocess.run(
        ["mysql", "-h", _host, "-P", _port, "-u", _user, f"-p{_password}", RESTORED_DB],
        stdin=dump_file.open("r"), check=True, timeout=30,
    )

    return TEST_MYSQL_ROOT_URL.rsplit("/", 1)[0] + f"/{RESTORED_DB}"


def test_dump_includes_triggers_flag_captured_all_three_tables(restored_db):
    """Capture audit_events, quarantined_audit_events, and audit_legal_holds in the backup dump and
    produce a non-empty dump file."""
    engine = create_engine(restored_db)
    with engine.connect() as conn:
        tables = {row[0] for row in conn.execute(text("SHOW TABLES"))}
    assert {"audit_events", "quarantined_audit_events", "audit_legal_holds"} <= tables


def test_restored_audit_event_id_and_hash_survive_byte_for_byte(source_db_with_data, restored_db):
    """Preserve an audit event's event_id and record_integrity_hash byte-for-byte through a real
    backup/restore round trip."""
    source_engine = create_engine(source_db_with_data)
    restored_engine = create_engine(restored_db)

    with source_engine.connect() as conn:
        source_row = conn.execute(text(
            "SELECT event_id, record_integrity_hash FROM audit_events WHERE event_id='evt-backup-roundtrip'"
        )).one()
    with restored_engine.connect() as conn:
        restored_row = conn.execute(text(
            "SELECT event_id, record_integrity_hash FROM audit_events WHERE event_id='evt-backup-roundtrip'"
        )).one()

    assert restored_row.event_id == source_row.event_id
    assert restored_row.record_integrity_hash == source_row.record_integrity_hash
    assert restored_row.record_integrity_hash is not None


def test_restored_quarantine_record_survives_byte_for_byte(source_db_with_data, restored_db):
    """Preserve a quarantine record's raw_data and record_integrity_hash byte-for-byte through a
    real backup/restore round trip."""
    source_engine = create_engine(source_db_with_data)
    restored_engine = create_engine(restored_db)

    with source_engine.connect() as conn:
        source_row = conn.execute(text(
            "SELECT raw_data, record_integrity_hash FROM quarantined_audit_events WHERE stream_message_id='bk-1-0'"
        )).one()
    with restored_engine.connect() as conn:
        restored_row = conn.execute(text(
            "SELECT raw_data, record_integrity_hash FROM quarantined_audit_events WHERE stream_message_id='bk-1-0'"
        )).one()

    assert restored_row.raw_data == source_row.raw_data
    assert restored_row.record_integrity_hash == source_row.record_integrity_hash


def test_restored_legal_hold_survives(restored_db):
    """Preserve a legal hold row through a real backup/restore round trip."""
    engine = create_engine(restored_db)
    with engine.connect() as conn:
        count = conn.execute(text(
            "SELECT COUNT(*) FROM audit_legal_holds WHERE record_table='audit_events' "
            "AND record_key='evt-backup-roundtrip'"
        )).scalar_one()
    assert count == 1


def test_restored_database_integrity_verification_reports_zero_tampering(restored_db):
    """The round trip itself must never introduce false positives --
    every record that was valid before backup/restore must still verify
    as valid after."""
    from sqlalchemy.orm import sessionmaker

    from audit.config import AuditConfig
    from scripts.verify_audit_integrity import (
        verify_audit_events,
        verify_quarantine_records,
    )

    engine = create_engine(restored_db)
    Session = sessionmaker(bind=engine)
    with Session() as session:
        event_stats = verify_audit_events(session, AuditConfig.EVENT_SIGNING_SECRET)
        quarantine_stats = verify_quarantine_records(session, AuditConfig.EVENT_SIGNING_SECRET)

    assert event_stats["invalid"] == []
    assert event_stats["structural"] == []
    assert quarantine_stats["invalid"] == []
    assert quarantine_stats["structural"] == []


def test_restored_database_append_only_triggers_are_recreated(restored_db):
    """A restore must not silently produce a LESS protected database --
    the triggers must exist on the restored copy too (mysqldump with
    --triggers, the default, includes them; this pins that they are
    real, present, and functional after restore, not just present in
    the dump text)."""
    engine = create_engine(restored_db)
    with engine.connect() as conn, pytest.raises(Exception):  # noqa: B017 -- denial is the point
        conn.execute(text(
            "UPDATE audit_events SET service='tampered-after-restore' WHERE event_id='evt-backup-roundtrip'"
        ))
        conn.commit()
