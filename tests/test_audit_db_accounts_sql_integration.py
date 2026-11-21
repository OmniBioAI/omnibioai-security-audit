"""scripts/sql/audit_db_accounts.sql against a REAL, isolated MySQL server.

1. Parity: the SQL script grants audit_writer / audit_reader /
   audit_maintenance exactly what scripts/provision_audit_db_users.py
   grants, so provisioning can move to root@localhost over the server's
   socket without a network-reachable root account.
2. audit_migrator: `alembic upgrade head` runs to the head revision as
   that account alone, the append-only triggers it creates still reject
   UPDATE (SQLSTATE 45000, error 1644), and the account holds nothing
   outside the target schema.

Same isolation rules as the other destructive MySQL tests here
(tests/_mysql_integration_guard.py): skipped without B0_TEST_MYSQL_ROOT_URL,
port 3306 refused, and accounts are only created if no account of that name
exists yet, and only those are dropped at teardown.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

import pymysql
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine.url import make_url

from tests._mysql_integration_guard import (
    MissingTestMySQLEndpoint,
    refuse_if_accounts_exist,
    validate_test_mysql_url,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SQL_FILE = REPO_ROOT / "scripts" / "sql" / "audit_db_accounts.sql"
try:
    TEST_MYSQL_ROOT_URL = validate_test_mysql_url(os.environ.get("B0_TEST_MYSQL_ROOT_URL"))
except MissingTestMySQLEndpoint:
    TEST_MYSQL_ROOT_URL = None
_RUN_ID = uuid.uuid4().hex[:8]
_RUNTIME_USERS = ("audit_writer", "audit_reader", "audit_maintenance")
_MIGRATOR = "audit_migrator"
_HEAD = "0006_integrity_key_id"


def _real_mysql_available():
    """Whether the configured test-MySQL root URL is reachable."""
    if TEST_MYSQL_ROOT_URL is None:
        return False
    try:
        with create_engine(TEST_MYSQL_ROOT_URL, connect_args={"connect_timeout": 2}).connect():
            pass
    except Exception:  # noqa: BLE001 -- availability probe
        return False
    return True


pytestmark = pytest.mark.skipif(
    not _real_mysql_available(),
    reason="real MySQL not reachable (set B0_TEST_MYSQL_ROOT_URL to an isolated, "
    "non-production instance) -- skipped, not failed",
)


def _root_conn(database=None):
    url = make_url(TEST_MYSQL_ROOT_URL)
    return pymysql.connect(
        host=url.host, port=url.port, user=url.username, password=url.password or "",
        database=database, autocommit=True,
    )


def _statements():
    """The SQL file's statements, comments dropped, split on `;` followed by
    whitespace (the file has no `;` inside string literals)."""
    body = "\n".join(line for line in SQL_FILE.read_text().splitlines() if not line.lstrip().startswith("--"))
    return [s.strip() for s in re.split(r";\s+", body + "\n") if s.strip()]


def _run_sql_file(variables):
    """Runs the SQL file as root with the given session variables set first,
    the way an operator pipes it into `mysql` over the socket."""
    conn = _root_conn()
    try:
        with conn.cursor() as cur:
            for name, value in variables.items():
                cur.execute(f"SET @{name} = %s", (value,))
            for stmt in _statements():
                cur.execute(stmt)
    finally:
        conn.close()


def _grants(user):
    conn = _root_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(f"SHOW GRANTS FOR '{user}'@'%'")
            return sorted(row[0] for row in cur.fetchall())
    finally:
        conn.close()


def _drop_users(users):
    conn = _root_conn()
    try:
        with conn.cursor() as cur:
            for user in users:
                cur.execute(f"DROP USER IF EXISTS '{user}'@'%'")
    finally:
        conn.close()


@pytest.fixture
def throwaway_db():
    name = f"omnibioai_audit_acct_test_{uuid.uuid4().hex[:8]}"
    conn = _root_conn()
    with conn.cursor() as cur:
        cur.execute(f"CREATE DATABASE `{name}`")
    conn.close()
    yield name
    conn = _root_conn()
    with conn.cursor() as cur:
        cur.execute(f"DROP DATABASE IF EXISTS `{name}`")
    conn.close()


def _owned_accounts(names):
    with create_engine(TEST_MYSQL_ROOT_URL).connect() as conn:
        refuse_if_accounts_exist(conn, list(names))


def _alembic(database, user, password, *args):
    base = make_url(TEST_MYSQL_ROOT_URL)
    url = f"mysql+pymysql://{user}:{password}@{base.host}:{base.port}/{database}"
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args], cwd=REPO_ROOT,
        env={**os.environ, "AUDIT_DATABASE_URL": url}, capture_output=True, text=True, timeout=120,
        check=False,
    )


def test_sql_file_grants_match_python_provisioner(throwaway_db):
    """SHOW GRANTS after the SQL file equals SHOW GRANTS after
    provision_audit_db_users.py, for all three runtime accounts."""
    _owned_accounts(_RUNTIME_USERS)
    passwords = {u: f"{u}-pw-{_RUN_ID}" for u in _RUNTIME_USERS}
    try:
        # Tables must exist for table-level grants: migrate as root first.
        base = make_url(TEST_MYSQL_ROOT_URL)
        migrated = _alembic(throwaway_db, base.username, base.password, "upgrade", "head")
        assert migrated.returncode == 0, migrated.stderr[-2000:]

        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "provision_audit_db_users.py")],
            env={
                **os.environ,
                "AUDIT_DB_ADMIN_URL": TEST_MYSQL_ROOT_URL.rsplit("/", 1)[0] + f"/{throwaway_db}",
                "AUDIT_WRITER_DB_PASSWORD": passwords["audit_writer"],
                "AUDIT_READER_DB_PASSWORD": passwords["audit_reader"],
                "AUDIT_MAINTENANCE_DB_PASSWORD": passwords["audit_maintenance"],
            },
            capture_output=True, text=True, timeout=30, check=False,
        )
        assert result.returncode == 0, result.stderr
        from_python = {u: _grants(u) for u in _RUNTIME_USERS}

        _drop_users(_RUNTIME_USERS)
        _run_sql_file({
            "audit_db": throwaway_db,
            "audit_writer_password": passwords["audit_writer"],
            "audit_reader_password": passwords["audit_reader"],
            "audit_maintenance_password": passwords["audit_maintenance"],
        })
        from_sql = {u: _grants(u) for u in _RUNTIME_USERS}
        assert from_sql == from_python
        assert all(from_sql.values())
    finally:
        _drop_users(_RUNTIME_USERS)


def test_sql_file_stops_without_audit_db():
    """Unset @audit_db aborts before any account is created."""
    _owned_accounts((_MIGRATOR,))
    try:
        with pytest.raises(pymysql.err.ProgrammingError):
            _run_sql_file({"audit_migrator_password": f"m-{_RUN_ID}"})
        conn = _root_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM mysql.user WHERE user = %s", (_MIGRATOR,))
            assert cur.fetchone()[0] == 0
        conn.close()
    finally:
        _drop_users((_MIGRATOR,))


def _server_allows_trigger_creation_without_super():
    conn = _root_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT @@log_bin, @@log_bin_trust_function_creators")
            log_bin, trust = cur.fetchone()
    finally:
        conn.close()
    return not log_bin or bool(trust)


def test_migrations_run_as_audit_migrator_only(throwaway_db):
    """`alembic upgrade head` as audit_migrator reaches head; its triggers
    work; the account has no privilege outside the schema; downgrade is
    refused without DROP."""
    if not _server_allows_trigger_creation_without_super():
        pytest.skip("test server has binary logging on and log_bin_trust_function_creators=0 "
                    "(CREATE TRIGGER from a non-SUPER account fails with 1419)")
    _owned_accounts((_MIGRATOR,))
    password = f"migrator-pw-{_RUN_ID}"
    try:
        _run_sql_file({"audit_db": throwaway_db, "audit_migrator_password": password})

        grants = _grants(_MIGRATOR)
        assert grants == sorted([
            f"GRANT USAGE ON *.* TO `{_MIGRATOR}`@`%`",
            f"GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, INDEX, ALTER, TRIGGER ON `{throwaway_db}`.* "
            f"TO `{_MIGRATOR}`@`%`",
        ])

        up = _alembic(throwaway_db, _MIGRATOR, password, "upgrade", "head")
        assert up.returncode == 0, up.stderr[-2000:]

        conn = _root_conn(throwaway_db)
        with conn.cursor() as cur:
            cur.execute("SELECT version_num FROM alembic_version")
            assert cur.fetchone()[0] == _HEAD
            cur.execute(
                "SELECT TRIGGER_NAME, DEFINER FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = %s",
                (throwaway_db,),
            )
            triggers = dict(cur.fetchall())
        conn.close()
        assert set(triggers) == {
            "trg_audit_events_no_update", "trg_audit_events_no_delete",
            "trg_quarantined_audit_events_no_update", "trg_quarantined_audit_events_no_delete",
            "trg_audit_legal_holds_no_update",
        }
        assert set(triggers.values()) == {f"{_MIGRATOR}@%"}

        base = make_url(TEST_MYSQL_ROOT_URL)
        mig = pymysql.connect(host=base.host, port=base.port, user=_MIGRATOR, password=password,
                              database=throwaway_db, autocommit=True)
        try:
            with mig.cursor() as cur:
                cur.execute(
                    "INSERT INTO audit_legal_holds (record_table, record_key, reason) VALUES ('t', %s, 'x')",
                    (_RUN_ID,),
                )
                with pytest.raises(pymysql.err.OperationalError) as exc:
                    cur.execute("UPDATE audit_legal_holds SET reason = 'y' WHERE record_key = %s", (_RUN_ID,))
                assert exc.value.args[0] == 1644
                with pytest.raises(pymysql.err.OperationalError) as exc:
                    cur.execute("CREATE TABLE mysql.audit_migrator_probe (id INT)")
                assert exc.value.args[0] == 1142
        finally:
            mig.close()

        down = _alembic(throwaway_db, _MIGRATOR, password, "downgrade", "base")
        assert down.returncode != 0
        assert "DROP command denied" in down.stderr
    finally:
        _drop_users((_MIGRATOR,))
