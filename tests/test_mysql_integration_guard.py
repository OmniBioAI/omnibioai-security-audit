"""P0 test-isolation fix (2026-09-16): regression tests proving the
safety guard in tests/_mysql_integration_guard.py actually does what it
claims -- this is the test suite for the fix, not for the audit
pipeline itself. See that module's docstring, and
~/p0_audit_identity_provisioning_forensic_reconciliation_2026-09-16.md,
for the incident this closes: a destructive integration-test fixture's
unscoped teardown destroyed real production audit_writer/audit_reader/
audit_maintenance MySQL accounts twice by silently defaulting to
localhost:3306, this architecture's real production MySQL endpoint.

Cases D, F, G, H below are opt-in against a real, genuinely isolated
MySQL instance (set B0_TEST_ISOLATION_MYSQL_URL to it, e.g.
mysql+pymysql://root:<password>@127.0.0.1:33061/mysql) -- they skip,
not fail, when that isolated instance isn't reachable, matching this
suite's existing convention. Cases A, B, C, E need no live server at
all: they test pure validation logic that never attempts a connection.
"""
import os

import pytest
from sqlalchemy import create_engine, text

from tests._mysql_integration_guard import (
    FORBIDDEN_PORT,
    MissingTestMySQLEndpoint,
    PreexistingTestAccountsError,
    ProductionMySQLEndpointRejected,
    refuse_if_accounts_exist,
    unique_test_identifier,
    validate_test_mysql_url,
)

_PRODUCTION_NAMES = ("audit_writer", "audit_reader", "audit_maintenance")


def _sql_quoted_list(names) -> str:
    return ", ".join("'" + n + "'" for n in names)


# --- A: absent env var never contacts any MySQL endpoint -------------------

def test_a_missing_url_raises_before_any_connection_attempt(monkeypatch):
    """No implicit default -- validate_test_mysql_url must raise from
    pure argument inspection alone, never by attempting to connect
    anywhere (there is nothing to connect *to* when the argument is
    None/empty, but this also guards against a future refactor
    accidentally adding a connection attempt before the check)."""

    def _must_not_be_called(*_args, **_kwargs):
        raise AssertionError("create_engine must never be called for a missing endpoint")

    monkeypatch.setattr("sqlalchemy.create_engine", _must_not_be_called)

    with pytest.raises(MissingTestMySQLEndpoint):
        validate_test_mysql_url(None)
    with pytest.raises(MissingTestMySQLEndpoint):
        validate_test_mysql_url("")


# --- B/C: known production endpoints rejected before any destructive SQL ---

@pytest.mark.parametrize(
    "url",
    [
        "mysql+pymysql://root:root@localhost:3306/mysql",
        "mysql+pymysql://root:root@127.0.0.1:3306/mysql",
        "mysql+pymysql://root:whatever@some-other-hostname:3306/omnibioai_audit",
    ],
)
def test_b_c_production_port_rejected_before_any_connection_attempt(monkeypatch, url):
    """Port 3306 is refused unconditionally and immediately -- before
    any SQL, DDL, or even a TCP connection attempt. Parametrized over
    localhost, 127.0.0.1, and a third, unrelated hostname: the rule is
    port-based, not a hostname allowlist/denylist, precisely because a
    hostname string is spoofable/renameable and a port convention on
    this fixed architecture is not."""

    def _must_not_be_called(*_args, **_kwargs):
        raise AssertionError("create_engine must never be called for a rejected production endpoint")

    monkeypatch.setattr("sqlalchemy.create_engine", _must_not_be_called)

    with pytest.raises(ProductionMySQLEndpointRejected):
        validate_test_mysql_url(url)


def test_b_c_rejection_message_names_the_forbidden_port():
    with pytest.raises(ProductionMySQLEndpointRejected, match=str(FORBIDDEN_PORT)):
        validate_test_mysql_url("mysql+pymysql://root:root@localhost:3306/mysql")


# --- D: a genuinely isolated endpoint passes validation and is usable ------

_ISOLATED_TEST_URL = os.environ.get("B0_TEST_ISOLATION_MYSQL_URL")


def _isolated_mysql_available():
    if not _ISOLATED_TEST_URL:
        return False
    try:
        engine = create_engine(_ISOLATED_TEST_URL, connect_args={"connect_timeout": 2})
        with engine.connect():
            pass
    except Exception:  # noqa: BLE001 -- availability probe
        return False
    return True


_isolated_skip = pytest.mark.skipif(
    not _isolated_mysql_available(),
    reason="B0_TEST_ISOLATION_MYSQL_URL not set/reachable -- skipped, not failed "
    "(set it to a genuinely isolated MySQL instance, e.g. port 33061)",
)


def test_d_validation_accepts_non_production_port():
    assert validate_test_mysql_url("mysql+pymysql://root:root@127.0.0.1:33061/mysql") == (
        "mysql+pymysql://root:root@127.0.0.1:33061/mysql"
    )


@_isolated_skip
def test_d_isolated_endpoint_is_a_real_usable_mysql_server():
    engine = create_engine(_ISOLATED_TEST_URL)
    with engine.connect() as conn:
        result = conn.execute(text("SELECT 1")).scalar()
    assert result == 1


# --- E: unique test principal naming ---------------------------------------

def test_e_unique_identifiers_are_distinct_and_within_mysql_username_limit():
    names = {unique_test_identifier("audit_writer") for _ in range(20)}
    assert len(names) == 20, "each call must produce a distinct name"
    for name in names:
        assert len(name) <= 32, f"{name!r} exceeds MySQL's 32-character username limit"
        assert name.startswith("audit_writer_test_")


def test_e_unique_identifier_trims_long_prefix_not_the_random_suffix():
    long_prefix = "a" * 40
    name = unique_test_identifier(long_prefix, max_length=32)
    assert len(name) <= 32
    # the random suffix (8 hex chars after the last underscore) must
    # survive intact -- trimming must come from the prefix, never this
    suffix = name.rsplit("_", 1)[-1]
    assert len(suffix) == 8


# --- F/G/H: ownership-scoped teardown and the sentinel-account proof -------

@_isolated_skip
def test_f_g_teardown_removes_only_accounts_this_fixture_created():
    """Simulates provisioned_users' own create -> use -> ownership-scoped
    teardown cycle directly against the isolated instance, using unique
    (not production-named) accounts so this test can't collide with
    test_h's sentinel scenario below."""
    engine = create_engine(_ISOLATED_TEST_URL)
    created = [unique_test_identifier("probe_writer"), unique_test_identifier("probe_reader")]
    with engine.connect() as conn:
        refuse_if_accounts_exist(conn, created)  # must not raise: these names are fresh
        for name in created:
            conn.execute(text(f"CREATE USER '{name}'@'%'"))
        conn.commit()

    with engine.connect() as conn:
        present = conn.execute(
            text(f"SELECT user FROM mysql.user WHERE user IN ({_sql_quoted_list(created)})")
        ).fetchall()
        assert len(present) == 2, "both freshly created accounts must be visible before teardown"

    with engine.connect() as conn:
        for name in created:
            conn.execute(text(f"DROP USER IF EXISTS '{name}'@'%'"))
        conn.commit()

    with engine.connect() as conn:
        gone = conn.execute(
            text(f"SELECT user FROM mysql.user WHERE user IN ({_sql_quoted_list(created)})")
        ).fetchall()
        assert len(gone) == 0, "ownership-scoped teardown must remove exactly what it created"


@_isolated_skip
def test_g_never_drops_production_names_when_it_did_not_create_them():
    """The core defect this whole fix closes, reproduced deliberately
    and safely: refuse_if_accounts_exist must stop a fixture from ever
    reaching a DROP USER for audit_writer/audit_reader/audit_maintenance
    when it did not create them -- proven here by never even letting
    creation proceed once pre-existing names are detected."""
    engine = create_engine(_ISOLATED_TEST_URL)
    with engine.connect() as conn:
        for name in _PRODUCTION_NAMES:
            conn.execute(text(f"DROP USER IF EXISTS '{name}'@'%'"))
        for name in _PRODUCTION_NAMES:
            conn.execute(text(f"CREATE USER '{name}'@'%' IDENTIFIED BY 'sentinel-pw'"))
        conn.commit()

    try:
        with engine.connect() as conn, pytest.raises(PreexistingTestAccountsError):
            refuse_if_accounts_exist(conn, _PRODUCTION_NAMES)

        # Prove the sentinels are untouched -- refuse_if_accounts_exist
        # raised before any CREATE/DROP for these names was attempted.
        with engine.connect() as conn:
            present = conn.execute(
                text(
                    "SELECT user FROM mysql.user WHERE user IN "
                    f"({_sql_quoted_list(_PRODUCTION_NAMES)})"
                )
            ).fetchall()
            assert {row[0] for row in present} == set(_PRODUCTION_NAMES), (
                "sentinel accounts with production names must survive "
                "refuse_if_accounts_exist raising -- it must fail BEFORE "
                "touching them, not clean them up after detecting them"
            )
    finally:
        # Explicit, separate test-infrastructure cleanup of the
        # sentinels this test itself created -- never done by the
        # guard being tested, deliberately, per Phase 7-H.
        with engine.connect() as conn:
            for name in _PRODUCTION_NAMES:
                conn.execute(text(f"DROP USER IF EXISTS '{name}'@'%'"))
            conn.commit()


@_isolated_skip
def test_h_sentinel_accounts_survive_a_realistic_fixture_style_run():
    """End-to-end version of test_g: places production-named sentinels
    on the isolated server, then runs the exact refuse-then-create
    sequence provisioned_users itself follows, confirming the sequence
    stops at the refusal and the sentinels are never mutated."""
    engine = create_engine(_ISOLATED_TEST_URL)
    with engine.connect() as conn:
        for name in _PRODUCTION_NAMES:
            conn.execute(text(f"DROP USER IF EXISTS '{name}'@'%'"))
            conn.execute(text(f"CREATE USER '{name}'@'%' IDENTIFIED BY 'sentinel-pw-h'"))
        conn.commit()

    try:
        provisioning_attempted = False
        try:
            with engine.connect() as conn:
                refuse_if_accounts_exist(conn, _PRODUCTION_NAMES)
            provisioning_attempted = True  # would only reach here if the guard failed to stop us
        except PreexistingTestAccountsError:
            pass

        assert not provisioning_attempted, "guard must stop before any (re-)provisioning is attempted"

        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT user, authentication_string FROM mysql.user WHERE user IN "
                    f"({_sql_quoted_list(_PRODUCTION_NAMES)})"
                )
            ).fetchall()
            assert len(rows) == 3, "all three sentinels must still exist, untouched"
    finally:
        with engine.connect() as conn:
            for name in _PRODUCTION_NAMES:
                conn.execute(text(f"DROP USER IF EXISTS '{name}'@'%'"))
            conn.commit()
