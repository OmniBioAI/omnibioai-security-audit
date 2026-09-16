"""Shared safety guard for destructive real-MySQL integration tests.

P0 test-isolation fix (2026-09-16): every destructive real-MySQL
integration test in this suite used to default its root/admin URL to
mysql+pymysql://root:root@localhost:3306/mysql when B0_TEST_MYSQL_ROOT_URL
was unset. On this project's dev host, localhost:3306 IS the real
production MySQL server -- the same one omnibioai-studio's own compose
stack publishes on host port 3306. That silent default let
tests/test_retention_immutability_integration.py's module-teardown
(`DROP USER IF EXISTS 'audit_writer'@'%'` etc., against whatever
B0_TEST_MYSQL_ROOT_URL resolved to) destroy real production least-
privilege identities twice on 2026-09-16, since MySQL users are global
principals, not scoped to the throwaway database these tests otherwise
correctly isolate.

Two independent guards, both required, both used by every destructive
integration test module in this suite:

1. No implicit default. If B0_TEST_MYSQL_ROOT_URL is unset, these tests
   skip (not fail) -- matching this suite's existing convention of
   skipping rather than failing when an opt-in real backend isn't
   configured.
2. Even when set, port 3306 is refused outright, unconditionally, with
   no override. Production's MySQL is always reachable on port 3306 on
   this architecture; a genuinely isolated test instance must run on a
   different port (this repo's own P0 rehearsal-container convention
   already uses 33061). There is deliberately no
   ALLOW_PRODUCTION_TESTS-style escape hatch -- there is no supported
   mode where these tests intentionally operate against production.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy.engine.url import make_url

ENV_VAR = "B0_TEST_MYSQL_ROOT_URL"
FORBIDDEN_PORT = 3306


class MissingTestMySQLEndpoint(RuntimeError):
    """B0_TEST_MYSQL_ROOT_URL is not set."""


class ProductionMySQLEndpointRejected(RuntimeError):
    """B0_TEST_MYSQL_ROOT_URL resolves to this architecture's production
    MySQL port -- refused unconditionally, before any destructive SQL."""


class PreexistingTestAccountsError(RuntimeError):
    """One or more of this fixture's target account names already exist
    on the target server before this fixture ran. Refuses to proceed
    rather than mutating or deleting accounts it does not own -- see
    Phase 7-H's sentinel-account regression test."""


def validate_test_mysql_url(url_str: str | None, env_var: str = ENV_VAR) -> str:
    """Pure validation, no pytest side effects -- deliberately testable
    in isolation (see tests/test_mysql_integration_guard.py cases A-C).

    Raises MissingTestMySQLEndpoint if url_str is falsy, or
    ProductionMySQLEndpointRejected if it resolves to port 3306.
    Returns url_str unchanged otherwise.
    """
    if not url_str:
        raise MissingTestMySQLEndpoint(
            f"{env_var} is not set -- destructive real-MySQL integration "
            "tests require an explicit, isolated test MySQL endpoint and "
            "never fall back to a default"
        )
    port = make_url(url_str).port or FORBIDDEN_PORT
    if port == FORBIDDEN_PORT:
        raise ProductionMySQLEndpointRejected(
            f"{env_var} resolves to port {FORBIDDEN_PORT}, which is this "
            "architecture's production MySQL port on this host -- refusing "
            "to run destructive integration tests against it. Point "
            f"{env_var} at a genuinely isolated test MySQL instance on a "
            "different port instead (e.g. 33061, matching this repo's own "
            "P0 rehearsal-container convention). There is no override for "
            "this check."
        )
    return url_str


def required_test_mysql_root_url(env_var: str = ENV_VAR) -> str | None:
    """pytest-integrated wrapper: skips the test (missing endpoint) or
    fails it loudly (production endpoint) rather than raising past the
    caller. Returns None only after calling pytest.skip(), which itself
    raises internally -- callers can treat a None return as unreachable.
    """
    import os

    try:
        return validate_test_mysql_url(os.environ.get(env_var), env_var)
    except MissingTestMySQLEndpoint as exc:
        pytest.skip(str(exc))
    except ProductionMySQLEndpointRejected as exc:
        pytest.fail(str(exc))
    return None  # pragma: no cover -- pytest.skip/fail always raise


def unique_test_identifier(prefix: str, max_length: int = 32) -> str:
    """A per-invocation-unique identifier safe for both MySQL database
    names and (<=32-char, MySQL's default limit) user names, e.g.
    'audit_writer_test_a1b2c3'. Trims the prefix, never the random
    suffix -- the suffix is what keeps concurrent runs from colliding.
    """
    suffix = uuid.uuid4().hex[:8]
    candidate = f"{prefix}_test_{suffix}"
    if len(candidate) <= max_length:
        return candidate
    keep = max_length - len(f"_test_{suffix}")
    return f"{prefix[:keep]}_test_{suffix}"


def refuse_if_accounts_exist(conn, usernames: list[str]) -> None:
    """Pre-flight ownership check: refuses to let a fixture proceed if
    any of `usernames` already exist on the target server, rather than
    silently layering this fixture's grants onto (or later deleting) an
    account it did not create. This is what makes Phase 7-H's sentinel
    test meaningful: pre-existing accounts survive because this check
    stops the fixture before it ever touches them.
    """
    from sqlalchemy import text

    placeholders = ", ".join(f"'{u}'" for u in usernames)
    existing = conn.execute(
        text(f"SELECT user FROM mysql.user WHERE user IN ({placeholders})")
    ).fetchall()
    if existing:
        names = ", ".join(row[0] for row in existing)
        raise PreexistingTestAccountsError(
            f"Refusing to provision test accounts -- the following account "
            f"name(s) already exist on this MySQL server and this fixture "
            f"does not own them: {names}. This fixture never mutates or "
            f"deletes accounts it did not itself create."
        )
