"""Shared safety guard for real-Redis integration tests.

PHI P1-5 test-isolation fix: every real-Redis integration test in this
suite (test_worker_pel_recovery_integration.py, test_worker_quarantine_
integration.py, test_worker_integration_real_backends.py) defaulted
B0_TEST_REDIS_URL to redis://localhost:6380 when unset. On this project's
dev host, localhost:6380 IS the real, single, shared Redis instance --
the one omnibioai-studio's own compose stack publishes on host port 6380,
carrying live IAM identity caches, the real `audit:events` stream (87,968+
entries at last count), Celery traffic, and PHI-capable application
caches. That silent default let every "real backend" test in this suite
run for real against that shared instance whenever B0_TEST_REDIS_URL
happened to be unset, rather than against a genuinely isolated instance --
the identical class of bug tests/_mysql_integration_guard.py was written
to close for B0_TEST_MYSQL_ROOT_URL/port 3306, after that exact silent-
default pattern let a MySQL integration test's teardown destroy real
production least-privilege accounts twice on 2026-09-16. Each test file
here already scopes its own stream name to a random per-run suffix (never
literally `audit:events` itself), so the blast radius is narrower than
the MySQL incident was -- but "narrower" is not "safe": every run still
opens a real connection to, and creates real consumer-group/stream state
on, whatever shared instance is listening on port 6380 unless a genuinely
isolated endpoint is configured.

Two guards, mirroring _mysql_integration_guard.py exactly:

1. No implicit default. If B0_TEST_REDIS_URL is unset, these tests skip
   (not fail) -- matching this suite's existing convention of skipping
   rather than failing when an opt-in real backend isn't configured.
2. Even when set, port 6380 is refused outright, unconditionally, with no
   override. Production's Redis is always reachable on port 6380 on this
   architecture; a genuinely isolated test instance must run on a
   different port. There is deliberately no escape hatch -- there is no
   supported mode where these tests intentionally operate against the
   shared production-adjacent instance.
"""
from __future__ import annotations

from urllib.parse import urlsplit

import pytest

ENV_VAR = "B0_TEST_REDIS_URL"
FORBIDDEN_PORT = 6380


class MissingTestRedisEndpoint(RuntimeError):
    """B0_TEST_REDIS_URL is not set."""


class ProductionRedisEndpointRejected(RuntimeError):
    """B0_TEST_REDIS_URL resolves to this architecture's shared,
    production-adjacent Redis port -- refused unconditionally, before any
    connection is opened."""


def validate_test_redis_url(url_str: str | None, env_var: str = ENV_VAR) -> str:
    """Pure validation, no pytest side effects -- mirrors
    _mysql_integration_guard.py::validate_test_mysql_url exactly.

    Raises MissingTestRedisEndpoint if url_str is falsy, or
    ProductionRedisEndpointRejected if it resolves to port 6380.
    Returns url_str unchanged otherwise.
    """
    if not url_str:
        raise MissingTestRedisEndpoint(
            f"{env_var} is not set -- real-Redis integration tests require "
            "an explicit, isolated test Redis endpoint and never fall back "
            "to a default"
        )
    port = urlsplit(url_str).port or FORBIDDEN_PORT
    if port == FORBIDDEN_PORT:
        raise ProductionRedisEndpointRejected(
            f"{env_var} resolves to port {FORBIDDEN_PORT}, which is this "
            "architecture's shared, production-adjacent Redis port on this "
            f"host -- refusing to run integration tests against it. Point "
            f"{env_var} at a genuinely isolated test Redis instance on a "
            "different port instead. There is no override for this check."
        )
    return url_str


def required_test_redis_url(env_var: str = ENV_VAR) -> str | None:
    """pytest-integrated wrapper: skips the test (missing endpoint) or
    fails it loudly (production endpoint) rather than raising past the
    caller. Returns None only after calling pytest.skip()/pytest.fail(),
    which themselves raise internally -- callers can treat a None return
    as unreachable.
    """
    import os

    try:
        return validate_test_redis_url(os.environ.get(env_var), env_var)
    except MissingTestRedisEndpoint as exc:
        pytest.skip(str(exc))
    except ProductionRedisEndpointRejected as exc:
        pytest.fail(str(exc))
    return None  # pragma: no cover -- pytest.skip/fail always raise
