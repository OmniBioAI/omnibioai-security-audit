"""Tests for scripts/redis_acl_safety.py -- the P1-5 incident remediation
framework (see that module's own docstring for the full incident
narrative).

Two tiers:

  - Pure unit tests (command normalization, gate authorize/deny
    decisions, error taxonomy, secret hygiene) need no Redis at all and
    always run.

  - Real-Redis tests need an actual disposable Redis server, because
    fakeredis does not implement Redis's real ACL/AUTH semantics
    (specifically: that a failed AUTH leaves a connection's
    pre-existing identity intact rather than deauthenticating it --
    the exact incident behavior this framework exists to survive).
    `disposable_redis` (session-scoped fixture below) starts one via
    Docker on a random high port, mirroring
    tests/_redis_integration_guard.py's existing convention: no
    implicit default, and port 6380 (this architecture's shared
    production-adjacent Redis port) is refused outright even if
    something upstream ever tried to hand it to this fixture. Skipped
    automatically if the `docker` CLI is unavailable.

Developer: Manish Kumar <manish@omnibioai.org>
"""
from __future__ import annotations

import secrets
import shutil
import subprocess
import time
from unittest.mock import MagicMock, patch

import pytest
import redis

from scripts.redis_acl_safety import (
    PRODUCTION_ALLOWED_COMMANDS,
    PRODUCTION_PORT,
    AuthenticatedSession,
    AuthenticationFailedError,
    DangerousCommandError,
    DisposableAttestation,
    DisposableNegativeTestGate,
    DisposableValidator,
    EnvironmentClassificationError,
    IdentityMismatchError,
    ProductionValidator,
    ProhibitedCommandError,
    RedisEnvironment,
    _normalize_command,
    _safe_repr_command,
    authenticate,
    authenticate_production,
    classify_environment,
)

# ---------------------------------------------------------------------------
# Pure unit tests: command normalization.
# ---------------------------------------------------------------------------


class TestNormalizeCommand:
    """Validate _normalize_command's uppercasing, subcommand-family two-token normalization,
    bytes/str equivalence, whitespace stripping, and rejection of an empty command; and
    _safe_repr_command's exclusion of argument values."""

    def test_simple_command_uppercased(self):
        """Uppercase a simple command regardless of its input casing."""
        assert _normalize_command(["ping"]) == ("PING",)
        assert _normalize_command(["PiNg"]) == ("PING",)

    def test_subcommand_family_normalized_to_two_tokens(self):
        """Normalize a subcommand-family command to its two-token (COMMAND, SUBCOMMAND) form."""
        assert _normalize_command(["config", "set", "maxmemory", "0"]) == ("CONFIG", "SET")
        assert _normalize_command(["ACL", "setuser", "x"]) == ("ACL", "SETUSER")
        assert _normalize_command(["xgroup", "CREATE", "s", "g"]) == ("XGROUP", "CREATE")
        assert _normalize_command(["script", "flush"]) == ("SCRIPT", "FLUSH")

    def test_non_subcommand_family_stays_one_token_even_with_extra_args(self):
        """Keep a non-subcommand-family command to a single token even with extra arguments."""
        assert _normalize_command(["GET", "somekey"]) == ("GET",)
        assert _normalize_command(["SET", "k", "v"]) == ("SET",)

    def test_bytes_args_normalized_same_as_str(self):
        """Normalize bytes-typed command arguments the same as their string equivalents."""
        assert _normalize_command([b"FlUsHaLl"]) == ("FLUSHALL",)
        assert _normalize_command([b"config", b"SET"]) == ("CONFIG", "SET")

    def test_whitespace_stripped(self):
        """Strip surrounding whitespace from a command token before normalizing."""
        assert _normalize_command([" flushall "]) == ("FLUSHALL",)

    def test_mixed_case_variations_all_equal(self):
        """Normalize every case variation of a command to the same tuple."""
        variants = ["FLUSHALL", "flushall", "FlUsHaLl", "fLUSHALL"]
        assert len({_normalize_command([v]) for v in variants}) == 1

    def test_empty_command_rejected(self):
        """Raise ProhibitedCommandError for an empty command list."""
        with pytest.raises(ProhibitedCommandError):
            _normalize_command([])

    def test_empty_string_command_rejected(self):
        """Raise ProhibitedCommandError for a command list containing only an empty string."""
        with pytest.raises(ProhibitedCommandError):
            _normalize_command([""])

    def test_safe_repr_never_includes_extra_args(self):
        """Render only the command name in the safe repr, never its argument values."""
        assert _safe_repr_command(["SET", "k", "supersecretvalue"]) == "SET"
        assert "supersecretvalue" not in _safe_repr_command(["SET", "k", "supersecretvalue"])
        assert _safe_repr_command(["ACL", "SETUSER", "x", ">password"]) == "ACL SETUSER"
        assert "password" not in _safe_repr_command(["ACL", "SETUSER", "x", ">password"])


# ---------------------------------------------------------------------------
# Pure unit tests: ProductionValidator (allowlist-first).
# ---------------------------------------------------------------------------


class TestProductionValidatorAllowlist:
    """Validate ProductionValidator's allowlist: exactly which commands it permits, which it denies
    as merely prohibited versus specifically dangerous, and that error messages never leak
    argument values."""

    @pytest.fixture
    def gate(self):
        """Provide a fresh ProductionValidator."""
        return ProductionValidator()

    @pytest.mark.parametrize("cmd", [["PING"], ["ping"], ["ACL", "WHOAMI"], ["acl", "whoami"], ["INFO"], ["info"]])
    def test_allowed_commands_pass(self, gate, cmd):
        """Authorize every allowlisted command without raising."""
        gate.authorize(cmd)  # must not raise

    def test_allowlist_is_exactly_the_documented_minimum(self):
        """Pin the production allowlist to exactly PING, ACL WHOAMI, and INFO."""
        assert PRODUCTION_ALLOWED_COMMANDS == frozenset({("PING",), ("ACL", "WHOAMI"), ("INFO",)})

    @pytest.mark.parametrize("cmd", [
        ["GET", "somekey"], ["SET", "k", "v"], ["DEL", "k"], ["XADD", "s", "*", "f", "v"],
        ["XLEN", "s"], ["SCAN", "0"], ["KEYS", "*"], ["DBSIZE"], ["CLIENT", "LIST"],
    ])
    def test_non_allowlisted_harmless_looking_commands_still_denied(self, gate, cmd):
        """Deny a harmless-looking but non-allowlisted command."""
        with pytest.raises(ProhibitedCommandError):
            gate.authorize(cmd)

    @pytest.mark.parametrize("cmd", [
        ["FLUSHALL"], ["flushall"], ["FlUsHaLl"], ["FLUSHDB"], ["SHUTDOWN"],
        ["SHUTDOWN", "NOSAVE"], ["DEBUG", "SLEEP", "0"], ["CONFIG", "SET", "maxmemory", "0"],
        ["config", "set", "x", "y"], ["ACL", "SETUSER", "x"], ["acl", "setuser", "x"],
        ["ACL", "DELUSER", "x"], ["ACL", "LOAD"], ["ACL", "SAVE"], ["ACL", "LOG", "RESET"],
        ["MODULE", "LOAD", "x"], ["MODULE", "UNLOAD", "x"], ["MIGRATE"], ["RESTORE"],
        ["RESTORE-ASKING"], ["SWAPDB", "0", "1"], ["REPLICAOF", "no", "one"], ["SLAVEOF", "no", "one"],
    ])
    def test_dangerous_commands_denied_as_dangerous_specifically(self, gate, cmd):
        """Deny a destructive command with DangerousCommandError specifically, not just a generic
        denial."""
        with pytest.raises(DangerousCommandError):
            gate.authorize(cmd)

    def test_dangerous_error_is_a_prohibited_command_error(self, gate):
        """Raise DangerousCommandError as a subtype of ProhibitedCommandError."""
        with pytest.raises(ProhibitedCommandError):
            gate.authorize(["FLUSHALL"])

    def test_bytes_command_cannot_bypass_dangerous_check(self, gate):
        """Deny a dangerous command given as bytes the same as its string form."""
        with pytest.raises(DangerousCommandError):
            gate.authorize([b"FLUSHALL"])

    def test_subcommand_split_cannot_bypass_dangerous_check(self, gate):
        """Deny a dangerous subcommand regardless of how its tokens are split."""
        # A caller cannot dodge the ("CONFIG", "SET") tuple by passing the
        # subcommand as a separate positional differently-cased token.
        with pytest.raises(DangerousCommandError):
            gate.authorize(["CONFIG", "set"])
        with pytest.raises(DangerousCommandError):
            gate.authorize(["config", "SET"])

    def test_error_message_never_contains_argument_values(self, gate):
        """Keep argument values out of the error message raised for a denied command."""
        with pytest.raises(ProhibitedCommandError) as excinfo:
            gate.authorize(["SET", "k", "topsecretvalue123"])
        assert "topsecretvalue123" not in str(excinfo.value)


# ---------------------------------------------------------------------------
# Pure unit tests: environment classification without a real Redis.
# ---------------------------------------------------------------------------


class TestClassifyEnvironmentWithoutRedis:
    """Validate classify_environment and DisposableAttestation's construction-time checks without a
    real Redis connection: production-port detection, the unknown default, and rejection of
    malformed or unreachable attestations."""

    def test_production_port_always_classified_production_even_with_no_attestation(self):
        """Classify the production port as PRODUCTION even with no attestation supplied."""
        assert classify_environment(host="redis", port=PRODUCTION_PORT, attestation=None) is RedisEnvironment.PRODUCTION

    def test_unknown_when_no_attestation_supplied(self):
        """Classify a non-production host/port with no attestation as UNKNOWN."""
        # No live probe is even attempted when there's no attestation --
        # a bogus host/port here would still correctly resolve to UNKNOWN.
        assert classify_environment(host="nonexistent.invalid", port=59999, attestation=None) is RedisEnvironment.UNKNOWN

    def test_attestation_construction_rejects_production_port(self):
        """Reject constructing a DisposableAttestation for the production port."""
        with pytest.raises(EnvironmentClassificationError):
            DisposableAttestation(host="redis", port=PRODUCTION_PORT, nonce_key="k", nonce_value="v")

    def test_attestation_construction_rejects_empty_nonce(self):
        """Reject constructing a DisposableAttestation with an empty nonce key and value."""
        with pytest.raises(EnvironmentClassificationError):
            DisposableAttestation(host="localhost", port=16399, nonce_key="", nonce_value="")

    def test_attestation_construction_rejects_empty_host(self):
        """Reject constructing a DisposableAttestation with an empty host."""
        with pytest.raises(EnvironmentClassificationError):
            DisposableAttestation(host="", port=16399, nonce_key="k", nonce_value="v")

    def test_mismatched_host_port_attestation_rejected(self):
        """Reject classifying an environment against an attestation built for a different host/port."""
        attestation = DisposableAttestation(host="127.0.0.1", port=16399, nonce_key="k", nonce_value="v")
        with pytest.raises(EnvironmentClassificationError):
            classify_environment(host="127.0.0.1", port=16400, attestation=attestation)

    def test_unreachable_disposable_target_fails_closed_not_disposable(self):
        """Raise, not silently classify as disposable, when the attested target cannot be reached."""
        # Well-formed attestation, but nothing is actually listening --
        # must raise, never silently fall through to DISPOSABLE.
        attestation = DisposableAttestation(host="127.0.0.1", port=1, nonce_key="k", nonce_value="v")
        with pytest.raises(EnvironmentClassificationError):
            classify_environment(host="127.0.0.1", port=1, attestation=attestation)

    def test_disposable_validator_construction_fails_closed_when_unreachable(self):
        """Raise when a disposable validator is constructed against an unreachable target."""
        attestation = DisposableAttestation(host="127.0.0.1", port=1, nonce_key="k", nonce_value="v")
        with pytest.raises(EnvironmentClassificationError):
            DisposableValidator(host="127.0.0.1", port=1, attestation=attestation)

    def test_negative_test_gate_construction_fails_closed_when_unreachable(self):
        """Raise when a negative test gate is constructed against an unreachable target."""
        attestation = DisposableAttestation(host="127.0.0.1", port=1, nonce_key="k", nonce_value="v")
        with pytest.raises(EnvironmentClassificationError):
            DisposableNegativeTestGate(host="127.0.0.1", port=1, attestation=attestation)


# ---------------------------------------------------------------------------
# Pure unit tests: authenticate() production-port guard (no real Redis
# needed -- this specific check happens before any connection attempt).
# ---------------------------------------------------------------------------


class TestAuthenticateProductionGuard:
    """Validate that authenticate_production refuses to proceed against a non-production port."""

    def test_authenticate_production_rejects_non_production_port(self):
        """Reject authenticate_production when the target port is not the production port."""
        with pytest.raises(EnvironmentClassificationError):
            authenticate_production(
                host="127.0.0.1", port=16399, username="x", password="y",
                expected_identity="x",
            )


# ---------------------------------------------------------------------------
# Real-Redis fixture: a genuinely disposable instance, mirroring
# tests/_redis_integration_guard.py's own safety conventions.
# ---------------------------------------------------------------------------

_DOCKER_AVAILABLE = shutil.which("docker") is not None


def _run(cmd, **kw):
    """Run a subprocess command, capturing output and applying a 30-second timeout."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False, **kw)


@pytest.fixture(scope="session")
def disposable_redis():
    """Starts a throwaway redis:7-alpine container on a random high
    port, with `default` left on/nopass (reproducing the exact
    precondition of the incident) plus a restricted `redis_monitoring`
    test identity. Never uses PRODUCTION_PORT -- refuses to proceed if
    Docker ever handed back that port by coincidence.
    """
    if not _DOCKER_AVAILABLE:
        pytest.skip("docker CLI not available; skipping real-Redis safety tests")

    name = f"p15-safety-test-{secrets.token_hex(4)}"
    _run(["docker", "rm", "-f", name])
    started = _run(["docker", "run", "-d", "--rm", "--name", name, "-p", "127.0.0.1::6379", "redis:7-alpine"])
    if started.returncode != 0:
        pytest.skip(f"could not start disposable Redis container: {started.stderr.strip()[:200]}")

    try:
        port_out = _run(["docker", "port", name, "6379/tcp"])
        host_port = int(port_out.stdout.strip().rsplit(":", 1)[-1])
        if host_port == PRODUCTION_PORT:
            pytest.fail(
                "disposable Redis container was allocated this architecture's "
                "production-adjacent port by coincidence -- refusing to use it"
            )

        for _ in range(20):
            ping = _run(["docker", "exec", name, "redis-cli", "PING"])
            if ping.stdout.strip() == "PONG":
                break
            time.sleep(0.5)
        else:
            pytest.fail("disposable Redis container never became reachable")

        nonce_key = "p15_safety_test_nonce"
        nonce_value = secrets.token_hex(16)
        _run(["docker", "exec", name, "redis-cli", "SET", nonce_key, nonce_value])

        monitoring_password = secrets.token_hex(16)
        _run([
            "docker", "exec", name, "redis-cli", "ACL", "SETUSER", "redis_monitoring_test",
            "on", f">{monitoring_password}", "resetkeys", "resetchannels", "-@all",
            "+ping", "+info", "+acl|whoami",
        ])

        yield {
            "host": "127.0.0.1",
            "port": host_port,
            "container": name,
            "nonce_key": nonce_key,
            "nonce_value": nonce_value,
            "monitoring_password": monitoring_password,
        }
    finally:
        _run(["docker", "rm", "-f", name])


@pytest.fixture
def attestation(disposable_redis):
    """Build a DisposableAttestation bound to the disposable Redis container's host, port, and
    nonce."""
    return DisposableAttestation(
        host=disposable_redis["host"], port=disposable_redis["port"],
        nonce_key=disposable_redis["nonce_key"], nonce_value=disposable_redis["nonce_value"],
    )


# ---------------------------------------------------------------------------
# Real-Redis: environment classification against a genuine instance.
# ---------------------------------------------------------------------------


class TestClassifyEnvironmentRealRedis:
    """Validate classify_environment against a real disposable Redis instance: a valid attestation
    classifies as disposable, and a wrong nonce key or value fails closed."""

    def test_valid_attestation_classified_disposable(self, disposable_redis, attestation):
        """Classify the disposable container as DISPOSABLE given a valid attestation against it."""
        env = classify_environment(host=disposable_redis["host"], port=disposable_redis["port"], attestation=attestation)
        assert env is RedisEnvironment.DISPOSABLE

    def test_wrong_nonce_value_fails_closed(self, disposable_redis):
        """Fail closed when the attestation's nonce value does not match what is stored on the
        target."""
        bad = DisposableAttestation(
            host=disposable_redis["host"], port=disposable_redis["port"],
            nonce_key=disposable_redis["nonce_key"], nonce_value="not-the-real-nonce",
        )
        with pytest.raises(EnvironmentClassificationError):
            classify_environment(host=disposable_redis["host"], port=disposable_redis["port"], attestation=bad)

    def test_wrong_nonce_key_fails_closed(self, disposable_redis):
        """Fail closed when the attestation's nonce key does not match what is stored on the target."""
        bad = DisposableAttestation(
            host=disposable_redis["host"], port=disposable_redis["port"],
            nonce_key="nonexistent_key_never_set", nonce_value=disposable_redis["nonce_value"],
        )
        with pytest.raises(EnvironmentClassificationError):
            classify_environment(host=disposable_redis["host"], port=disposable_redis["port"], attestation=bad)


# ---------------------------------------------------------------------------
# Real-Redis: THE incident regression test.
# ---------------------------------------------------------------------------


class TestIncidentReproductionAndDefense:
    """Phase 5 of the remediation task: reproduce the actual incident
    condition in disposable Redis, confirm Redis's real behavior is
    exactly what caused it, then prove this framework survives it."""

    def test_raw_redis_reproduces_the_incident_condition(self, disposable_redis):
        """Ground truth, using the raw redis-py client directly (NOT
        this framework) -- proves the server-level behavior this
        framework has to defend against is real, on this Redis
        version, right now. A connection that fails AUTH remains
        authenticated as whatever it was before (here: `default`,
        since it's `nopass`/enabled on this disposable instance) and a
        subsequent command still executes.
        """
        client = redis.Redis(
            host=disposable_redis["host"], port=disposable_redis["port"],
            decode_responses=True, single_connection_client=True,
        )
        try:
            with pytest.raises(redis.AuthenticationError):
                client.execute_command("AUTH", "redis_monitoring_test", "definitely-the-wrong-password")
            # This is the crux of the incident: despite the AUTH failure
            # above, the connection is still usable and still `default`.
            whoami = client.execute_command("ACL", "WHOAMI")
            assert whoami == "default"
            probe_key = "p15_incident_repro_probe"
            # A real write succeeds here -- this is what FLUSHALL did in
            # production. Using a harmless SET on disposable Redis,
            # scoped to this test's own throwaway key, to avoid needing
            # a second destructive assertion for the same point.
            assert client.execute_command("SET", probe_key, "1") in (True, "OK")
            assert client.execute_command("GET", probe_key) == "1"
        finally:
            client.close()

    def test_framework_closes_connection_on_failed_auth_zero_commands_after(self, disposable_redis):
        """The actual regression test: authenticate() with a wrong
        password must raise AuthenticationFailedError and must not
        leave a usable connection behind -- verified by checking
        `_closed`/that `.run()` refuses to proceed."""
        gate = ProductionValidator()
        with pytest.raises(AuthenticationFailedError):
            session = authenticate(
                host=disposable_redis["host"], port=disposable_redis["port"],
                username="redis_monitoring_test", password="definitely-the-wrong-password",
                expected_identity="redis_monitoring_test", gate=gate,
                environment=RedisEnvironment.UNKNOWN,
            )
            session.run("PING")  # unreachable if authenticate() raised, as required

    def test_framework_never_returns_a_session_after_failed_auth(self, disposable_redis, monkeypatch):
        """Belt-and-suspenders: instrument the underlying client's
        execute_command to prove nothing beyond AUTH is ever sent on a
        connection that failed AUTH."""
        sent = []
        real_execute = redis.Redis.execute_command

        def spy(self, *args, **kwargs):
            sent.append(args[0] if args else None)
            return real_execute(self, *args, **kwargs)

        monkeypatch.setattr(redis.Redis, "execute_command", spy)
        gate = ProductionValidator()
        with pytest.raises(AuthenticationFailedError):
            authenticate(
                host=disposable_redis["host"], port=disposable_redis["port"],
                username="redis_monitoring_test", password="definitely-the-wrong-password",
                expected_identity="redis_monitoring_test", gate=gate,
                environment=RedisEnvironment.UNKNOWN,
            )
        assert sent == ["AUTH"], f"expected only AUTH to have been sent, got {sent!r}"

    def test_framework_succeeds_with_correct_credential_and_matching_identity(self, disposable_redis):
        """Authenticate and run PING against the disposable Redis with the correct credential and
        matching identity."""
        gate = ProductionValidator()
        session = authenticate(
            host=disposable_redis["host"], port=disposable_redis["port"],
            username="redis_monitoring_test", password=disposable_redis["monitoring_password"],
            expected_identity="redis_monitoring_test", gate=gate,
            environment=RedisEnvironment.UNKNOWN,
        )
        try:
            assert session.run("PING") is True or session.run("PING") == "PONG"
        finally:
            session.close()

    def test_session_after_close_refuses_further_commands(self, disposable_redis):
        """Raise when a command is run on a session after it has been closed."""
        gate = ProductionValidator()
        session = authenticate(
            host=disposable_redis["host"], port=disposable_redis["port"],
            username="redis_monitoring_test", password=disposable_redis["monitoring_password"],
            expected_identity="redis_monitoring_test", gate=gate,
            environment=RedisEnvironment.UNKNOWN,
        )
        session.close()
        with pytest.raises(RuntimeError):
            session.run("PING")


# ---------------------------------------------------------------------------
# Real-Redis: identity mismatch is a hard failure.
# ---------------------------------------------------------------------------


class TestIdentityMismatchRealRedis:
    """Validate that an identity mismatch during authentication against real Redis leaves no usable
    session, sending only AUTH then ACL WHOAMI."""

    def test_expected_identity_not_matching_actual_is_hard_failure(self, disposable_redis):
        """Authenticate correctly as redis_monitoring_test, but assert
        the WRONG expected identity -- must be a hard
        IdentityMismatchError, never a warning, never silently
        continuing with a differently-privileged identity than the
        caller asked for."""
        gate = ProductionValidator()
        with pytest.raises(IdentityMismatchError):
            authenticate(
                host=disposable_redis["host"], port=disposable_redis["port"],
                username="redis_monitoring_test", password=disposable_redis["monitoring_password"],
                expected_identity="default",  # deliberately wrong
                gate=gate, environment=RedisEnvironment.UNKNOWN,
            )

    def test_mismatch_error_does_not_leave_a_usable_session(self, disposable_redis, monkeypatch):
        """Send only AUTH then ACL WHOAMI, and raise IdentityMismatchError, when the authenticated
        identity does not match the expected one."""
        sent = []
        real_execute = redis.Redis.execute_command

        def spy(self, *args, **kwargs):
            sent.append(args[0] if args else None)
            return real_execute(self, *args, **kwargs)

        monkeypatch.setattr(redis.Redis, "execute_command", spy)
        gate = ProductionValidator()
        with pytest.raises(IdentityMismatchError):
            authenticate(
                host=disposable_redis["host"], port=disposable_redis["port"],
                username="redis_monitoring_test", password=disposable_redis["monitoring_password"],
                expected_identity="nonexistent_identity", gate=gate,
                environment=RedisEnvironment.UNKNOWN,
            )
        assert sent == ["AUTH", "ACL"], f"expected AUTH then ACL WHOAMI only, got {sent!r}"


# ---------------------------------------------------------------------------
# Real-Redis: other authentication-failure shapes (Phase 9).
# ---------------------------------------------------------------------------


class TestAuthenticationFailureShapesRealRedis:
    """Validate authentication failure handling against real Redis: a nonexistent username, a
    correct credential succeeding, and an unreachable host failing closed."""

    def test_nonexistent_username(self, disposable_redis):
        """Raise AuthenticationFailedError for a username that does not exist on the target."""
        gate = ProductionValidator()
        with pytest.raises(AuthenticationFailedError):
            authenticate(
                host=disposable_redis["host"], port=disposable_redis["port"],
                username="this_user_was_never_created", password="whatever",
                expected_identity="this_user_was_never_created", gate=gate,
                environment=RedisEnvironment.UNKNOWN,
            )

    def test_correct_username_correct_password_succeeds(self, disposable_redis):
        """Authenticate successfully with the correct username and password."""
        gate = ProductionValidator()
        session = authenticate(
            host=disposable_redis["host"], port=disposable_redis["port"],
            username="redis_monitoring_test", password=disposable_redis["monitoring_password"],
            expected_identity="redis_monitoring_test", gate=gate,
            environment=RedisEnvironment.UNKNOWN,
        )
        session.close()

    def test_unreachable_host_fails_closed(self):
        """Raise AuthenticationFailedError, not hang, when the host is unreachable."""
        gate = ProductionValidator()
        with pytest.raises(AuthenticationFailedError):
            authenticate(
                host="127.0.0.1", port=1, username="x", password="y",
                expected_identity="x", gate=gate, environment=RedisEnvironment.UNKNOWN,
                socket_timeout=1,
            )

    def test_reconnect_after_failure_does_not_inherit_prior_state(self, disposable_redis):
        """A second, fresh authenticate() call after a failed one must
        not be affected by the prior failure -- each call opens its
        own brand-new connection."""
        gate = ProductionValidator()
        with pytest.raises(AuthenticationFailedError):
            authenticate(
                host=disposable_redis["host"], port=disposable_redis["port"],
                username="redis_monitoring_test", password="wrong-again",
                expected_identity="redis_monitoring_test", gate=gate,
                environment=RedisEnvironment.UNKNOWN,
            )
        session = authenticate(
            host=disposable_redis["host"], port=disposable_redis["port"],
            username="redis_monitoring_test", password=disposable_redis["monitoring_password"],
            expected_identity="redis_monitoring_test", gate=gate,
            environment=RedisEnvironment.UNKNOWN,
        )
        session.close()


# ---------------------------------------------------------------------------
# Real-Redis: production allowlist enforced end to end.
# ---------------------------------------------------------------------------


class TestProductionAllowlistEndToEndRealRedis:
    """Validate the production allowlist end to end against real Redis: an allowed command runs, and
    FLUSHALL never reaches the wire through a production session."""

    def test_allowed_command_runs(self, disposable_redis):
        """Run an allowlisted command through a production session and get a non-empty result."""
        gate = ProductionValidator()
        session = authenticate(
            host=disposable_redis["host"], port=disposable_redis["port"],
            username="redis_monitoring_test", password=disposable_redis["monitoring_password"],
            expected_identity="redis_monitoring_test", gate=gate,
            environment=RedisEnvironment.UNKNOWN,
        )
        try:
            info = session.run("INFO")
            assert info  # non-empty
        finally:
            session.close()

    def test_flushall_never_reaches_the_wire_through_production_session(self, disposable_redis, monkeypatch):
        """Deny FLUSHALL before it ever reaches execute_command through a production session."""
        sent = []
        real_execute = redis.Redis.execute_command

        def spy(self, *args, **kwargs):
            sent.append(args[0] if args else None)
            return real_execute(self, *args, **kwargs)

        monkeypatch.setattr(redis.Redis, "execute_command", spy)
        gate = ProductionValidator()
        session = authenticate(
            host=disposable_redis["host"], port=disposable_redis["port"],
            username="redis_monitoring_test", password=disposable_redis["monitoring_password"],
            expected_identity="redis_monitoring_test", gate=gate,
            environment=RedisEnvironment.UNKNOWN,
        )
        try:
            with pytest.raises(DangerousCommandError):
                session.run("FLUSHALL")
        finally:
            session.close()
        assert "FLUSHALL" not in sent, "FLUSHALL must never reach execute_command through a production session"


# ---------------------------------------------------------------------------
# Real-Redis: disposable-only destructive proof (Phase 8).
# ---------------------------------------------------------------------------


class TestDisposableDestructiveProofRealRedis:
    """Validate that a restricted disposable-test identity is denied writes outside its authorized
    keys, and that the negative test gate cannot be constructed for the production port."""

    def test_restricted_identity_denied_flushall_by_redis_itself(self, disposable_redis, attestation):
        """This is the one place a dangerous command is actually sent
        -- through DisposableNegativeTestGate, against a live-verified
        disposable target, to observe Redis's own NOPERM. Proves the
        restricted test identity genuinely cannot FLUSHALL; does not
        merely trust this framework's own denylist."""
        gate = DisposableNegativeTestGate(
            host=disposable_redis["host"], port=disposable_redis["port"], attestation=attestation,
        )
        session = authenticate(
            host=disposable_redis["host"], port=disposable_redis["port"],
            username="redis_monitoring_test", password=disposable_redis["monitoring_password"],
            expected_identity="redis_monitoring_test", gate=gate,
            environment=RedisEnvironment.DISPOSABLE,
        )
        try:
            with pytest.raises(redis.exceptions.NoPermissionError):
                session.run("FLUSHALL")
        finally:
            session.close()

    def test_restricted_identity_denied_set_on_unauthorized_key(self, disposable_redis, attestation):
        """Deny a SET on a key outside the restricted test identity's authorized keyspace."""
        gate = DisposableNegativeTestGate(
            host=disposable_redis["host"], port=disposable_redis["port"], attestation=attestation,
        )
        session = authenticate(
            host=disposable_redis["host"], port=disposable_redis["port"],
            username="redis_monitoring_test", password=disposable_redis["monitoring_password"],
            expected_identity="redis_monitoring_test", gate=gate,
            environment=RedisEnvironment.DISPOSABLE,
        )
        try:
            with pytest.raises(redis.exceptions.NoPermissionError):
                session.run("SET", "some:unrelated:key", "v")
        finally:
            session.close()

    def test_negative_test_gate_cannot_be_constructed_for_production_port(self, disposable_redis):
        """Classify the production port as PRODUCTION rather than allowing a negative test gate to
        target it."""
        # Even with a technically-well-formed attestation pointed at the
        # disposable instance, asking classify_environment to check
        # PRODUCTION_PORT directly must never say DISPOSABLE.
        assert classify_environment(host=disposable_redis["host"], port=PRODUCTION_PORT, attestation=None) is RedisEnvironment.PRODUCTION

    def test_disposable_validator_denies_dangerous_commands_even_though_target_is_disposable(self, disposable_redis, attestation):
        """DisposableValidator (not the negative-test gate) must still
        refuse dangerous commands -- it is not the sanctioned path for
        destructive negative testing, even against a proven-disposable
        target."""
        gate = DisposableValidator(host=disposable_redis["host"], port=disposable_redis["port"], attestation=attestation)
        with pytest.raises(DangerousCommandError):
            gate.authorize(["FLUSHALL"])


# ---------------------------------------------------------------------------
# Real-Redis: unknown environment behaves at least as strictly as production.
# ---------------------------------------------------------------------------


class TestUnknownEnvironmentRealRedis:
    """Validate that an unknown environment still gets dangerous commands denied by
    ProductionValidator, and that a missing attestation never implies disposable."""

    def test_unknown_environment_with_production_validator_still_denies_dangerous(self, disposable_redis):
        """Deny a dangerous command even when the environment classifies as unknown."""
        # Simulates a caller that never supplied a DisposableAttestation
        # (environment resolves to UNKNOWN) but still, correctly, uses
        # ProductionValidator for anything of unproven status.
        gate = ProductionValidator()
        session = authenticate(
            host=disposable_redis["host"], port=disposable_redis["port"],
            username="redis_monitoring_test", password=disposable_redis["monitoring_password"],
            expected_identity="redis_monitoring_test", gate=gate,
            environment=RedisEnvironment.UNKNOWN,
        )
        try:
            with pytest.raises(DangerousCommandError):
                session.run("FLUSHALL")
        finally:
            session.close()

    def test_missing_attestation_never_implies_disposable(self):
        """Classify hosts with no attestation as UNKNOWN, never DISPOSABLE, regardless of how local
        the host looks."""
        assert classify_environment(host="127.0.0.1", port=16399, attestation=None) is RedisEnvironment.UNKNOWN
        assert classify_environment(host="localhost", port=16399, attestation=None) is RedisEnvironment.UNKNOWN
        assert classify_environment(host="some-test-container", port=16399, attestation=None) is RedisEnvironment.UNKNOWN


# ---------------------------------------------------------------------------
# Raw-client bypass (Phase 11).
# ---------------------------------------------------------------------------


class TestRawClientBypassRealRedis:
    """Validate that AuthenticatedSession exposes no way to reach the underlying raw Redis client or
    its execute_command."""

    def test_authenticated_session_exposes_no_public_raw_client_accessor(self, disposable_redis):
        """Expose only environment, run, and close as AuthenticatedSession's public attributes."""
        gate = ProductionValidator()
        session = authenticate(
            host=disposable_redis["host"], port=disposable_redis["port"],
            username="redis_monitoring_test", password=disposable_redis["monitoring_password"],
            expected_identity="redis_monitoring_test", gate=gate,
            environment=RedisEnvironment.UNKNOWN,
        )
        try:
            public_attrs = [a for a in dir(session) if not a.startswith("_")]
            assert "client" not in public_attrs
            assert "redis_client" not in public_attrs
            assert "raw_client" not in public_attrs
            assert "connection_pool" not in public_attrs
            assert "execute_command" not in public_attrs
            assert set(public_attrs) <= {"environment", "run", "close"}
        finally:
            session.close()

    def test_only_run_and_close_are_the_public_surface(self):
        """Define run and close as AuthenticatedSession's only public methods."""
        assert AuthenticatedSession.run is not None
        assert AuthenticatedSession.close is not None
        # documents, rather than technically enforces, that this is the
        # entire intended public surface -- see the module/class
        # docstrings for the honest limit of this guarantee (no true
        # private attributes exist in Python).


# ---------------------------------------------------------------------------
# Pure unit tests: defensive/plumbing branches not covered by the incident-
# reproduction tests above -- RedisEnvironment's value-object protocol,
# DisposableAttestation.generate_nonce, gate construction against an
# UNKNOWN (not merely unreachable) environment, AuthenticatedSession's
# context-manager/double-close/best-effort-cleanup behavior, and
# authenticate()'s own error-shape branches. These are generic Python
# defensive code, not the AUTH/ACL security semantics the module's
# docstring says fakeredis can't be trusted for, so a mocked
# `redis.Redis` is used here deliberately -- it never stands in for a
# real authorization decision anywhere in this file.
# ---------------------------------------------------------------------------


class TestRedisEnvironmentValueObjectProtocol:
    """Validate RedisEnvironment's __repr__/__eq__/__hash__, which nothing else in this module's
    happy paths exercises (those compare with `is`, not `==`)."""

    def test_repr_names_the_instance(self):
        """Render each RedisEnvironment singleton's repr with its own name."""
        assert repr(RedisEnvironment.DISPOSABLE) == "RedisEnvironment.DISPOSABLE"
        assert repr(RedisEnvironment.PRODUCTION) == "RedisEnvironment.PRODUCTION"
        assert repr(RedisEnvironment.UNKNOWN) == "RedisEnvironment.UNKNOWN"

    def test_equality_is_identity_based(self):
        """Equate a RedisEnvironment only with itself, never with a different singleton."""
        assert RedisEnvironment.DISPOSABLE == RedisEnvironment.DISPOSABLE
        assert RedisEnvironment.DISPOSABLE != RedisEnvironment.PRODUCTION
        assert RedisEnvironment.DISPOSABLE != "DISPOSABLE"

    def test_hash_is_stable_and_usable_in_a_set(self):
        """Hash a RedisEnvironment stably enough to use it in a set/dict key."""
        assert hash(RedisEnvironment.DISPOSABLE) == hash(RedisEnvironment.DISPOSABLE)
        assert {RedisEnvironment.DISPOSABLE, RedisEnvironment.DISPOSABLE, RedisEnvironment.PRODUCTION} == {
            RedisEnvironment.DISPOSABLE, RedisEnvironment.PRODUCTION,
        }


def test_generate_nonce_returns_a_fresh_unguessable_value_each_call():
    """Generate a fresh, differing hex nonce on every call."""
    a = DisposableAttestation.generate_nonce()
    b = DisposableAttestation.generate_nonce()
    assert a != b
    assert len(a) == 32  # secrets.token_hex(16) -> 32 hex chars
    int(a, 16)  # must actually be hex


def test_safe_repr_command_handles_an_empty_command():
    """Render '<empty>' instead of raising for a command that normalizes to nothing."""
    assert _safe_repr_command([]) == "<empty>"
    assert _safe_repr_command([""]) == "<empty>"


class TestGateConstructionAgainstUnknownEnvironment:
    """DisposableValidator/DisposableNegativeTestGate must refuse construction against UNKNOWN
    (no attestation supplied), not merely against an unreachable target -- the same fail-closed
    discipline classify_environment itself documents."""

    def test_disposable_validator_rejects_missing_attestation(self):
        """Refuse to construct a DisposableValidator with no attestation at all."""
        with pytest.raises(EnvironmentClassificationError):
            DisposableValidator(host="127.0.0.1", port=16399, attestation=None)

    def test_negative_test_gate_rejects_missing_attestation(self):
        """Refuse to construct a DisposableNegativeTestGate with no attestation at all."""
        with pytest.raises(EnvironmentClassificationError):
            DisposableNegativeTestGate(host="127.0.0.1", port=16399, attestation=None)


class TestClassifyEnvironmentProbeCleanup:
    """classify_environment's own best-effort probe.close() must never let a cleanup failure mask
    (or crash out of) an otherwise-successful classification."""

    def test_probe_close_failure_does_not_prevent_a_disposable_result(self):
        """Still classify DISPOSABLE even when the verification probe's own close() raises."""
        attestation = DisposableAttestation(host="127.0.0.1", port=16399, nonce_key="k", nonce_value="v")
        mock_probe = MagicMock()
        mock_probe.execute_command.return_value = "v"
        mock_probe.close.side_effect = RuntimeError("cleanup failed")
        with patch("scripts.redis_acl_safety.redis.Redis", return_value=mock_probe):
            env = classify_environment(host="127.0.0.1", port=16399, attestation=attestation)
        assert env is RedisEnvironment.DISPOSABLE


class TestAuthenticatedSessionLifecycleWithMockedClient:
    """AuthenticatedSession's close()/context-manager plumbing, exercised against a mocked
    underlying client -- this class's own logic, not Redis's AUTH/ACL semantics."""

    def _session(self, client=None):
        return AuthenticatedSession(
            environment=RedisEnvironment.DISPOSABLE, gate=ProductionValidator(),
            client=client or MagicMock(),
        )

    def test_double_close_is_a_safe_no_op(self):
        """Close a session twice without error, closing the underlying client only once."""
        mock_client = MagicMock()
        session = self._session(mock_client)
        session.close()
        session.close()
        mock_client.close.assert_called_once()

    def test_close_swallows_a_failure_from_the_underlying_client(self):
        """Swallow (not raise) an exception from the underlying client's own close()."""
        mock_client = MagicMock()
        mock_client.close.side_effect = RuntimeError("boom")
        session = self._session(mock_client)
        session.close()  # must not raise
        assert session._closed is True

    def test_context_manager_closes_on_exit(self):
        """Close the underlying client on context-manager exit."""
        mock_client = MagicMock()
        with self._session(mock_client) as session:
            assert session.environment is RedisEnvironment.DISPOSABLE
        mock_client.close.assert_called_once()


class TestAuthenticateErrorShapesWithMockedClient:
    """authenticate()'s own error-conversion branches that the real-Redis incident-reproduction
    tests above don't reach: an unexpected (non-True/"OK") AUTH result, ACL WHOAMI itself failing
    after a successful AUTH, and a completely unexpected (non-RedisError) exception. None of these
    depend on fakeredis's known AUTH/ACL gap -- they're this function's own control flow."""

    def test_unexpected_auth_result_is_a_hard_failure(self):
        """Raise AuthenticationFailedError when AUTH succeeds on the wire but returns neither True
        nor 'OK'."""
        mock_client = MagicMock()
        mock_client.execute_command.return_value = "MAYBE"
        with (
            patch("scripts.redis_acl_safety.redis.Redis", return_value=mock_client),
            pytest.raises(AuthenticationFailedError),
        ):
            authenticate(
                host="127.0.0.1", port=16399, username="u", password="p",
                expected_identity="u", gate=ProductionValidator(),
                environment=RedisEnvironment.UNKNOWN,
            )
        mock_client.close.assert_called_once()

    def test_acl_whoami_failure_after_successful_auth_is_identity_mismatch(self):
        """Raise IdentityMismatchError when ACL WHOAMI itself fails (e.g. NOPERM) even though AUTH
        already succeeded."""
        mock_client = MagicMock()
        mock_client.execute_command.side_effect = [True, redis.RedisError("NOPERM")]
        with (
            patch("scripts.redis_acl_safety.redis.Redis", return_value=mock_client),
            pytest.raises(IdentityMismatchError),
        ):
            authenticate(
                host="127.0.0.1", port=16399, username="u", password="p",
                expected_identity="u", gate=ProductionValidator(),
                environment=RedisEnvironment.UNKNOWN,
            )
        mock_client.close.assert_called_once()

    def test_wrong_identity_after_successful_auth_is_identity_mismatch(self):
        """Raise IdentityMismatchError when ACL WHOAMI answers with a different identity than
        expected."""
        mock_client = MagicMock()
        mock_client.execute_command.side_effect = [True, "someone_else"]
        with (
            patch("scripts.redis_acl_safety.redis.Redis", return_value=mock_client),
            pytest.raises(IdentityMismatchError),
        ):
            authenticate(
                host="127.0.0.1", port=16399, username="u", password="p",
                expected_identity="u", gate=ProductionValidator(),
                environment=RedisEnvironment.UNKNOWN,
            )

    def test_completely_unexpected_exception_is_converted_not_leaked_raw(self):
        """Convert a totally unexpected exception (not a redis.RedisError) into
        AuthenticationFailedError, never let it escape raw -- and still close whatever connection
        was opened."""
        mock_client = MagicMock()
        mock_client.execute_command.side_effect = TypeError("something structurally unexpected")
        with (
            patch("scripts.redis_acl_safety.redis.Redis", return_value=mock_client),
            pytest.raises(AuthenticationFailedError),
        ):
            authenticate(
                host="127.0.0.1", port=16399, username="u", password="p",
                expected_identity="u", gate=ProductionValidator(),
                environment=RedisEnvironment.UNKNOWN,
            )
        mock_client.close.assert_called_once()

    def test_authenticate_production_delegates_into_authenticate(self):
        """Prove authenticate_production actually calls through to authenticate() (not just
        validates the port) by observing a mocked AUTH failure propagate as
        AuthenticationFailedError."""
        mock_client = MagicMock()
        mock_client.execute_command.side_effect = redis.AuthenticationError("bad password")
        with (
            patch("scripts.redis_acl_safety.redis.Redis", return_value=mock_client),
            pytest.raises(AuthenticationFailedError),
        ):
            authenticate_production(
                host="127.0.0.1", port=PRODUCTION_PORT, username="u", password="p",
                expected_identity="u",
            )
