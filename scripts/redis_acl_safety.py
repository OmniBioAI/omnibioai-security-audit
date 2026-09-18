#!/usr/bin/env python3
"""P1-5 incident remediation.

On 2026-09-18, a production Redis FLUSHALL was executed during ad hoc
ACL negative testing of the redis-exporter monitoring identity, because:

  1. Redis's `default` user was enabled with `nopass`.
  2. A connection opened to production Redis was therefore already
     authenticated as `default` the instant it connected -- before any
     AUTH was ever attempted.
  3. An explicit `AUTH redis_monitoring <wrong password>` failed.
  4. The failed AUTH did NOT deauthenticate the connection -- Redis
     left it exactly as it was: authenticated as the already-logged-in
     `default` user.
  5. Subsequent commands issued on that same connection, including
     FLUSHALL, therefore executed with default's unrestricted +@all
     permissions instead of failing.

This module exists to make that entire failure class structurally
impossible for any caller that uses it, rather than relying on
operator discipline the next time someone needs to validate a Redis
ACL identity:

  - `RedisEnvironment` is a closed three-way classification
    (DISPOSABLE / PRODUCTION / UNKNOWN). UNKNOWN is treated at least as
    strictly as PRODUCTION everywhere below -- there is no code path
    that relaxes any check merely because classification evidence is
    absent. Disposable status is never inferred from a hostname,
    port difference, container name, or an unset/empty environment
    variable; it requires a `DisposableAttestation` that this module
    independently re-verifies live against the target instance (a
    fresh nonce round-trip plus a hard rejection of this
    architecture's known production-adjacent port), mirroring the
    existing `tests/_redis_integration_guard.py` pattern used
    elsewhere in this repo for exactly the same class of mistake.
  - Every authenticated session is built on a brand-new connection
    (never a reused/pooled one that might already be authenticated as
    someone else). `authenticate()` sends AUTH as the very first
    command on that connection; on ANY failure the connection is
    closed immediately and unconditionally, before a second command
    can ever reach the wire -- see `authenticate()`'s own test
    coverage for the exact incident sequence reproduced end to end.
  - After AUTH succeeds, the session is unusable until `ACL WHOAMI`
    has confirmed the *actual* authenticated identity equals the
    identity the caller asked for. A mismatch is a hard failure, never
    a warning.
  - Every command a caller wants to run passes through exactly one
    gate (`CommandGate.authorize`) before it reaches the wire.
    `ProductionValidator` enforces a narrow allowlist; disposable
    callers get `DisposableValidator` (allowlist-free, but a
    hard-denylist for the always-dangerous administrative command
    family still applies) or, for the one legitimate case where a test
    must prove Redis's own ACL denies a dangerous command,
    `DisposableNegativeTestGate` -- the only gate that passes
    dangerous commands through, and the only gate that requires a
    freshly-reverified `DisposableAttestation` to even construct.
  - `AuthenticatedSession` never exposes the underlying `redis.Redis`
    client through any public method or attribute -- "get the raw
    client and do whatever you want" is exactly the escape hatch that
    would defeat every guarantee above. (Python has no true private
    attributes; see this module's own tests and the accompanying
    report for the honest limit of what "no bypass" means here.)

Nothing in this module ever prints, logs, or includes in an exception
message a password, a credential-bearing URL, a JWT, or an ACL hash --
see `RedisSafetyError` and `_safe_repr_command`.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Sequence
from urllib.parse import urlsplit

import redis

# This architecture's shared, production-adjacent Redis port (matches
# tests/_redis_integration_guard.py's FORBIDDEN_PORT convention exactly --
# kept as a plain module constant here rather than imported from there,
# since that module is pytest-only and this one is not).
PRODUCTION_PORT = 6380


# ---------------------------------------------------------------------------
# Errors -- never include secret material in a message.
# ---------------------------------------------------------------------------


class RedisSafetyError(RuntimeError):
    """Base class for every error this module raises. Messages may
    freely include: environment classification, expected/actual
    identity names, command category, and reason. They must never
    include a password, a credential-bearing URL, a JWT, or an ACL
    hash."""


class EnvironmentClassificationError(RedisSafetyError):
    """A target could not be positively proven DISPOSABLE (or a
    disposable-only construct was asked to trust a target that isn't
    one)."""


class AuthenticationFailedError(RedisSafetyError):
    """AUTH did not unambiguously succeed. The connection that produced
    this error has already been closed by the time this is raised --
    see `authenticate()`."""


class IdentityMismatchError(RedisSafetyError):
    """`ACL WHOAMI`'s answer did not exactly equal the identity the
    caller asserted before issuing it."""


class ProhibitedCommandError(RedisSafetyError):
    """A caller asked a `CommandGate` to run a command that its active
    policy does not permit."""


class DangerousCommandError(ProhibitedCommandError):
    """The specific case of `ProhibitedCommandError` for a command on
    the hard, environment-independent dangerous-command denylist."""


# ---------------------------------------------------------------------------
# Environment classification -- disposable status is proven, never inferred.
# ---------------------------------------------------------------------------


class RedisEnvironment:
    """Closed three-way classification. Deliberately not an IntEnum/str
    subclass a caller could accidentally coerce from an arbitrary
    string -- these three instances are the only values that exist."""

    DISPOSABLE = None  # assigned below
    PRODUCTION = None
    UNKNOWN = None

    def __init__(self, name: str):
        self._name = name

    def __repr__(self) -> str:
        return f"RedisEnvironment.{self._name}"

    def __eq__(self, other):
        return self is other

    def __hash__(self):
        return id(self)


RedisEnvironment.DISPOSABLE = RedisEnvironment("DISPOSABLE")
RedisEnvironment.PRODUCTION = RedisEnvironment("PRODUCTION")
RedisEnvironment.UNKNOWN = RedisEnvironment("UNKNOWN")


@dataclass(frozen=True)
class DisposableAttestation:
    """Positive, independently-reverifiable proof that a specific
    Redis endpoint is disposable test infrastructure.

    Every field is required, with no default -- there is no way to
    construct one of these by omission. `nonce_value` must already
    have been written to `nonce_key` on the target instance by the
    caller's own disposable-Redis bootstrap code (using whatever
    access that caller's disposable instance grants -- this module
    never writes it). `classify_environment` independently reads it
    back; a caller that has not actually written a matching key to the
    actual target instance cannot manufacture a passing attestation by
    editing Python values alone.
    """

    host: str
    port: int
    nonce_key: str
    nonce_value: str

    def __post_init__(self):
        if self.port == PRODUCTION_PORT:
            raise EnvironmentClassificationError(
                f"port {self.port} is this architecture's shared, "
                "production-adjacent Redis port -- refusing to attest "
                "any endpoint on it as disposable, regardless of other "
                "evidence"
            )
        if not self.host:
            raise EnvironmentClassificationError("attestation requires a non-empty host")
        if not self.nonce_key or not self.nonce_value:
            raise EnvironmentClassificationError(
                "attestation requires a non-empty nonce_key/nonce_value pair "
                "-- an empty nonce proves nothing"
            )

    @staticmethod
    def generate_nonce() -> str:
        """Convenience for callers: a fresh, unguessable nonce value.
        Still the caller's responsibility to actually write it to the
        disposable instance before constructing the attestation."""
        return secrets.token_hex(16)


def classify_environment(
    *, host: str, port: int, attestation: DisposableAttestation | None
) -> RedisEnvironment:
    """Returns DISPOSABLE only after independently re-verifying the
    attestation against the live instance. Returns UNKNOWN whenever no
    attestation was supplied -- there is no fallback path that infers
    DISPOSABLE from a hostname, a port merely being *different* from
    PRODUCTION_PORT, a container name, an empty database, or an unset
    environment variable alone."""
    if port == PRODUCTION_PORT:
        return RedisEnvironment.PRODUCTION
    if attestation is None:
        return RedisEnvironment.UNKNOWN
    if attestation.host != host or attestation.port != port:
        raise EnvironmentClassificationError(
            "attestation host/port do not match the target host/port -- "
            "refusing to trust an attestation for a different endpoint "
            "than the one being classified"
        )
    probe = None
    try:
        # Construction itself may connect eagerly (redis-py does this
        # when single_connection_client=True), so it must be inside
        # this same try/except -- a connection failure at construction
        # time must fail closed exactly like a failure during the
        # command that follows it.
        probe = redis.Redis(
            host=host, port=port, socket_timeout=2, socket_connect_timeout=2,
            decode_responses=True, single_connection_client=True,
        )
        got = probe.execute_command("GET", attestation.nonce_key)
    except redis.RedisError as exc:
        raise EnvironmentClassificationError(
            f"could not independently verify disposable attestation: probe "
            f"connection/command failed ({type(exc).__name__})"
        ) from None
    finally:
        if probe is not None:
            try:
                probe.close()
            except Exception:  # noqa: BLE001 -- best-effort cleanup only
                pass
    if got != attestation.nonce_value:
        raise EnvironmentClassificationError(
            "disposable attestation nonce did not match the value actually "
            "stored on the live instance -- refusing to classify as "
            "DISPOSABLE"
        )
    return RedisEnvironment.DISPOSABLE


# ---------------------------------------------------------------------------
# Command classification -- allowlist-first, denylist as defense in depth.
# ---------------------------------------------------------------------------

# Commands/subcommands that are unconditionally prohibited through this
# module's gates, regardless of environment -- including on disposable
# Redis, via every gate except DisposableNegativeTestGate (whose entire,
# sole purpose is proving Redis's own ACL denies these to a restricted
# identity; see its own docstring).
DANGEROUS_COMMANDS: frozenset[tuple[str, ...]] = frozenset({
    ("FLUSHALL",),
    ("FLUSHDB",),
    ("SHUTDOWN",),
    ("DEBUG",),
    ("CONFIG", "SET"),
    ("ACL", "SETUSER"),
    ("ACL", "DELUSER"),
    ("ACL", "LOAD"),
    ("ACL", "SAVE"),
    ("ACL", "LOG"),
    ("MODULE", "LOAD"),
    ("MODULE", "UNLOAD"),
    ("MIGRATE",),
    ("RESTORE",),
    ("RESTORE-ASKING",),
    ("SWAPDB",),
    ("REPLICAOF",),
    ("SLAVEOF",),
})

# The minimum set of operations needed to demonstrate connectivity and
# harmless read-only capability against PRODUCTION Redis. Deliberately
# small: this module's own job is to prove "this identity authenticates
# and is who we expect", not to exercise application-level behavior --
# that belongs in each service's own tests against its own scoped
# identity (see e.g. the redis_lims_cache/redis_audit_health_reader
# validation performed during the P1-5 migrations, which used the real
# application client code, not this harness).
PRODUCTION_ALLOWED_COMMANDS: frozenset[tuple[str, ...]] = frozenset({
    ("PING",),
    ("ACL", "WHOAMI"),
    ("INFO",),
})

# Commands whose ACL representation in this codebase's generated
# users.acl is a two-token "COMMAND SUBCOMMAND" form (see
# ~/omnibioai-redis-backups/bin/generate_production_acl.sh) -- used to
# decide whether to normalize a caller's args to one or two tokens.
_KNOWN_SUBCOMMAND_PREFIXES = frozenset({
    "ACL", "CONFIG", "CLIENT", "XGROUP", "XINFO", "SCRIPT", "FUNCTION",
    "MODULE", "COMMAND", "CLUSTER", "LATENCY", "SLOWLOG", "MEMORY",
    "OBJECT", "PUBSUB",
})


def _normalize_command(args: Sequence) -> tuple[str, ...]:
    """Case-insensitive, bytes-or-str-insensitive, whitespace-insensitive
    normalization to a canonical (COMMAND,) or (COMMAND, SUBCOMMAND)
    tuple. This is the single place command identity is decided --
    every gate calls this, so a bypass would have to avoid this
    function entirely, not merely pass a differently-cased string
    through it."""
    if not args:
        raise ProhibitedCommandError("refusing to authorize an empty command")
    parts = []
    for a in args:
        if isinstance(a, bytes):
            a = a.decode("utf-8", errors="replace")
        parts.append(str(a).strip().upper())
    if not parts or not parts[0]:
        raise ProhibitedCommandError("refusing to authorize an empty command")
    if len(parts) >= 2 and parts[0] in _KNOWN_SUBCOMMAND_PREFIXES:
        return (parts[0], parts[1])
    return (parts[0],)


def _safe_repr_command(args: Sequence) -> str:
    """A command's name/subcommand only, for use in error messages --
    never the full argv, which could contain a value being written
    (e.g. a credential) even for an otherwise-harmless-looking
    command."""
    try:
        cmd = _normalize_command(args)
    except ProhibitedCommandError:
        return "<empty>"
    return " ".join(cmd)


# ---------------------------------------------------------------------------
# Command gates.
# ---------------------------------------------------------------------------


class CommandGate:
    """Base class. Every concrete gate must implement `authorize`,
    which either returns None (permitted) or raises a
    `ProhibitedCommandError` subclass. No subclass may add a method
    that lets a caller run a command without going through
    `authorize` first."""

    def authorize(self, args: Sequence) -> None:  # pragma: no cover - abstract
        raise NotImplementedError


class ProductionValidator(CommandGate):
    """The only gate usable for PRODUCTION or UNKNOWN environments.
    Allowlist-first: a command must be explicitly on
    `PRODUCTION_ALLOWED_COMMANDS` to pass, and is additionally checked
    against `DANGEROUS_COMMANDS` first as defense in depth (redundant
    today, since the allowlist is already a strict subset of safe
    commands, but kept so a future accidental allowlist expansion
    still can't silently permit a dangerous command)."""

    def authorize(self, args: Sequence) -> None:
        cmd = _normalize_command(args)
        if cmd in DANGEROUS_COMMANDS:
            raise DangerousCommandError(
                f"command {' '.join(cmd)!r} is unconditionally prohibited "
                "in production validation"
            )
        if cmd not in PRODUCTION_ALLOWED_COMMANDS:
            raise ProhibitedCommandError(
                f"command {' '.join(cmd)!r} is not on the production "
                f"validation allowlist "
                f"{sorted(' '.join(c) for c in PRODUCTION_ALLOWED_COMMANDS)}"
            )


class DisposableValidator(CommandGate):
    """For ordinary (non-destructive-negative-test) validation against
    a proven-disposable target -- e.g. exercising the same
    authenticate()/assert-identity flow used in production, but against
    disposable Redis. Broad allow, EXCEPT the hard dangerous-command
    denylist still applies here too: this gate is not the sanctioned
    path for negative destructive tests -- see
    `DisposableNegativeTestGate` for that.

    Construction re-verifies disposability itself (via
    `classify_environment`) rather than trusting a `RedisEnvironment`
    value the caller might have computed incorrectly or reused stale."""

    def __init__(self, *, host: str, port: int, attestation: DisposableAttestation):
        environment = classify_environment(host=host, port=port, attestation=attestation)
        if environment is not RedisEnvironment.DISPOSABLE:
            raise EnvironmentClassificationError(
                "DisposableValidator requires a live-verified DISPOSABLE "
                "environment; construction refused"
            )
        self.environment = environment

    def authorize(self, args: Sequence) -> None:
        cmd = _normalize_command(args)
        if cmd in DANGEROUS_COMMANDS:
            raise DangerousCommandError(
                f"command {' '.join(cmd)!r} is on the hard denylist; use "
                "DisposableNegativeTestGate if a test specifically needs to "
                "prove Redis's own ACL denies this command to a restricted "
                "identity"
            )


class DisposableNegativeTestGate(CommandGate):
    """The ONLY gate that passes dangerous commands through to the
    wire. Exists solely so a negative test can prove that a restricted
    identity's own Redis ACL denies e.g. FLUSHALL, by actually sending
    FLUSHALL and observing Redis's NOPERM response -- never by this
    module silently agreeing not to send it.

    Structurally cannot be constructed for a non-disposable target:
    like `DisposableValidator`, construction re-runs
    `classify_environment` itself. There is no flag, kwarg, or
    subclass that widens this gate's reach to PRODUCTION or UNKNOWN --
    the only environment `classify_environment` will ever return
    besides DISPOSABLE is PRODUCTION or UNKNOWN, both of which raise
    here.
    """

    def __init__(self, *, host: str, port: int, attestation: DisposableAttestation):
        environment = classify_environment(host=host, port=port, attestation=attestation)
        if environment is not RedisEnvironment.DISPOSABLE:
            raise EnvironmentClassificationError(
                "DisposableNegativeTestGate requires a live-verified "
                "DISPOSABLE environment; construction refused"
            )
        self.environment = environment

    def authorize(self, args: Sequence) -> None:
        _normalize_command(args)  # validate shape only; everything permitted


# ---------------------------------------------------------------------------
# Authenticated sessions.
# ---------------------------------------------------------------------------


class AuthenticatedSession:
    """A single Redis connection that has just been proven to
    authenticate as exactly the identity the caller expected, paired
    with the `CommandGate` that authorizes every command sent on it.

    Deliberately exposes no method or attribute that returns the
    underlying `redis.Redis` client. This is a genuine API design
    choice, not a hard security boundary -- Python has no true private
    attributes, so code inside this same process that specifically
    reaches for `session._client` can still get at it. What this
    guarantees is that no *ordinary* caller path (including every
    other function in this module) ever needs or is given that
    access; see `test_redis_acl_safety.py::test_no_raw_client_escape_hatch`
    for exactly what is and is not enforced.
    """

    def __init__(self, *, environment: RedisEnvironment, gate: CommandGate, client: "redis.Redis"):
        self.environment = environment
        self._gate = gate
        self._client = client
        self._closed = False

    def run(self, *args: str):
        if self._closed:
            raise RedisSafetyError("cannot run a command on a closed session")
        self._gate.authorize(args)
        return self._client.execute_command(*args)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._client.close()
        except Exception:  # noqa: BLE001 -- best-effort cleanup only
            pass

    def __enter__(self) -> "AuthenticatedSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def authenticate(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    expected_identity: str,
    gate: CommandGate,
    environment: RedisEnvironment,
    socket_timeout: float = 3.0,
) -> AuthenticatedSession:
    """Opens a brand-new connection (never a reused/pooled one),
    attempts AUTH as the very first command on it, and -- this is the
    exact property the incident depended on NOT holding -- closes that
    connection unconditionally on ANY failure before returning control
    to the caller. There is no path through this function that leaves
    a caller holding a connection that failed AUTH but remains
    implicitly authenticated as whatever the server treats a fresh
    connection as (typically `default`).

    After AUTH succeeds, immediately asserts identity via `ACL WHOAMI`
    (itself passed through `gate.authorize`, so every gate's allowlist
    must include it -- `PRODUCTION_ALLOWED_COMMANDS` does). A mismatch
    is a hard `IdentityMismatchError`; there is no warning-only path.
    """
    client = None
    try:
        try:
            # Construction itself may connect eagerly (redis-py does
            # this when single_connection_client=True), so it must be
            # inside this same try/except -- an unreachable host must
            # fail closed exactly like an AUTH failure does, not leak
            # a raw redis.ConnectionError past this function.
            client = redis.Redis(
                host=host, port=port, socket_timeout=socket_timeout,
                socket_connect_timeout=socket_timeout, decode_responses=True,
                single_connection_client=True,
            )
            ok = client.execute_command("AUTH", username, password)
        except redis.AuthenticationError:
            raise AuthenticationFailedError(
                f"AUTH failed for expected identity {expected_identity!r}"
            ) from None
        except redis.RedisError as exc:
            raise AuthenticationFailedError(
                f"AUTH did not succeed for expected identity "
                f"{expected_identity!r}: {type(exc).__name__}"
            ) from None
        if ok is not True and ok != "OK":
            raise AuthenticationFailedError(
                f"AUTH returned an unexpected result for expected identity "
                f"{expected_identity!r}"
            )
        gate.authorize(("ACL", "WHOAMI"))
        try:
            actual = client.execute_command("ACL", "WHOAMI")
        except redis.RedisError as exc:
            raise IdentityMismatchError(
                f"could not confirm identity for expected {expected_identity!r}: "
                f"{type(exc).__name__}"
            ) from None
        if actual != expected_identity:
            raise IdentityMismatchError(
                f"expected identity {expected_identity!r}, ACL WHOAMI reported "
                f"{actual!r}"
            )
    except RedisSafetyError:
        if client is not None:
            client.close()
        raise
    except Exception as exc:  # noqa: BLE001 -- convert anything unexpected to a safety error, never leak it raw
        if client is not None:
            client.close()
        raise AuthenticationFailedError(
            f"unexpected error establishing identity for {expected_identity!r}: "
            f"{type(exc).__name__}"
        ) from exc
    return AuthenticatedSession(environment=environment, gate=gate, client=client)


def authenticate_production(
    *, host: str, port: int, username: str, password: str, expected_identity: str,
    socket_timeout: float = 3.0,
) -> AuthenticatedSession:
    """Convenience wrapper: production validation, always. Refuses to
    proceed if `port` is not this architecture's known production
    port, so a caller cannot accidentally point "production" validation
    at something else and get the narrow allowlist confused for a
    disposable-appropriate check."""
    if port != PRODUCTION_PORT:
        raise EnvironmentClassificationError(
            f"authenticate_production requires port {PRODUCTION_PORT}; got "
            f"{port}. Use authenticate() directly with an explicit gate for "
            "any other target."
        )
    return authenticate(
        host=host, port=port, username=username, password=password,
        expected_identity=expected_identity, gate=ProductionValidator(),
        environment=RedisEnvironment.PRODUCTION, socket_timeout=socket_timeout,
    )
