"""Per-producer audit-event verification keys.

Every producer so far signs `audit:events` entries with a key derived from
the platform JWT_SECRET (audit/signing.py, AuditConfig.EVENT_SIGNING_SECRET).
JWT_SECRET also signs access tokens (HS256), so a producer that runs outside
the platform's own services -- the OmniBioAI MCP server, on a user's machine
-- must not be given it: whoever holds it can mint tokens for any user.

A *registered producer* instead has its own verification key, read from a
mode-600 file, and its events are verified with that key ONLY:

    XADD audit:events * data <json> sig v1:<hmac> producer mcp

`sig` is the unchanged v1 construction (audit/signing.py), just keyed with
the producer's own secret instead of JWT_SECRET.

An entry is routed to a registered producer when it declares one in the
`producer` stream field, OR when its `service` is one the producer owns, OR
when its `event_type` starts with one of the producer's prefixes ("mcp.").
The last two close the downgrade: an "omnibioai-mcp" or "mcp.tool_call"
event that omits `producer` (or uses a look-alike service name) is still
verified with the mcp key, never with JWT_SECRET, so holding JWT_SECRET is
not enough to forge MCP events. A producer may sign
only for its own services, so holding the mcp key is not enough to forge
another service's events either.

Anything that does not verify -- unknown producer, service not owned by it,
no signature, wrong signature, key file missing or unsafe -- is quarantined
(worker/main.py::quarantine_and_ack, failure_category "signature_rejected"),
not persisted as canonical evidence. Entries with neither a `producer` field
nor a registered service take the existing JWT_SECRET path, unchanged.

Keys are read once per worker process; restart the worker after creating or
rotating a key file. A key file that is missing, not a regular file, a
symlink, owned by another user, readable by group/others, shorter than 32
bytes, or equal to JWT_SECRET is treated as absent (and printed once).
"""
from __future__ import annotations

import hmac
import os
import stat
from dataclasses import dataclass

from audit.signing import verify_audit_event

PRODUCER_FIELD = "producer"
SIGNATURE_REJECTED = "signature_rejected"
MIN_KEY_BYTES = 32
MAX_KEY_BYTES = 4096


@dataclass(frozen=True)
class ProducerSpec:
    services: frozenset[str]
    key_file_env: str
    default_key_file: str
    # Event types reserved for this producer (prefix match), whatever the service.
    event_type_prefixes: tuple[str, ...] = ()


# Registered producers. Producers not listed here keep the JWT_SECRET path.
PRODUCERS: dict[str, ProducerSpec] = {
    "mcp": ProducerSpec(
        services=frozenset({"omnibioai-mcp"}),
        key_file_env="AUDIT_PRODUCER_KEY_FILE_MCP",
        default_key_file="/run/secrets/audit_producer_mcp_key",
        event_type_prefixes=("mcp.",),
    ),
}


def key_file_path(producer: str) -> str:
    spec = PRODUCERS[producer]
    return os.getenv(spec.key_file_env) or spec.default_key_file


def load_key_file(path: str, *, jwt_secret: str | None) -> tuple[str | None, str | None]:
    """(key, None) or (None, reason). Never raises; the reason never contains key material."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None, "missing"
    except OSError:
        return None, "unreadable"
    if stat.S_ISLNK(st.st_mode):
        return None, "symlink"
    if not stat.S_ISREG(st.st_mode):
        return None, "not_a_regular_file"
    if st.st_uid != os.geteuid():
        return None, "wrong_owner"
    if st.st_mode & 0o077:
        return None, "mode_not_600"
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            if (os.fstat(fd).st_ino, os.fstat(fd).st_dev) != (st.st_ino, st.st_dev):
                return None, "changed_while_reading"
            raw = os.read(fd, MAX_KEY_BYTES + 1)
        finally:
            os.close(fd)
    except OSError:
        return None, "unreadable"
    if len(raw) > MAX_KEY_BYTES:
        return None, "too_large"
    try:
        key = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None, "not_text"
    if len(key.encode()) < MIN_KEY_BYTES:
        return None, "too_short"
    if jwt_secret and hmac.compare_digest(key.encode(), jwt_secret.encode()):
        # The whole point: a JWT_SECRET holder must not be able to sign for this producer.
        return None, "equals_jwt_secret"
    return key, None


class ProducerKeys:
    """Lazily loaded, process-lifetime cache of registered producers' keys."""

    def __init__(self, jwt_secret: str | None):
        self._jwt_secret = jwt_secret
        self._keys: dict[str, str | None] = {}

    def get(self, producer: str) -> str | None:
        if producer not in self._keys:
            path = key_file_path(producer)
            key, reason = load_key_file(path, jwt_secret=self._jwt_secret)
            if key is None:
                print(
                    f"[WORKER] audit producer key for {producer!r} unavailable ({reason}) at "
                    f"{path}; its events will be quarantined until the worker restarts with a "
                    f"valid key"
                )
            self._keys[producer] = key
        return self._keys[producer]


def producer_for(fields: dict, service: str | None, event_type: str | None = None) -> str | None:
    """The producer an entry must be verified as, or None for the legacy JWT_SECRET path.

    A declared but unregistered producer is returned as is (it is then quarantined).
    """
    declared = fields.get(PRODUCER_FIELD)
    if declared is not None:
        return declared if isinstance(declared, str) else repr(type(declared))
    for name, spec in PRODUCERS.items():
        if service in spec.services:
            return name
        if spec.event_type_prefixes and isinstance(event_type, str) and event_type.startswith(
            spec.event_type_prefixes
        ):
            return name
    return None


def preload(keys: ProducerKeys) -> None:
    """Load every registered producer's key now, so a missing one is reported at startup."""
    for name in PRODUCERS:
        if keys.get(name) is not None:
            print(f"[WORKER] audit producer key for {name!r} loaded from {key_file_path(name)}")


def verify_producer_event(
    producer: str, service: str, signature: str | None, data: str, keys: ProducerKeys
) -> str | None:
    """None if the entry verifies under the producer's own key, else a short rejection reason."""
    spec = PRODUCERS.get(producer)
    if spec is None:
        return "UnknownProducer"
    if service not in spec.services:
        return "ServiceNotOwnedByProducer"
    key = keys.get(producer)
    if key is None:
        return "ProducerKeyUnavailable"
    if not signature:
        return "Unsigned"
    if not verify_audit_event(service, data, signature, key):
        return "SignatureInvalid"
    return None
