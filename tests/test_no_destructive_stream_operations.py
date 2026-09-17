"""Incident (2026-09-16) regression: a cleanup operation ran a
key-level DEL against the shared production `audit:events` stream after
an exact-match KEYS lookup, following an operator's response to a
worker crash loop. See worker/main.py::handle_message's docstring for
the crash-loop side of this incident and its fix.

This repository's own operational code was audited and found to
contain NO destructive Redis stream operation anywhere -- this file is
a pure regression guard ensuring that stays true, not a fix for
existing destructive code (none was found).

Scope, deliberately narrow: only OPERATIONAL source (scripts/, api/,
services/, consumers/, worker/, audit/, db/) is checked. Test fixtures
in tests/ legitimately create and tear down their OWN disposable,
per-run UUID-suffixed stream names (see test_worker_quarantine_
integration.py's TEST_STREAM convention) -- that is safe, expected,
and explicitly NOT what this guard prohibits.

The check is scoped to the `.redis.<method>(` attribute-access
convention this codebase uses everywhere a Redis client is actually
invoked (StreamReader.redis, reader.redis, etc.) -- not a blanket
`.delete(` ban, which would also flag legitimate, unrelated SQLAlchemy
row deletion (e.g. a future retention/cleanup script). A method that
only exists to delete/trim/flush Redis keys has no legitimate purpose
in this codebase's operational paths, so its mere presence is the
violation -- no attempt is made to reason about which specific key it
might target.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

OPERATIONAL_DIRS = ("scripts", "api", "services", "consumers", "worker", "audit", "db")

# Redis client method calls that can destroy stream/key data outright.
# `.redis.` is this codebase's one, consistent attribute name for an
# actual Redis client instance (see consumers/stream_reader.py); this
# avoids false positives against unrelated SQLAlchemy `.delete(...)`
# calls on ORM sessions/rows.
_DESTRUCTIVE_PATTERN = re.compile(
    r"\.redis\.(delete|unlink|flushdb|flushall|xtrim)\s*\(",
)
# Raw command-string forms of the same operations, plus KEYS (the exact
# lookup mechanism the incident used before its destructive DEL).
_RAW_COMMAND_PATTERN = re.compile(
    r"execute_command\s*\(\s*[\"'](DEL|UNLINK|FLUSHDB|FLUSHALL|XTRIM|KEYS)\b",
    re.IGNORECASE,
)
_KEYS_METHOD_PATTERN = re.compile(r"\.redis\.keys\s*\(")


def _operational_python_files():
    for dirname in OPERATIONAL_DIRS:
        directory = REPO_ROOT / dirname
        if not directory.is_dir():
            continue
        yield from directory.rglob("*.py")


def test_no_destructive_redis_operations_in_operational_code():
    violations = []
    for path in _operational_python_files():
        if "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in (_DESTRUCTIVE_PATTERN, _RAW_COMMAND_PATTERN, _KEYS_METHOD_PATTERN):
            for match in pattern.finditer(text):
                line_no = text.count("\n", 0, match.start()) + 1
                violations.append(f"{path.relative_to(REPO_ROOT)}:{line_no}: {match.group(0)!r}")

    assert not violations, (
        "Destructive Redis operation(s) found in operational code -- production "
        "audit-stream verification/cleanup must never DEL/UNLINK/FLUSHDB/FLUSHALL/"
        "XTRIM or use KEYS against the shared stream (2026-09-16 incident):\n"
        + "\n".join(violations)
    )


def test_guard_actually_detects_a_synthetic_violation(tmp_path):
    """The regex-based check above is only meaningful if it can actually
    catch something -- proven here against synthetic snippets, entirely
    independent of this repo's real source tree."""
    samples = [
        'self.redis.delete(AuditConfig.STREAM_NAME)',
        'reader.redis.flushall()',
        'client.redis.xtrim(stream, maxlen=0)',
        'r.execute_command("KEYS", "audit:*")',
        'reader.redis.keys("audit:*")',
    ]
    for sample in samples:
        found = (
            _DESTRUCTIVE_PATTERN.search(sample)
            or _RAW_COMMAND_PATTERN.search(sample)
            or _KEYS_METHOD_PATTERN.search(sample)
        )
        assert found, f"guard failed to detect a destructive pattern in: {sample!r}"


def test_guard_does_not_flag_legitimate_sqlalchemy_delete():
    """A future retention/cleanup script may legitimately call
    session.delete(row) against MySQL -- this must never be confused
    with a Redis-destructive call."""
    sample = "session.delete(record)\nconn.execute(text('DELETE FROM audit_legal_holds WHERE ...'))"
    assert not _DESTRUCTIVE_PATTERN.search(sample)
    assert not _RAW_COMMAND_PATTERN.search(sample)
    assert not _KEYS_METHOD_PATTERN.search(sample)


def test_guard_does_not_flag_legitimate_test_fixture_teardown():
    """Test fixtures tearing down their OWN disposable, UUID-suffixed
    test stream (never the literal audit:events) are explicitly allowed
    and must not be flagged by this operational-code-only scan -- proven
    here by confirming the scan is scoped to OPERATIONAL_DIRS, which
    excludes tests/ entirely."""
    assert "tests" not in OPERATIONAL_DIRS
