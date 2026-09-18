"""Incident (2026-09-16) regression: worker/main.py's NOGROUP handling.

audit:events and its audit-workers consumer group were destructively
deleted in production. The worker's only response was a continuous,
un-alerted NOGROUP retry loop -- invisible to anyone not actively
tailing container logs, and with no backoff (spinning as fast as
exceptions could be thrown and caught).

Covers, against a mocked StreamReader (see test_worker_quarantine_
integration.py / test_worker_pel_recovery_integration.py for the real-
Redis proof that ensure_group()'s own BUSYGROUP tolerance actually
holds against a live server):

- a NOGROUP condition always emits a critical alert, never crashes;
- auto-recreation is OFF by default (the safe default, see
  AuditConfig.WORKER_AUTO_RECREATE_STREAM_ON_NOGROUP's own docstring);
- when explicitly opted in, recreation is attempted, is bounded (rate-
  limited, not attempted on every single failure), tolerates an
  existing group (BUSYGROUP) without touching it, and lets the loop
  continue consuming afterward;
- a backoff is applied specifically on this condition, so the loop
  does not spin tightly.

IMPORTANT: every test that calls worker.run() MUST patch
"worker.main.StreamReader" to return the mocked reader -- run() always
constructs its own StreamReader() internally (see worker/main.py) and
never accepts one as a parameter. Omitting this patch was caught
during this file's own development: it silently let run() connect to
a real, unrelated, pre-existing Redis instance on this host's default
port 6379 (not this project's own Docker Compose stack, which
publishes Redis on a different port) and process 20 of its real
entries. No evidence of any resulting write to the real
omnibioai_audit.audit_events table was found; the bug was in this test
file, not any application code. Every test below patches StreamReader
for exactly this reason -- do not remove it.

Developer: Manish Kumar <manish@omnibioai.org>
"""
from unittest.mock import MagicMock, patch

import pytest

import worker.main as worker
from audit.config import AuditConfig


@pytest.fixture(autouse=True)
def _reset_recreate_ratelimit_and_alert_dedup():
    """Both the recreate-attempt rate limiter (module-level in
    worker.main) and emit_security_alert()'s own dedup window are shared
    mutable state across tests -- reset both so tests don't leak into
    each other."""
    from audit.security_alerts import _reset_dedup_state_for_tests

    worker._last_nogroup_recreate_attempt = 0.0
    _reset_dedup_state_for_tests()
    yield
    worker._last_nogroup_recreate_attempt = 0.0
    _reset_dedup_state_for_tests()


def _nogroup_error():
    """Build a NOGROUP exception shaped like a real Redis consumer-group-missing error."""
    return Exception("NOGROUP No such key 'audit:events' or consumer group 'audit-workers'")


# ---------------------------------------------------------------------------
# Detection + alerting (always on, regardless of the recreate opt-in)
# ---------------------------------------------------------------------------

def test_read_group_nogroup_emits_critical_alert(monkeypatch):
    """Fire a critical audit_stream_or_group_missing alert on the audit-worker component when
    read_group raises NOGROUP."""
    monkeypatch.setattr(AuditConfig, "WORKER_AUTO_RECREATE_STREAM_ON_NOGROUP", False)
    reader = MagicMock()
    reader.read_group.side_effect = [_nogroup_error(), []]
    reader.claim_stale.return_value = ([], [])

    calls = []
    with patch("worker.main.StreamReader", return_value=reader), \
         patch("worker.main.emit_security_alert", side_effect=lambda **kw: calls.append(kw)), \
         patch("worker.main.time.sleep"):
        worker.run(max_iterations=2)  # must not raise

    conditions = [c["condition"] for c in calls]
    assert "audit_stream_or_group_missing" in conditions
    fired = next(c for c in calls if c["condition"] == "audit_stream_or_group_missing")
    assert fired["severity"] == "critical"
    assert fired["component"] == "audit-worker"


def test_sweep_pending_nogroup_also_emits_alert():
    """Fire the audit_stream_or_group_missing alert when claim_stale raises NOGROUP too."""
    reader = MagicMock()
    reader.claim_stale.side_effect = _nogroup_error()

    calls = []
    with patch("worker.main.emit_security_alert", side_effect=lambda **kw: calls.append(kw)):
        worker.sweep_pending(reader)  # must not raise; sweep_pending takes reader directly, no StreamReader patch needed

    assert any(c["condition"] == "audit_stream_or_group_missing" for c in calls)


def test_non_nogroup_error_does_not_trigger_nogroup_handling(monkeypatch):
    """A generic connection error (not NOGROUP) must not be mistaken for
    it -- no recreate attempt, no NOGROUP-specific alert, matching the
    pre-existing print-and-continue behavior exactly."""
    monkeypatch.setattr(AuditConfig, "WORKER_AUTO_RECREATE_STREAM_ON_NOGROUP", True)
    reader = MagicMock()
    reader.read_group.side_effect = [Exception("connection reset by peer"), []]
    reader.claim_stale.return_value = ([], [])

    with patch("worker.main.StreamReader", return_value=reader), \
         patch("worker.main.emit_security_alert") as mock_emit, \
         patch("worker.main.time.sleep") as mock_sleep:
        worker.run(max_iterations=2)

    mock_emit.assert_not_called()
    mock_sleep.assert_not_called()
    reader.ensure_group.assert_called_once()  # only run()'s own startup call


# ---------------------------------------------------------------------------
# Backoff -- "do not enter a tight loop"
# ---------------------------------------------------------------------------

def test_nogroup_on_read_group_applies_backoff(monkeypatch):
    """Sleep for the configured backoff duration after a NOGROUP error on read_group."""
    monkeypatch.setattr(AuditConfig, "WORKER_AUTO_RECREATE_STREAM_ON_NOGROUP", False)
    monkeypatch.setattr(AuditConfig, "WORKER_NOGROUP_RETRY_BACKOFF_SECONDS", 2.0)
    reader = MagicMock()
    reader.read_group.side_effect = [_nogroup_error(), []]
    reader.claim_stale.return_value = ([], [])

    with patch("worker.main.StreamReader", return_value=reader), \
         patch("worker.main.emit_security_alert"), \
         patch("worker.main.time.sleep") as mock_sleep:
        worker.run(max_iterations=2)

    mock_sleep.assert_called_once_with(2.0)


def test_idle_timeout_path_never_sleeps_the_nogroup_backoff():
    """The pre-existing, unrelated idle-stream RedisTimeoutError path
    must remain completely unaffected by this change -- no new sleep
    introduced there."""
    from redis.exceptions import TimeoutError as RedisTimeoutError

    reader = MagicMock()
    reader.read_group.side_effect = [RedisTimeoutError("timeout"), []]
    reader.claim_stale.return_value = ([], [])

    with patch("worker.main.StreamReader", return_value=reader), \
         patch("worker.main.time.sleep") as mock_sleep:
        worker.run(max_iterations=2)

    mock_sleep.assert_not_called()


# ---------------------------------------------------------------------------
# Opt-in recreation: bounded, BUSYGROUP-tolerant, never touches an
# existing group, lets consumption continue afterward.
# ---------------------------------------------------------------------------

def test_recreation_disabled_by_default_does_not_call_ensure_group_again(monkeypatch):
    """Call ensure_group only once, at startup, when auto-recreation is disabled."""
    monkeypatch.setattr(AuditConfig, "WORKER_AUTO_RECREATE_STREAM_ON_NOGROUP", False)
    reader = MagicMock()
    reader.read_group.side_effect = [_nogroup_error(), []]
    reader.claim_stale.return_value = ([], [])

    with patch("worker.main.StreamReader", return_value=reader), \
         patch("worker.main.emit_security_alert"), patch("worker.main.time.sleep"):
        worker.run(max_iterations=2)

    reader.ensure_group.assert_called_once()  # only run()'s own startup call, no recovery attempt


def test_recreation_enabled_attempts_ensure_group_on_nogroup(monkeypatch):
    """Call ensure_group a second time and fire a recovered alert when auto-recreation is enabled."""
    monkeypatch.setattr(AuditConfig, "WORKER_AUTO_RECREATE_STREAM_ON_NOGROUP", True)
    reader = MagicMock()
    reader.read_group.side_effect = [_nogroup_error(), []]
    reader.claim_stale.return_value = ([], [])

    with patch("worker.main.StreamReader", return_value=reader), \
         patch("worker.main.emit_security_alert") as mock_emit, patch("worker.main.time.sleep"):
        worker.run(max_iterations=2)

    # once at startup (run()'s own call) + once from the NOGROUP handler
    assert reader.ensure_group.call_count == 2
    conditions = [call.kwargs.get("condition") for call in mock_emit.call_args_list]
    assert "audit_stream_or_group_missing_recovered" in conditions


def test_recreation_tolerates_busygroup_without_raising(monkeypatch):
    """Concurrent BUSYGROUP: another worker already recreated the group.
    ensure_group() itself already swallows BUSYGROUP (see
    consumers/stream_reader.py) -- this proves the NOGROUP handler
    surfaces that success cleanly rather than treating a BUSYGROUP-
    tolerant no-op as a failure."""
    monkeypatch.setattr(AuditConfig, "WORKER_AUTO_RECREATE_STREAM_ON_NOGROUP", True)
    reader = MagicMock()
    reader.read_group.side_effect = [_nogroup_error(), []]
    reader.claim_stale.return_value = ([], [])
    # ensure_group() itself never raises for BUSYGROUP (that's its own
    # existing contract) -- simulate that by simply not raising here.

    with patch("worker.main.StreamReader", return_value=reader), \
         patch("worker.main.emit_security_alert") as mock_emit, patch("worker.main.time.sleep"):
        worker.run(max_iterations=2)  # must not raise

    assert any(
        call.kwargs.get("condition") == "audit_stream_or_group_missing_recovered"
        for call in mock_emit.call_args_list
    )


def test_recreation_attempt_is_rate_limited_not_every_failure(monkeypatch):
    """Bounded: repeated NOGROUP failures in quick succession must only
    attempt ensure_group() once per WORKER_NOGROUP_RETRY_BACKOFF_SECONDS,
    not on every single failed read."""
    monkeypatch.setattr(AuditConfig, "WORKER_AUTO_RECREATE_STREAM_ON_NOGROUP", True)
    monkeypatch.setattr(AuditConfig, "WORKER_NOGROUP_RETRY_BACKOFF_SECONDS", 9999.0)
    reader = MagicMock()
    reader.read_group.side_effect = [_nogroup_error(), _nogroup_error(), []]
    reader.claim_stale.return_value = ([], [])

    with patch("worker.main.StreamReader", return_value=reader), \
         patch("worker.main.emit_security_alert"), patch("worker.main.time.sleep"):
        worker.run(max_iterations=3)

    # one from run()'s own startup, and at most one more recreate attempt
    # across both NOGROUP failures (the second is rate-limited away)
    assert reader.ensure_group.call_count == 2


def test_recreate_failure_does_not_crash_worker(monkeypatch):
    """Keep the worker running instead of crashing when the recreate attempt itself fails."""
    monkeypatch.setattr(AuditConfig, "WORKER_AUTO_RECREATE_STREAM_ON_NOGROUP", True)
    reader = MagicMock()
    reader.read_group.side_effect = [_nogroup_error(), []]
    reader.claim_stale.return_value = ([], [])
    # First ensure_group() call is run()'s own startup call (succeeds);
    # the second is the NOGROUP handler's recovery attempt (fails).
    reader.ensure_group.side_effect = [None, Exception("still unreachable")]

    with patch("worker.main.StreamReader", return_value=reader), \
         patch("worker.main.emit_security_alert"), patch("worker.main.time.sleep"):
        worker.run(max_iterations=2)  # must not raise


def test_recovery_continues_consumption_on_next_iteration(monkeypatch):
    """After a NOGROUP-triggered recreate attempt, the very next
    read_group() call succeeding and returning a real message must still
    be processed normally -- recovery isn't just "stop crashing," it's
    "keep working.\""""
    monkeypatch.setattr(AuditConfig, "WORKER_AUTO_RECREATE_STREAM_ON_NOGROUP", True)
    reader = MagicMock()
    reader.read_group.side_effect = [
        _nogroup_error(),
        [(AuditConfig.STREAM_NAME, [("1-0", {"data": "some-payload"})])],
    ]
    reader.claim_stale.return_value = ([], [])

    with patch("worker.main.StreamReader", return_value=reader), \
         patch("worker.main.emit_security_alert"), patch("worker.main.time.sleep"), \
         patch("worker.main.handle_message") as mock_handle:
        worker.run(max_iterations=2)

    mock_handle.assert_called_once_with(reader, "1-0", {"data": "some-payload"})


def test_existing_group_and_cursor_are_never_touched_by_recovery(monkeypatch):
    """Structural guarantee, not just behavioral: the NOGROUP handler
    only ever calls ensure_group() (XGROUP CREATE ... MKSTREAM,
    BUSYGROUP-tolerant) -- never XGROUP SETID, XGROUP DESTROY, or any
    other call that could reset or remove an existing group's delivery
    cursor. Proven by asserting no such method is ever invoked on the
    reader."""
    monkeypatch.setattr(AuditConfig, "WORKER_AUTO_RECREATE_STREAM_ON_NOGROUP", True)
    reader = MagicMock()
    reader.read_group.side_effect = [_nogroup_error(), []]
    reader.claim_stale.return_value = ([], [])

    with patch("worker.main.StreamReader", return_value=reader), \
         patch("worker.main.emit_security_alert"), patch("worker.main.time.sleep"):
        worker.run(max_iterations=2)

    called_names = {call[0] for call in reader.method_calls}
    assert "xgroup_setid" not in called_names
    assert "xgroup_destroy" not in called_names
    assert called_names <= {"ensure_group", "read_group", "claim_stale"}
