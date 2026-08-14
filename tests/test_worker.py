"""PR4.2 regression tests: worker/main.py -- the Redis Streams consumer-group
loop that reads audit:events, parses/persists each message, and only ACKs
after a successful DB write.

PR2 additions (bottom of file): integrity_status classification -- signed
valid/invalid events and unsigned (today's only real traffic shape) all
persist and ACK; only "invalid" gets the distinct observability print."""
import json
from unittest.mock import MagicMock, patch

import worker.main as worker
from audit.signing import sign_audit_event


def _raw(event_id="evt-1"):
    return json.dumps({
        "event_id": event_id,
        "timestamp": "2026-01-01T12:00:00",
        "service": "auth",
        "event_type": "auth_login",
        "decision": "success",
    })


# ---------------------------------------------------------------------------
# handle_message
# ---------------------------------------------------------------------------

def test_handle_message_persists_and_acks():
    reader = MagicMock()
    mock_sink_instance = MagicMock()
    mock_sink_instance.write.return_value = True

    with patch("worker.main.SessionLocal") as mock_session_local, \
         patch("worker.main.Sink", return_value=mock_sink_instance) as mock_sink_cls:
        mock_db = MagicMock()
        mock_session_local.return_value = mock_db

        result = worker.handle_message(reader, "1-0", {"data": _raw()})

    assert result is True
    mock_sink_cls.assert_called_once_with(mock_db)
    mock_sink_instance.write.assert_called_once()
    reader.ack.assert_called_once_with("1-0")
    mock_db.close.assert_called_once()


def test_handle_message_passes_full_event_payload_to_sink():
    reader = MagicMock()
    mock_sink_instance = MagicMock()

    with patch("worker.main.SessionLocal"), \
         patch("worker.main.Sink", return_value=mock_sink_instance):
        worker.handle_message(reader, "1-0", {"data": _raw(event_id="evt-full")})

    written = mock_sink_instance.write.call_args[0][0]
    assert written["event_id"] == "evt-full"
    assert written["service"] == "auth"


def test_handle_message_does_not_ack_on_parse_failure():
    reader = MagicMock()

    result = worker.handle_message(reader, "1-0", {"data": "not-json"})

    assert result is False
    reader.ack.assert_not_called()


def test_handle_message_does_not_ack_on_db_failure():
    reader = MagicMock()
    mock_sink_instance = MagicMock()
    mock_sink_instance.write.side_effect = Exception("db connection lost")

    with patch("worker.main.SessionLocal") as mock_session_local, \
         patch("worker.main.Sink", return_value=mock_sink_instance):
        mock_db = MagicMock()
        mock_session_local.return_value = mock_db

        result = worker.handle_message(reader, "1-0", {"data": _raw()})

    assert result is False
    reader.ack.assert_not_called()
    # session is still closed even on failure
    mock_db.close.assert_called_once()


def test_handle_message_retry_after_failure_then_succeeds():
    """Simulates a worker restart/retry: the same (unacked) message is
    handled again and this time persistence succeeds -- it must now ack."""
    reader = MagicMock()
    failing_sink = MagicMock()
    failing_sink.write.side_effect = Exception("transient db error")
    succeeding_sink = MagicMock()
    succeeding_sink.write.return_value = True

    with patch("worker.main.SessionLocal"), \
         patch("worker.main.Sink", side_effect=[failing_sink, succeeding_sink]):
        first = worker.handle_message(reader, "1-0", {"data": _raw()})
        second = worker.handle_message(reader, "1-0", {"data": _raw()})

    assert first is False
    assert second is True
    reader.ack.assert_called_once_with("1-0")


# ---------------------------------------------------------------------------
# run() -- consumer-group startup + loop
# ---------------------------------------------------------------------------

def test_run_creates_consumer_group_on_startup():
    mock_reader = MagicMock()
    mock_reader.read_group.return_value = []

    with patch("worker.main.StreamReader", return_value=mock_reader):
        worker.run(max_iterations=1)

    mock_reader.ensure_group.assert_called_once()


def test_run_processes_messages_from_read_group():
    mock_reader = MagicMock()
    mock_reader.read_group.return_value = [
        (worker.AuditConfig.STREAM_NAME, [("1-0", {"data": _raw("evt-a")})]),
    ]

    with patch("worker.main.StreamReader", return_value=mock_reader), \
         patch("worker.main.handle_message") as mock_handle:
        worker.run(max_iterations=1)

    mock_handle.assert_called_once_with(mock_reader, "1-0", {"data": _raw("evt-a")})


def test_run_stops_after_max_iterations():
    mock_reader = MagicMock()
    mock_reader.read_group.return_value = []

    with patch("worker.main.StreamReader", return_value=mock_reader):
        worker.run(max_iterations=3)

    assert mock_reader.read_group.call_count == 3


# ---------------------------------------------------------------------------
# run() -- PR-B0 follow-up: read_group() timeout/error handling
#
# Regression coverage for the crash loop found during PR-B0 runtime
# validation: run() previously had no exception handling around the
# blocking reader.read_group() call itself (only handle_message() did).
# redis-py's own socket-level read timeout can fire once an idle stream
# leaves the blocking XREADGROUP call sitting at its `block` (5000ms)
# boundary with nothing new to deliver -- expected, not a failure -- and
# that uncaught redis.exceptions.TimeoutError crashed the whole worker
# process every ~5s, with Docker's restart: on-failure just repeating the
# identical crash forever.
# ---------------------------------------------------------------------------

def test_run_continues_after_read_group_timeout():
    """The exact failure mode: a real redis.exceptions.TimeoutError from
    read_group() (not a generic Exception) must not terminate run() --
    it's treated as an empty read and the loop continues to the next
    iteration, proven here by reaching all 3 requested iterations."""
    from redis.exceptions import TimeoutError as RedisTimeoutError

    mock_reader = MagicMock()
    mock_reader.read_group.side_effect = RedisTimeoutError("Timeout reading from socket")

    with patch("worker.main.StreamReader", return_value=mock_reader):
        worker.run(max_iterations=3)  # must not raise

    assert mock_reader.read_group.call_count == 3


def test_run_processes_a_message_after_a_timeout():
    """A read timeout on one iteration must not prevent a real message
    from being processed -- and still acked via handle_message()'s
    existing, unmodified behavior -- on the next iteration."""
    from redis.exceptions import TimeoutError as RedisTimeoutError

    mock_reader = MagicMock()
    mock_reader.read_group.side_effect = [
        RedisTimeoutError("Timeout reading from socket"),
        [(worker.AuditConfig.STREAM_NAME, [("1-0", {"data": _raw("evt-after-timeout")})])],
    ]

    with patch("worker.main.StreamReader", return_value=mock_reader), \
         patch("worker.main.handle_message") as mock_handle:
        worker.run(max_iterations=2)

    mock_handle.assert_called_once_with(
        mock_reader, "1-0", {"data": _raw("evt-after-timeout")}
    )


def test_run_logs_but_survives_unexpected_read_group_exception(capsys):
    """A non-timeout Redis exception (e.g. a real connection drop) must
    also not crash the worker -- but unlike the expected-timeout case,
    it must be printed, matching the existing print-and-continue
    convention used by handle_message()/audit/logger.py, not silently
    swallowed."""
    from redis.exceptions import ConnectionError as RedisConnectionError

    mock_reader = MagicMock()
    mock_reader.read_group.side_effect = [
        RedisConnectionError("connection reset by peer"),
        [],
    ]

    with patch("worker.main.StreamReader", return_value=mock_reader):
        worker.run(max_iterations=2)  # must not raise

    captured = capsys.readouterr()
    assert "read_group failed" in captured.out
    assert "connection reset by peer" in captured.out


def test_run_does_not_swallow_keyboard_interrupt():
    """Clean shutdown must keep working: KeyboardInterrupt (Ctrl+C /
    SIGINT, per the __main__ block's own except KeyboardInterrupt:
    sys.exit(0)) is a BaseException, not an Exception, so the new
    `except Exception` added around read_group() must not catch it --
    it has to keep propagating out of run() exactly as before this
    fix."""
    mock_reader = MagicMock()
    mock_reader.read_group.side_effect = KeyboardInterrupt()

    with patch("worker.main.StreamReader", return_value=mock_reader):
        raised = False
        try:
            worker.run()
        except KeyboardInterrupt:
            raised = True

    assert raised is True


# ---------------------------------------------------------------------------
# PR2: integrity_status classification (consumers/processor.py::
# classify_event_integrity), wired into handle_message()
# ---------------------------------------------------------------------------

SECRET = "synthetic-worker-test-secret"


def _handle_with_status(fields, secret=SECRET):
    """Runs handle_message() with EVENT_SIGNING_SECRET fixed to a known
    synthetic value and SessionLocal/Sink mocked, returning
    (handle_result, integrity_status_written_to_sink)."""
    reader = MagicMock()
    mock_sink_instance = MagicMock()
    mock_sink_instance.write.return_value = True

    with patch("worker.main.SessionLocal") as mock_session_local, \
         patch("worker.main.Sink", return_value=mock_sink_instance), \
         patch.object(worker.AuditConfig, "EVENT_SIGNING_SECRET", secret):
        mock_session_local.return_value = MagicMock()
        result = worker.handle_message(reader, "1-0", fields)

    written = mock_sink_instance.write.call_args[0][0] if mock_sink_instance.write.called else None
    status = written["integrity_status"] if written else None
    return result, status, reader


def test_valid_signed_event_persists_as_valid_and_acks():
    raw = _raw(event_id="evt-valid")
    sig = sign_audit_event("auth", raw, SECRET)

    result, status, reader = _handle_with_status({"data": raw, "sig": sig})

    assert result is True
    assert status == "valid"
    reader.ack.assert_called_once_with("1-0")


def test_unsigned_event_persists_as_unsigned_and_acks():
    """Today's only real traffic shape -- no sig field at all."""
    raw = _raw(event_id="evt-unsigned")

    result, status, reader = _handle_with_status({"data": raw})

    assert result is True
    assert status == "unsigned"
    reader.ack.assert_called_once_with("1-0")


def test_invalid_signature_persists_as_invalid_and_acks():
    raw = _raw(event_id="evt-invalid")
    sig = sign_audit_event("auth", raw, "a-different-secret-entirely")

    result, status, reader = _handle_with_status({"data": raw, "sig": sig})

    assert result is True
    assert status == "invalid"
    reader.ack.assert_called_once_with("1-0")


def test_malformed_signature_persists_as_invalid_and_acks():
    raw = _raw(event_id="evt-malformed-sig")

    result, status, reader = _handle_with_status({"data": raw, "sig": "not-a-real-signature"})

    assert result is True
    assert status == "invalid"
    reader.ack.assert_called_once_with("1-0")


def test_invalid_signature_emits_distinct_observability_message(capsys):
    raw = _raw(event_id="evt-loud-invalid")
    sig = sign_audit_event("auth", raw, "wrong-secret")

    _handle_with_status({"data": raw, "sig": sig})

    captured = capsys.readouterr()
    assert "SIGNATURE INVALID" in captured.out
    assert "evt-loud-invalid" in captured.out


def test_valid_signature_does_not_emit_the_invalid_message(capsys):
    raw = _raw(event_id="evt-quiet-valid")
    sig = sign_audit_event("auth", raw, SECRET)

    _handle_with_status({"data": raw, "sig": sig})

    captured = capsys.readouterr()
    assert "SIGNATURE INVALID" not in captured.out


def test_unsigned_event_does_not_emit_the_invalid_message(capsys):
    raw = _raw(event_id="evt-quiet-unsigned")

    _handle_with_status({"data": raw})

    captured = capsys.readouterr()
    assert "SIGNATURE INVALID" not in captured.out


def test_invalid_signature_message_does_not_print_the_secret_or_signature():
    """Security check: the observability print must never leak the secret
    or the signature/data payload -- only identifying metadata."""
    raw = _raw(event_id="evt-secret-check")
    sig = sign_audit_event("auth", raw, "wrong-secret")

    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        _handle_with_status({"data": raw, "sig": sig})

    output = buf.getvalue()
    assert SECRET not in output
    assert "wrong-secret" not in output
    assert sig not in output


def test_malformed_json_still_does_not_ack_unchanged_behavior():
    """Parse/schema failures remain retriable -- integrity classification
    must never run on data that failed to parse at all."""
    result, status, reader = _handle_with_status({"data": "not-json"})

    assert result is False
    assert status is None
    reader.ack.assert_not_called()


def test_db_failure_still_does_not_ack_unchanged_behavior():
    reader = MagicMock()
    mock_sink_instance = MagicMock()
    mock_sink_instance.write.side_effect = Exception("db connection lost")
    raw = _raw(event_id="evt-db-fail")

    with patch("worker.main.SessionLocal") as mock_session_local, \
         patch("worker.main.Sink", return_value=mock_sink_instance), \
         patch.object(worker.AuditConfig, "EVENT_SIGNING_SECRET", SECRET):
        mock_db = MagicMock()
        mock_session_local.return_value = mock_db
        result = worker.handle_message(reader, "1-0", {"data": raw})

    assert result is False
    reader.ack.assert_not_called()
