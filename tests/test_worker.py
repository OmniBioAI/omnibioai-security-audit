"""PR4.2 regression tests: worker/main.py -- the Redis Streams consumer-group
loop that reads audit:events, parses/persists each message, and only ACKs
after a successful DB write."""
import json
from unittest.mock import MagicMock, patch

import worker.main as worker


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
