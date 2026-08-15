"""HIPAA P0: abandoned Pending Entries List recovery -- worker.main's
sweep_pending() and its wiring into run(), against a mocked StreamReader
(see tests/test_worker_integration_real_backends.py for the real-Redis
proof of the concurrency/race claims made in StreamReader.claim_stale's
own docstring, which a mock cannot meaningfully exercise).

Covers the specific gap this PR closes: a message delivered via
read_group() but never acked (worker crash, transient persistence
failure) was previously invisible to every future read_group() call
forever -- read_group() only ever asks Redis for ">" (strictly new
messages). sweep_pending() is what makes such an entry reachable again.
"""
import json
from unittest.mock import MagicMock, patch

import worker.main as worker
from audit.config import AuditConfig


def _raw(event_id="evt-1"):
    return json.dumps({
        "event_id": event_id,
        "timestamp": "2026-01-01T12:00:00",
        "service": "auth",
        "event_type": "auth_login",
        "decision": "success",
    })


# ---------------------------------------------------------------------------
# sweep_pending()
# ---------------------------------------------------------------------------

def test_sweep_pending_processes_each_reclaimed_message():
    reader = MagicMock()
    reader.claim_stale.return_value = (
        [("2-0", {"data": _raw("evt-reclaimed-a")}), ("2-1", {"data": _raw("evt-reclaimed-b")})],
        [],
    )

    with patch("worker.main.handle_message") as mock_handle:
        worker.sweep_pending(reader)

    reader.claim_stale.assert_called_once_with(AuditConfig.CONSUMER_NAME)
    assert mock_handle.call_count == 2
    mock_handle.assert_any_call(reader, "2-0", {"data": _raw("evt-reclaimed-a")})
    mock_handle.assert_any_call(reader, "2-1", {"data": _raw("evt-reclaimed-b")})


def test_sweep_pending_reclaimed_message_goes_through_real_handle_message_and_acks():
    """Not a mocked handle_message this time -- proves a reclaimed entry
    runs through the exact same classify/persist/ack path a freshly-read
    message does, ending in a real ack() call."""
    reader = MagicMock()
    reader.claim_stale.return_value = ([("3-0", {"data": _raw("evt-real-path")})], [])
    mock_sink_instance = MagicMock()
    mock_sink_instance.write.return_value = True

    with patch("worker.main.SessionLocal") as mock_session_local, \
         patch("worker.main.Sink", return_value=mock_sink_instance):
        mock_session_local.return_value = MagicMock()
        worker.sweep_pending(reader)

    mock_sink_instance.write.assert_called_once()
    reader.ack.assert_called_once_with("3-0")


def test_sweep_pending_does_not_reprocess_poison_ids():
    reader = MagicMock()
    reader.claim_stale.return_value = ([], ["9-0", "9-1"])

    with patch("worker.main.handle_message") as mock_handle:
        worker.sweep_pending(reader)

    mock_handle.assert_not_called()


def test_sweep_pending_logs_poison_ids_loudly(capsys):
    reader = MagicMock()
    reader.claim_stale.return_value = ([], ["9-0"])

    worker.sweep_pending(reader)

    captured = capsys.readouterr()
    assert "POISON MESSAGE" in captured.out
    assert "9-0" in captured.out


def test_sweep_pending_survives_claim_stale_raising(capsys):
    """A Redis blip during the sweep itself must not propagate -- matches
    read_group()'s own contract in run()."""
    reader = MagicMock()
    reader.claim_stale.side_effect = Exception("redis connection reset")

    worker.sweep_pending(reader)  # must not raise

    captured = capsys.readouterr()
    assert "pending-entry sweep failed" in captured.out


def test_sweep_pending_no_op_when_nothing_stale():
    reader = MagicMock()
    reader.claim_stale.return_value = ([], [])

    with patch("worker.main.handle_message") as mock_handle:
        worker.sweep_pending(reader)

    mock_handle.assert_not_called()
    reader.ack.assert_not_called()


# ---------------------------------------------------------------------------
# run() wiring -- sweep_pending() called once per iteration, before
# read_group(), and its own failures never interrupt the read_group/
# handle_message half of the loop.
# ---------------------------------------------------------------------------

def test_run_calls_sweep_pending_every_iteration():
    mock_reader = MagicMock()
    mock_reader.read_group.return_value = []
    mock_reader.claim_stale.return_value = ([], [])

    with patch("worker.main.StreamReader", return_value=mock_reader):
        worker.run(max_iterations=3)

    assert mock_reader.claim_stale.call_count == 3


def test_run_still_processes_new_messages_when_sweep_finds_nothing():
    mock_reader = MagicMock()
    mock_reader.claim_stale.return_value = ([], [])
    mock_reader.read_group.return_value = [
        (worker.AuditConfig.STREAM_NAME, [("1-0", {"data": _raw("evt-new")})]),
    ]

    with patch("worker.main.StreamReader", return_value=mock_reader), \
         patch("worker.main.handle_message") as mock_handle:
        worker.run(max_iterations=1)

    mock_handle.assert_called_once_with(mock_reader, "1-0", {"data": _raw("evt-new")})


def test_run_processes_both_reclaimed_and_new_messages_in_one_iteration():
    mock_reader = MagicMock()
    mock_reader.claim_stale.return_value = ([("2-0", {"data": _raw("evt-reclaimed")})], [])
    mock_reader.read_group.return_value = [
        (worker.AuditConfig.STREAM_NAME, [("3-0", {"data": _raw("evt-new")})]),
    ]

    with patch("worker.main.StreamReader", return_value=mock_reader), \
         patch("worker.main.handle_message") as mock_handle:
        worker.run(max_iterations=1)

    assert mock_handle.call_count == 2
    mock_handle.assert_any_call(mock_reader, "2-0", {"data": _raw("evt-reclaimed")})
    mock_handle.assert_any_call(mock_reader, "3-0", {"data": _raw("evt-new")})


def test_run_survives_sweep_pending_raising_and_still_reads_new_messages():
    mock_reader = MagicMock()
    mock_reader.claim_stale.side_effect = Exception("redis blip during sweep")
    mock_reader.read_group.return_value = [
        (worker.AuditConfig.STREAM_NAME, [("1-0", {"data": _raw("evt-after-sweep-blip")})]),
    ]

    with patch("worker.main.StreamReader", return_value=mock_reader), \
         patch("worker.main.handle_message") as mock_handle:
        worker.run(max_iterations=1)  # must not raise

    mock_handle.assert_called_once_with(
        mock_reader, "1-0", {"data": _raw("evt-after-sweep-blip")}
    )
