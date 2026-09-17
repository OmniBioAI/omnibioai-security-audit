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
    """V2-002: poison entries go through quarantine_and_ack(), never
    handle_message() -- a signature/schema failure is permanent, not
    something retrying via the normal persist path could ever fix."""
    reader = MagicMock()
    reader.claim_stale.return_value = (
        [],
        [("9-0", {"data": "not json"}, 5), ("9-1", {"data": "also not json"}, 5)],
    )
    mock_quarantine_instance = MagicMock()
    mock_quarantine_instance.write.return_value = True

    with patch("worker.main.handle_message") as mock_handle, \
         patch("worker.main.SessionLocal") as mock_session_local, \
         patch("worker.main.QuarantineSink", return_value=mock_quarantine_instance):
        mock_session_local.return_value = MagicMock()
        worker.sweep_pending(reader)

    mock_handle.assert_not_called()
    assert mock_quarantine_instance.write.call_count == 2


def test_sweep_pending_quarantines_then_acks_poison_entries(capsys):
    """V2-002: the durable quarantine write must happen BEFORE the ack --
    proven here by mocking QuarantineSink to record call order relative
    to reader.ack."""
    reader = MagicMock()
    reader.claim_stale.return_value = ([], [("9-0", {"data": "not json"}, 5)])

    call_order = []
    mock_quarantine_instance = MagicMock()
    mock_quarantine_instance.write.side_effect = lambda *a, **kw: call_order.append("quarantine_write")
    reader.ack.side_effect = lambda *a, **kw: call_order.append("ack")

    with patch("worker.main.SessionLocal") as mock_session_local, \
         patch("worker.main.QuarantineSink", return_value=mock_quarantine_instance):
        mock_session_local.return_value = MagicMock()
        worker.sweep_pending(reader)

    assert call_order == ["quarantine_write", "ack"]
    mock_quarantine_instance.write.assert_called_once_with("9-0", {"data": "not json"}, 5)
    reader.ack.assert_called_once_with("9-0")

    captured = capsys.readouterr()
    assert "POISON MESSAGE" in captured.out
    assert "9-0" in captured.out
    assert "quarantined" in captured.out


def test_sweep_pending_quarantines_missing_data_field_poison_entry(capsys):
    """Incident (2026-09-16) regression, requirement B: a poison entry
    whose `fields` dict has no "data" key at all (the exact incident
    shape) must be quarantined through the same durable path as a
    malformed-JSON entry, not crash sweep_pending() or the worker.
    QuarantineSink itself is real here (not mocked) so
    classify_poison_reason()'s dedicated `raw_data is None` branch
    ("malformed"/"MissingDataField") is genuinely exercised end-to-end,
    only the DB session is mocked."""
    reader = MagicMock()
    reader.claim_stale.return_value = ([], [("9-0", {}, 5)])  # no "data" key

    mock_db = MagicMock()
    written = {}

    def _capture_add(record):
        written["record"] = record

    mock_db.add.side_effect = _capture_add

    with patch("worker.main.SessionLocal", return_value=mock_db):
        worker.sweep_pending(reader)  # must not raise

    reader.ack.assert_called_once_with("9-0")
    mock_db.commit.assert_called_once()
    record = written["record"]
    assert record.stream_message_id == "9-0"
    assert record.raw_data is None
    assert record.failure_category == "malformed"
    assert record.failure_detail == "MissingDataField"

    captured = capsys.readouterr()
    assert "POISON MESSAGE" in captured.out
    assert "9-0" in captured.out


def test_sweep_pending_continues_to_next_entry_after_missing_data_poison(capsys):
    """Requirement C: one poison entry missing `data` must not prevent a
    second, independent poison entry (malformed JSON, the pre-existing
    case) from also being quarantined in the same sweep -- proving the
    fix doesn't just avoid a crash, it lets the loop keep going."""
    reader = MagicMock()
    reader.claim_stale.return_value = (
        [],
        [("9-0", {}, 5), ("10-0", {"data": "not json"}, 5)],
    )

    with patch("worker.main.SessionLocal") as mock_session_local:
        mock_session_local.return_value = MagicMock()
        worker.sweep_pending(reader)  # must not raise

    assert reader.ack.call_count == 2
    reader.ack.assert_any_call("9-0")
    reader.ack.assert_any_call("10-0")

    captured = capsys.readouterr()
    assert captured.out.count("POISON MESSAGE") == 2


def test_sweep_pending_does_not_ack_poison_entry_when_quarantine_write_fails():
    """V2-002 core requirement: quarantine failure must never silently
    ack (and thereby discard) the original poison message."""
    reader = MagicMock()
    reader.claim_stale.return_value = ([], [("9-0", {"data": "not json"}, 5)])
    mock_quarantine_instance = MagicMock()
    mock_quarantine_instance.write.side_effect = Exception("simulated MySQL outage")

    with patch("worker.main.SessionLocal") as mock_session_local, \
         patch("worker.main.QuarantineSink", return_value=mock_quarantine_instance):
        mock_session_local.return_value = MagicMock()
        worker.sweep_pending(reader)  # must not raise

    reader.ack.assert_not_called()


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
