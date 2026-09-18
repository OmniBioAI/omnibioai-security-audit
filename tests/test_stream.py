"""Validate StreamReader with a mocked Redis client: reading new entries via XREAD, consumer-group
creation and reads, acknowledgement, and claim_stale's stale-entry reclaiming and poison-entry
detection.

Developer: Manish Kumar <manish@omnibioai.org>
"""

import pytest
from redis.exceptions import ResponseError

from audit.config import AuditConfig

# ---------------------------------------------------------------------------
# StreamReader.read()
# ---------------------------------------------------------------------------

def test_stream_reader_calls_xread(stream_reader):
    """Read entries through XREAD from the given last id."""
    reader, mock_redis = stream_reader
    mock_redis.xread.return_value = [("audit:events", [("1-0", {"data": "{}"})])]

    result = reader.read(last_id="0-0")

    mock_redis.xread.assert_called_once_with(
        {AuditConfig.STREAM_NAME: "0-0"}, block=5000
    )
    assert result is not None


def test_stream_reader_default_last_id(stream_reader):
    """Default the read to start from id 0-0 when none is given."""
    reader, mock_redis = stream_reader
    mock_redis.xread.return_value = []

    reader.read()

    call_args = mock_redis.xread.call_args[0][0]
    assert "0-0" in call_args.values()


def test_stream_reader_passes_custom_last_id(stream_reader):
    """Pass a caller-supplied last id through to XREAD."""
    reader, mock_redis = stream_reader
    mock_redis.xread.return_value = []

    reader.read(last_id="1234-5")

    call_args = mock_redis.xread.call_args[0][0]
    assert "1234-5" in call_args.values()


def test_stream_reader_returns_empty_on_timeout(stream_reader):
    """Return an empty list when XREAD times out with no new entries."""
    reader, mock_redis = stream_reader
    mock_redis.xread.return_value = []

    result = reader.read()

    assert result == []


def test_stream_reader_uses_config_stream_name(stream_reader):
    """Read from the stream name configured in AuditConfig."""
    reader, mock_redis = stream_reader
    mock_redis.xread.return_value = []

    reader.read()

    call_args = mock_redis.xread.call_args[0][0]
    assert AuditConfig.STREAM_NAME in call_args


def test_stream_reader_returns_multiple_entries(stream_reader):
    """Return every entry XREAD reports for a stream."""
    reader, mock_redis = stream_reader
    entries = [
        ("0-1", {"data": '{"event_type": "auth_login"}'}),
        ("0-2", {"data": '{"event_type": "auth_failed"}'}),
    ]
    mock_redis.xread.return_value = [(AuditConfig.STREAM_NAME, entries)]

    result = reader.read()

    assert len(result) == 1
    assert len(result[0][1]) == 2


# ---------------------------------------------------------------------------
# PR4.2: consumer-group reads
# ---------------------------------------------------------------------------

def test_ensure_group_creates_group(stream_reader):
    """Create the consumer group with a single XGROUP CREATE call."""
    reader, mock_redis = stream_reader

    reader.ensure_group()

    mock_redis.xgroup_create.assert_called_once_with(
        AuditConfig.STREAM_NAME, AuditConfig.CONSUMER_GROUP, id="0-0", mkstream=True
    )


def test_ensure_group_is_idempotent_when_group_exists(stream_reader):
    """A pre-existing group (BUSYGROUP) must not raise -- group creation
    on worker startup has to be safe to call every time."""
    reader, mock_redis = stream_reader
    mock_redis.xgroup_create.side_effect = ResponseError(
        "BUSYGROUP Consumer Group name already exists"
    )

    reader.ensure_group()  # must not raise


def test_ensure_group_reraises_other_response_errors(stream_reader):
    """Re-raise any ResponseError other than BUSYGROUP raised while creating the group."""
    reader, mock_redis = stream_reader
    mock_redis.xgroup_create.side_effect = ResponseError("NOGROUP some other error")

    with pytest.raises(ResponseError):
        reader.ensure_group()


def test_read_group_calls_xreadgroup(stream_reader):
    """Read new messages through XREADGROUP for the given consumer."""
    reader, mock_redis = stream_reader
    mock_redis.xreadgroup.return_value = []

    reader.read_group("worker-1")

    mock_redis.xreadgroup.assert_called_once_with(
        AuditConfig.CONSUMER_GROUP,
        "worker-1",
        {AuditConfig.STREAM_NAME: ">"},
        count=10,
        block=5000,
    )


def test_ack_calls_xack(stream_reader):
    """Acknowledge a message through XACK."""
    reader, mock_redis = stream_reader

    reader.ack("1-0")

    mock_redis.xack.assert_called_once_with(
        AuditConfig.STREAM_NAME, AuditConfig.CONSUMER_GROUP, "1-0"
    )


# ---------------------------------------------------------------------------
# HIPAA P0: StreamReader.claim_stale() -- abandoned-PEL-entry recovery.
# ---------------------------------------------------------------------------

def _pending_entry(message_id, times_delivered):
    """Build an XPENDING-range-style pending entry dict with the given message id and delivery
    count."""
    return {
        "message_id": message_id,
        "consumer": "some-dead-consumer",
        "time_since_delivered": 60000,
        "times_delivered": times_delivered,
    }


def test_claim_stale_queries_xpending_range_with_config_defaults(stream_reader):
    """Query XPENDING_RANGE with the configured default idle time and max count, returning nothing
    claimed when there is no backlog."""
    reader, mock_redis = stream_reader
    mock_redis.xpending_range.return_value = []

    claimed, poison_entries = reader.claim_stale("worker-2")

    mock_redis.xpending_range.assert_called_once_with(
        AuditConfig.STREAM_NAME,
        AuditConfig.CONSUMER_GROUP,
        min="-",
        max="+",
        count=AuditConfig.PEL_SWEEP_BATCH,
        idle=AuditConfig.PEL_MIN_IDLE_MS,
    )
    assert claimed == []
    assert poison_entries == []


def test_claim_stale_returns_empty_when_nothing_stale(stream_reader):
    """Return no claimed or poison entries, and never call XCLAIM or XACK, when nothing is stale."""
    reader, mock_redis = stream_reader
    mock_redis.xpending_range.return_value = []

    claimed, poison_entries = reader.claim_stale("worker-2")

    assert claimed == []
    assert poison_entries == []
    mock_redis.xclaim.assert_not_called()
    mock_redis.xack.assert_not_called()


def test_claim_stale_reclaims_entries_under_max_deliveries(stream_reader):
    """Reclaim a stale entry under the max-deliveries threshold via XCLAIM without acking it."""
    reader, mock_redis = stream_reader
    mock_redis.xpending_range.return_value = [_pending_entry("5-0", times_delivered=2)]
    mock_redis.xclaim.return_value = [("5-0", {"data": "{}"})]

    claimed, poison_entries = reader.claim_stale("worker-2")

    mock_redis.xclaim.assert_called_once_with(
        AuditConfig.STREAM_NAME,
        AuditConfig.CONSUMER_GROUP,
        "worker-2",
        AuditConfig.PEL_MIN_IDLE_MS,
        ["5-0"],
    )
    mock_redis.xack.assert_not_called()
    assert claimed == [("5-0", {"data": "{}"})]
    assert poison_entries == []


def test_claim_stale_does_not_ack_poison_entries_itself(stream_reader):
    """V2-002: claim_stale() must NOT ack poison entries -- that decision
    belongs to the caller, only after a durable quarantine write
    succeeds (worker/main.py::quarantine_and_ack). It fetches the
    entry's fields via XRANGE (a pure read) instead, so the caller has
    something to quarantine."""
    reader, mock_redis = stream_reader
    mock_redis.xpending_range.return_value = [
        _pending_entry("6-0", times_delivered=AuditConfig.PEL_MAX_DELIVERIES)
    ]
    mock_redis.xrange.return_value = [("6-0", {"data": "some raw payload"})]

    claimed, poison_entries = reader.claim_stale("worker-2")

    mock_redis.xack.assert_not_called()
    mock_redis.xclaim.assert_not_called()
    mock_redis.xrange.assert_called_once_with(
        AuditConfig.STREAM_NAME, min="6-0", max="6-0"
    )
    assert claimed == []
    assert poison_entries == [("6-0", {"data": "some raw payload"}, AuditConfig.PEL_MAX_DELIVERIES)]


def test_claim_stale_poison_entry_with_no_xrange_result_gets_empty_fields(stream_reader):
    """Defensive case: the entry could theoretically have expired from
    the stream between XPENDING and XRANGE (e.g. concurrent trimming) --
    must not crash, just hand back empty fields for the caller to
    quarantine as best it can."""
    reader, mock_redis = stream_reader
    mock_redis.xpending_range.return_value = [
        _pending_entry("6-1", times_delivered=AuditConfig.PEL_MAX_DELIVERIES)
    ]
    mock_redis.xrange.return_value = []

    _claimed, poison_entries = reader.claim_stale("worker-2")

    assert poison_entries == [("6-1", {}, AuditConfig.PEL_MAX_DELIVERIES)]


def test_claim_stale_splits_a_mixed_batch_correctly(stream_reader):
    """Split a mixed batch into reclaimed entries and poison entries by delivery count."""
    reader, mock_redis = stream_reader
    mock_redis.xpending_range.return_value = [
        _pending_entry("7-0", times_delivered=1),
        _pending_entry("7-1", times_delivered=AuditConfig.PEL_MAX_DELIVERIES + 3),
        _pending_entry("7-2", times_delivered=AuditConfig.PEL_MAX_DELIVERIES - 1),
    ]
    mock_redis.xclaim.return_value = [("7-0", {"data": "a"}), ("7-2", {"data": "c"})]
    mock_redis.xrange.return_value = [("7-1", {"data": "poison-payload"})]

    claimed, poison_entries = reader.claim_stale("worker-2")

    mock_redis.xack.assert_not_called()
    mock_redis.xrange.assert_called_once_with(AuditConfig.STREAM_NAME, min="7-1", max="7-1")
    mock_redis.xclaim.assert_called_once_with(
        AuditConfig.STREAM_NAME,
        AuditConfig.CONSUMER_GROUP,
        "worker-2",
        AuditConfig.PEL_MIN_IDLE_MS,
        ["7-0", "7-2"],
    )
    assert poison_entries == [("7-1", {"data": "poison-payload"}, AuditConfig.PEL_MAX_DELIVERIES + 3)]
    assert claimed == [("7-0", {"data": "a"}), ("7-2", {"data": "c"})]


def test_claim_stale_honors_explicit_overrides_over_config_defaults(stream_reader):
    """Use caller-supplied idle time and count overrides in place of the config defaults."""
    reader, mock_redis = stream_reader
    mock_redis.xpending_range.return_value = []

    reader.claim_stale(
        "worker-2", group="other-group", min_idle_ms=999, max_deliveries=1, batch=7,
    )

    mock_redis.xpending_range.assert_called_once_with(
        AuditConfig.STREAM_NAME, "other-group", min="-", max="+", count=7, idle=999,
    )
