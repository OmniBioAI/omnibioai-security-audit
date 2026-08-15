import pytest
from redis.exceptions import ResponseError

from audit.config import AuditConfig

# ---------------------------------------------------------------------------
# StreamReader.read()
# ---------------------------------------------------------------------------

def test_stream_reader_calls_xread(stream_reader):
    reader, mock_redis = stream_reader
    mock_redis.xread.return_value = [("audit:events", [("1-0", {"data": "{}"})])]

    result = reader.read(last_id="0-0")

    mock_redis.xread.assert_called_once_with(
        {AuditConfig.STREAM_NAME: "0-0"}, block=5000
    )
    assert result is not None


def test_stream_reader_default_last_id(stream_reader):
    reader, mock_redis = stream_reader
    mock_redis.xread.return_value = []

    reader.read()

    call_args = mock_redis.xread.call_args[0][0]
    assert "0-0" in call_args.values()


def test_stream_reader_passes_custom_last_id(stream_reader):
    reader, mock_redis = stream_reader
    mock_redis.xread.return_value = []

    reader.read(last_id="1234-5")

    call_args = mock_redis.xread.call_args[0][0]
    assert "1234-5" in call_args.values()


def test_stream_reader_returns_empty_on_timeout(stream_reader):
    reader, mock_redis = stream_reader
    mock_redis.xread.return_value = []

    result = reader.read()

    assert result == []


def test_stream_reader_uses_config_stream_name(stream_reader):
    reader, mock_redis = stream_reader
    mock_redis.xread.return_value = []

    reader.read()

    call_args = mock_redis.xread.call_args[0][0]
    assert AuditConfig.STREAM_NAME in call_args


def test_stream_reader_returns_multiple_entries(stream_reader):
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
    reader, mock_redis = stream_reader
    mock_redis.xgroup_create.side_effect = ResponseError("NOGROUP some other error")

    with pytest.raises(ResponseError):
        reader.ensure_group()


def test_read_group_calls_xreadgroup(stream_reader):
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
    reader, mock_redis = stream_reader

    reader.ack("1-0")

    mock_redis.xack.assert_called_once_with(
        AuditConfig.STREAM_NAME, AuditConfig.CONSUMER_GROUP, "1-0"
    )


# ---------------------------------------------------------------------------
# HIPAA P0: StreamReader.claim_stale() -- abandoned-PEL-entry recovery.
# ---------------------------------------------------------------------------

def _pending_entry(message_id, times_delivered):
    return {
        "message_id": message_id,
        "consumer": "some-dead-consumer",
        "time_since_delivered": 60000,
        "times_delivered": times_delivered,
    }


def test_claim_stale_queries_xpending_range_with_config_defaults(stream_reader):
    reader, mock_redis = stream_reader
    mock_redis.xpending_range.return_value = []

    claimed, poison_ids = reader.claim_stale("worker-2")

    mock_redis.xpending_range.assert_called_once_with(
        AuditConfig.STREAM_NAME,
        AuditConfig.CONSUMER_GROUP,
        min="-",
        max="+",
        count=AuditConfig.PEL_SWEEP_BATCH,
        idle=AuditConfig.PEL_MIN_IDLE_MS,
    )
    assert claimed == []
    assert poison_ids == []


def test_claim_stale_returns_empty_when_nothing_stale(stream_reader):
    reader, mock_redis = stream_reader
    mock_redis.xpending_range.return_value = []

    claimed, poison_ids = reader.claim_stale("worker-2")

    assert claimed == []
    assert poison_ids == []
    mock_redis.xclaim.assert_not_called()
    mock_redis.xack.assert_not_called()


def test_claim_stale_reclaims_entries_under_max_deliveries(stream_reader):
    reader, mock_redis = stream_reader
    mock_redis.xpending_range.return_value = [_pending_entry("5-0", times_delivered=2)]
    mock_redis.xclaim.return_value = [("5-0", {"data": "{}"})]

    claimed, poison_ids = reader.claim_stale("worker-2")

    mock_redis.xclaim.assert_called_once_with(
        AuditConfig.STREAM_NAME,
        AuditConfig.CONSUMER_GROUP,
        "worker-2",
        AuditConfig.PEL_MIN_IDLE_MS,
        ["5-0"],
    )
    mock_redis.xack.assert_not_called()
    assert claimed == [("5-0", {"data": "{}"})]
    assert poison_ids == []


def test_claim_stale_acks_poison_entries_without_reclaiming(stream_reader):
    reader, mock_redis = stream_reader
    mock_redis.xpending_range.return_value = [
        _pending_entry("6-0", times_delivered=AuditConfig.PEL_MAX_DELIVERIES)
    ]

    claimed, poison_ids = reader.claim_stale("worker-2")

    mock_redis.xack.assert_called_once_with(
        AuditConfig.STREAM_NAME, AuditConfig.CONSUMER_GROUP, "6-0"
    )
    mock_redis.xclaim.assert_not_called()
    assert claimed == []
    assert poison_ids == ["6-0"]


def test_claim_stale_splits_a_mixed_batch_correctly(stream_reader):
    reader, mock_redis = stream_reader
    mock_redis.xpending_range.return_value = [
        _pending_entry("7-0", times_delivered=1),
        _pending_entry("7-1", times_delivered=AuditConfig.PEL_MAX_DELIVERIES + 3),
        _pending_entry("7-2", times_delivered=AuditConfig.PEL_MAX_DELIVERIES - 1),
    ]
    mock_redis.xclaim.return_value = [("7-0", {"data": "a"}), ("7-2", {"data": "c"})]

    claimed, poison_ids = reader.claim_stale("worker-2")

    mock_redis.xack.assert_called_once_with(
        AuditConfig.STREAM_NAME, AuditConfig.CONSUMER_GROUP, "7-1"
    )
    mock_redis.xclaim.assert_called_once_with(
        AuditConfig.STREAM_NAME,
        AuditConfig.CONSUMER_GROUP,
        "worker-2",
        AuditConfig.PEL_MIN_IDLE_MS,
        ["7-0", "7-2"],
    )
    assert poison_ids == ["7-1"]
    assert claimed == [("7-0", {"data": "a"}), ("7-2", {"data": "c"})]


def test_claim_stale_honors_explicit_overrides_over_config_defaults(stream_reader):
    reader, mock_redis = stream_reader
    mock_redis.xpending_range.return_value = []

    reader.claim_stale(
        "worker-2", group="other-group", min_idle_ms=999, max_deliveries=1, batch=7,
    )

    mock_redis.xpending_range.assert_called_once_with(
        AuditConfig.STREAM_NAME, "other-group", min="-", max="+", count=7, idle=999,
    )
