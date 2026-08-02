"""
AuditLogger tests.

AuditLogger.log() serializes events via AuditEvent.model_dump(mode="json"),
which recursively converts non-JSON-native types (e.g. the datetime
timestamp) into their JSON-safe form (ISO-8601 string) before json.dumps()
ever sees them. Tests that assert xadd is called supply a mock event whose
.model_dump() returns fully JSON-serializable data; tests that need to
exercise the real serializer construct a real AuditEvent.
"""
import json
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from audit.config import AuditConfig
from audit.models import AuditEvent


def _serializable_event(service="auth", event_type="login", **extra):
    """Return a MagicMock AuditEvent whose .model_dump() is JSON-serializable."""
    payload = {
        "event_id": "test-event-id",
        "timestamp": "2024-01-01T00:00:00",
        "service": service,
        "event_type": event_type,
        "user_id": extra.get("user_id"),
        "action": extra.get("action", ""),
        "resource": extra.get("resource"),
        "decision": extra.get("decision"),
        "reason": extra.get("reason"),
        "trace_id": extra.get("trace_id"),
        "context": extra.get("context", {}),
    }
    event = MagicMock()
    event.model_dump.return_value = payload
    return event, payload


# ---------------------------------------------------------------------------
# Successful log path
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_log_writes_to_redis_stream(audit_logger):
    logger, mock_redis = audit_logger
    mock_redis.xadd = AsyncMock()

    event, payload = _serializable_event(service="auth", event_type="auth_login",
                                         user_id="u1", action="login", decision="success")
    await logger.log(event)

    mock_redis.xadd.assert_called_once()
    call_args = mock_redis.xadd.call_args
    assert call_args[0][0] == AuditConfig.STREAM_NAME
    stored = json.loads(call_args[0][1]["data"])
    assert stored["service"] == "auth"
    assert stored["decision"] == "success"


@pytest.mark.asyncio
async def test_log_passes_maxlen_and_approximate(audit_logger):
    logger, mock_redis = audit_logger
    mock_redis.xadd = AsyncMock()

    event, _ = _serializable_event()
    await logger.log(event)

    _, kwargs = mock_redis.xadd.call_args
    assert "maxlen" in kwargs
    assert kwargs["maxlen"] == AuditConfig.MAX_STREAM_LENGTH
    assert kwargs.get("approximate") is True


@pytest.mark.asyncio
async def test_log_uses_config_stream_name(audit_logger):
    logger, mock_redis = audit_logger
    mock_redis.xadd = AsyncMock()

    event, _ = _serializable_event(service="svc")
    await logger.log(event)

    stream_name = mock_redis.xadd.call_args[0][0]
    assert stream_name == AuditConfig.STREAM_NAME


@pytest.mark.asyncio
async def test_log_event_includes_all_fields(audit_logger):
    logger, mock_redis = audit_logger
    mock_redis.xadd = AsyncMock()

    event, expected = _serializable_event(
        service="iam",
        event_type="iam_cache_hit",
        user_id="u2",
        action="validate",
        resource="token",
        decision="allow",
        reason="cache hit",
        trace_id="trace-abc",
        context={"ip": "1.2.3.4"},
    )
    await logger.log(event)

    raw = mock_redis.xadd.call_args[0][1]["data"]
    stored = json.loads(raw)
    assert stored["user_id"] == "u2"
    assert stored["trace_id"] == "trace-abc"
    assert stored["context"] == {"ip": "1.2.3.4"}


# ---------------------------------------------------------------------------
# PR4.1.5: real AuditEvent must actually reach Redis
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_log_real_event_reaches_redis(audit_logger):
    """A real AuditEvent (with its native datetime timestamp) must be
    written to Redis -- this is the PR4.1.5 regression case: previously
    json.dumps(event.dict()) raised on the raw datetime and the write was
    silently swallowed."""
    logger, mock_redis = audit_logger
    mock_redis.xadd = AsyncMock()

    real_event = AuditEvent(service="svc", event_type="test")
    await logger.log(real_event)

    mock_redis.xadd.assert_called_once()


@pytest.mark.asyncio
async def test_log_real_event_payload_is_valid_json(audit_logger):
    """The data written to the stream must parse as JSON."""
    logger, mock_redis = audit_logger
    mock_redis.xadd = AsyncMock()

    real_event = AuditEvent(service="svc", event_type="test")
    await logger.log(real_event)

    raw = mock_redis.xadd.call_args[0][1]["data"]
    stored = json.loads(raw)  # must not raise
    assert stored["service"] == "svc"


@pytest.mark.asyncio
async def test_log_real_event_timestamp_is_iso8601_string(audit_logger):
    """timestamp must be serialized as an ISO-8601 string, not a raw datetime."""
    logger, mock_redis = audit_logger
    mock_redis.xadd = AsyncMock()

    real_event = AuditEvent(service="svc", event_type="test")
    await logger.log(real_event)

    raw = mock_redis.xadd.call_args[0][1]["data"]
    stored = json.loads(raw)
    assert isinstance(stored["timestamp"], str)
    # round-trips through fromisoformat without error
    datetime.fromisoformat(stored["timestamp"])
    assert stored["timestamp"].startswith(str(real_event.timestamp.year))


@pytest.mark.asyncio
async def test_log_real_event_id_survives_serialization(audit_logger):
    """event_id must be preserved unchanged through serialization."""
    logger, mock_redis = audit_logger
    mock_redis.xadd = AsyncMock()

    real_event = AuditEvent(service="svc", event_type="test", event_id="fixed-id-123")
    await logger.log(real_event)

    raw = mock_redis.xadd.call_args[0][1]["data"]
    stored = json.loads(raw)
    assert stored["event_id"] == "fixed-id-123"


# ---------------------------------------------------------------------------
# Error path: failures must never propagate
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_log_swallows_redis_exception(audit_logger):
    """Redis xadd failure must not propagate to the caller."""
    logger, mock_redis = audit_logger
    event, _ = _serializable_event()
    mock_redis.xadd = AsyncMock(side_effect=Exception("Redis down"))

    # Must not raise
    await logger.log(event)


@pytest.mark.asyncio
async def test_log_swallows_genuinely_non_serializable_payload(audit_logger):
    """A value in the free-form `context` dict that Pydantic itself cannot
    render to JSON (e.g. an arbitrary object) must still be swallowed, not
    propagated -- the fire-and-forget guarantee holds even though the bug
    fixed by PR4.1.5 (datetime handling) no longer applies."""
    logger, mock_redis = audit_logger
    mock_redis.xadd = AsyncMock()

    class Unserializable:
        pass

    real_event = AuditEvent(
        service="svc", event_type="test", context={"bad": Unserializable()}
    )

    # Must not raise
    await logger.log(real_event)
    mock_redis.xadd.assert_not_called()
