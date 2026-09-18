"""Validate the /health and /audit/test endpoints with a mocked Redis-backed logger: response shape
and the logged test event's fields.

Developer: Manish Kumar <manish@omnibioai.org>
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Build a TestClient for the audit API with Redis patched out, yielding the client together
    with the mocked logger."""
    mock_redis = AsyncMock()
    mock_redis.xadd = AsyncMock()

    with patch("audit.logger.redis") as mock_redis_module:
        mock_redis_module.from_url.return_value = mock_redis
        from api.main import app
        tc = TestClient(app)
        # Patch the logger instance on the routes module
        with patch("api.routes_audit.logger") as mock_logger:
            mock_logger.log = AsyncMock()
            yield tc, mock_logger


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------

def test_health_returns_ok(client):
    """Report {"status": "ok"} from /health."""
    tc, _ = client
    response = tc.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# GET /audit/test
# ---------------------------------------------------------------------------

def test_audit_test_returns_logged_true(client):
    """Return {"logged": true} from /audit/test."""
    tc, mock_logger = client
    response = tc.get("/audit/test")
    assert response.status_code == 200
    assert response.json() == {"logged": True}


def test_audit_test_calls_logger_log(client):
    """Call the logger's log method exactly once for /audit/test."""
    tc, mock_logger = client
    tc.get("/audit/test")
    mock_logger.log.assert_called_once()


def test_audit_test_logs_correct_event_type(client):
    """Log a test event with the health_check action and a success decision."""
    tc, mock_logger = client
    tc.get("/audit/test")
    event = mock_logger.log.call_args[0][0]
    assert event.event_type == "test"
    assert event.action == "health_check"
    assert event.decision == "success"
