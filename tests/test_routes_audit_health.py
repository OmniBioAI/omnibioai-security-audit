"""V2-002 (Track E2): GET /audit/pipeline-health -- HTTP-level, platform-
admin gated, same auth-header convention as test_routes_audit_events.py.

Developer: Manish Kumar <manish@omnibioai.org>
"""
from unittest.mock import MagicMock, patch

import jwt

SECRET = "test-secret"


def _token(**claims):
    """Sign an HS256 test token with the shared test secret, applying any extra claims."""
    return jwt.encode(claims, SECRET, algorithm="HS256")


def _auth_headers(**claims):
    """Build an Authorization header carrying a token for the given roles."""
    roles = claims.pop("roles", ["platform_admin"])
    token = _token(sub="1", roles=roles, **claims)
    return {"Authorization": f"Bearer {token}"}


def test_missing_auth_header_returns_401(audit_events_client):
    """Reject a /audit/pipeline-health request with no Authorization header with 401."""
    client, _sessions = audit_events_client

    resp = client.get("/audit/pipeline-health")

    assert resp.status_code == 401


def test_non_admin_role_returns_403(audit_events_client):
    """Reject a /audit/pipeline-health request from a non-platform-admin role with 403."""
    client, _sessions = audit_events_client

    resp = client.get("/audit/pipeline-health", headers=_auth_headers(roles=["org_admin"]))

    assert resp.status_code == 403


def test_platform_admin_gets_pipeline_health(audit_events_client):
    """Report Redis and persistence as available with a pending count and a generated_at timestamp."""
    client, _sessions = audit_events_client

    mock_reader = MagicMock()
    mock_reader.redis.xlen.return_value = 0
    mock_reader.redis.xpending.return_value = {"pending": 0}
    mock_reader.redis.xinfo_groups.return_value = []
    mock_reader.redis.xinfo_consumers.return_value = []

    with patch("api.routes_audit_health.StreamReader", return_value=mock_reader):
        resp = client.get("/audit/pipeline-health", headers=_auth_headers())

    assert resp.status_code == 200
    body = resp.json()
    assert body["redis"]["available"] is True
    assert body["redis"]["pending_count"] == 0
    assert body["persistence"]["available"] is True
    assert "generated_at" in body


def test_pipeline_health_degrades_when_redis_unreachable(audit_events_client):
    """Report Redis as unavailable, with a null pending count, while the endpoint itself still
    returns 200."""
    client, _sessions = audit_events_client

    mock_reader = MagicMock()
    mock_reader.redis.xlen.side_effect = ConnectionError("redis down")

    with patch("api.routes_audit_health.StreamReader", return_value=mock_reader):
        resp = client.get("/audit/pipeline-health", headers=_auth_headers())

    assert resp.status_code == 200  # the endpoint itself stays up
    body = resp.json()
    assert body["redis"]["available"] is False
    assert body["redis"]["pending_count"] is None
