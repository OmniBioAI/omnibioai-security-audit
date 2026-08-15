"""PR4.3: GET /audit/events -- the read-only audit query API. HTTP-level
tests via the audit_events_client fixture (real SQLite DB + real FastAPI
dependency injection, not mocks); SQL-level filter/order/pagination
correctness is covered separately in tests/test_audit_query_service.py."""
from datetime import datetime, timedelta

import jwt

from db.models import AuditEventRecord

SECRET = "test-secret"


def _token(**claims):
    return jwt.encode(claims, SECRET, algorithm="HS256")


def _auth_headers(**claims):
    roles = claims.pop("roles", ["platform_admin"])
    token = _token(sub="1", roles=roles, **claims)
    return {"Authorization": f"Bearer {token}"}


def _seed(session_factory, count=3):
    db = session_factory()
    for i in range(count):
        db.add(
            AuditEventRecord(
                event_id=f"evt-{i}",
                timestamp=datetime(2026, 1, 1, 12, 0, 0) + timedelta(minutes=i),  # noqa: DTZ001 -- AuditEventRecord.timestamp is a naive DateTime column (db/models.py)
                service="auth",
                event_type="auth_login",
                user_id="u1",
                action="login",
                decision="success",
                context={"i": i},
            )
        )
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------

def test_platform_admin_can_query_audit_events(audit_events_client):
    client, sessions = audit_events_client
    _seed(sessions, count=1)

    resp = client.get("/audit/events", headers=_auth_headers())

    assert resp.status_code == 200
    assert resp.json()["total"] == 1


def test_missing_auth_header_returns_401(audit_events_client):
    client, _ = audit_events_client

    resp = client.get("/audit/events")

    assert resp.status_code == 401


def test_non_platform_admin_receives_403(audit_events_client):
    client, sessions = audit_events_client
    _seed(sessions, count=1)

    resp = client.get("/audit/events", headers=_auth_headers(roles=["org_admin"]))

    assert resp.status_code == 403


def test_org_admin_never_sees_audit_data_even_with_valid_token(audit_events_client):
    """Explicitly guards the 'org admins must not see audit logs'
    requirement -- a well-formed, unexpired token for a real org role must
    still be rejected, and the body must not leak any event data."""
    client, sessions = audit_events_client
    _seed(sessions, count=5)

    resp = client.get(
        "/audit/events", headers=_auth_headers(roles=["org_admin", "team_lead"])
    )

    assert resp.status_code == 403
    assert "items" not in resp.json()


# ---------------------------------------------------------------------------
# Response shape / pagination
# ---------------------------------------------------------------------------

def test_response_contains_expected_fields(audit_events_client):
    client, sessions = audit_events_client
    _seed(sessions, count=1)

    resp = client.get("/audit/events", headers=_auth_headers())

    body = resp.json()
    assert set(body.keys()) == {"items", "total", "page", "page_size", "total_pages"}
    item = body["items"][0]
    assert set(item.keys()) == {
        "event_id", "timestamp", "service", "event_type", "user_id",
        "action", "resource", "decision", "reason", "trace_id", "context",
        "created_at", "integrity_status",
    }
    assert item["event_id"] == "evt-0"
    assert item["context"] == {"i": 0}
    # _seed() rows are constructed without an explicit integrity_status --
    # the DB column's own server_default="unsigned" (0002_integrity_status)
    # applies, same as every real historical event before any producer
    # signed.
    assert item["integrity_status"] == "unsigned"


def test_pagination_works(audit_events_client):
    client, sessions = audit_events_client
    _seed(sessions, count=5)

    resp = client.get(
        "/audit/events", headers=_auth_headers(), params={"page": 2, "page_size": 2}
    )

    body = resp.json()
    assert body["page"] == 2
    assert body["page_size"] == 2
    assert body["total"] == 5
    assert body["total_pages"] == 3
    assert len(body["items"]) == 2


def test_empty_result_returns_empty_items_not_error(audit_events_client):
    client, _ = audit_events_client

    resp = client.get("/audit/events", headers=_auth_headers())

    assert resp.status_code == 200
    body = resp.json()
    assert body["items"] == []
    assert body["total"] == 0
    assert body["total_pages"] == 0


def test_newest_events_appear_first(audit_events_client):
    client, sessions = audit_events_client
    _seed(sessions, count=3)

    resp = client.get("/audit/events", headers=_auth_headers())

    ids = [item["event_id"] for item in resp.json()["items"]]
    assert ids == ["evt-2", "evt-1", "evt-0"]


# ---------------------------------------------------------------------------
# Filters (HTTP-level smoke coverage; exhaustive filter/SQL correctness is
# in test_audit_query_service.py)
# ---------------------------------------------------------------------------

def test_filter_by_service_via_query_param(audit_events_client):
    client, sessions = audit_events_client
    db = sessions()
    db.add(AuditEventRecord(
        event_id="e1", timestamp=datetime(2026, 1, 1), service="auth",  # noqa: DTZ001 -- naive DateTime column
        event_type="auth_login", context={},
    ))
    db.add(AuditEventRecord(
        event_id="e2", timestamp=datetime(2026, 1, 1), service="policy",  # noqa: DTZ001 -- naive DateTime column
        event_type="policy_decision", context={},
    ))
    db.commit()
    db.close()

    resp = client.get(
        "/audit/events", headers=_auth_headers(), params={"service": "policy"}
    )

    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["event_id"] == "e2"


def test_filter_by_decision_and_event_type_via_query_params(audit_events_client):
    client, sessions = audit_events_client
    db = sessions()
    db.add(AuditEventRecord(
        event_id="e1", timestamp=datetime(2026, 1, 1), service="auth",  # noqa: DTZ001 -- naive DateTime column
        event_type="user_suspended", decision="success", context={},
    ))
    db.add(AuditEventRecord(
        event_id="e2", timestamp=datetime(2026, 1, 1), service="auth",  # noqa: DTZ001 -- naive DateTime column
        event_type="user_suspended", decision="failure", context={},
    ))
    db.commit()
    db.close()

    resp = client.get(
        "/audit/events",
        headers=_auth_headers(),
        params={"event_type": "user_suspended", "decision": "failure"},
    )

    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["event_id"] == "e2"


def test_filter_by_integrity_status_via_query_param(audit_events_client):
    client, sessions = audit_events_client
    db = sessions()
    db.add(AuditEventRecord(
        event_id="e1", timestamp=datetime(2026, 1, 1), service="tes",  # noqa: DTZ001 -- naive DateTime column
        event_type="workflow_execution_denied", context={}, integrity_status="valid",
    ))
    db.add(AuditEventRecord(
        event_id="e2", timestamp=datetime(2026, 1, 1), service="tes",  # noqa: DTZ001 -- naive DateTime column
        event_type="workflow_execution_denied", context={}, integrity_status="invalid",
    ))
    db.commit()
    db.close()

    resp = client.get(
        "/audit/events", headers=_auth_headers(), params={"integrity_status": "invalid"}
    )

    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["event_id"] == "e2"
    assert body["items"][0]["integrity_status"] == "invalid"


# ---------------------------------------------------------------------------
# Existing endpoints unaffected
# ---------------------------------------------------------------------------

def test_health_endpoint_still_works(audit_events_client):
    client, _ = audit_events_client
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
