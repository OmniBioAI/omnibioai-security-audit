from datetime import datetime, timedelta
from unittest.mock import patch

import jwt
from sqlalchemy.exc import OperationalError

from api.deps_audit import AuditAccess
from api.routes_audit_safe import list_safe_audit_events
from db.models import AuditEventRecord

SECRET = "test-secret"


def _headers(*, org_id=None, org_role=None, permissions=None):
    claims = {"sub": "actor", "roles": [], "org_role": org_role or [], "permissions": permissions or []}
    if org_id is not None:
        claims["org_id"] = org_id
    return {"Authorization": f"Bearer {jwt.encode(claims, SECRET, algorithm='HS256')}"}


def _seed(factory):
    db = factory()
    base = datetime(2026, 1, 1, 12, 0, 0)  # noqa: DTZ001
    for i, (scope, org) in enumerate((("organization", "1"), ("organization", "2"), ("global", None), ("unknown", None))):
        db.add(AuditEventRecord(
            event_id=f"safe-{i}", timestamp=base + timedelta(minutes=i), service="auth",
            event_type="login", action="login", user_id=f"u-{i}", organization_id=org,
            tenant_scope=scope, context={"request_id": f"r-{i}", "Authorization": "secret", "drop": "x"},
        ))
    db.commit()
    db.close()


def test_org_scope_excludes_other_global_and_unknown_and_is_sql_paginated(audit_events_client):
    client, sessions = audit_events_client
    _seed(sessions)
    response = client.get("/audit/events/safe", headers=_headers(org_id="1", org_role=["org_admin"]), params={"page_size": 1})
    assert response.status_code == 200
    body = response.json()
    assert body["source_availability"] == "AVAILABLE"
    assert body["total"] == 1
    assert [item["event_id"] for item in body["items"]] == ["safe-0"]
    assert body["items"][0]["metadata"] == {"request_id": "r-0"}
    assert body["freshness"]["status"] == "UNKNOWN"
    assert body["retention"] == {"status": "UNKNOWN", "retention_days": None, "oldest_available_event_at": None}


def test_platform_scope_sees_global_and_unknown(audit_events_client):
    client, sessions = audit_events_client
    _seed(sessions)
    response = client.get("/audit/events/safe", headers=_headers(permissions=["manage_all_orgs"]))
    assert response.status_code == 200
    assert response.json()["total"] == 4
    assert [x["event_id"] for x in response.json()["items"]] == ["safe-3", "safe-2", "safe-1", "safe-0"]


def test_org_query_override_cannot_widen(audit_events_client):
    client, _ = audit_events_client
    response = client.get("/audit/events/safe", headers=_headers(org_id="1", org_role=["org_admin"]), params={"organization_id": "2"})
    assert response.status_code == 403


def test_empty_safe_result_is_available(audit_events_client):
    client, _ = audit_events_client
    response = client.get("/audit/events/safe", headers=_headers(org_id="1", org_role=["org_admin"]))
    body = response.json()
    assert response.status_code == 200
    assert body["items"] == []
    assert body["total"] == 0
    assert body["source_availability"] == "AVAILABLE"


def test_safe_auth_failures_and_validation(audit_events_client):
    client, _ = audit_events_client
    assert client.get("/audit/events/safe").status_code == 401
    assert client.get("/audit/events/safe", headers=_headers()).status_code == 403
    assert client.get("/audit/events/safe", headers=_headers(org_role=["org_admin"])).status_code == 403
    assert client.get("/audit/events/safe", headers=_headers(permissions=["manage_all_orgs"]), params={"page_size": 101}).status_code == 422


def test_safe_database_failure_is_normalized_without_internal_details():
    with patch(
        "api.routes_audit_safe.audit_query_service.list_safe_audit_events",
        side_effect=OperationalError("SELECT audit_events", {}, Exception("db.internal")),
    ):
        response = list_safe_audit_events(
            page=1, page_size=20, user_id=None, service=None, event_type=None,
            decision=None, from_timestamp=None, to_timestamp=None,
            integrity_status=None, organization_id=None,
            access=AuditAccess(True, None), db=object()
        )

    assert response.status_code == 503
    body = response.body.decode()
    assert "AUDIT_SOURCE_UNAVAILABLE" in body
    assert "SELECT" not in body
    assert "db.internal" not in body
