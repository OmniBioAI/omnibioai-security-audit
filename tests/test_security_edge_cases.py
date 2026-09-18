"""Hermetic security-boundary tests not requiring FastAPI or live backends."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import ValidationError

from api import routes_audit, routes_audit_events
from audit import signing
from db.session import get_db
from schemas.audit import AuditEventListResponse, AuditEventOut


def test_fastapi_app_registers_both_audit_routers():
    from api.main import app

    paths = {route.path for route in app.routes}
    assert "/health" in paths
    assert "/audit/test" in paths
    assert "/audit/events" in paths


def test_signing_rejects_empty_service_and_none_data():
    with pytest.raises(ValueError, match="service"):
        signing.sign_audit_event("", "{}", "secret")
    with pytest.raises(ValueError, match="data"):
        signing.sign_audit_event("auth", None, "secret")


@pytest.mark.parametrize(
    "service,data,signature",
    [
        ("auth", "{}", None),
        ("auth", "{}", 123),
        (None, "{}", "v1:abc"),
        (123, "{}", "v1:abc"),
        ("auth", None, "v1:abc"),
        ("auth", "{}", ""),
        ("auth", "{}", "v2:abc"),
        ("auth", "{}", "v1"),
    ],
)
def test_signature_verification_fails_closed_for_malformed_wire_values(service, data, signature):
    assert signing.verify_audit_event(service, data, signature, "secret") is False


def test_signature_verification_fails_closed_if_compare_digest_raises(monkeypatch):
    valid = signing.sign_audit_event("auth", '{"event_id":"1"}', "secret")
    monkeypatch.setattr(signing.hmac, "compare_digest", MagicMock(side_effect=RuntimeError("bad crypto")))

    assert signing.verify_audit_event("auth", '{"event_id":"1"}', valid, "secret") is False


def test_health_route_is_side_effect_free():
    assert routes_audit.health() == {"status": "ok"}


@pytest.mark.asyncio
async def test_audit_test_route_builds_and_logs_service_event(monkeypatch):
    logger = MagicMock()
    logger.log = AsyncMock()
    monkeypatch.setattr(routes_audit, "logger", logger)
    monkeypatch.setattr("audit.config.AuditConfig.SERVICE_NAME", "security-audit-test")

    result = await routes_audit.test_log()

    assert result == {"logged": True}
    event = logger.log.call_args.args[0]
    assert event.service == "security-audit-test"
    assert event.event_type == "test"
    assert event.action == "health_check"
    assert event.decision == "success"


def test_audit_event_schema_requires_integrity_and_core_fields():
    with pytest.raises(ValidationError):
        AuditEventOut(event_id="evt-1")


def test_audit_event_schema_supports_orm_attributes_and_nullable_identity():
    row = SimpleNamespace(
        event_id="evt-1",
        timestamp=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        service="auth",
        event_type="login",
        user_id=None,
        action="authenticate",
        resource=None,
        decision=None,
        reason=None,
        trace_id=None,
        context={"ip": "127.0.0.1"},
        created_at=datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
        integrity_status="unsigned",
    )

    result = AuditEventOut.model_validate(row, from_attributes=True)

    assert result.event_id == "evt-1"
    assert result.user_id is None
    assert result.context == {"ip": "127.0.0.1"}
    assert result.integrity_status == "unsigned"


def test_audit_event_list_response_preserves_pagination_contract():
    response = AuditEventListResponse(items=[], total=3, page=2, page_size=2, total_pages=2)

    assert response.model_dump() == {
        "items": [], "total": 3, "page": 2, "page_size": 2, "total_pages": 2,
    }


def test_list_audit_events_route_forwards_all_security_filters(monkeypatch):
    db = MagicMock()
    captured = {}

    def fake_list(db_arg, **kwargs):
        captured["db"] = db_arg
        captured.update(kwargs)
        return [], 0

    monkeypatch.setattr(routes_audit_events.audit_query_service, "list_audit_events", fake_list)
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    end = datetime(2026, 1, 2, tzinfo=timezone.utc)

    result = routes_audit_events.list_audit_events(
        page=2, page_size=10, user_id="u1", service="auth",
        event_type="login", decision="allow", from_timestamp=start,
        to_timestamp=end, integrity_status="valid", db=db, _admin={"sub": "admin"},
    )

    assert result.total == 0
    assert result.total_pages == 0
    assert captured == {
        "db": db, "page": 2, "page_size": 10, "user_id": "u1",
        "service": "auth", "event_type": "login", "decision": "allow",
        "from_timestamp": start, "to_timestamp": end,
        "integrity_status": "valid",
    }


def test_list_audit_events_route_calculates_nonempty_total_pages(monkeypatch):
    monkeypatch.setattr(
        routes_audit_events.audit_query_service,
        "list_audit_events",
        lambda *args, **kwargs: ([], 21),
    )

    result = routes_audit_events.list_audit_events(
        page=1, page_size=20, db=MagicMock(), _admin={"sub": "admin"}
    )

    assert result.total == 21
    assert result.total_pages == 2


def test_get_db_closes_session_after_normal_iteration(monkeypatch):
    db = MagicMock()
    monkeypatch.setattr("db.session.SessionLocal", MagicMock(return_value=db))

    yielded = list(get_db())

    assert yielded == [db]
    db.close.assert_called_once_with()


def test_get_db_closes_session_when_consumer_raises(monkeypatch):
    db = MagicMock()
    monkeypatch.setattr("db.session.SessionLocal", MagicMock(return_value=db))
    generator = get_db()

    assert next(generator) is db
    with pytest.raises(RuntimeError, match="request failed"):
        generator.throw(RuntimeError("request failed"))
    db.close.assert_called_once_with()
