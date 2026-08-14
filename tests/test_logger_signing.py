"""HIPAA PR3b: producer-side signing for AuditLogger.log() -- this
repo's own native audit:events producer, used by api/routes_audit.py.

Unlike every other producer in the platform (api-gateway, tes,
workflow-bundles, control-center, rag -- all separate deployables that
hand-port sign_audit_event()), this one lives in the same repo as
audit.signing itself and imports it directly: no drift risk, no parallel
copy to keep in sync. These tests exercise AuditLogger.log()'s new
signing behavior specifically; tests/test_signing.py already covers
sign_audit_event/verify_audit_event in isolation and is untouched.
"""
import json
from unittest.mock import AsyncMock

import pytest

from audit.config import AuditConfig
from audit.models import AuditEvent
from audit.signing import verify_audit_event


@pytest.mark.asyncio
async def test_log_signs_the_exact_data_string_it_publishes(audit_logger, monkeypatch):
    logger, mock_redis = audit_logger
    mock_redis.xadd = AsyncMock()
    monkeypatch.setattr(AuditConfig, "EVENT_SIGNING_SECRET", "s3cr3t")

    event = AuditEvent(service="security-audit", event_type="platform_admin_action")
    await logger.log(event)

    fields = mock_redis.xadd.call_args[0][1]
    data = fields["data"]
    sig = fields["sig"]
    assert verify_audit_event("security-audit", data, sig, "s3cr3t") is True
    assert json.loads(data)["event_id"] == event.event_id


@pytest.mark.asyncio
async def test_log_includes_both_data_and_sig_fields(audit_logger, monkeypatch):
    logger, mock_redis = audit_logger
    mock_redis.xadd = AsyncMock()
    monkeypatch.setattr(AuditConfig, "EVENT_SIGNING_SECRET", "s3cr3t")

    await logger.log(AuditEvent(service="security-audit", event_type="platform_admin_action"))

    fields = mock_redis.xadd.call_args[0][1]
    assert "data" in fields
    assert fields["sig"].startswith("v1:")


@pytest.mark.asyncio
async def test_log_signature_does_not_verify_under_a_different_secret(audit_logger, monkeypatch):
    logger, mock_redis = audit_logger
    mock_redis.xadd = AsyncMock()
    monkeypatch.setattr(AuditConfig, "EVENT_SIGNING_SECRET", "s3cr3t")

    await logger.log(AuditEvent(service="security-audit", event_type="platform_admin_action"))

    fields = mock_redis.xadd.call_args[0][1]
    assert verify_audit_event("security-audit", fields["data"], fields["sig"], "wrong-secret") is False


@pytest.mark.asyncio
async def test_log_tampered_data_fails_verification(audit_logger, monkeypatch):
    """Proves the signature is bound to this exact payload -- modifying
    even one field after signing must invalidate it."""
    logger, mock_redis = audit_logger
    mock_redis.xadd = AsyncMock()
    monkeypatch.setattr(AuditConfig, "EVENT_SIGNING_SECRET", "s3cr3t")

    await logger.log(AuditEvent(service="security-audit", event_type="platform_admin_action", decision="allow"))

    fields = mock_redis.xadd.call_args[0][1]
    tampered = fields["data"].replace('"allow"', '"deny"')
    assert verify_audit_event("security-audit", tampered, fields["sig"], "s3cr3t") is False
    # the untampered original still verifies -- proves the failure above
    # is specifically about the tampering, not a broken signature.
    assert verify_audit_event("security-audit", fields["data"], fields["sig"], "s3cr3t") is True


@pytest.mark.asyncio
async def test_log_without_a_service_still_publishes_unsigned(audit_logger, monkeypatch):
    """AuditEvent.service is a required, non-empty field on the real
    model, so this can only happen via a MagicMock stand-in whose
    model_dump() omits it -- still must not silently drop the event."""
    from unittest.mock import MagicMock

    logger, mock_redis = audit_logger
    mock_redis.xadd = AsyncMock()
    monkeypatch.setattr(AuditConfig, "EVENT_SIGNING_SECRET", "s3cr3t")

    fake_event = MagicMock()
    fake_event.model_dump.return_value = {
        "event_id": "e1", "timestamp": "2024-01-01T00:00:00", "event_type": "x",
        "user_id": None, "action": "", "resource": None, "decision": None,
        "reason": None, "trace_id": None, "context": {},
    }  # no "service" key
    await logger.log(fake_event)

    fields = mock_redis.xadd.call_args[0][1]
    assert "data" in fields
    assert "sig" not in fields


@pytest.mark.asyncio
async def test_log_exception_never_leaks_the_secret(audit_logger, monkeypatch, capsys):
    logger, mock_redis = audit_logger
    mock_redis.xadd = AsyncMock(side_effect=RuntimeError("boom"))
    monkeypatch.setattr(AuditConfig, "EVENT_SIGNING_SECRET", "super-secret-value")

    await logger.log(
        AuditEvent(service="security-audit", event_type="platform_admin_action")
    )  # must not raise

    captured = capsys.readouterr()
    assert "super-secret-value" not in captured.out
    assert "super-secret-value" not in captured.err


def test_config_signing_secret_is_the_one_source_of_truth():
    """AuditConfig.EVENT_SIGNING_SECRET (audit/config.py) was already
    defined by PR2 specifically for this eventual purpose -- signing
    imports it directly rather than reading JWT_SECRET a second time."""
    import os

    assert AuditConfig.EVENT_SIGNING_SECRET == os.getenv("JWT_SECRET", "change-me")
