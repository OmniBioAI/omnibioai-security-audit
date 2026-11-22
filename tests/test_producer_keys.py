"""Per-producer verification keys (audit/producer_keys.py) and their worker wiring.

The "mcp" producer's events are verified with the mcp key ONLY; anything that
fails is quarantined as "signature_rejected". Every other producer keeps the
JWT_SECRET path: tests/test_worker.py's signature tests run unchanged.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import json
from unittest.mock import MagicMock, patch

import pytest

import worker.main as worker
from audit import producer_keys as pk
from audit.signing import sign_audit_event
from consumers.quarantine import QuarantineSink

JWT = "synthetic-platform-jwt-secret-for-tests-0001"
MCP_KEY = "synthetic-mcp-producer-key-for-tests-0123456789"


def _raw(service="omnibioai-mcp", event_id="evt-mcp-1", event_type="mcp.tool_call"):
    return json.dumps({
        "event_id": event_id,
        "timestamp": "2026-11-22T12:00:00+00:00",
        "service": service,
        "event_type": event_type,
        "user_id": "5",
        "organization_id": "1",
        "tenant_scope": "organization",
        "action": "graphs_list",
        "decision": "ok",
        "context": {"client_id": "stdio-dev", "request_id": "r1"},
    })


def _key_file(tmp_path, content=MCP_KEY, mode=0o600):
    path = tmp_path / "audit_producer_mcp_key"
    path.write_text(content + "\n")
    path.chmod(mode)
    return path


@pytest.fixture
def mcp_key(tmp_path, monkeypatch):
    """A valid mcp key file, and a fresh key cache in the worker."""
    path = _key_file(tmp_path)
    monkeypatch.setenv("AUDIT_PRODUCER_KEY_FILE_MCP", str(path))
    monkeypatch.setattr(worker, "_producer_keys", pk.ProducerKeys(JWT))
    return path


@pytest.fixture
def no_mcp_key(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_PRODUCER_KEY_FILE_MCP", str(tmp_path / "absent"))
    monkeypatch.setattr(worker, "_producer_keys", pk.ProducerKeys(JWT))


def _handle(fields):
    """handle_message() with DB sinks mocked. Returns (result, persisted, quarantined, reader)."""
    reader = MagicMock()
    sink, quarantine = MagicMock(), MagicMock()
    sink.write.return_value = quarantine.write.return_value = True
    with patch("worker.main.SessionLocal", return_value=MagicMock()), \
         patch("worker.main.Sink", return_value=sink), \
         patch("worker.main.QuarantineSink", return_value=quarantine), \
         patch.object(worker.AuditConfig, "EVENT_SIGNING_SECRET", JWT):
        result = worker.handle_message(reader, "7-0", fields)
    persisted = sink.write.call_args[0][0] if sink.write.called else None
    quarantined = quarantine.write.call_args if quarantine.write.called else None
    return result, persisted, quarantined, reader


def _rejected(quarantined, reason):
    args, kwargs = quarantined
    assert args[0] == "7-0"
    assert kwargs == {"failure_category": "signature_rejected", "failure_detail": reason}


# ── the three required cases ────────────────────────────────────────────────


def test_valid_mcp_event_is_accepted_as_valid(mcp_key):
    raw = _raw()
    fields = {"data": raw, "sig": sign_audit_event("omnibioai-mcp", raw, MCP_KEY), "producer": "mcp"}
    result, persisted, quarantined, reader = _handle(fields)
    assert result is True and quarantined is None
    assert persisted["integrity_status"] == "valid" and persisted["service"] == "omnibioai-mcp"
    reader.ack.assert_called_once_with("7-0")


def test_mcp_event_signed_with_jwt_secret_is_quarantined(mcp_key):
    raw = _raw()
    fields = {"data": raw, "sig": sign_audit_event("omnibioai-mcp", raw, JWT), "producer": "mcp"}
    result, persisted, quarantined, reader = _handle(fields)
    assert result is True and persisted is None
    _rejected(quarantined, "SignatureInvalid")
    reader.ack.assert_called_once_with("7-0")  # quarantined first, then acked


def test_missing_key_file_quarantines_mcp_events_and_leaves_others_alone(no_mcp_key):
    raw = _raw()
    fields = {"data": raw, "sig": sign_audit_event("omnibioai-mcp", raw, MCP_KEY), "producer": "mcp"}
    result, persisted, quarantined, _ = _handle(fields)
    assert result is True and persisted is None
    _rejected(quarantined, "ProducerKeyUnavailable")

    other = _raw(service="api-gateway", event_id="evt-gw-1", event_type="request")
    result, persisted, quarantined, reader = _handle(
        {"data": other, "sig": sign_audit_event("api-gateway", other, JWT)}
    )
    assert result is True and quarantined is None
    assert persisted["integrity_status"] == "valid"
    reader.ack.assert_called_once_with("7-0")


# ── routing and downgrade ───────────────────────────────────────────────────


def test_mcp_service_without_producer_field_still_needs_the_mcp_key(mcp_key):
    """Dropping `producer` must not fall back to JWT_SECRET (a JWT_SECRET holder can't forge MCP)."""
    raw = _raw()
    _, persisted, quarantined, _ = _handle(
        {"data": raw, "sig": sign_audit_event("omnibioai-mcp", raw, JWT)}
    )
    assert persisted is None
    _rejected(quarantined, "SignatureInvalid")

    _, persisted, quarantined, _ = _handle(
        {"data": raw, "sig": sign_audit_event("omnibioai-mcp", raw, MCP_KEY)}
    )
    assert quarantined is None and persisted["integrity_status"] == "valid"


def test_mcp_event_type_under_a_look_alike_service_needs_the_mcp_key(mcp_key):
    """Review N6: event_type mcp.* is reserved too, not only service omnibioai-mcp."""
    raw = _raw(service="omnibioai-mcp2")
    _, persisted, quarantined, _ = _handle(
        {"data": raw, "sig": sign_audit_event("omnibioai-mcp2", raw, JWT)}
    )
    assert persisted is None
    _rejected(quarantined, "ServiceNotOwnedByProducer")


def test_legacy_event_types_are_not_routed():
    assert pk.producer_for({}, "api-gateway", "request") is None
    assert pk.producer_for({}, "tes", "tes_submit") is None
    assert pk.producer_for({}, "lims", "mcpish_event") is None  # prefix is "mcp." with the dot
    assert pk.producer_for({}, "x", "mcp.tool_call") == "mcp"


def test_preload_reports_the_key_at_startup(mcp_key, capsys):
    keys = pk.ProducerKeys(JWT)
    pk.preload(keys)
    assert "audit producer key for 'mcp' loaded" in capsys.readouterr().out
    mcp_key.unlink()
    assert keys.get("mcp") == MCP_KEY  # loaded once, at startup


def test_preload_reports_a_missing_key_without_failing(no_mcp_key, capsys):
    pk.preload(pk.ProducerKeys(JWT))
    assert "unavailable (missing)" in capsys.readouterr().out


def test_mcp_key_cannot_sign_for_another_service(mcp_key):
    raw = _raw(service="api-gateway", event_type="request")
    _, persisted, quarantined, _ = _handle(
        {"data": raw, "sig": sign_audit_event("api-gateway", raw, MCP_KEY), "producer": "mcp"}
    )
    assert persisted is None
    _rejected(quarantined, "ServiceNotOwnedByProducer")


@pytest.mark.parametrize(
    ("fields_extra", "reason"),
    [({"producer": "billing"}, "UnknownProducer"), ({}, "Unsigned")],
)
def test_unknown_producer_and_unsigned_mcp_are_quarantined(mcp_key, fields_extra, reason):
    raw = _raw()
    fields = {"data": raw, **fields_extra}
    if reason == "UnknownProducer":
        fields["sig"] = sign_audit_event("omnibioai-mcp", raw, MCP_KEY)
    _, persisted, quarantined, _ = _handle(fields)
    assert persisted is None
    _rejected(quarantined, reason)


def test_legacy_producers_are_untouched_by_routing():
    assert pk.producer_for({"data": "{}"}, "api-gateway") is None
    assert pk.producer_for({"data": "{}", "sig": "v1:x"}, "auth") is None
    assert pk.producer_for({}, "omnibioai-mcp") == "mcp"
    assert pk.producer_for({"producer": "mcp"}, "anything") == "mcp"


def test_quarantine_write_failure_leaves_the_mcp_entry_pending(mcp_key):
    raw = _raw()
    reader, quarantine = MagicMock(), MagicMock()
    quarantine.write.side_effect = RuntimeError("mysql down")
    with patch("worker.main.SessionLocal", return_value=MagicMock()), \
         patch("worker.main.QuarantineSink", return_value=quarantine):
        result = worker.handle_message(reader, "7-0", {"data": raw, "producer": "mcp"})
    assert result is False
    reader.ack.assert_not_called()


def test_rejection_message_never_prints_key_or_signature(mcp_key, capsys):
    raw = _raw()
    sig = sign_audit_event("omnibioai-mcp", raw, JWT)
    _handle({"data": raw, "sig": sig, "producer": "mcp"})
    out = capsys.readouterr().out
    assert "PRODUCER SIGNATURE REJECTED" in out and "SignatureInvalid" in out
    for secret in (MCP_KEY, JWT, sig):
        assert secret not in out


# ── key file rules ──────────────────────────────────────────────────────────


def test_key_file_is_read_once_per_process(mcp_key):
    keys = pk.ProducerKeys(JWT)
    assert keys.get("mcp") == MCP_KEY
    mcp_key.unlink()
    assert keys.get("mcp") == MCP_KEY  # cached; rotation needs a restart


@pytest.mark.parametrize(
    ("content", "mode", "reason"),
    [
        (MCP_KEY, 0o644, "mode_not_600"),
        (MCP_KEY, 0o640, "mode_not_600"),
        ("short", 0o600, "too_short"),
        (JWT, 0o600, "equals_jwt_secret"),
    ],
)
def test_unsafe_key_files_are_refused(tmp_path, content, mode, reason):
    key, why = pk.load_key_file(str(_key_file(tmp_path, content, mode)), jwt_secret=JWT)
    assert key is None and why == reason


def test_symlink_missing_and_directory_are_refused(tmp_path):
    target = _key_file(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(target)
    assert pk.load_key_file(str(link), jwt_secret=JWT) == (None, "symlink")
    assert pk.load_key_file(str(tmp_path / "nope"), jwt_secret=JWT) == (None, "missing")
    assert pk.load_key_file(str(tmp_path), jwt_secret=JWT) == (None, "not_a_regular_file")


def test_unavailable_key_is_reported_once_without_key_material(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AUDIT_PRODUCER_KEY_FILE_MCP", str(_key_file(tmp_path, mode=0o644)))
    keys = pk.ProducerKeys(JWT)
    assert keys.get("mcp") is None and keys.get("mcp") is None
    out = capsys.readouterr().out
    assert out.count("unavailable (mode_not_600)") == 1 and MCP_KEY not in out


def test_default_key_path(monkeypatch):
    monkeypatch.delenv("AUDIT_PRODUCER_KEY_FILE_MCP", raising=False)
    assert pk.key_file_path("mcp") == "/run/secrets/audit_producer_mcp_key"


# ── quarantine record ───────────────────────────────────────────────────────


def test_quarantine_sink_records_the_override_category():
    db_session = MagicMock()
    QuarantineSink(db_session).write(
        "7-0",
        {"data": _raw(), "sig": "v1:bad", "producer": "mcp"},
        1,
        failure_category="signature_rejected",
        failure_detail="SignatureInvalid",
    )
    record = db_session.add.call_args[0][0]
    assert (record.failure_category, record.failure_detail) == ("signature_rejected", "SignatureInvalid")
    assert record.service == "omnibioai-mcp" and record.raw_signature == "v1:bad"
    assert record.record_integrity_hash
