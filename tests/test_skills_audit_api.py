"""HTTP contract and default-off checks using only synthetic workload identities."""

import json
import socket
from pathlib import Path

from fastapi.testclient import TestClient

from api.deps_skills_audit import (
    require_skills_audit_reader,
    require_skills_audit_writer,
)
from api.main import app
from api.routes_skills_audit import (
    get_live_receipt_reader_service,
    get_live_receipt_service,
)
from audit.skills_contract import Ed25519ReceiptSigner
from db.session import get_writer_db
from services.skills_audit_receipts import DurableReceiptService
from tests.test_skills_audit_contract import SIGNING_SEED, MemoryStore, policy_event


def _event_payload() -> dict:
    return json.loads(
        (Path(__file__).parent / "fixtures/skills_audit_receipt_v1.json").read_text(
            encoding="utf-8"
        )
    )["event"]


def test_disabled_default_fails_without_network_or_store_access(monkeypatch):
    monkeypatch.delenv("SKILLS_SECURITY_AUDIT_LIVE", raising=False)
    monkeypatch.delenv("SKILLS_SECURITY_AUDIT_KILL_SWITCH", raising=False)
    monkeypatch.delenv("AUDIT_SKILLS_RECEIPT_SIGNING_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("AUDIT_SKILLS_PRINCIPAL_PSEUDONYMIZATION_KEY", raising=False)

    def unexpected_network(*_args, **_kwargs):
        raise AssertionError("network I/O attempted while the feature is disabled")

    monkeypatch.setattr(socket.socket, "connect", unexpected_network)

    def writer_db_override():
        yield None

    app.dependency_overrides[get_writer_db] = writer_db_override
    app.dependency_overrides[require_skills_audit_writer] = lambda: "7"
    try:
        with TestClient(app) as client:
            response = client.post(
                "/audit/receipts",
                json=_event_payload(),
                headers={
                    "Authorization": "Bearer synthetic-token",
                    "Idempotency-Key": _event_payload()["event_id"],
                },
            )
        assert response.status_code == 503
        assert "disabled" in response.json()["detail"]
    finally:
        app.dependency_overrides.pop(get_writer_db, None)
        app.dependency_overrides.pop(require_skills_audit_writer, None)


def test_receipt_endpoints_return_sdk_and_policy_wire_contracts():
    signer = Ed25519ReceiptSigner(
        private_key=SIGNING_SEED,
        key_id="skills-receipt-test-v1",
    )
    service = DurableReceiptService(store=MemoryStore(), signer=signer)
    app.dependency_overrides[get_live_receipt_service] = lambda: service
    app.dependency_overrides[get_live_receipt_reader_service] = lambda: service
    app.dependency_overrides[require_skills_audit_writer] = lambda: "42"
    app.dependency_overrides[require_skills_audit_reader] = lambda: "42"
    try:
        with TestClient(app) as client:
            sdk_event = _event_payload()
            sdk_response = client.post(
                "/audit/receipts",
                json=sdk_event,
                headers={"Idempotency-Key": sdk_event["event_id"]},
            )
            assert sdk_response.status_code == 200
            sdk_receipt = sdk_response.json()
            assert sdk_receipt["event_id"] == sdk_event["event_id"]
            assert sdk_receipt["signature"].startswith("ed25519:")
            assert (
                client.get(f"/audit/receipts/{sdk_event['event_id']}").json()
                == sdk_receipt
            )

            policy = policy_event(organization_id="42").model_dump(mode="json")
            policy_response = client.post("/audit/receipts", json=policy)
            assert policy_response.status_code == 200
            policy_receipt = policy_response.json()
            assert policy_receipt["event_id"] == policy["event_id"]
            assert policy_receipt["accepted_schema_version"] == "policy-audit/v1"
            assert signer.verify(
                {
                    key: value
                    for key, value in policy_receipt.items()
                    if key != "signature"
                },
                policy_receipt["signature"],
            )
    finally:
        app.dependency_overrides.pop(get_live_receipt_service, None)
        app.dependency_overrides.pop(get_live_receipt_reader_service, None)
        app.dependency_overrides.pop(require_skills_audit_writer, None)
        app.dependency_overrides.pop(require_skills_audit_reader, None)
