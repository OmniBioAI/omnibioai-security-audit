"""Synthetic contract tests for Skills and Policy durable audit receipts."""

from base64 import urlsafe_b64encode
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from audit.skills_contract import (
    CONTRACT_APPROVAL_REFERENCE,
    RETENTION_APPROVAL_REFERENCE,
    SIGNING_APPROVAL_REFERENCE,
    DurableAuditReceiptV1,
    Ed25519ReceiptSigner,
    PolicyAuditEventV1,
    SkillsAuditEventV1,
)
from db.models import AuditEventRecord, SkillsAuditReceiptRecord
from services.skills_audit_receipts import (
    AuditIdempotencyConflict,
    AuditTenantMismatch,
    DurableReceiptService,
    ReceiptIntegrityError,
    SkillsAuditDisabled,
    SkillsAuditSettings,
    SQLReceiptStore,
    StoredReceipt,
)

NOW = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)
SIGNING_SEED = bytes(range(32))
SIGNING_KEY = urlsafe_b64encode(SIGNING_SEED).decode().rstrip("=")
PSEUDONYM_KEY = "synthetic principal pseudonymization key, 32 bytes"


class MemoryStore:
    def __init__(self) -> None:
        self.records: dict[str, StoredReceipt] = {}
        self.events: dict[str, object] = {}

    def health(self) -> bool:
        return True

    def persist(self, event, receipt):
        existing = self.records.get(event.event_id)
        if existing:
            if existing.event_digest != receipt.event_digest:
                raise AuditIdempotencyConflict("conflict")
            return existing
        self.records[event.event_id] = receipt
        self.events[event.event_id] = event
        return receipt

    def get(self, event_id: str):
        return self.records.get(event_id)


def skills_event(**changes) -> SkillsAuditEventV1:
    values = {
        "timestamp": NOW,
        "event_type": "skill_plan_validated",
        "organization_id": "7",
        "principal_id": "principal-42",
        "action": "skills.validate",
        "resource": "skill:org.example.tool@1.0.0",
        "outcome": "success",
        "correlation_id": "corr-1",
        "decision_id": "decision-1",
    }
    values.update(changes)
    return SkillsAuditEventV1.build(**values)


def policy_event(**changes) -> PolicyAuditEventV1:
    values = {
        "event_id": "0123456789abcdef0123456789abcdef",
        "timestamp": NOW,
        "service": "omnibioai-policy-engine",
        "event_type": "skill_authorization",
        "user_id": "principal-42",
        "organization_id": "7",
        "tenant_scope": "organization",
        "action": "skill.plan",
        "resource": "skill:org.example.tool@1.0.0",
        "decision": "allow",
        "reason": "NONE",
        "trace_id": "corr-1",
        "context": {
            "decision_id": "decision-1",
            "policy_version": "skills-policy-v2",
            "policy_source": "SKILLS_PERMISSION",
            "enforcement": "enforced",
            "cache_age_bucket": "fresh",
            "latency_bucket": "lt_100ms",
            "error_code": "NONE",
        },
    }
    values.update(changes)
    return PolicyAuditEventV1.model_validate(values)


def receipt_service(store=None, *, times=(NOW,)):
    clock_values = iter(times)
    signer = Ed25519ReceiptSigner(
        private_key=SIGNING_SEED, key_id="skills-receipt-test-v1"
    )
    return DurableReceiptService(
        store=store or MemoryStore(),
        signer=signer,
        clock=lambda: next(clock_values),
    )


def test_live_feature_and_runtime_providers_are_off_or_absent_by_default(monkeypatch):
    for name in (
        "SKILLS_SECURITY_AUDIT_LIVE",
        "SKILLS_SECURITY_AUDIT_KILL_SWITCH",
        "AUDIT_RETENTION_DAYS",
        "AUDIT_SKILLS_RECEIPT_SIGNING_PRIVATE_KEY",
        "AUDIT_SKILLS_RECEIPT_SIGNING_KEY_ID",
        "AUDIT_SKILLS_PRINCIPAL_PSEUDONYMIZATION_KEY",
        "SKILLS_AUDIT_SCHEMA_APPROVAL",
        "SKILLS_AUDIT_RETENTION_APPROVAL",
        "SKILLS_AUDIT_SIGNING_APPROVAL",
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(SkillsAuditDisabled):
        SkillsAuditSettings.from_env().build_signer()


def test_activation_requires_approved_contract_and_independent_keys(monkeypatch):
    settings = {
        "SKILLS_SECURITY_AUDIT_LIVE": "true",
        "SKILLS_SECURITY_AUDIT_KILL_SWITCH": "false",
        "AUDIT_RETENTION_DAYS": "90",
        "AUDIT_SKILLS_RECEIPT_SIGNING_PRIVATE_KEY": SIGNING_KEY,
        "AUDIT_SKILLS_RECEIPT_SIGNING_KEY_ID": "skills-receipt-v1",
        "AUDIT_SKILLS_PRINCIPAL_PSEUDONYMIZATION_KEY": PSEUDONYM_KEY,
        "SKILLS_AUDIT_SCHEMA_APPROVAL": CONTRACT_APPROVAL_REFERENCE,
        "SKILLS_AUDIT_RETENTION_APPROVAL": RETENTION_APPROVAL_REFERENCE,
        "SKILLS_AUDIT_SIGNING_APPROVAL": SIGNING_APPROVAL_REFERENCE,
    }
    for name, value in settings.items():
        monkeypatch.setenv(name, value)
    assert SkillsAuditSettings.from_env().build_signer().key_id == "skills-receipt-v1"
    monkeypatch.setenv("AUDIT_SKILLS_PRINCIPAL_PSEUDONYMIZATION_KEY", SIGNING_KEY)
    with pytest.raises(SkillsAuditDisabled, match="distinct"):
        SkillsAuditSettings.from_env().build_signer()


@pytest.mark.parametrize("tenant", ["tenant-a", "７", "", "1" * 256, "042", 42])
def test_skills_event_requires_opaque_ascii_decimal_tenant(tenant):
    with pytest.raises(ValidationError):
        skills_event(organization_id=tenant)


@pytest.mark.parametrize("reason", ["access granted", "Bearer x", "token=abc"])
def test_skills_reason_fields_accept_machine_codes_only(reason):
    with pytest.raises(ValidationError):
        skills_event(reason_code=reason)


def test_skills_event_rejects_unknown_payload_fields_and_detects_tampering():
    event = skills_event()
    with pytest.raises(ValidationError):
        SkillsAuditEventV1.model_validate(
            {**event.model_dump(mode="json"), "inputs": {"patient": "synthetic"}}
        )
    with pytest.raises(ValidationError, match="does not bind"):
        SkillsAuditEventV1.model_validate(
            {**event.model_dump(mode="json"), "correlation_id": "changed"}
        )


def test_policy_compatibility_schema_matches_upstream_and_rejects_extra_context():
    event = policy_event()
    assert event.organization_id == "7"
    with pytest.raises(ValidationError):
        policy_event(organization_id="042")
    with pytest.raises(ValidationError):
        policy_event(organization_id=42)
    with pytest.raises(ValidationError):
        policy_event(context={"raw_payload": "synthetic"})
    with pytest.raises(ValidationError):
        policy_event(organization_id="tenant-a")


def test_signed_durable_receipt_is_bound_and_replay_is_idempotent():
    store = MemoryStore()
    later = NOW + timedelta(seconds=1)
    service = receipt_service(store, times=(NOW, later))
    event = skills_event()
    first = service.emit(event, idempotency_key=event.event_id, verified_tenant="7")
    again = service.emit(event, idempotency_key=event.event_id, verified_tenant="7")
    assert isinstance(first, DurableAuditReceiptV1)
    assert again == first
    assert service._signer.verify(first.signed_fields(), first.signature)
    assert not service._signer.verify(
        {"event_id": first.event_id, "organization_id": first.organization_id},
        first.signature,
    )
    assert len(store.records) == 1


def test_policy_event_receives_full_signed_receipt_before_local_projection():
    event = policy_event()
    receipt = receipt_service().emit(
        event, idempotency_key=event.event_id, verified_tenant="7"
    )
    assert isinstance(receipt, DurableAuditReceiptV1)
    assert receipt.event_id == event.event_id
    assert receipt.durable is True
    assert receipt.accepted_schema_version == "policy-audit/v1"
    assert receipt_service()._signer.verify(receipt.signed_fields(), receipt.signature)


def test_idempotency_tenant_health_and_signature_fail_closed():
    service = receipt_service()
    event = skills_event()
    with pytest.raises(AuditIdempotencyConflict):
        service.emit(event, idempotency_key="different", verified_tenant="7")
    with pytest.raises(AuditTenantMismatch):
        service.emit(event, idempotency_key=event.event_id, verified_tenant="8")
    with pytest.raises(AuditTenantMismatch):
        service.emit(event, idempotency_key=event.event_id, verified_tenant="tenant-a")

    class Unhealthy(MemoryStore):
        def health(self) -> bool:
            return False

    with pytest.raises(SkillsAuditDisabled):
        receipt_service(Unhealthy()).emit(
            event, idempotency_key=event.event_id, verified_tenant="7"
        )

    class TamperingStore(MemoryStore):
        def persist(self, source, receipt):
            return super().persist(
                source, replace(receipt, signature="ed25519:tampered")
            )

    with pytest.raises(ReceiptIntegrityError):
        receipt_service(TamperingStore()).emit(
            event, idempotency_key=event.event_id, verified_tenant="7"
        )


def test_sql_store_persists_event_and_signed_receipt_atomically_with_pseudonym(
    db_session,
):
    event = skills_event()
    signer = Ed25519ReceiptSigner(
        private_key=SIGNING_SEED, key_id="skills-receipt-test-v1"
    )
    service = DurableReceiptService(
        store=SQLReceiptStore(db_session, principal_key=PSEUDONYM_KEY),
        signer=signer,
        clock=lambda: NOW,
    )
    receipt = service.emit(event, idempotency_key=event.event_id, verified_tenant="7")
    audit_row = db_session.get(AuditEventRecord, event.event_id)
    receipt_row = db_session.get(SkillsAuditReceiptRecord, event.event_id)
    assert audit_row is not None
    assert audit_row.user_id.startswith("p_")
    assert audit_row.user_id != event.principal_id
    assert receipt_row is not None
    assert receipt_row.signature == receipt.signature
    assert service.get(event_id=event.event_id, verified_tenant="7") == receipt
    with pytest.raises(AuditTenantMismatch):
        service.get(event_id=event.event_id, verified_tenant="8")


def test_lane1_receipt_fixture_has_expected_wire_shape():
    import json

    raw = json.loads(
        (Path(__file__).parent / "fixtures/skills_audit_receipt_v1.json").read_text(
            encoding="utf-8"
        )
    )
    event = SkillsAuditEventV1.model_validate(raw["event"])
    receipt = DurableAuditReceiptV1.model_validate(raw["receipt"])
    assert receipt.event_id == event.event_id
    assert receipt.organization_id == event.organization_id
    assert receipt.accepted_schema_version == event.schema_version
    signer = Ed25519ReceiptSigner(private_key=SIGNING_SEED, key_id=receipt.key_id)
    assert signer.verify(receipt.signed_fields(), receipt.signature)
    with pytest.raises(ValidationError):
        DurableAuditReceiptV1.model_validate(
            {**raw["receipt"], "organization_id": "042"}
        )
