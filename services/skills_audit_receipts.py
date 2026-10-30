"""Transactional durable receipts for approved Skills audit events."""

from __future__ import annotations

import hashlib
import hmac
import os
from base64 import urlsafe_b64decode
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy.exc import IntegrityError as SQLIntegrityError
from sqlalchemy.orm import Session

from audit.config import AuditConfig
from audit.record_integrity import compute_audit_event_hash, to_naive_utc
from audit.skills_contract import (
    CONTRACT_APPROVAL_REFERENCE,
    MINIMUM_RETENTION_DAYS,
    RETENTION_APPROVAL_REFERENCE,
    SIGNING_APPROVAL_REFERENCE,
    DurableAuditReceiptV1,
    Ed25519ReceiptSigner,
    PolicyAuditEventV1,
    PolicyAuditReceiptV1,
    ReceiptSigner,
    SkillsAuditEventV1,
    event_digest,
    event_schema_version,
    event_tenant,
)
from db.models import AuditEventRecord, SkillsAuditReceiptRecord


class SkillsAuditDisabled(RuntimeError):
    pass


class AuditSchemaRejected(ValueError):
    pass


class AuditTenantMismatch(PermissionError):
    pass


class AuditIdempotencyConflict(RuntimeError):
    pass


class ReceiptIntegrityError(RuntimeError):
    pass


@dataclass(frozen=True)
class SkillsAuditSettings:
    live: bool
    kill_switch: bool
    retention_days: int | None
    signing_private_key: str | None
    signing_key_id: str | None
    schema_approval: str | None
    retention_approval: str | None
    signing_approval: str | None
    principal_pseudonymization_key: str | None

    @classmethod
    def from_env(cls) -> SkillsAuditSettings:
        retention = os.getenv("AUDIT_RETENTION_DAYS")
        try:
            retention_days = int(retention) if retention else None
        except ValueError:
            retention_days = None
        return cls(
            live=os.getenv("SKILLS_SECURITY_AUDIT_LIVE", "false").lower() == "true",
            kill_switch=os.getenv("SKILLS_SECURITY_AUDIT_KILL_SWITCH", "false").lower()
            == "true",
            retention_days=retention_days,
            signing_private_key=os.getenv("AUDIT_SKILLS_RECEIPT_SIGNING_PRIVATE_KEY"),
            signing_key_id=os.getenv("AUDIT_SKILLS_RECEIPT_SIGNING_KEY_ID"),
            schema_approval=os.getenv("SKILLS_AUDIT_SCHEMA_APPROVAL"),
            retention_approval=os.getenv("SKILLS_AUDIT_RETENTION_APPROVAL"),
            signing_approval=os.getenv("SKILLS_AUDIT_SIGNING_APPROVAL"),
            principal_pseudonymization_key=os.getenv(
                "AUDIT_SKILLS_PRINCIPAL_PSEUDONYMIZATION_KEY"
            ),
        )

    def build_signer(self) -> Ed25519ReceiptSigner:
        if not self.live or self.kill_switch:
            raise SkillsAuditDisabled("Skills durable audit is disabled")
        if self.retention_days is None or self.retention_days < MINIMUM_RETENTION_DAYS:
            raise SkillsAuditDisabled("approved Skills audit retention is absent")
        if self.schema_approval != CONTRACT_APPROVAL_REFERENCE:
            raise SkillsAuditDisabled("Skills event schema approval is absent")
        if self.retention_approval != RETENTION_APPROVAL_REFERENCE:
            raise SkillsAuditDisabled("Skills retention approval is absent")
        if self.signing_approval != SIGNING_APPROVAL_REFERENCE:
            raise SkillsAuditDisabled("receipt signing approval is absent")
        if not self.signing_private_key or not self.signing_key_id:
            raise SkillsAuditDisabled("receipt signing provider is absent")
        if (
            not self.principal_pseudonymization_key
            or len(self.principal_pseudonymization_key.encode()) < 32
        ):
            raise SkillsAuditDisabled("principal pseudonymization provider is absent")
        for unrelated in (
            AuditConfig.EVENT_SIGNING_SECRET,
            AuditConfig.RECORD_INTEGRITY_KEY,
        ):
            if unrelated and (
                hmac.compare_digest(self.signing_private_key, unrelated)
                or hmac.compare_digest(self.principal_pseudonymization_key, unrelated)
            ):
                raise SkillsAuditDisabled(
                    "Skills audit keys must be independent from other keys"
                )
        if hmac.compare_digest(
            self.signing_private_key, self.principal_pseudonymization_key
        ):
            raise SkillsAuditDisabled(
                "receipt and pseudonymization keys must be distinct"
            )
        try:
            private_key = urlsafe_b64decode(
                self.signing_private_key + "=" * (-len(self.signing_private_key) % 4)
            )
            return Ed25519ReceiptSigner(
                private_key=private_key, key_id=self.signing_key_id
            )
        except (ValueError, TypeError) as exc:
            raise SkillsAuditDisabled("receipt signing provider is invalid") from exc


@dataclass(frozen=True)
class StoredReceipt:
    event_id: str
    receipt_id: str
    schema_version: str
    organization_id: str
    event_digest: str
    durable_at: datetime
    sink_partition: str
    key_id: str
    signature: str


class ReceiptStore(Protocol):
    def health(self) -> bool: ...

    def persist(
        self,
        event: SkillsAuditEventV1 | PolicyAuditEventV1,
        receipt: StoredReceipt,
    ) -> StoredReceipt: ...

    def get(self, event_id: str) -> StoredReceipt | None: ...


def _audit_row_values(
    event: SkillsAuditEventV1 | PolicyAuditEventV1,
) -> dict[str, object]:
    if isinstance(event, SkillsAuditEventV1):
        context = {
            key: value
            for key, value in {
                "schema_version": event.schema_version,
                "decision_id": event.decision_id,
                "plan_fingerprint": event.plan_fingerprint,
                "catalog_revision": event.catalog_revision,
                "error_code": event.error_code,
            }.items()
            if value is not None
        }
        return {
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "service": "omnibioai-skills",
            "event_type": event.event_type,
            "user_id": event.principal_id,
            "organization_id": event.organization_id,
            "tenant_scope": "organization",
            "action": event.action,
            "resource": event.resource,
            "decision": event.outcome,
            "reason": event.reason_code,
            "trace_id": event.correlation_id,
            "context": context,
            "integrity_status": "valid",
        }
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "service": event.service,
        "event_type": event.event_type,
        "user_id": event.user_id,
        "organization_id": event.organization_id,
        "tenant_scope": event.tenant_scope,
        "action": event.action,
        "resource": event.resource,
        "decision": event.decision,
        "reason": event.reason,
        "trace_id": event.trace_id,
        "context": event.context,
        "integrity_status": "valid",
    }


class SQLReceiptStore:
    """Persist an event and its receipt atomically in the writer database."""

    def __init__(self, session: Session, *, principal_key: str) -> None:
        self._session = session
        if len(principal_key.encode()) < 32:
            raise ValueError(
                "principal pseudonymization key must contain at least 256 bits"
            )
        self._principal_key = principal_key.encode()

    def _principal_pseudonym(self, principal_id: str | None) -> str | None:
        if principal_id is None:
            return None
        message = b"omnibioai-security-audit-principal-v1\x00" + principal_id.encode(
            "utf-8"
        )
        digest = hmac.new(self._principal_key, message, hashlib.sha256).hexdigest()
        return f"p_{digest}"

    def _audit_row_values(
        self, event: SkillsAuditEventV1 | PolicyAuditEventV1
    ) -> dict[str, object]:
        values = _audit_row_values(event)
        principal_id = (
            event.principal_id
            if isinstance(event, SkillsAuditEventV1)
            else event.user_id
        )
        values["user_id"] = self._principal_pseudonym(principal_id)
        return values

    def health(self) -> bool:
        try:
            self._session.query(SkillsAuditReceiptRecord.event_id).limit(1).all()
            return True
        except Exception:  # noqa: BLE001 - health must fail closed
            return False

    @staticmethod
    def _stored(row: SkillsAuditReceiptRecord) -> StoredReceipt:
        return StoredReceipt(
            event_id=row.event_id,
            receipt_id=row.receipt_id,
            schema_version=row.schema_version,
            organization_id=row.organization_id,
            event_digest=row.event_digest,
            durable_at=row.durable_at.replace(tzinfo=UTC)
            if row.durable_at.tzinfo is None
            else row.durable_at,
            sink_partition=row.sink_partition,
            key_id=row.key_id,
            signature=row.signature,
        )

    def _existing(self, event_id: str) -> StoredReceipt | None:
        row = self._session.get(SkillsAuditReceiptRecord, event_id)
        return self._stored(row) if row is not None else None

    def get(self, event_id: str) -> StoredReceipt | None:
        return self._existing(event_id)

    @staticmethod
    def _check_duplicate(
        existing: StoredReceipt, candidate: StoredReceipt
    ) -> StoredReceipt:
        if (
            existing.event_digest != candidate.event_digest
            or existing.organization_id != candidate.organization_id
            or existing.schema_version != candidate.schema_version
        ):
            raise AuditIdempotencyConflict(
                "event_id was reused for different canonical bytes"
            )
        return existing

    def persist(
        self,
        event: SkillsAuditEventV1 | PolicyAuditEventV1,
        receipt: StoredReceipt,
    ) -> StoredReceipt:
        existing = self._existing(event.event_id)
        if existing is not None:
            return self._check_duplicate(existing, receipt)

        values = self._audit_row_values(event)
        timestamp = to_naive_utc(values["timestamp"])
        integrity_key, integrity_key_id = AuditConfig.require_record_integrity_key()
        integrity_values = {**values, "timestamp": timestamp}
        record_hash = compute_audit_event_hash(
            integrity_values, integrity_key, key_id=integrity_key_id
        )
        self._session.add(
            AuditEventRecord(
                **{**values, "timestamp": timestamp},
                record_integrity_hash=record_hash,
                integrity_key_id=integrity_key_id,
            )
        )
        self._session.add(
            SkillsAuditReceiptRecord(
                event_id=receipt.event_id,
                receipt_id=receipt.receipt_id,
                schema_version=receipt.schema_version,
                organization_id=receipt.organization_id,
                event_digest=receipt.event_digest,
                durable_at=to_naive_utc(receipt.durable_at),
                sink_partition=receipt.sink_partition,
                key_id=receipt.key_id,
                signature=receipt.signature,
            )
        )
        try:
            self._session.commit()
        except SQLIntegrityError as exc:
            self._session.rollback()
            existing = self._existing(event.event_id)
            if existing is None:
                raise AuditIdempotencyConflict(
                    "event identifier conflicts with existing audit evidence"
                ) from exc
            return self._check_duplicate(existing, receipt)
        return receipt


class DurableReceiptService:
    def __init__(
        self,
        *,
        store: ReceiptStore,
        signer: ReceiptSigner,
        verifiers: Mapping[str, ReceiptSigner] | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._store = store
        self._signer = signer
        self._verifiers = dict(verifiers or {}) | {signer.key_id: signer}
        self._clock = clock

    def health(self, *, require_durable: bool) -> bool:
        return bool(require_durable and self._store.health())

    def emit(
        self,
        event: SkillsAuditEventV1 | PolicyAuditEventV1,
        *,
        idempotency_key: str,
        verified_tenant: str,
    ) -> DurableAuditReceiptV1 | PolicyAuditReceiptV1:
        if not self._store.health():
            raise SkillsAuditDisabled("durable receipt store is unavailable")
        if idempotency_key != event.event_id:
            raise AuditIdempotencyConflict("idempotency key must equal event_id")
        if not re_full_decimal(verified_tenant) or not hmac.compare_digest(
            verified_tenant, event_tenant(event)
        ):
            raise AuditTenantMismatch("verified tenant does not match event tenant")

        digest = event_digest(event)
        schema = event_schema_version(event)
        durable_at = self._clock()
        if durable_at.tzinfo is None:
            raise ReceiptIntegrityError("receipt clock must include a timezone")
        receipt_id = (
            "receipt-"
            + hashlib.sha256(f"{schema}:{event.event_id}:{digest}".encode()).hexdigest()
        )
        partition = f"skills-{event.organization_id}"
        unsigned = DurableAuditReceiptV1(
            event_id=event.event_id,
            receipt_id=receipt_id,
            accepted_schema_version=schema,
            durable_at=durable_at,
            organization_id=event.organization_id,
            sink_partition=partition,
            key_id=self._signer.key_id,
            signature="pending",
        )
        signature = self._signer.sign(unsigned.signed_fields())
        candidate = StoredReceipt(
            event_id=event.event_id,
            receipt_id=receipt_id,
            schema_version=schema,
            organization_id=event.organization_id,
            event_digest=digest,
            durable_at=durable_at,
            sink_partition=partition,
            key_id=self._signer.key_id,
            signature=signature,
        )
        stored = self._store.persist(event, candidate)
        full = DurableAuditReceiptV1(
            event_id=stored.event_id,
            receipt_id=stored.receipt_id,
            accepted_schema_version=stored.schema_version,
            durable_at=stored.durable_at,
            organization_id=stored.organization_id,
            sink_partition=stored.sink_partition,
            key_id=stored.key_id,
            signature=stored.signature,
        )
        verifier = self._verifiers.get(full.key_id)
        if verifier is None or not verifier.verify(
            full.signed_fields(), full.signature
        ):
            raise ReceiptIntegrityError("stored receipt signature is invalid")
        if isinstance(event, PolicyAuditEventV1):
            return PolicyAuditReceiptV1(
                receipt_id=full.receipt_id,
                event_id=full.event_id,
                persisted_at=full.durable_at,
            )
        return full

    def get(
        self, *, event_id: str, verified_tenant: str
    ) -> DurableAuditReceiptV1 | None:
        if not re_full_decimal(verified_tenant):
            raise AuditTenantMismatch("verified tenant is invalid")
        stored = self._store.get(event_id)
        if stored is None:
            return None
        if not hmac.compare_digest(stored.organization_id, verified_tenant):
            raise AuditTenantMismatch("receipt is outside verified tenant")
        receipt = DurableAuditReceiptV1(
            event_id=stored.event_id,
            receipt_id=stored.receipt_id,
            accepted_schema_version=stored.schema_version,
            durable_at=stored.durable_at,
            organization_id=stored.organization_id,
            sink_partition=stored.sink_partition,
            key_id=stored.key_id,
            signature=stored.signature,
        )
        verifier = self._verifiers.get(receipt.key_id)
        if verifier is None or not verifier.verify(
            receipt.signed_fields(), receipt.signature
        ):
            raise ReceiptIntegrityError("stored receipt signature is invalid")
        return receipt


def re_full_decimal(value: str) -> bool:
    return bool(value) and len(value) <= 255 and value.isascii() and value.isdecimal()
