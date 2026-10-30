"""Approved schemas and signed durable receipts for Skills audit events."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SKILLS_SCHEMA_VERSION = "skills-audit/v1"
POLICY_SCHEMA_VERSION = "policy-audit/v1"
CONTRACT_APPROVAL_REFERENCE = "skills-security-audit-contract/2026-10-29"
RETENTION_APPROVAL_REFERENCE = "skills-security-audit-retention/90d/2026-10-29"
SIGNING_APPROVAL_REFERENCE = "skills-security-audit-receipts/ed25519-v1/2026-10-29"
MINIMUM_RETENTION_DAYS = 90
RECONCILIATION_WINDOW_DAYS = 7

TenantId = str
Outcome = Literal["allow", "deny", "success", "fail"]
SkillsEventType = Literal[
    "skill_discovery",
    "skill_authorization",
    "skill_planning",
    "skill_revocation",
    "skill_validation_failed",
    "skill_execution_rejected",
    "skill_plan_validated",
]

_TENANT = re.compile(r"^(?:0|[1-9][0-9]{0,254})$")
_REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_SKILLS_ACTIONS = frozenset(
    {
        "skills.discover",
        "skills.recommend",
        "skills.plan_preview",
        "skills.authorize",
        "skills.revocation_observed",
        "skills.validation_failed",
        "skills.execution_rejected",
        "skills.validate",
    }
)
_POLICY_ACTION = re.compile(r"^skill\.(discover|execute|plan|validate)$")
_POLICY_CONTEXT_KEYS = frozenset(
    {
        "decision_id",
        "policy_version",
        "policy_source",
        "enforcement",
        "cache_age_bucket",
        "latency_bucket",
        "error_code",
    }
)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def sha256_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SkillsAuditEventV1(StrictModel):
    schema_version: Literal["skills-audit/v1"] = SKILLS_SCHEMA_VERSION
    event_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    timestamp: datetime
    event_type: SkillsEventType
    organization_id: TenantId
    principal_id: str | None = Field(default=None, max_length=256)
    action: str = Field(min_length=1, max_length=128)
    resource: str | None = Field(default=None, max_length=512)
    outcome: Outcome
    reason_code: str | None = Field(default=None, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=256)
    decision_id: str | None = Field(default=None, max_length=256)
    plan_fingerprint: str | None = Field(default=None, max_length=256)
    catalog_revision: str | None = Field(default=None, max_length=256)
    error_code: str | None = Field(default=None, max_length=128)

    @field_validator("organization_id")
    @classmethod
    def validate_tenant(cls, value: str) -> str:
        if not _TENANT.fullmatch(value):
            raise ValueError("organization_id must be an opaque decimal string")
        return value

    @field_validator("action")
    @classmethod
    def validate_action(cls, value: str) -> str:
        if value not in _SKILLS_ACTIONS:
            raise ValueError("action is not approved for skills-audit/v1")
        return value

    @field_validator("reason_code", "error_code")
    @classmethod
    def validate_code(cls, value: str | None) -> str | None:
        if value is not None and not _REASON_CODE.fullmatch(value):
            raise ValueError("reason and error fields accept machine codes only")
        return value

    @model_validator(mode="after")
    def validate_integrity(self) -> SkillsAuditEventV1:
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        expected = sha256_digest(self.model_dump(mode="json", exclude={"event_id"}))
        if not hmac.compare_digest(expected, self.event_id):
            raise ValueError("event_id does not bind the canonical event")
        return self

    @classmethod
    def build(cls, **values: Any) -> SkillsAuditEventV1:
        draft = cls.model_construct(event_id="0" * 64, **values)
        event_id = sha256_digest(draft.model_dump(mode="json", exclude={"event_id"}))
        return cls.model_validate(
            draft.model_dump(mode="json") | {"event_id": event_id}
        )


class PolicyAuditEventV1(StrictModel):
    """Compatibility envelope emitted by policy-engine commit ``afdf899``."""

    event_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    timestamp: datetime
    service: Literal["omnibioai-policy-engine"]
    event_type: Literal["skill_authorization"]
    user_id: str = Field(min_length=1, max_length=256)
    organization_id: TenantId
    tenant_scope: Literal["organization"]
    action: str
    resource: str = Field(min_length=1, max_length=512)
    decision: Literal["allow", "deny", "fail"]
    reason: str = Field(min_length=1, max_length=128)
    trace_id: str = Field(min_length=1, max_length=256)
    context: dict[str, str]

    @field_validator("organization_id")
    @classmethod
    def validate_tenant(cls, value: str) -> str:
        if not _TENANT.fullmatch(value):
            raise ValueError("organization_id must be an opaque decimal string")
        return value

    @field_validator("action")
    @classmethod
    def validate_action(cls, value: str) -> str:
        if not _POLICY_ACTION.fullmatch(value):
            raise ValueError("action is not approved for policy-audit/v1")
        return value

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        if not _REASON_CODE.fullmatch(value):
            raise ValueError("policy reason must be a machine error code")
        return value

    @field_validator("context")
    @classmethod
    def validate_context(cls, value: dict[str, str]) -> dict[str, str]:
        if not value or set(value) - _POLICY_CONTEXT_KEYS:
            raise ValueError("policy context contains unapproved fields")
        if any(not isinstance(item, str) or len(item) > 256 for item in value.values()):
            raise ValueError("policy context values must be bounded strings")
        return value

    @model_validator(mode="after")
    def validate_timestamp(self) -> PolicyAuditEventV1:
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        return self


class DurableAuditReceiptV1(StrictModel):
    event_id: str
    receipt_id: str
    accepted_schema_version: Literal["skills-audit/v1", "policy-audit/v1"]
    durable_at: datetime
    organization_id: TenantId
    sink_partition: str
    key_id: str
    signature: str
    durable: Literal[True] = True

    @field_validator("organization_id")
    @classmethod
    def validate_tenant(cls, value: str) -> str:
        if not _TENANT.fullmatch(value):
            raise ValueError("organization_id must be a canonical decimal string")
        return value

    @field_validator("durable_at")
    @classmethod
    def validate_utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("durable_at must be a timezone-aware UTC timestamp")
        return value.astimezone(UTC)

    def signed_fields(self) -> dict[str, Any]:
        """Return every canonical receipt field covered by the detached signature."""
        return self.model_dump(mode="json", exclude={"signature"})


class PolicyAuditReceiptV1(StrictModel):
    receipt_id: str = Field(min_length=8, max_length=256)
    event_id: str = Field(min_length=8, max_length=256)
    source: Literal["security-audit"] = "security-audit"
    durable: Literal[True] = True
    persisted_at: datetime


class ReceiptSigner(Protocol):
    @property
    def key_id(self) -> str: ...

    def sign(self, fields: dict[str, Any]) -> str: ...

    def verify(self, fields: dict[str, Any], signature: str) -> bool: ...


class Ed25519ReceiptSigner:
    """Runtime-injected Ed25519 signer with public verification capability."""

    _DOMAIN = b"omnibioai-security-audit-receipt-v1\x00"

    def __init__(self, *, private_key: bytes, key_id: str) -> None:
        if len(private_key) != 32:
            raise ValueError("Ed25519 private seed must be exactly 32 bytes")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", key_id):
            raise ValueError("receipt signing key ID is invalid")
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
        except ImportError as exc:  # pragma: no cover - runtime dep is mandatory
            raise ValueError("Ed25519 support is unavailable") from exc
        self._private_key = Ed25519PrivateKey.from_private_bytes(private_key)
        self._public_key = self._private_key.public_key()
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, fields: dict[str, Any]) -> str:
        signature = self._private_key.sign(self._DOMAIN + canonical_json(fields))
        return "ed25519:" + urlsafe_b64encode(signature).decode().rstrip("=")

    def verify(self, fields: dict[str, Any], signature: str) -> bool:
        from cryptography.exceptions import InvalidSignature

        prefix, separator, encoded = signature.partition(":")
        if not separator or prefix != "ed25519":
            return False
        try:
            raw = urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            self._public_key.verify(raw, self._DOMAIN + canonical_json(fields))
        except (InvalidSignature, ValueError):
            return False
        return True


def event_schema_version(event: SkillsAuditEventV1 | PolicyAuditEventV1) -> str:
    return (
        SKILLS_SCHEMA_VERSION
        if isinstance(event, SkillsAuditEventV1)
        else POLICY_SCHEMA_VERSION
    )


def event_tenant(event: SkillsAuditEventV1 | PolicyAuditEventV1) -> str:
    return event.organization_id


def event_digest(event: SkillsAuditEventV1 | PolicyAuditEventV1) -> str:
    return sha256_digest(event.model_dump(mode="json"))
