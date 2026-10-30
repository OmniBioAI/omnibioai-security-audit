# Security Audit live-interface design (B-06, B-07)

Status: design complete; event schema/retention approval and sink implementation are gated.

## Current offline contract

The proposed action/event/outcome mapping and mandatory evidence are allowlisted (`src/omnibioai_skills/integration/audit.py:24-111`). `SkillsAuditEvent` carries organization tenancy; construction exposes no input-payload parameter and redacts bounded context (`src/omnibioai_skills/integration/audit.py:114-168`). The local recorder is idempotent, the production emitter always raises, and receipt mismatch/failure blocks the action (`src/omnibioai_skills/integration/audit.py:224-286`).

## Target interface

Injected port `health(require_durable=true) -> Health`, `emit(event,idempotency_key) -> Receipt`, optionally `get_receipt(event_id)` for reconciliation.

- Event: approved schema/version, event ID/time/service/type, verified tenant/principal, action/resource, decision, bounded redacted reason, correlation, decision/plan/catalog references, error code; never payload.
- Receipt: event ID, receipt ID, accepted schema version, durable time, tenant, sink partition, signature/key ID. Client verifies all bound fields/signature.
- Errors: schema/rejection/tenant/idempotency conflict/signature invalid (non-retryable); unavailable/backpressure/timeout/rate limit (retryable). A queued but non-durable acknowledgement is insufficient for protected actions.
- Idempotency: key equals event ID. Same event is acknowledged once; same ID/different canonical bytes is conflict. Retention must exceed all retry/reconciliation windows.
- Timeout/retry/backoff: 250 ms connect, 1 s durable receipt, 1500 ms total; up to three full-jitter retries (50/100/200 ms) for transient errors with bounded local backpressure. No dropping or “best effort” for mandatory events.
- Pagination: emit/health none. Receipt reconciliation uses opaque tenant/time-bound cursor, max 100; not on the critical execution path.

## Authentication, authorization, and tenancy

Host injects workload identity/signing provider backed by external key management; private keys/tokens are never stored here. Scope `audit.events.write:skills` and optional `audit.receipts.read:skills`, tenant constrained. Sink independently validates producer, schema and organization partition; caller cannot choose a different tenant.

## Audit

The emitted audit events are the records. Sink operational telemetry contains receipt/event ID, tenant partition, schema version, result/error, durability and latency only. Never include credentials/signatures/private keys, raw claims, inputs/outputs, artifact paths, prompts, free-text clinical data, PHI/PII. Reasons are code-first and allowlist-redacted; principal pseudonymization follows owner policy.

## Failure and fail-closed rules

Unhealthy sink, backpressure, timeout, malformed/tampered receipt, wrong event/tenant, unsupported schema, signing failure, or uncertain durability blocks protected authorization/validation/execution. Discovery may return safe failure only after its failure event is durably accepted, per owner policy. No local log substitutes for a receipt.

## Flags and kill switches

`SKILLS_SECURITY_AUDIT_LIVE=false`, approval absent. Enabling requires schema/retention/signing approval, injected providers and healthy durable sink. Audit-specific kill switch blocks protected actions; global execution kill switch also emits a rejection event when healthy. Disabled emitter continues to raise.

## Test plan

Fake tests cover health, idempotent duplicate, conflict, tenant mismatch, prohibited fields, outage, retry/backpressure, and receipt binding. Real qualification verifies upstream schema, signatures/key rotation, durable receipt, retention, tenancy, replay, outage and recovery SLO with synthetic identifiers only.

## Owned outside this repo

- [ ] Security Audit owner approves event types, required fields, outcomes and version negotiation (B-06).
- [ ] Owner approves redaction/pseudonymization, signing/key rotation and tenant partitioning.
- [ ] Owner defines durable receipt semantics, idempotency and retention/reconciliation windows.
- [ ] Service publishes availability, backpressure, timeout and recovery SLOs.
- [ ] Security owner provides immutable schema/config approval and qualification evidence.
