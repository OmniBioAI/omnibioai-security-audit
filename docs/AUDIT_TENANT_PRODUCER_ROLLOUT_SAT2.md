# Security Audit Tenant Producer Rollout — SAT-2 release closure

## Baseline

SAT-2 was reconciled against Security Audit main at merge
073e02377da5f05ba5aa2e9dc1b18e81ea09dcab. That baseline contains SAT-1's
first-class organization_id and tenant_scope
fields, signed serialized event payloads, durable persistence, the nullable
organization column, the unknown default, migration 0003_tenant_contract,
and the organization/timestamp/event index.

## Classification rules

- organization: only an organization ID obtained from an independently
  verified IAM identity, authenticated server context, or trusted persisted
  ownership record.
- global: only an explicitly platform-wide operation whose contract says it
  is not tenant-owned. It is never a fallback for missing identity.
- unknown: no authoritative organization is available. Missing organization
  data is represented as organization_id: null and tenant_scope: unknown.

Context remains observability metadata, not tenant authority. No producer may
derive a tenant from URLs, headers that were not verified, usernames, resource
names, paths, workflow/run/trace IDs, scheduler handles, service names, or
environment variables.

## Producer inventory and rollout

| Producer | Authoritative source | SAT-2 status | Remaining gap |
|---|---|---|---|
| API Gateway | IAM-validated identity attached to request state | COMPLETE | Pre-auth and trace events remain UNKNOWN |
| TES | IAM-validated Identity.organization_id; persisted RunRecord ownership for timeout events | COMPLETE | No harmless live audited fixture |
| RAG | IAM-validated UserContext.org_id | COMPLETE | Pre-auth events remain UNKNOWN |
| Workflow Bundles | IAM-validated UserContext.org_id | COMPLETE | No harmless live audited fixture |
| LIMS | independently verified request IAM context via get_verified_org_id | COMPLETE | local-session/Django-admin and SSO paths remain UNKNOWN |
| Model Registry | no Security Audit stream emission path found | NOT_APPLICABLE | Integrate with Security Audit when an approved path exists |
| Security SDK | generic client exists but is not used by discovered Security Audit producers | NOT_APPLICABLE | Future contract hardening/adoption requires an owner |
| Auth-related ledger | separate IAM audit ledger, not Security Audit stream | NOT_APPLICABLE | Separate integration decision |
| Control Center | explicitly out of SAT-2 scope; no changes made | NOT_APPLICABLE | Review in its own authorized work |
| Workbench/local audit log | local application audit path, not a discovered Security Audit producer | NOT_APPLICABLE | Confirm during its own integration work |

## Release closure matrix

| Producer | Code | Tests | Live evidence | Release |
|---|---|---|---|---|
| Gateway | COMPLETE | PASS | CERTIFIED | READY |
| RAG | COMPLETE | PASS | CERTIFIED | READY |
| LIMS | COMPLETE | PASS | CERTIFIED | READY |
| TES | COMPLETE | PASS | FIXTURE LIMITED | REVIEWABLE |
| Workflow Bundles | COMPLETE | PASS | FIXTURE LIMITED | REVIEWABLE |
| Model Registry | N/A | N/A | N/A | OUT OF SCOPE |
| Security SDK | N/A | N/A | N/A | FUTURE |

## Integrity and compatibility

All changed producers place tenant fields in the event dictionary before
JSON serialization and HMAC signing. The exact serialized data string is
signed and published, so tenant fields are integrity-covered through Redis,
the consumer, and SQL persistence. Existing call sites can omit the optional
fields and safely produce null/unknown; no legacy event is rejected.

No global event producer was added in SAT-2. Platform startup/configuration
events require an explicit contract decision before being classified global.

## Live certification evidence

The local deployment was inspected using its actual Compose service names. The
SAT-1 Security Audit API/worker was rebuilt from the merged SAT-1 source because
the previously running worker image loaded a pre-SAT-1 model; no database,
Redis, Auth, Control Center, or unrelated service was restarted. Only the five
SAT-2 producer services and then the Security Audit API/worker were recreated.

The deployed database was verified read-only to contain `organization_id`,
non-null `tenant_scope` with the `unknown` default, migration `0003`, and
`ix_audit_events_org_timestamp_event`.

With a disposable Auth-created organization (`589`) and a validated identity,
fresh durable rows with `integrity_status=valid` were observed for:

- API Gateway: `iam_auth_success`, `request`, and `upstream_forward`, all
  `organization_id=589`, `tenant_scope=organization`.
- RAG: a source-correct serving deployment durably persisted
  `organization_id=590`, `tenant_scope=organization`, and
  `integrity_status=valid`. The image copies `/app/ragbio` and installs the
  checked-out project; certification must use that release image/source path,
  not an ad hoc `PYTHONPATH` overlay.
- LIMS: `sample_exported`, `organization_id=589`,
  `tenant_scope=organization`.

TES list operations and Workflow Bundles list operations do not emit audited
events, and the live stores had no existing run/workflow fixture that could be
used for a harmless audited read. Their propagation is covered by focused
unit/contract tests, but not live durable certification in SAT-2.1. GLOBAL was
not exercised because no legitimate global producer event was found. An
unauthenticated Gateway request produced a valid `NULL/unknown` row.

The Redis stream also showed tenant-bearing Gateway and LIMS payloads before
the rebuilt worker persisted them, confirming tenant fields were present in
the signed producer payload. No raw payloads, signatures, tokens, or keys were
exposed in the evidence collection.

## Validation and follow-up

Each changed producer has focused contract coverage for top-level tenant
fields, context non-authority, unknown defaults, and signing serialization.
Current focused results: Gateway 25 passed; TES signing 16 passed; RAG audit
9 passed; Workflow Bundles signing 15 passed; LIMS signed-audit 45 passed.
Gateway's stale pre-SAT-2 envelope assertion was updated to the merged
contract. TES route-isolation tests collected 15 environment-skipped cases.
Full TES/Workflow suites were not used as release gates because they enter
long-running backend/integration paths. Changed-file compilation and diff
checks pass when bytecode is redirected outside the read-only worktrees.
Ruff passes for RAG and LIMS; touched Gateway, TES, and Workflow files retain
pre-existing lint debt, with no broad cleanup performed.

SAT-2.2 closed the RAG live defect in the certification deployment. The
source already passed the verified `UserContext.org_id` as the top-level
tenant field; the deployed `ragbio-server` had instead imported a stale
installed package because `/app` was absent from its serving-process import
path. Running the released package from `/app` produced and durably persisted
`organization_id=590`, `tenant_scope=organization`, and
`integrity_status=valid`. The production image/build must include the SAT-2
source rather than rely on a source overlay.

TES and Workflow Bundles remain live-unvalidated because their available list
operations emit no audit event and no harmless audited fixture was present.
This is a LIVE EVIDENCE LIMITATION, not an implementation blocker. SAT-3 may add
organization-scoped query authorization only after
the Security Audit contract and producer rollout are merged. SAT-4 freshness
and retention semantics remain separate work.
