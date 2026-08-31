# SAT-1 — Security Audit Tenant Contract

Status: **implemented; SAT-1 scope complete**

This is the historical SAT-1 contract document. SAT-1 established the tenant
contract; it did not implement the later safe query authorization or source
evidence contracts. Those later statuses are noted below without changing the
original SAT-1 boundary.

## Current lifecycle

Producers create an `AuditEvent`, serialize it once, sign that exact JSON
string, and publish it to Redis `audit:events`. The worker parses the payload,
classifies integrity, and persists it to SQL `audit_events`. `GET /audit/events`
reads the durable table. Redis remains ingestion/backlog, not query history.

## Canonical tenant contract

`organization_id: string | null` is now a first-class event-envelope and
durable column. It is separate from `context` and is covered by existing
signing because the logger signs the complete serialized envelope.

`tenant_scope` distinguishes:

| Value | Meaning |
|---|---|
| `organization` | `organization_id` is authoritative and present |
| `global` | Producer explicitly declares a platform/global event |
| `unknown` | Tenant is unavailable or event predates SAT-1 |

Null `organization_id` never means global. Legacy payloads default to
`unknown`; the consumer does not infer tenant identity from context, resources,
URLs, users, traces, or service names.

## Producer coverage matrix (SAT-1-era baseline)

| Producer | Authoritative tenant | Current propagation | SAT-1-era follow-up | Risk |
|---|---|---|---|---|
| Security Audit native logger/test route | No for platform smoke events; field supported | Envelope model/logger | Explicitly mark global only when deliberate | Low |
| API Gateway | Verified user/org context exists | Builder omits field | Pass verified org ID | Medium |
| RAG | Verified IAM `UserContext.org_id` | Context in several paths | Pass top-level field | Medium |
| TES | Organization context on authenticated runs | Older producer contract | Add verified field | Medium |
| Workflow Bundles | Varies by path | Producer-specific context | Establish verified propagation | High |
| LIMS | Request identity varies | Producer-specific context | Add only when verified | High |
| Model Registry | No confirmed Security Audit producer path | Not applicable | Integrate only after an approved path exists | Medium |
| Control Center/other producers | Varies | Producer-specific payloads | Adopt selectively | Medium |

No upstream repositories were modified. Old producers remain readable and
become `tenant_scope=unknown`.

SAT-2 later completed signed top-level tenant propagation for the confirmed
Gateway, RAG, LIMS, TES, and Workflow Bundles producer code paths. Gateway,
RAG, and LIMS have live durable evidence; TES and Workflow Bundles remain
live-evidence limited because the available harmless operations produced no
audited fixture. This does not make the SAT-1 contract a producer-completeness
claim; Security SDK adoption remains future work and Model Registry is not a
confirmed Security Audit producer.

## Storage and query preparation

Migration `0003_tenant_contract` adds nullable `organization_id` and non-null
`tenant_scope` with an `unknown` server default. Existing rows are not
rewritten. Index `ix_audit_events_org_timestamp_event` supports bounded
organization/time/ID queries. The query service accepts an internal
`organization_id` filter. Subsequent SAT-3/SAT-4 work exposed the merged
`GET /audit/events/safe` route with verified organization-scoped access and
platform-wide `manage_all_orgs` access; it does not trust a query-string tenant
ID to establish or widen scope.

## Authorization boundary

SAT-1 retained the platform-admin boundary. SAT-3 later added the merged safe
route: platform-wide access is verified JWT plus `manage_all_orgs`, while
organization-scoped access requires the verified `org_admin`
role and verified `org_id`. A browser-supplied organization ID must never
establish or widen scope.

## Integrity, metadata, retention, and freshness

The tenant fields are included in signed JSON bytes; verification is unchanged.
Raw signatures and keys remain absent from responses. Legacy arbitrary `context`
is retained for compatibility but is not tenant identity and needs an explicit
allowlist before Audit Explorer exposes it. SAT-3 now supplies that safe
allowlisted projection. Credentials, tokens, cookies, JWTs,
authorization headers, API keys, signing material, environment values, private
paths, and unrestricted context are excluded from the safe response.

Redis max length is a backlog cap, not retention. SAT-4 now supplies safe
durable-query source availability and the safe response reports safe metadata;
freshness, retention, and
ingestion lag remain explicitly UNKNOWN.

## AE-2 prerequisites

Historically, AE-2 required expanded producer coverage, verified caller scope,
platform-wide override rules, unknown/global handling, bounded filters, safe
metadata output, and unavailable/error behavior. SAT-2, SAT-3, and SAT-4 later
addressed those prerequisites in their respective contracts. They do not make
SAT-1 itself an implementation of later query or authorization behavior.
