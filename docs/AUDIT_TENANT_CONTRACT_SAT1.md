# SAT-1 — Security Audit Tenant Contract

Status: **implemented; ready for AE-2 authorization work**

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

## Producer coverage matrix

| Producer | Authoritative tenant | Current propagation | Required future change | Risk |
|---|---|---|---|---|
| Security Audit native logger/test route | No for platform smoke events; field supported | Envelope model/logger | Explicitly mark global only when deliberate | Low |
| API Gateway | Verified user/org context exists | Builder omits field | Pass verified org ID | Medium |
| RAG | Verified IAM `UserContext.org_id` | Context in several paths | Pass top-level field | Medium |
| TES | Organization context on authenticated runs | Older producer contract | Add verified field | Medium |
| Workflow Bundles | Varies by path | Producer-specific context | Establish verified propagation | High |
| LIMS | Request identity varies | Producer-specific context | Add only when verified | High |
| Model Registry | Verified `UserContext.org_id` | Producer-specific clients | Pass explicit field | Medium |
| Control Center/other producers | Varies | Producer-specific payloads | Adopt selectively | Medium |

No upstream repositories were modified. Old producers remain readable and
become `tenant_scope=unknown`.

## Storage and query preparation

Migration `0003_tenant_contract` adds nullable `organization_id` and non-null
`tenant_scope` with an `unknown` server default. Existing rows are not
rewritten. Index `ix_audit_events_org_timestamp_event` supports future bounded
organization/time/ID queries. The query service accepts an internal
`organization_id` filter, but the existing HTTP route remains platform-admin
only; SAT-1 does not expose organization-scoped access or trust a query-string
tenant ID.

## Authorization boundary

Platform-wide access remains verified JWT plus `platform_admin`. Organization-
scoped access is deferred until the authoritative permission and verified claim
used to derive caller organization are specified and tested. A browser-supplied
organization ID must never widen scope.

## Integrity, metadata, retention, and freshness

The tenant fields are included in signed JSON bytes; verification is unchanged.
Raw signatures and keys remain absent from responses. Legacy arbitrary `context`
is retained for compatibility but is not tenant identity and needs an explicit
allowlist before Audit Explorer exposes it. Credentials, tokens, cookies, JWTs,
authorization headers, API keys, signing material, environment values, private
paths, and unrestricted context are excluded from the future safe response.

Redis max length is a backlog cap, not retention. Durable retention,
freshness/as-of timestamps, source-unavailable responses, and safe metadata
redaction remain undefined and are not invented here.

## AE-2 prerequisites

Expand producer coverage, then define verified caller scope, platform-wide
override rules, unknown/global handling, bounded filters, safe metadata output,
and unavailable/error behavior. Do not broaden the existing route based on this
migration alone.
