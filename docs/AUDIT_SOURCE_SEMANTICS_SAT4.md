# SAT-4 source evidence semantics

`GET /audit/events/safe` reports durable SQL query evidence separately from
ingestion health. A completed SQL query is `source_availability: AVAILABLE`,
including an empty result. SQL failure is `UNAVAILABLE` with a normalized
`AUDIT_SOURCE_UNAVAILABLE` HTTP 503.

Durable retention is `UNKNOWN`: `retention_days` and
`oldest_available_event_at` are null. `AUDIT_MAXLEN` is a Redis backlog cap,
not SQL retention. Freshness is also `UNKNOWN`; this service has no
authoritative heartbeat, as-of marker, lag metric, or stale threshold. It
never emits `CURRENT`, `STALE`, a retention duration, or inferred lag.

Responses include `source`, `source_availability`, `generated_at`,
`source_checked_at`, `freshness`, `retention`, and safe warning codes. The two
timestamps are timezone-aware UTC values. Redis/consumer health does not make
a successful SQL query unavailable.

SAT-3 owns `/audit/events/safe` authentication, verified tenant scope, SQL
tenant filtering, pagination, and allowlisted metadata. Organization callers
cannot see GLOBAL or UNKNOWN events; platform callers require
`manage_all_orgs`. SAT-4 supplies the evidence fields and failure behavior;
there is one safe response contract.

No raw context, SQL, connection details, credentials, tokens, or stack traces
are returned. Stronger freshness and retention claims require authoritative
upstream evidence from the worker/deployment contract. SAT-2 producer changes
remain outside this worktree.

## Live certification

The deployed `GET /audit/events/safe` contract was live-certified with a
supported organization-owner identity. The owner received HTTP 200 and only
organization-scoped events for the verified organization; legacy UNKNOWN
events were present in storage but excluded. An ordinary authenticated
identity received 403, unauthenticated access received 401, and an explicit
cross-organization override was rejected with 403. Read-only method behavior
remained enforced.

The live evidence does not establish CURRENT freshness, retention duration, or
GLOBAL visibility because no legitimate GLOBAL event was available. SAT-2
producer limitations for TES and Workflow Bundles live fixtures remain
separate and are not represented as ecosystem-wide producer completeness.
