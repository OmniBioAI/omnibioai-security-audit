# Skills durable-receipt availability SLO

This SLO applies only after the live feature is explicitly enabled and Phase 3
qualification is approved.

- Monthly durable-receipt availability: 99.9%, measured as valid durable
  receipts divided by eligible authenticated requests, excluding caller schema,
  tenancy, authorization, and idempotency-conflict errors.
- Latency: p95 at or below 500 ms and p99 at or below 1 second from accepted
  request to committed receipt. The client has a 1.5-second total budget.
- Backpressure: reject within 1 second with a retryable `BACKPRESSURE` or
  `RATE_LIMITED` response; never accept and silently drop.
- Recovery: service restoration objective 15 minutes. Recovery point objective
  is zero for every request for which a durable receipt was returned.
- Reconciliation: retained receipts remain queryable for seven days after the
  original request, subject to exact tenant authorization and opaque cursors.
- Retention: receipts are retained for at least 90 days, with legal holds
  suppressing deletion.

Qualification must exercise outage, recovery, duplicate replay, key rotation,
tenant isolation, and database-commit uncertainty using synthetic identifiers.
Until that evidence exists, availability is `UNQUALIFIED`, not assumed healthy.
