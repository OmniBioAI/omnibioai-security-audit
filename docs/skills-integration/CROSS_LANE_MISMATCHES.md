# Cross-lane contract notes

- Policy Engine `afdf899` emits tenancy examples such as `tenant-a`, while
  this Security Audit contract requires the platform's canonical opaque
  decimal tenant string. **Policy Engine should send its verified canonical
  tenant ID** (for example, `7`). The audit endpoint rejects non-decimal IDs
  and fails closed; it does not coerce or map tenant identifiers.
- The Skills SDK offline fixtures use `tenant-a` for test readability. The
  receipt fixture at `tests/fixtures/skills_audit_receipt_v1.json` uses the
  corresponding wire-valid synthetic tenant `7`. **SDK integration fixtures
  should use decimal strings** before end-to-end qualification.
- Policy Engine `afdf899` publishes a five-field receipt (`receipt_id`,
  `event_id`, `source`, `durable`, `persisted_at`) with `extra=forbid`. The SDK
  requires a richer signed receipt. The endpoint negotiates on the event
  schema: Policy receives its exact five-field projection; SDK receives the
  signed, tenant-bound receipt.
