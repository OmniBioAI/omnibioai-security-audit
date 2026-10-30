# Cross-lane contract notes

- Tenant decision (Auth `c9c997a`): tenant IDs on the wire are opaque,
  canonical decimal strings such as `"42"`. Integers and non-canonical strings
  such as `"042"` are rejected; the service does not coerce or normalize them.
  Policy Engine examples such as `tenant-a` and SDK offline fixtures using
  `tenant-a` are not valid wire IDs and must be replaced with their verified
  canonical tenant strings before end-to-end qualification. The signed
  Lane 1 fixture uses synthetic tenant `"42"`.
- Receipt decision: the complete signed `DurableAuditReceiptV1` serialization
  is canonical and authoritative. Consumers must verify Ed25519 over every
  canonical receipt field except the detached `signature` member, using the
  receipt's `key_id`, before projecting fields into a narrower local shape.
  Policy Engine may continue to expose its five-field response (`receipt_id`,
  `event_id`, `source`, `durable`, `persisted_at`) to its caller, but it must
  verify the full signed receipt first; verifying the five-field projection is
  not sufficient. Canonical bytes and the verification procedure are specified
  in `CONTRACT_APPROVAL.md`.
