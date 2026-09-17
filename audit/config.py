import os


class AuditConfig:
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
    STREAM_NAME = os.getenv("AUDIT_STREAM", "audit:events")
    SERVICE_NAME = os.getenv("SERVICE_NAME", "unknown-service")
    # Redis is a buffer, not the source of truth (PR4.2) -- 1M entries is a
    # generous backlog cap for consumer downtime, not a retention policy.
    # Durable history now lives in audit_events; see PR4.2 report for the
    # retention rationale.
    MAX_STREAM_LENGTH = int(os.getenv("AUDIT_MAXLEN", "1000000"))

    # PR4.2: durable persistence + consumer group settings.
    DATABASE_URL = os.getenv(
        "AUDIT_DATABASE_URL",
        "mysql+pymysql://root:root@localhost:3306/omnibioai_audit",
    )

    # V2-003 (Track E3): least-privilege runtime DB credentials. The
    # worker (writer) only ever needs INSERT+SELECT on audit_events and
    # quarantined_audit_events; the read-only API routes only ever need
    # SELECT. Both default to DATABASE_URL (the pre-existing,
    # unrestricted-by-default connection) so an unprovisioned deployment
    # keeps working exactly as before this change -- provisioning
    # restricted `audit_writer`/`audit_reader` MySQL users (see
    # scripts/provision_audit_db_users.py) and pointing these two env
    # vars at them is a documented, opt-in rollout step, not a breaking
    # requirement. Migrations/admin tooling continue using DATABASE_URL
    # (unchanged, still typically root) -- schema management is
    # deliberately not restricted by this change.
    WRITER_DATABASE_URL = os.getenv("AUDIT_WRITER_DATABASE_URL", DATABASE_URL)
    READER_DATABASE_URL = os.getenv("AUDIT_READER_DATABASE_URL", DATABASE_URL)
    CONSUMER_GROUP = os.getenv("AUDIT_CONSUMER_GROUP", "audit-workers")
    CONSUMER_NAME = os.getenv("AUDIT_CONSUMER_NAME", f"worker-{os.getpid()}")

    # HIPAA P0 (abandoned-PEL-entry recovery): a message this consumer
    # group delivered but never acked -- crash before persistence, a
    # transient MySQL failure, the process getting killed mid-write --
    # sits in the group's Pending Entries List. CONSUMER_NAME above is
    # per-process (pid-based) by design (multiple worker replicas must
    # never collide on one identity), which means a crashed worker's
    # pending entries are *never* revisited by that same identity again --
    # nothing "restarts" a dead pid. Recovery has to come from any live
    # worker sweeping the whole group's PEL, not from self-continuity, so
    # these thresholds are named generically (PEL_*, not "own pending").
    #
    # PEL_MIN_IDLE_MS: how long an entry must sit unacked before ANY
    # worker (including the one that originally received it, if it's
    # still alive and just slow) is allowed to reclaim it. Must safely
    # exceed one full handle_message() -- including a real MySQL
    # round-trip -- under normal load, or a live-but-slow worker would
    # have its own in-flight message reclaimed out from under it.
    PEL_MIN_IDLE_MS = int(os.getenv("AUDIT_PEL_MIN_IDLE_MS", "30000"))
    # PEL_MAX_DELIVERIES: once an entry has been *delivered* (original
    # read + every reclaim) this many times without a successful ack, it
    # is treated as poison -- a deterministically-unparseable payload,
    # not a transient failure -- and ACKed without further processing so
    # it can never loop forever. See worker/main.py::sweep_pending.
    PEL_MAX_DELIVERIES = int(os.getenv("AUDIT_PEL_MAX_DELIVERIES", "5"))
    # PEL_SWEEP_BATCH: cap on stale entries inspected per sweep call, same
    # "bounded work per loop iteration" shape MAX_ENTRIES-style caps use
    # elsewhere in this platform -- a PEL of unbounded size must not turn
    # one sweep into an unbounded-latency Redis call.
    PEL_SWEEP_BATCH = int(os.getenv("AUDIT_PEL_SWEEP_BATCH", "100"))

    # Incident (2026-09-16): audit:events and its consumer group were
    # destructively deleted in production. The worker's response
    # (continuous NOGROUP retries with only a print()) was invisible to
    # anyone not actively tailing logs. Two independent, narrowly scoped
    # fixes -- see worker/main.py's NOGROUP handling:
    #
    # WORKER_AUTO_RECREATE_STREAM_ON_NOGROUP: deliberately OFF by
    # default. Recreating audit:events/audit-workers via `XGROUP CREATE
    # ... MKSTREAM` is only safe when NEITHER already exists (an existing
    # group's own BUSYGROUP response is always tolerated and never
    # touched -- see StreamReader.ensure_group()); it can never reset an
    # existing group's cursor. But a worker that *always* auto-heals a
    # missing stream/group cannot distinguish "accidental deletion,
    # please heal" from "an operator is intentionally decommissioning
    # this stream and does not want it silently recreated out from under
    # them" -- an unresolvable semantic ambiguity from inside the worker
    # alone. Left opt-in for deployments that have decided that
    # tradeoff is acceptable for them; the safe default is to alert
    # loudly (always on, see below) and let a human decide, not to
    # silently paper over every deletion.
    WORKER_AUTO_RECREATE_STREAM_ON_NOGROUP = (
        os.getenv("AUDIT_WORKER_AUTO_RECREATE_STREAM_ON_NOGROUP", "false").lower() == "true"
    )
    # WORKER_NOGROUP_RETRY_BACKOFF_SECONDS: applied only when a NOGROUP
    # condition was just observed, so a worker stuck in this state polls
    # Redis at a bounded, sane rate instead of spinning as fast as
    # exceptions can be thrown and caught -- never applied on the normal,
    # healthy read path.
    WORKER_NOGROUP_RETRY_BACKOFF_SECONDS = float(
        os.getenv("AUDIT_WORKER_NOGROUP_RETRY_BACKOFF_SECONDS", "2.0")
    )

    # PR2 of the audit:events integrity remediation (see audit/signing.py,
    # PR1): reuses the same JWT_SECRET every other platform service (and
    # this repo's own audit/jwt_verify.py) already reads -- not a new
    # secret, not a new convention. Falls back to "change-me" the same way
    # jwt_verify.JWT_SECRET does; a deployment that never set the real
    # JWT_SECRET already has a forgeable HS256 token secret, so this adds
    # no new exposure. See PR2's own report: the dev-compose worker
    # container currently has JWT_SECRET unset entirely (falls back here
    # too) -- until that's fixed, this worker cannot correctly verify a
    # signature made with the platform's real secret. Harmless today since
    # no producer signs yet (every event classifies as "unsigned"), but
    # this default must not be trusted once a producer starts signing.
    EVENT_SIGNING_SECRET = os.getenv("JWT_SECRET", "change-me")