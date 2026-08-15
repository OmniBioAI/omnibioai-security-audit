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