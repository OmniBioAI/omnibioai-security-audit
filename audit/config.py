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