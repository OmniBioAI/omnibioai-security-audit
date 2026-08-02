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