from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from audit.config import AuditConfig

# V2-003 (Track E3): writer engine, used directly by worker/main.py --
# the only runtime path that ever INSERTs. Bound to
# AuditConfig.WRITER_DATABASE_URL (defaults to the pre-existing
# DATABASE_URL if a restricted writer user hasn't been provisioned --
# see scripts/provision_audit_db_users.py).
engine = create_engine(AuditConfig.WRITER_DATABASE_URL, pool_pre_ping=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# V2-003: reader engine, used only by get_db() below -- every current
# get_db() consumer (routes_audit_events.py, routes_audit_safe.py,
# routes_audit_health.py) is read-only. Bound to
# AuditConfig.READER_DATABASE_URL (same fallback behavior as above).
# Deliberately a separate engine/sessionmaker from the writer's, even
# though both may resolve to the same connection string today -- that's
# what makes pointing them at genuinely different, separately-
# privileged MySQL users a config-only change later, not a code change.
reader_engine = create_engine(AuditConfig.READER_DATABASE_URL, pool_pre_ping=True)
ReaderSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=reader_engine)


def get_db():
    """Read-only DB session for API routes. Kept as `get_db` (not
    renamed to `get_reader_db`) so every existing route/test that
    already depends on this exact name needs no change -- only its
    binding changed, from the writer engine to the reader engine."""
    db = ReaderSessionLocal()
    try:
        yield db
    finally:
        db.close()
