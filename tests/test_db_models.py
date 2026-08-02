"""PR4.2 regression tests: the audit_events table (db/models.py)."""
from datetime import datetime

import pytest
from sqlalchemy.exc import IntegrityError

from db.models import AuditEventRecord


def test_audit_event_record_inserts_successfully(db_session):
    record = AuditEventRecord(
        event_id="evt-1",
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        service="auth",
        event_type="auth_login",
        user_id="u1",
        action="login",
        decision="success",
        context={},
    )
    db_session.add(record)
    db_session.commit()

    fetched = db_session.get(AuditEventRecord, "evt-1")
    assert fetched is not None
    assert fetched.service == "auth"
    assert fetched.decision == "success"


def test_audit_event_record_preserves_json_context(db_session):
    context = {"ip": "1.2.3.4", "nested": {"a": [1, 2, 3]}}
    record = AuditEventRecord(
        event_id="evt-2",
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        service="iam",
        event_type="iam_cache_hit",
        context=context,
    )
    db_session.add(record)
    db_session.commit()

    fetched = db_session.get(AuditEventRecord, "evt-2")
    assert fetched.context == context


def test_audit_event_record_created_at_defaults(db_session):
    record = AuditEventRecord(
        event_id="evt-3",
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        service="svc",
        event_type="test",
        context={},
    )
    db_session.add(record)
    db_session.commit()

    fetched = db_session.get(AuditEventRecord, "evt-3")
    assert fetched.created_at is not None


def test_audit_event_record_duplicate_event_id_rejected(db_session):
    """event_id is the primary key -- a second insert of the same id must
    fail at the database level (this is what consumers/sink.py relies on
    to make duplicate delivery a safe no-op instead of a second row)."""
    kwargs = dict(
        event_id="evt-dup",
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        service="svc",
        event_type="test",
        context={},
    )
    db_session.add(AuditEventRecord(**kwargs))
    db_session.commit()

    db_session.add(AuditEventRecord(**kwargs))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    # exactly one row exists
    count = db_session.query(AuditEventRecord).filter_by(event_id="evt-dup").count()
    assert count == 1
