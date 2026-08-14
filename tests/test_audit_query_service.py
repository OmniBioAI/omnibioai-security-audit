"""PR4.3: services/audit_query_service.py -- SQL-level filtering, ordering,
and pagination over audit_events, exercised against a real (SQLite) DB via
the `db_session` fixture (no HTTP layer)."""
from datetime import datetime, timedelta

from db.models import AuditEventRecord
from services import audit_query_service


def _add(db_session, event_id, minutes_offset=0, **overrides):
    row = AuditEventRecord(
        event_id=event_id,
        timestamp=datetime(2026, 1, 1, 12, 0, 0) + timedelta(minutes=minutes_offset),
        service=overrides.get("service", "auth"),
        event_type=overrides.get("event_type", "auth_login"),
        user_id=overrides.get("user_id", "u1"),
        action=overrides.get("action", "login"),
        resource=overrides.get("resource"),
        decision=overrides.get("decision", "success"),
        reason=overrides.get("reason"),
        trace_id=overrides.get("trace_id"),
        context=overrides.get("context", {}),
    )
    if "integrity_status" in overrides:
        row.integrity_status = overrides["integrity_status"]
    db_session.add(row)
    return row


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------

def test_filters_by_user_id(db_session):
    _add(db_session, "e1", user_id="u1")
    _add(db_session, "e2", user_id="u2")
    db_session.commit()

    rows, total = audit_query_service.list_audit_events(
        db_session, page=1, page_size=20, user_id="u1"
    )
    assert total == 1
    assert [r.event_id for r in rows] == ["e1"]


def test_filters_by_service(db_session):
    _add(db_session, "e1", service="auth")
    _add(db_session, "e2", service="policy")
    db_session.commit()

    rows, total = audit_query_service.list_audit_events(
        db_session, page=1, page_size=20, service="policy"
    )
    assert total == 1
    assert rows[0].event_id == "e2"


def test_filters_by_event_type(db_session):
    _add(db_session, "e1", event_type="auth_login")
    _add(db_session, "e2", event_type="user_suspended")
    db_session.commit()

    rows, total = audit_query_service.list_audit_events(
        db_session, page=1, page_size=20, event_type="user_suspended"
    )
    assert total == 1
    assert rows[0].event_id == "e2"


def test_filters_by_decision(db_session):
    _add(db_session, "e1", decision="success")
    _add(db_session, "e2", decision="deny")
    db_session.commit()

    rows, total = audit_query_service.list_audit_events(
        db_session, page=1, page_size=20, decision="deny"
    )
    assert total == 1
    assert rows[0].event_id == "e2"


def test_filters_by_timestamp_range(db_session):
    _add(db_session, "e1", minutes_offset=0)
    _add(db_session, "e2", minutes_offset=10)
    _add(db_session, "e3", minutes_offset=20)
    db_session.commit()

    rows, total = audit_query_service.list_audit_events(
        db_session,
        page=1,
        page_size=20,
        from_timestamp=datetime(2026, 1, 1, 12, 5, 0),
        to_timestamp=datetime(2026, 1, 1, 12, 15, 0),
    )
    assert total == 1
    assert rows[0].event_id == "e2"


def test_filters_by_integrity_status(db_session):
    _add(db_session, "e1", integrity_status="valid")
    _add(db_session, "e2", integrity_status="invalid")
    _add(db_session, "e3")  # unspecified -- DB server_default="unsigned" applies
    db_session.commit()

    rows, total = audit_query_service.list_audit_events(
        db_session, page=1, page_size=20, integrity_status="invalid"
    )
    assert total == 1
    assert rows[0].event_id == "e2"


def test_filters_by_integrity_status_unsigned_matches_the_default(db_session):
    _add(db_session, "e1", integrity_status="valid")
    _add(db_session, "e2")
    db_session.commit()

    rows, total = audit_query_service.list_audit_events(
        db_session, page=1, page_size=20, integrity_status="unsigned"
    )
    assert total == 1
    assert rows[0].event_id == "e2"


def test_combined_filters_no_cross_leakage(db_session):
    """A row matching only one of two filters must not appear -- filters
    combine with AND, not OR."""
    _add(db_session, "e1", service="auth", decision="success")
    _add(db_session, "e2", service="auth", decision="deny")
    _add(db_session, "e3", service="policy", decision="deny")
    db_session.commit()

    rows, total = audit_query_service.list_audit_events(
        db_session, page=1, page_size=20, service="auth", decision="deny"
    )
    assert total == 1
    assert rows[0].event_id == "e2"


def test_no_filters_returns_all(db_session):
    _add(db_session, "e1")
    _add(db_session, "e2")
    _add(db_session, "e3")
    db_session.commit()

    rows, total = audit_query_service.list_audit_events(db_session, page=1, page_size=20)
    assert total == 3


def test_empty_result(db_session):
    _add(db_session, "e1", service="auth")
    db_session.commit()

    rows, total = audit_query_service.list_audit_events(
        db_session, page=1, page_size=20, service="nonexistent"
    )
    assert total == 0
    assert rows == []


# ---------------------------------------------------------------------------
# Ordering
# ---------------------------------------------------------------------------

def test_ordering_newest_first(db_session):
    _add(db_session, "e1", minutes_offset=0)
    _add(db_session, "e2", minutes_offset=10)
    _add(db_session, "e3", minutes_offset=5)
    db_session.commit()

    rows, _ = audit_query_service.list_audit_events(db_session, page=1, page_size=20)
    assert [r.event_id for r in rows] == ["e2", "e3", "e1"]


def test_ordering_tiebreak_by_event_id_desc(db_session):
    """Two events sharing a timestamp must still sort deterministically."""
    _add(db_session, "e-a", minutes_offset=0)
    _add(db_session, "e-b", minutes_offset=0)
    _add(db_session, "e-c", minutes_offset=0)
    db_session.commit()

    rows, _ = audit_query_service.list_audit_events(db_session, page=1, page_size=20)
    assert [r.event_id for r in rows] == ["e-c", "e-b", "e-a"]


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------

def test_pagination_page_boundaries(db_session):
    for i in range(5):
        _add(db_session, f"e{i}", minutes_offset=i)
    db_session.commit()

    page1, total = audit_query_service.list_audit_events(db_session, page=1, page_size=2)
    page2, _ = audit_query_service.list_audit_events(db_session, page=2, page_size=2)
    page3, _ = audit_query_service.list_audit_events(db_session, page=3, page_size=2)

    assert total == 5
    assert [r.event_id for r in page1] == ["e4", "e3"]
    assert [r.event_id for r in page2] == ["e2", "e1"]
    assert [r.event_id for r in page3] == ["e0"]  # partial last page


def test_pagination_out_of_range_page_returns_empty(db_session):
    _add(db_session, "e1")
    db_session.commit()

    rows, total = audit_query_service.list_audit_events(db_session, page=99, page_size=20)
    assert rows == []
    assert total == 1  # total reflects all matching rows, not just this page


def test_pagination_total_unaffected_by_page_size(db_session):
    for i in range(7):
        _add(db_session, f"e{i}", minutes_offset=i)
    db_session.commit()

    rows, total = audit_query_service.list_audit_events(db_session, page=1, page_size=3)
    assert len(rows) == 3
    assert total == 7
