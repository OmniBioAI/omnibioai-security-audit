"""Unit tests for consumers/quarantine.py: classify_poison_reason's
diagnosis branches and QuarantineSink.write's idempotent-duplicate
(IntegrityError -> rollback) path. Mirrors tests/test_sink.py's
mocked-db_session pattern -- no real MySQL needed, and
tests/test_worker_pel_recovery.py already exercises this module's
raw_data=None branch end-to-end through the worker, so it isn't
repeated here.

Developer: Manish Kumar <manish@omnibioai.org>
"""
from unittest.mock import MagicMock

from sqlalchemy.exc import IntegrityError

from consumers.quarantine import QuarantineSink, classify_poison_reason

# ---------------------------------------------------------------------------
# classify_poison_reason
# ---------------------------------------------------------------------------


def test_missing_raw_data_classified_malformed():
    """Classify a None raw_data as malformed with no service extracted."""
    category, service, detail = classify_poison_reason(None)
    assert category == "malformed"
    assert service is None
    assert detail == "MissingDataField"


def test_unparseable_json_classified_malformed():
    """Classify raw_data that fails to parse as JSON as malformed."""
    category, service, detail = classify_poison_reason("{not json")
    assert category == "malformed"
    assert service is None
    assert detail == "JSONDecodeError"


def test_json_that_is_not_an_object_classified_malformed():
    """Classify raw_data that parses but isn't a JSON object as malformed."""
    category, service, detail = classify_poison_reason("[1, 2, 3]")
    assert category == "malformed"
    assert service is None
    assert detail == "NotAJsonObject"


def test_well_formed_object_classified_persistence_exhausted_with_service_extracted():
    """Classify a well-formed JSON object as persistence_exhausted and extract its service field."""
    category, service, detail = classify_poison_reason('{"service": "auth", "action": "login"}')
    assert category == "persistence_exhausted"
    assert service == "auth"
    assert detail is None


def test_well_formed_object_with_non_string_service_field_leaves_service_none():
    """Never surface a non-string service value -- treat it as absent instead."""
    category, service, detail = classify_poison_reason('{"service": 123}')
    assert category == "persistence_exhausted"
    assert service is None
    assert detail is None


def test_well_formed_object_without_service_field_leaves_service_none():
    """Leave service None when the payload object has no service key at all."""
    category, service, detail = classify_poison_reason('{"action": "login"}')
    assert category == "persistence_exhausted"
    assert service is None
    assert detail is None


# ---------------------------------------------------------------------------
# QuarantineSink.write
# ---------------------------------------------------------------------------


def test_write_commits_a_new_quarantine_record():
    """Add and commit a new QuarantinedAuditEvent for a fresh message id."""
    db_session = MagicMock()
    sink = QuarantineSink(db_session)

    result = sink.write("1-0", {"data": '{"service": "auth"}', "sig": "sig"}, delivery_attempts=5)

    assert result is True
    db_session.add.assert_called_once()
    db_session.commit.assert_called_once()
    db_session.rollback.assert_not_called()


def test_write_rolls_back_and_still_returns_true_on_duplicate_insert():
    """Treat a duplicate quarantine write (IntegrityError on commit) as a
    safe idempotent no-op: rollback, but still report success."""
    db_session = MagicMock()
    db_session.commit.side_effect = IntegrityError("duplicate", {}, Exception("dup"))
    sink = QuarantineSink(db_session)

    result = sink.write("1-0", {"data": None, "sig": None}, delivery_attempts=3)

    assert result is True
    db_session.rollback.assert_called_once()
