"""V2-002 (Track E2): durable poison-message quarantine, against REAL
Redis and REAL MySQL -- same harness/isolation conventions as
tests/test_worker_pel_recovery_integration.py (own throwaway stream, own
throwaway database, skips rather than fails when real backends aren't
reachable). See that file's module docstring for the full rationale.

Covers what test_worker_pel_recovery_integration.py's malformed-event
test doesn't: a "persistence_exhausted" poison entry (a perfectly valid
event that simply never reached MySQL in time), quarantine-write failure
NOT acking the original, and quarantine-write idempotency across a
crash-after-quarantine-before-ack gap.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import json
import os
import time
import uuid
from datetime import datetime, timezone

import pytest
import redis as redis_lib
from sqlalchemy import create_engine, text

from tests._mysql_integration_guard import (
    MissingTestMySQLEndpoint,
    validate_test_mysql_url,
)
from tests._redis_integration_guard import (
    MissingTestRedisEndpoint,
    validate_test_redis_url,
)

try:
    # PHI P1-5 test-isolation fix: no implicit localhost:6380 default --
    # ProductionRedisEndpointRejected is deliberately NOT caught here, so
    # a misconfigured production endpoint fails collection loudly instead
    # of silently running against the shared, real Redis instance. See
    # tests/_redis_integration_guard.py.
    TEST_REDIS_URL = validate_test_redis_url(os.environ.get("B0_TEST_REDIS_URL"))
except MissingTestRedisEndpoint:
    TEST_REDIS_URL = None
try:
    # P0 test-isolation fix (2026-09-16): no implicit localhost:3306
    # default -- ProductionMySQLEndpointRejected is deliberately NOT
    # caught here, so a misconfigured production endpoint fails
    # collection loudly instead of silently running destructive SQL
    # against it. See tests/_mysql_integration_guard.py.
    TEST_MYSQL_ROOT_URL = validate_test_mysql_url(os.environ.get("B0_TEST_MYSQL_ROOT_URL"))
except MissingTestMySQLEndpoint:
    TEST_MYSQL_ROOT_URL = None
TEST_DB_NAME = "omnibioai_audit_e2_quarantine_test"
TEST_STREAM = f"audit:events:e2-quarantine-test-{uuid.uuid4().hex[:8]}"
TEST_GROUP = "audit-workers"


def _real_backends_available():
    """Report whether both the configured test-MySQL root URL and test-Redis URL are reachable,
    returning False when either is unconfigured or unreachable."""
    if TEST_MYSQL_ROOT_URL is None or TEST_REDIS_URL is None:
        return False
    try:
        r = redis_lib.from_url(TEST_REDIS_URL, socket_connect_timeout=2)
        r.ping()
    except Exception:  # noqa: BLE001 -- availability probe
        return False
    try:
        engine = create_engine(TEST_MYSQL_ROOT_URL, connect_args={"connect_timeout": 2})
        with engine.connect():
            pass
    except Exception:  # noqa: BLE001 -- same as above
        return False
    return True


pytestmark = pytest.mark.skipif(
    not _real_backends_available(),
    reason="real Redis/MySQL not reachable (set B0_TEST_REDIS_URL / "
    "B0_TEST_MYSQL_ROOT_URL, or run against the dev docker-compose stack)",
)


@pytest.fixture
def real_redis_stream():
    """Point the stream reader at an isolated test stream and consumer group, then destroy the group
    and delete the stream on teardown -- never touches the production audit:events stream."""
    from audit.config import AuditConfig
    from consumers.stream_reader import StreamReader

    original_stream = AuditConfig.STREAM_NAME
    original_group = AuditConfig.CONSUMER_GROUP
    AuditConfig.STREAM_NAME = TEST_STREAM
    AuditConfig.CONSUMER_GROUP = TEST_GROUP
    try:
        reader = StreamReader()
        reader.ensure_group()
        yield reader
    finally:
        try:
            reader.redis.xgroup_destroy(TEST_STREAM, TEST_GROUP)
        except Exception as cleanup_err:  # noqa: BLE001 -- best-effort teardown
            print(f"[TEST TEARDOWN] xgroup_destroy failed (non-fatal): {cleanup_err}")
        try:
            reader.redis.delete(TEST_STREAM)
        except Exception as cleanup_err:  # noqa: BLE001 -- same as above
            print(f"[TEST TEARDOWN] stream delete failed (non-fatal): {cleanup_err}")
        AuditConfig.STREAM_NAME = original_stream
        AuditConfig.CONSUMER_GROUP = original_group


@pytest.fixture
def real_mysql_url():
    """Create a throwaway database, run the real Alembic migration against it, yield its URL, then
    drop it."""
    root_engine = create_engine(TEST_MYSQL_ROOT_URL)
    with root_engine.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {TEST_DB_NAME}"))
        conn.execute(text(f"CREATE DATABASE {TEST_DB_NAME}"))
        conn.commit()

    db_url = TEST_MYSQL_ROOT_URL.rsplit("/", 1)[0] + f"/{TEST_DB_NAME}"

    from pathlib import Path

    from alembic.config import Config

    from alembic import command

    repo_root = Path(__file__).resolve().parent.parent
    cfg = Config(str(repo_root / "alembic.ini"))
    cfg.set_main_option("script_location", str(repo_root / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")

    yield db_url

    with root_engine.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {TEST_DB_NAME}"))
        conn.commit()


def _session_local(real_mysql_url):
    """Build a SQLAlchemy sessionmaker bound to the throwaway test-MySQL database."""
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(real_mysql_url)
    return sessionmaker(bind=engine)


def _valid_payload(event_id):
    """Build a valid JSON audit-event payload string for the given event id."""
    return json.dumps({
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "e2-quarantine-integration-test",
        "event_type": "test",
        "user_id": "test-user",
        "action": "e2_persistence_exhausted_smoke",
        "resource": None,
        "decision": "success",
        "reason": None,
        "trace_id": "e2-trace-1",
        "context": {},
    })


# ---------------------------------------------------------------------------
# 1. "persistence_exhausted" poison: a well-formed, valid event that simply
#    never reached MySQL across every delivery attempt -- distinct
#    diagnosis from a malformed payload, and the raw event must be fully
#    recoverable from quarantine (it's real, legitimate audit content).
# ---------------------------------------------------------------------------

def test_real_persistence_exhausted_event_is_quarantined_with_recoverable_payload(
    real_redis_stream, real_mysql_url, monkeypatch,
):
    """Quarantine an event whose persistence keeps failing until max deliveries, with the
    quarantined row carrying a recoverable payload."""
    import worker.main as worker_module
    from consumers.sink import Sink

    TestSessionLocal = _session_local(real_mysql_url)

    class _AlwaysFailingSink(Sink):
        def write(self, event):
            raise Exception("simulated sustained MySQL outage")  # noqa: TRY002

    event_id = f"e2-exhausted-{uuid.uuid4()}"
    raw_data = _valid_payload(event_id)
    real_redis_stream.redis.xadd(TEST_STREAM, {"data": raw_data})

    monkeypatch.setattr(worker_module, "SessionLocal", TestSessionLocal)
    monkeypatch.setattr(worker_module, "Sink", _AlwaysFailingSink)

    MAX_DELIVERIES = 1  # a single failed delivery is already enough to test poison classification here
    response = real_redis_stream.read_group("worker-a", block=2000)
    assert response
    message_id, fields = response[0][1][0]
    result = worker_module.handle_message(real_redis_stream, message_id, fields)
    assert result is False  # MySQL "down" -- persistence fails, stays pending

    time.sleep(0.1)
    claimed, poison_entries = real_redis_stream.claim_stale(
        "worker-b", min_idle_ms=50, max_deliveries=MAX_DELIVERIES,
    )
    assert claimed == []
    assert len(poison_entries) == 1
    poison_message_id, poison_fields, delivery_attempts = poison_entries[0]
    assert delivery_attempts == MAX_DELIVERIES

    # Quarantine must succeed even while Sink (the normal persistence
    # path) is still "down" -- QuarantineSink is entirely independent of
    # it and uses its own DB write.
    quarantined = worker_module.quarantine_and_ack(
        real_redis_stream, poison_message_id, poison_fields, delivery_attempts,
    )
    assert quarantined is True

    pending_after = real_redis_stream.redis.xpending(TEST_STREAM, TEST_GROUP)
    assert pending_after["pending"] == 0

    with TestSessionLocal() as session:
        from db.models import AuditEventRecord, QuarantinedAuditEvent

        # Never inserted into the canonical trusted table.
        assert session.get(AuditEventRecord, event_id) is None

        row = session.get(QuarantinedAuditEvent, poison_message_id)
        assert row is not None
        assert row.failure_category == "persistence_exhausted"
        assert row.service == "e2-quarantine-integration-test"
        assert row.delivery_attempts == MAX_DELIVERIES
        # The original event is fully recoverable from quarantine.
        recovered = json.loads(row.raw_data)
        assert recovered["event_id"] == event_id
        assert recovered["action"] == "e2_persistence_exhausted_smoke"


# ---------------------------------------------------------------------------
# 2. Quarantine-write failure must NOT ack the original -- the exact
#    "quarantine failure does not silently discard original" requirement,
#    proven against a real Redis PEL, not a mock.
# ---------------------------------------------------------------------------

def test_real_quarantine_write_failure_does_not_ack_original(
    real_redis_stream, real_mysql_url, monkeypatch,
):
    """Leave the original message unacknowledged when the quarantine write itself fails."""
    import worker.main as worker_module
    from consumers.quarantine import QuarantineSink

    TestSessionLocal = _session_local(real_mysql_url)
    monkeypatch.setattr(worker_module, "SessionLocal", TestSessionLocal)

    class _FailingQuarantineSink(QuarantineSink):
        def write(self, message_id, fields, delivery_attempts):
            raise Exception("simulated MySQL outage during quarantine write")  # noqa: TRY002

    monkeypatch.setattr(worker_module, "QuarantineSink", _FailingQuarantineSink)

    real_redis_stream.redis.xadd(TEST_STREAM, {"data": "not valid json"})
    response = real_redis_stream.read_group("worker-a", block=2000)
    assert response
    message_id, fields = response[0][1][0]
    worker_module.handle_message(real_redis_stream, message_id, fields)

    time.sleep(0.1)
    _claimed, poison_entries = real_redis_stream.claim_stale(
        "worker-b", min_idle_ms=50, max_deliveries=1,
    )
    assert len(poison_entries) == 1
    poison_message_id, poison_fields, delivery_attempts = poison_entries[0]

    quarantined = worker_module.quarantine_and_ack(
        real_redis_stream, poison_message_id, poison_fields, delivery_attempts,
    )
    assert quarantined is False

    # Still pending -- the original message was NOT discarded.
    pending = real_redis_stream.redis.xpending(TEST_STREAM, TEST_GROUP)
    assert pending["pending"] == 1

    with TestSessionLocal() as session:
        from db.models import QuarantinedAuditEvent

        assert session.get(QuarantinedAuditEvent, poison_message_id) is None


# ---------------------------------------------------------------------------
# 3. Quarantine-write succeeds but the process "crashes" before the
#    follow-up ack -- a later retry of quarantine_and_ack() for the same
#    entry must not create a duplicate quarantine row, and must still
#    reach ack.
# ---------------------------------------------------------------------------

def test_real_requarantine_after_crash_before_ack_is_idempotent(
    real_redis_stream, real_mysql_url, monkeypatch,
):
    """Quarantine a poison message exactly once even when it is reclaimed and requarantined after a
    crash before ack."""
    import worker.main as worker_module
    from consumers.quarantine import QuarantineSink

    TestSessionLocal = _session_local(real_mysql_url)
    monkeypatch.setattr(worker_module, "SessionLocal", TestSessionLocal)

    real_redis_stream.redis.xadd(TEST_STREAM, {"data": "not valid json either"})
    response = real_redis_stream.read_group("worker-a", block=2000)
    assert response
    message_id, fields = response[0][1][0]
    worker_module.handle_message(real_redis_stream, message_id, fields)

    time.sleep(0.1)
    _claimed, poison_entries = real_redis_stream.claim_stale(
        "worker-b", min_idle_ms=50, max_deliveries=1,
    )
    poison_message_id, poison_fields, delivery_attempts = poison_entries[0]

    # First call: quarantine write succeeds, but "crash" before ack --
    # call QuarantineSink directly to model exactly that gap, same
    # pattern test_worker_pel_recovery_integration.py's duplicate-
    # delivery test uses for the analogous Sink gap.
    db = TestSessionLocal()
    try:
        QuarantineSink(db).write(poison_message_id, poison_fields, delivery_attempts)
    finally:
        db.close()
    # Deliberately no ack() here.

    with TestSessionLocal() as session:
        from sqlalchemy import func

        from db.models import QuarantinedAuditEvent

        count_before = session.query(func.count(QuarantinedAuditEvent.stream_message_id)).filter(
            QuarantinedAuditEvent.stream_message_id == poison_message_id
        ).scalar()
        assert count_before == 1

    pending = real_redis_stream.redis.xpending(TEST_STREAM, TEST_GROUP)
    assert pending["pending"] == 1  # still unacked

    # A later sweep reclaims the still-pending (still poison, still
    # over max_deliveries) entry and retries quarantine_and_ack() --
    # must be a safe no-op on the write, then successfully ack.
    time.sleep(0.1)
    _claimed2, poison_entries2 = real_redis_stream.claim_stale(
        "worker-c", min_idle_ms=50, max_deliveries=1,
    )
    assert len(poison_entries2) == 1
    second_message_id, second_fields, second_delivery_attempts = poison_entries2[0]
    assert second_message_id == poison_message_id

    quarantined = worker_module.quarantine_and_ack(
        real_redis_stream, second_message_id, second_fields, second_delivery_attempts,
    )
    assert quarantined is True

    with TestSessionLocal() as session:
        from sqlalchemy import func

        from db.models import QuarantinedAuditEvent

        count_after = session.query(func.count(QuarantinedAuditEvent.stream_message_id)).filter(
            QuarantinedAuditEvent.stream_message_id == poison_message_id
        ).scalar()
        assert count_after == 1  # still exactly one row, not two

    pending_after = real_redis_stream.redis.xpending(TEST_STREAM, TEST_GROUP)
    assert pending_after["pending"] == 0


# ---------------------------------------------------------------------------
# 4. Incident (2026-09-16) regression, real backends: a stream entry
#    missing the `data` field entirely (as opposed to `data` present but
#    unparseable) previously raised an uncaught KeyError in
#    handle_message() and crashed the whole worker process. Full pipeline
#    proof against a real Redis PEL and real MySQL: does not crash, does
#    not ack prematurely, and lands in quarantine with the exact
#    "malformed"/"MissingDataField" classification.
# ---------------------------------------------------------------------------

def test_real_missing_data_field_is_quarantined_not_crashed(
    real_redis_stream, real_mysql_url, monkeypatch,
):
    """Quarantine a message that carries no data field instead of crashing the worker."""
    import worker.main as worker_module

    TestSessionLocal = _session_local(real_mysql_url)
    monkeypatch.setattr(worker_module, "SessionLocal", TestSessionLocal)

    # The exact incident shape: no "data" field in the stream entry at all.
    real_redis_stream.redis.xadd(TEST_STREAM, {"sig": "irrelevant-signature"})

    response = real_redis_stream.read_group("worker-a", block=2000)
    assert response
    message_id, fields = response[0][1][0]
    assert "data" not in fields

    # Requirement A: must not raise, must not ack (retriable, same as a
    # malformed-JSON parse failure).
    result = worker_module.handle_message(real_redis_stream, message_id, fields)
    assert result is False

    pending_mid = real_redis_stream.redis.xpending(TEST_STREAM, TEST_GROUP)
    assert pending_mid["pending"] == 1  # still pending, not acked, not lost

    time.sleep(0.1)
    MAX_DELIVERIES = 1
    claimed, poison_entries = real_redis_stream.claim_stale(
        "worker-b", min_idle_ms=50, max_deliveries=MAX_DELIVERIES,
    )
    assert claimed == []
    assert len(poison_entries) == 1
    poison_message_id, poison_fields, delivery_attempts = poison_entries[0]

    # Requirement E: durable quarantine write must happen before ack --
    # already enforced by quarantine_and_ack() itself; confirmed here via
    # the same real-backend proof style as test 1/2/3 above.
    quarantined = worker_module.quarantine_and_ack(
        real_redis_stream, poison_message_id, poison_fields, delivery_attempts,
    )
    assert quarantined is True

    pending_after = real_redis_stream.redis.xpending(TEST_STREAM, TEST_GROUP)
    assert pending_after["pending"] == 0

    with TestSessionLocal() as session:
        from db.models import QuarantinedAuditEvent

        row = session.get(QuarantinedAuditEvent, poison_message_id)
        assert row is not None
        assert row.raw_data is None
        assert row.failure_category == "malformed"
        assert row.failure_detail == "MissingDataField"
        assert row.delivery_attempts == MAX_DELIVERIES


def test_real_processing_continues_after_missing_data_poison_entry(
    real_redis_stream, real_mysql_url, monkeypatch,
):
    """Requirement C, real backends: a missing-`data` poison entry must
    not prevent a subsequent, independent, well-formed event from being
    durably persisted through the normal (non-poison) path in the same
    worker."""
    import worker.main as worker_module

    TestSessionLocal = _session_local(real_mysql_url)
    monkeypatch.setattr(worker_module, "SessionLocal", TestSessionLocal)

    real_redis_stream.redis.xadd(TEST_STREAM, {"sig": "irrelevant"})  # poison: no "data"
    good_event_id = f"e2-after-poison-{uuid.uuid4()}"
    real_redis_stream.redis.xadd(TEST_STREAM, {"data": _valid_payload(good_event_id)})

    response = real_redis_stream.read_group("worker-a", block=2000, count=10)
    messages = response[0][1]
    assert len(messages) == 2

    results = [worker_module.handle_message(real_redis_stream, mid, f) for mid, f in messages]
    assert results == [False, True]  # poison stays pending, good event persists and acks

    with TestSessionLocal() as session:
        from db.models import AuditEventRecord

        assert session.get(AuditEventRecord, good_event_id) is not None
