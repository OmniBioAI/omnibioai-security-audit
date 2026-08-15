"""HIPAA P0: end-to-end regression against REAL Redis and REAL MySQL for
the abandoned-Pending-Entries-List recovery path (StreamReader.claim_stale
+ worker/main.py::sweep_pending). Mirrors
tests/test_worker_integration_real_backends.py's own harness/isolation
conventions exactly (own throwaway stream, own throwaway database, skips
rather than fails when real backends aren't reachable) -- see that file's
module docstring for the full rationale, not repeated here.

This is the one place in the suite that can actually prove the claims
StreamReader.claim_stale()'s docstring makes about concurrent-worker
safety: a mocked reader can assert "xclaim was called with these ids",
but only a real Redis server enforces that two XCLAIM calls racing for
the same still-idle entry can never both succeed.

Every scenario here uses small min_idle_ms/max_deliveries overrides
(never the real 30s/5-attempt production defaults, see audit/config.py)
so this file runs in well under a second, not tens of seconds.
"""
import json
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest
import redis as redis_lib
from sqlalchemy import create_engine, text

TEST_REDIS_URL = os.getenv("B0_TEST_REDIS_URL", "redis://localhost:6380")
TEST_MYSQL_ROOT_URL = os.getenv(
    "B0_TEST_MYSQL_ROOT_URL", "mysql+pymysql://root:root@localhost:3306/mysql"
)
TEST_DB_NAME = "omnibioai_audit_p0_pel_test"
TEST_STREAM = f"audit:events:p0-pel-test-{uuid.uuid4().hex[:8]}"
TEST_GROUP = "audit-workers"


def _real_backends_available():
    try:
        r = redis_lib.from_url(TEST_REDIS_URL, socket_connect_timeout=2)
        r.ping()
    except Exception:  # noqa: BLE001 -- availability probe: any failure means "unavailable", never a crash
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
    "B0_TEST_MYSQL_ROOT_URL, or run against the dev docker-compose stack) "
    "-- skipped, not failed, same convention as "
    "test_worker_integration_real_backends.py",
)


@pytest.fixture
def real_redis_stream():
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
        except Exception as cleanup_err:  # noqa: BLE001 -- best-effort teardown must never mask the real test failure
            print(f"[TEST TEARDOWN] xgroup_destroy failed (non-fatal): {cleanup_err}")
        try:
            reader.redis.delete(TEST_STREAM)
        except Exception as cleanup_err:  # noqa: BLE001 -- same as above
            print(f"[TEST TEARDOWN] stream delete failed (non-fatal): {cleanup_err}")
        AuditConfig.STREAM_NAME = original_stream
        AuditConfig.CONSUMER_GROUP = original_group


@pytest.fixture
def real_mysql_url():
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


def _payload(event_id, **overrides):
    payload = {
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "p0-pel-integration-test",
        "event_type": "test",
        "user_id": "test-user",
        "action": "p0_pel_smoke",
        "resource": None,
        "decision": "success",
        "reason": None,
        "trace_id": "p0-pel-trace-1",
        "context": {},
    }
    payload.update(overrides)
    return payload


def _session_local(real_mysql_url):
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(real_mysql_url)
    return sessionmaker(bind=engine)


# ---------------------------------------------------------------------------
# 1. Crash before ack -> the entry is claimable once idle, and a *second*
#    worker (distinct consumer identity, exactly like a different replica
#    or a restarted process with a new pid-based name) can pick it up and
#    successfully persist + ack it. Covers both "abandoned PEL entry
#    becoming claimable" and "second worker successfully claiming and
#    processing it" from the task's required scenario list in one
#    end-to-end proof.
# ---------------------------------------------------------------------------

def test_real_crash_before_ack_is_reclaimed_by_a_second_worker_and_persisted(
    real_redis_stream, real_mysql_url, monkeypatch,
):
    import worker.main as worker_module

    TestSessionLocal = _session_local(real_mysql_url)
    monkeypatch.setattr(worker_module, "SessionLocal", TestSessionLocal)

    event_id = f"p0-crash-{uuid.uuid4()}"
    real_redis_stream.redis.xadd(TEST_STREAM, {"data": json.dumps(_payload(event_id))})

    # "Worker A" reads it and then crashes -- never calls handle_message,
    # never acks. This is exactly what read_group() delivering a message
    # that's then never processed looks like from Redis's point of view.
    delivered = real_redis_stream.read_group("worker-a-crashed", block=2000)
    assert delivered, "expected the event to be delivered to worker A"

    # Confirm it's genuinely sitting in the PEL, unacked, before recovery.
    pending_before = real_redis_stream.redis.xpending(TEST_STREAM, TEST_GROUP)
    assert pending_before["pending"] == 1

    time.sleep(0.1)  # exceed the tiny min_idle_ms used below

    # "Worker B" -- a different consumer identity entirely -- sweeps and
    # reclaims it.
    claimed, poison_ids = real_redis_stream.claim_stale("worker-b-recovers", min_idle_ms=50)
    assert poison_ids == []
    assert len(claimed) == 1
    message_id, fields = claimed[0]

    result = worker_module.handle_message(real_redis_stream, message_id, fields)
    assert result is True

    with TestSessionLocal() as session:
        from db.models import AuditEventRecord

        row = session.get(AuditEventRecord, event_id)
        assert row is not None
        assert row.action == "p0_pel_smoke"

    pending_after = real_redis_stream.redis.xpending(TEST_STREAM, TEST_GROUP)
    assert pending_after["pending"] == 0


# ---------------------------------------------------------------------------
# 2. Multiple workers racing to recover the very same abandoned entry --
#    the concurrency-safety claim StreamReader.claim_stale()'s docstring
#    makes. Only real Redis can prove this; a mock can't enforce atomicity.
# ---------------------------------------------------------------------------

def test_real_concurrent_workers_racing_for_the_same_entry_only_one_wins(
    real_redis_stream, real_mysql_url,
):
    event_id = f"p0-race-{uuid.uuid4()}"
    real_redis_stream.redis.xadd(TEST_STREAM, {"data": json.dumps(_payload(event_id))})

    delivered = real_redis_stream.read_group("worker-a-crashed", block=2000)
    assert delivered
    time.sleep(0.1)

    from consumers.stream_reader import StreamReader

    reader_b = real_redis_stream
    reader_c = StreamReader()
    reader_c.stream = TEST_STREAM

    results = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(reader_b.claim_stale, "worker-b", group=TEST_GROUP, min_idle_ms=50),
            pool.submit(reader_c.claim_stale, "worker-c", group=TEST_GROUP, min_idle_ms=50),
        ]
        for f in futures:
            results.append(f.result())

    total_claimed = sum(len(claimed) for claimed, _poison in results)
    assert total_claimed == 1, (
        "exactly one of the two racing claim_stale() calls must win this "
        f"entry, got {total_claimed} total claims across both"
    )


# ---------------------------------------------------------------------------
# 3. Transient persistence failure -- previously permanent event loss
#    (see worker/main.py's old docstring claim vs. actual behavior),
#    now recoverable: the first delivery fails to persist, the message
#    is reclaimed once idle, and the retry succeeds.
# ---------------------------------------------------------------------------

def test_real_transient_persistence_failure_then_reclaim_succeeds(
    real_redis_stream, real_mysql_url, monkeypatch,
):
    import worker.main as worker_module
    from consumers.sink import Sink

    TestSessionLocal = _session_local(real_mysql_url)

    event_id = f"p0-transient-{uuid.uuid4()}"
    real_redis_stream.redis.xadd(TEST_STREAM, {"data": json.dumps(_payload(event_id))})

    response = real_redis_stream.read_group("worker-a", block=2000)
    assert response
    message_id, fields = response[0][1][0]

    # First attempt: simulate a transient MySQL failure during persistence.
    class _FailingSink(Sink):
        def write(self, event):
            raise Exception("simulated transient MySQL outage")  # noqa: TRY002 -- deliberately generic, standing in for "any real DB exception class"

    monkeypatch.setattr(worker_module, "SessionLocal", TestSessionLocal)
    monkeypatch.setattr(worker_module, "Sink", _FailingSink)
    first_result = worker_module.handle_message(real_redis_stream, message_id, fields)
    assert first_result is False

    pending = real_redis_stream.redis.xpending(TEST_STREAM, TEST_GROUP)
    assert pending["pending"] == 1  # still unacked after the transient failure

    time.sleep(0.1)

    # MySQL "recovers" -- restore the real Sink and reclaim + retry.
    monkeypatch.setattr(worker_module, "Sink", Sink)
    claimed, poison_ids = real_redis_stream.claim_stale("worker-b", min_idle_ms=50)
    assert poison_ids == []
    assert len(claimed) == 1
    second_message_id, second_fields = claimed[0]

    second_result = worker_module.handle_message(real_redis_stream, second_message_id, second_fields)
    assert second_result is True

    with TestSessionLocal() as session:
        from db.models import AuditEventRecord

        row = session.get(AuditEventRecord, event_id)
        assert row is not None


# ---------------------------------------------------------------------------
# 4. Duplicate delivery through the reclaim path specifically -- a
#    successful persist whose ack was itself lost (crash between the
#    MySQL commit and the XACK call) must not create a second row when
#    a different worker reclaims and reprocesses the same entry.
#    Complements test_real_duplicate_delivery_does_not_duplicate_row in
#    test_worker_integration_real_backends.py, which exercises Sink
#    directly rather than through claim_stale().
# ---------------------------------------------------------------------------

def test_real_duplicate_delivery_after_reclaim_does_not_duplicate_row(
    real_redis_stream, real_mysql_url, monkeypatch,
):
    import worker.main as worker_module

    TestSessionLocal = _session_local(real_mysql_url)
    monkeypatch.setattr(worker_module, "SessionLocal", TestSessionLocal)

    event_id = f"p0-dup-reclaim-{uuid.uuid4()}"
    real_redis_stream.redis.xadd(TEST_STREAM, {"data": json.dumps(_payload(event_id))})

    response = real_redis_stream.read_group("worker-a", block=2000)
    assert response
    _message_id, fields = response[0][1][0]

    # Worker A persists successfully but "crashes" before the ack() call
    # actually below -- call Sink directly to model exactly that gap.
    from consumers.sink import Sink

    db = TestSessionLocal()
    try:
        payload = json.loads(fields["data"])
        payload["integrity_status"] = "unsigned"
        Sink(db).write(payload)
    finally:
        db.close()
    # Deliberately no ack() here -- modeling the crash-after-commit gap.

    time.sleep(0.1)

    claimed, poison_ids = real_redis_stream.claim_stale("worker-b", min_idle_ms=50)
    assert poison_ids == []
    assert len(claimed) == 1
    second_message_id, second_fields = claimed[0]

    # Worker B reprocesses the same event_id end-to-end via the real
    # handle_message() -- Sink.write's IntegrityError-swallow (PK on
    # event_id) must make this a safe no-op, and worker B must still ack.
    result = worker_module.handle_message(real_redis_stream, second_message_id, second_fields)
    assert result is True

    with TestSessionLocal() as session:
        from sqlalchemy import func

        from db.models import AuditEventRecord

        count = session.query(func.count(AuditEventRecord.event_id)).filter(
            AuditEventRecord.event_id == event_id
        ).scalar()
        assert count == 1  # exactly one row, not two

    pending_after = real_redis_stream.redis.xpending(TEST_STREAM, TEST_GROUP)
    assert pending_after["pending"] == 0


# ---------------------------------------------------------------------------
# 5. Poison message (deterministically malformed, e.g. truly not JSON) --
#    must be retried a bounded number of times, never forever.
# ---------------------------------------------------------------------------

def test_real_malformed_event_is_abandoned_after_max_deliveries_not_retried_forever(
    real_redis_stream, real_mysql_url, monkeypatch,
):
    import worker.main as worker_module

    TestSessionLocal = _session_local(real_mysql_url)
    monkeypatch.setattr(worker_module, "SessionLocal", TestSessionLocal)

    MAX_DELIVERIES = 3
    real_redis_stream.redis.xadd(TEST_STREAM, {"data": "this is not valid json at all"})

    response = real_redis_stream.read_group("worker-a", block=2000)
    assert response
    message_id, fields = response[0][1][0]

    # Delivery #1 (the read above) already failed to parse -- handle_message
    # never acks. Reclaim it (MAX_DELIVERIES - 1) more times, each one also
    # failing identically (it's not transient -- the payload is simply not
    # JSON), to reach exactly MAX_DELIVERIES total deliveries.
    result = worker_module.handle_message(real_redis_stream, message_id, fields)
    assert result is False

    for _ in range(MAX_DELIVERIES - 1):
        time.sleep(0.1)
        claimed, poison_ids = real_redis_stream.claim_stale(
            "worker-b", min_idle_ms=50, max_deliveries=MAX_DELIVERIES,
        )
        assert poison_ids == []  # not poison yet -- still under the threshold
        assert len(claimed) == 1
        cmsg_id, cfields = claimed[0]
        result = worker_module.handle_message(real_redis_stream, cmsg_id, cfields)
        assert result is False  # still unparseable

    # One more sweep: this entry has now been delivered MAX_DELIVERIES
    # times without ever succeeding -- must be abandoned as poison, ACKed
    # directly by claim_stale(), never handed back for a (MAX_DELIVERIES+1)th
    # attempt.
    time.sleep(0.1)
    claimed, poison_ids = real_redis_stream.claim_stale(
        "worker-b", min_idle_ms=50, max_deliveries=MAX_DELIVERIES,
    )
    assert claimed == []
    assert len(poison_ids) == 1

    # The PEL is now empty -- proof the loop actually terminated, not
    # just that this one sweep classified it correctly.
    pending_after = real_redis_stream.redis.xpending(TEST_STREAM, TEST_GROUP)
    assert pending_after["pending"] == 0
