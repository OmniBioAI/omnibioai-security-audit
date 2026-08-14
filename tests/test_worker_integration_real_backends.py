"""PR-B0: end-to-end regression against REAL Redis and REAL MySQL, not the
mocks/SQLite used by the rest of the suite (tests/test_worker.py,
tests/test_sink.py, tests/test_stream.py, tests/test_migrations.py).

This exists specifically to prove the runtime path B0 makes deployable --
Redis Streams consumer group -> worker -> MySQL persistence -- actually
works against real backends, since nothing in the repo previously did.
It is intentionally isolated from any other data on those backends:

* Uses its own Redis stream name (never the production `audit:events`
  stream other services are actively writing to), destroyed at teardown.
* Uses its own throwaway MySQL database (never the `omnibioai_audit`
  database the real worker/API use), dropped at teardown.

Skips automatically (does not fail) when a real Redis/MySQL isn't
reachable -- e.g. in CI, which has no service containers configured for
this repo today (see .github/workflows/ci.yml). This is opportunistic
regression coverage for environments (like local dev-stack validation)
where real backends exist, not a hard CI requirement introduced by this
PR -- see the B0 report for why that's a deliberate, separately-flagged
follow-up rather than bundled into this change.
"""
import json
import os
import uuid

import pytest
import redis as redis_lib
from sqlalchemy import create_engine, text

TEST_REDIS_URL = os.getenv("B0_TEST_REDIS_URL", "redis://localhost:6380")
TEST_MYSQL_ROOT_URL = os.getenv(
    "B0_TEST_MYSQL_ROOT_URL", "mysql+pymysql://root:root@localhost:3306/mysql"
)
TEST_DB_NAME = "omnibioai_audit_b0_test"
TEST_STREAM = f"audit:events:b0-test-{uuid.uuid4().hex[:8]}"


def _real_backends_available():
    try:
        r = redis_lib.from_url(TEST_REDIS_URL, socket_connect_timeout=2)
        r.ping()
    except Exception:
        return False
    try:
        engine = create_engine(TEST_MYSQL_ROOT_URL, connect_args={"connect_timeout": 2})
        with engine.connect():
            pass
    except Exception:
        return False
    return True


pytestmark = pytest.mark.skipif(
    not _real_backends_available(),
    reason="real Redis/MySQL not reachable (set B0_TEST_REDIS_URL / "
    "B0_TEST_MYSQL_ROOT_URL, or run against the dev docker-compose stack) "
    "-- skipped, not failed, since CI has no service containers for this "
    "repo today",
)


@pytest.fixture
def real_mysql_url():
    """Creates a throwaway database, runs the real alembic migration
    against it (proving the actual migration -- not a hand-built schema --
    is what's being validated), yields its URL, then drops it."""
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


@pytest.fixture
def real_redis_stream():
    """Yields a real StreamReader pointed at an isolated test stream name,
    then destroys the consumer group and deletes the stream -- never
    touches the production `audit:events` stream."""
    from audit.config import AuditConfig
    from consumers.stream_reader import StreamReader

    original_stream = AuditConfig.STREAM_NAME
    AuditConfig.STREAM_NAME = TEST_STREAM
    try:
        reader = StreamReader()
        reader.ensure_group()
        yield reader
    finally:
        # Best-effort teardown of the isolated test stream/group -- if the
        # test itself already failed, the group/stream may be partially
        # created or already gone; swallow here so teardown never masks
        # the real assertion failure with a cleanup error.
        try:
            reader.redis.xgroup_destroy(TEST_STREAM, AuditConfig.CONSUMER_GROUP)
        except Exception as cleanup_err:
            print(f"[TEST TEARDOWN] xgroup_destroy failed (non-fatal): {cleanup_err}")
        try:
            reader.redis.delete(TEST_STREAM)
        except Exception as cleanup_err:
            print(f"[TEST TEARDOWN] stream delete failed (non-fatal): {cleanup_err}")
        AuditConfig.STREAM_NAME = original_stream


def test_real_stream_group_bootstrap_is_idempotent(real_redis_stream):
    """ensure_group() must be safely callable more than once against a
    real Redis instance (BUSYGROUP swallowed) -- the mocked version in
    tests/test_stream.py can't prove the real ResponseError string match
    holds against a real server's actual error text."""
    real_redis_stream.ensure_group()  # second call, must not raise


def test_real_produce_consume_persist_ack_round_trip(real_redis_stream, real_mysql_url, monkeypatch):
    """The exact chain B0 makes deployable: producer XADD -> real Redis
    Streams consumer group -> worker.handle_message -> real MySQL insert
    -> XACK. Uses the worker's actual handle_message(), not a
    reimplementation of it."""
    import json
    from datetime import datetime, timezone

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import worker.main as worker_module

    engine = create_engine(real_mysql_url)
    TestSessionLocal = sessionmaker(bind=engine)
    monkeypatch.setattr(worker_module, "SessionLocal", TestSessionLocal)

    event_id = f"b0-test-{uuid.uuid4()}"
    payload = {
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "b0-integration-test",
        "event_type": "test",
        "user_id": "test-user",
        "action": "b0_smoke",
        "resource": None,
        "decision": "success",
        "reason": None,
        "trace_id": "b0-trace-1",
        "context": {},
    }
    real_redis_stream.redis.xadd(TEST_STREAM, {"data": json.dumps(payload)})

    response = real_redis_stream.read_group(consumer_name="b0-test-consumer", block=3000)
    assert response, "expected the real event just XADDed to be delivered"

    acked = False
    for _stream_name, messages in response:
        for message_id, fields in messages:
            result = worker_module.handle_message(real_redis_stream, message_id, fields)
            assert result is True
            acked = True
    assert acked

    with TestSessionLocal() as session:
        from db.models import AuditEventRecord

        row = session.get(AuditEventRecord, event_id)
        assert row is not None
        assert row.service == "b0-integration-test"
        assert row.action == "b0_smoke"

    # Pending entries list must be empty -- the message was acked, not
    # left for retry.
    pending = real_redis_stream.redis.xpending(TEST_STREAM, "audit-workers")
    assert pending["pending"] == 0


def _integration_payload(event_id, service="b0-integration-test", **overrides):
    from datetime import datetime, timezone

    payload = {
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": service,
        "event_type": "test",
        "user_id": "test-user",
        "action": "pr2_integration_smoke",
        "resource": None,
        "decision": "success",
        "reason": None,
        "trace_id": "pr2-trace-1",
        "context": {},
    }
    payload.update(overrides)
    return payload


def _run_real_round_trip(real_redis_stream, real_mysql_url, monkeypatch, event_id, build_fields):
    """Shared plumbing for the three PR2 integration tests below --
    identical chain to test_real_produce_consume_persist_ack_round_trip
    above (real XADD -> real consumer-group read -> worker.handle_message
    -> real MySQL -> XACK).

    `build_fields(raw_data) -> dict` decides the extra Redis fields (a
    `sig`, or none) for this specific raw_data string -- taking a callback
    rather than a precomputed `sig` guarantees any signature is always
    computed against the exact bytes that get XADDed, not a separately
    (and therefore mismatched) constructed copy.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import worker.main as worker_module

    engine = create_engine(real_mysql_url)
    TestSessionLocal = sessionmaker(bind=engine)
    monkeypatch.setattr(worker_module, "SessionLocal", TestSessionLocal)

    raw_data = json.dumps(_integration_payload(event_id))
    fields = {"data": raw_data, **build_fields(raw_data)}
    real_redis_stream.redis.xadd(TEST_STREAM, fields)

    response = real_redis_stream.read_group(consumer_name="pr2-test-consumer", block=3000)
    assert response, "expected the real event just XADDed to be delivered"

    acked = False
    for _stream_name, messages in response:
        for message_id, delivered_fields in messages:
            result = worker_module.handle_message(real_redis_stream, message_id, delivered_fields)
            assert result is True
            acked = True
    assert acked

    with TestSessionLocal() as session:
        from db.models import AuditEventRecord

        row = session.get(AuditEventRecord, event_id)
        assert row is not None
        return row


# ---------------------------------------------------------------------------
# PR2: integrity_status through the real Redis -> worker -> MySQL chain.
#
# Signs with whatever AuditConfig.EVENT_SIGNING_SECRET actually resolves to
# in *this* process/environment -- worker.main.handle_message() (called
# inside _run_real_round_trip, same process) reads the same AuditConfig,
# so this is correct regardless of whether this environment has the real
# platform JWT_SECRET set or is falling back to "change-me". Never assumes
# which -- that is the entire point of reading it at test time rather than
# hard-coding a value.
# ---------------------------------------------------------------------------

def test_real_valid_signed_event_persists_as_valid(real_redis_stream, real_mysql_url, monkeypatch):
    from audit.config import AuditConfig
    from audit.signing import sign_audit_event

    event_id = f"pr2-valid-{uuid.uuid4()}"
    row = _run_real_round_trip(
        real_redis_stream, real_mysql_url, monkeypatch,
        event_id=event_id,
        build_fields=lambda raw_data: {
            "sig": sign_audit_event("b0-integration-test", raw_data, AuditConfig.EVENT_SIGNING_SECRET)
        },
    )
    assert row.integrity_status == "valid"


def test_real_unsigned_event_persists_as_unsigned(real_redis_stream, real_mysql_url, monkeypatch):
    event_id = f"pr2-unsigned-{uuid.uuid4()}"
    row = _run_real_round_trip(
        real_redis_stream, real_mysql_url, monkeypatch,
        event_id=event_id,
        build_fields=lambda raw_data: {},  # no sig field -- today's actual production traffic shape
    )
    assert row.integrity_status == "unsigned"


def test_real_invalid_signed_event_persists_as_invalid(real_redis_stream, real_mysql_url, monkeypatch):
    from audit.config import AuditConfig
    from audit.signing import sign_audit_event

    event_id = f"pr2-invalid-{uuid.uuid4()}"
    row = _run_real_round_trip(
        real_redis_stream, real_mysql_url, monkeypatch,
        event_id=event_id,
        # Well-formed v1 signature, correct secret, WRONG service -- signed
        # for a different producer identity than the event actually claims.
        build_fields=lambda raw_data: {
            "sig": sign_audit_event("some-other-service", raw_data, AuditConfig.EVENT_SIGNING_SECRET)
        },
    )
    assert row.integrity_status == "invalid"


def test_real_duplicate_delivery_does_not_duplicate_row(real_mysql_url):
    """Sink.write()'s IntegrityError-swallow behavior (consumers/sink.py)
    against a real MySQL unique-constraint violation, not SQLite's -- the
    exact exception type/rollback path differs enough between backends
    that this is worth proving directly, not just inferring from the
    SQLite-backed tests/test_sink.py coverage."""
    from datetime import datetime, timezone

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from consumers.sink import Sink

    engine = create_engine(real_mysql_url)
    TestSessionLocal = sessionmaker(bind=engine)

    event = {
        "event_id": f"b0-dup-test-{uuid.uuid4()}",
        "timestamp": datetime.now(timezone.utc),
        "service": "b0-integration-test",
        "event_type": "test",
        "user_id": None,
        "action": "dup_check",
        "resource": None,
        "decision": "success",
        "reason": None,
        "trace_id": None,
        "context": {},
    }

    with TestSessionLocal() as session1:
        first_result = Sink(session1).write(event)
    with TestSessionLocal() as session2:
        second_result = Sink(session2).write(event)  # redelivery, same event_id

    assert first_result is True
    assert second_result is True  # duplicate is a no-op success, not a crash

    with TestSessionLocal() as session:
        from sqlalchemy import func

        from db.models import AuditEventRecord

        count = session.query(func.count(AuditEventRecord.event_id)).filter(
            AuditEventRecord.event_id == event["event_id"]
        ).scalar()
        assert count == 1  # exactly one row, not two
