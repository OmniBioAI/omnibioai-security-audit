"""security-audit-worker: the Redis Streams consumer-group -> audit_events
persistence loop (PR4.2).

Deliberately a separate process/container from api/main.py's FastAPI app
(see Dockerfile.worker), not a background task started on FastAPI startup:
audit ingestion must survive API restarts/deploys, the consumer workload
scales independently of API request volume, and API request latency must
never depend on a database write happening on the ingestion side.
"""
import sys

from redis.exceptions import TimeoutError as RedisTimeoutError

from audit.config import AuditConfig
from consumers.processor import classify_event_integrity, parse_audit_event
from consumers.sink import Sink
from consumers.stream_reader import StreamReader
from db.session import SessionLocal


def handle_message(reader: StreamReader, message_id: str, fields: dict) -> bool:
    """Process one Redis Streams message. Returns True if it was acked.

    Deserialize -> classify -> persist -> ack, in that order, and only ack
    after a successful DB commit. Any failure along the way leaves the
    message unacknowledged in the consumer group's pending entries list.

    HIPAA P0: "unacknowledged" alone does NOT mean "will be retried" --
    that claim was this docstring's own, and it was false. read_group()
    only ever asks Redis for ">" (strictly new messages), so a delivered-
    but-unacked entry is invisible to every future read_group() call, from
    this consumer identity or any other, forever -- there was no retry
    path. What actually makes retry happen is run()'s call to
    sweep_pending() every loop iteration, via StreamReader.claim_stale()
    (XPENDING+XCLAIM): once an entry has sat unacked for
    AuditConfig.PEL_MIN_IDLE_MS, ANY live worker (this one after a
    reconnect, or a different replica entirely) reclaims it and runs it
    back through this exact function. A message is dropped only if it
    exceeds AuditConfig.PEL_MAX_DELIVERIES without ever succeeding --
    see sweep_pending()'s own docstring for why that bound exists.

    PR2: classification (valid/invalid/unsigned -- see consumers/
    processor.py::classify_event_integrity) is deliberately NOT another
    reason to leave a message unacked. Parse/DB failures above are retried
    because they may be transient or fixable; a signature is not -- it is
    either right or wrong forever, so retrying it accomplishes nothing.
    Every classification is persisted (as durable evidence, including
    forged attempts) and acked, exactly like today's fully-unsigned
    traffic. Uses fields["data"] itself, not a re-serialization of
    `event` -- the signature covers the exact transmitted bytes (see
    audit/signing.py).
    """
    raw_data = fields["data"]
    try:
        event = parse_audit_event(raw_data)
    except Exception as e:  # noqa: BLE001 -- any parse failure is retriable via sweep_pending(), never a crash
        print(f"[WORKER] failed to parse message {message_id}: {e}")
        return False

    integrity_status = classify_event_integrity(
        event.service, fields.get("sig"), raw_data, AuditConfig.EVENT_SIGNING_SECRET
    )
    if integrity_status == "invalid":
        # Distinct from the plain print() convention elsewhere in this
        # file: this is not an infra blip, it's a signature that failed
        # verification -- worth being loudly, separately visible.
        print(
            f"[WORKER] SIGNATURE INVALID for message {message_id} "
            f"(service={event.service!r}, event_id={event.event_id!r}) -- "
            f"persisting as durable evidence, not trusting the payload"
        )

    db = SessionLocal()
    try:
        payload = event.model_dump()
        payload["integrity_status"] = integrity_status
        Sink(db).write(payload)
    except Exception as e:  # noqa: BLE001 -- any persistence failure is retriable via sweep_pending(), never a crash
        print(f"[WORKER] failed to persist message {message_id}: {e}")
        return False
    finally:
        db.close()

    reader.ack(message_id)
    return True


def sweep_pending(reader: StreamReader) -> None:
    """Reclaims and processes Pending Entries List messages abandoned by
    a crashed or stuck consumer -- see StreamReader.claim_stale()'s own
    docstring for the XPENDING+XCLAIM mechanism this wraps. Called once
    per run() loop iteration, before reading new messages, so a backlog
    of abandoned events isn't starved by a steady stream of new traffic.

    Never raises: a Redis blip during the sweep itself must not kill the
    worker, matching read_group()'s own contract in run() below -- a
    failed sweep just tries again next iteration.

    Reclaimed entries run through the exact same handle_message() used
    for freshly-read messages -- same classify/persist/ack path, so a
    reclaimed message that fails again (still-down MySQL, say) is simply
    left pending again and picked up by the next sweep once
    PEL_MIN_IDLE_MS has re-elapsed, same as any other unacked entry.
    """
    try:
        claimed, poison_ids = reader.claim_stale(AuditConfig.CONSUMER_NAME)
    except Exception as e:  # noqa: BLE001 -- a Redis blip here must never kill the worker, same "NEVER break core system" contract read_group() below already has
        print(f"[WORKER] pending-entry sweep failed, will retry: {e}")
        return

    for message_id in poison_ids:
        print(
            f"[WORKER] POISON MESSAGE {message_id} abandoned after "
            f">={AuditConfig.PEL_MAX_DELIVERIES} delivery attempts -- "
            f"ACKed without processing, never persisted, will not be retried again"
        )

    for message_id, fields in claimed:
        handle_message(reader, message_id, fields)


def run(max_iterations=None):
    """Main consumer loop.

    max_iterations bounds the loop for tests; production (the __main__
    entrypoint below) leaves it None to run forever.
    """
    reader = StreamReader()
    reader.ensure_group()

    iterations = 0
    while max_iterations is None or iterations < max_iterations:
        sweep_pending(reader)
        try:
            response = reader.read_group(AuditConfig.CONSUMER_NAME)
        except RedisTimeoutError:
            # Expected on an idle stream: read_group() blocks for up to
            # `block` ms (default 5000, see StreamReader.read_group) and
            # redis-py's own socket-level read timeout can fire right at
            # that boundary even though the server side simply had
            # nothing new to deliver -- functionally identical to an
            # empty response, not a failure. Previously uncaught, this
            # crashed the process every ~5s once the stream went idle,
            # and Docker's restart: on-failure just repeated the same
            # crash forever (PR-B0 follow-up). No print here: this is
            # normal idle-stream behavior, not an error to alarm on.
            response = []
        except Exception as e:  # noqa: BLE001 -- a Redis blip here must never kill the worker
            # A genuine unexpected Redis/connection failure. Same
            # print-and-continue convention as handle_message()/
            # audit/logger.py above: never let a transient infra blip
            # kill the whole worker process, but keep it visible instead
            # of silently swallowed.
            print(f"[WORKER] read_group failed, will retry: {e}")
            response = []
        for _stream_name, messages in response:
            for message_id, fields in messages:
                handle_message(reader, message_id, fields)
        iterations += 1


if __name__ == "__main__":
    print(
        f"[WORKER] starting audit consumer "
        f"(group={AuditConfig.CONSUMER_GROUP}, "
        f"consumer={AuditConfig.CONSUMER_NAME}, "
        f"stream={AuditConfig.STREAM_NAME})"
    )
    try:
        run()
    except KeyboardInterrupt:
        sys.exit(0)
