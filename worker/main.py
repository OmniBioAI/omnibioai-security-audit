"""security-audit-worker: the Redis Streams consumer-group -> audit_events
persistence loop (PR4.2).

Deliberately a separate process/container from api/main.py's FastAPI app
(see Dockerfile.worker), not a background task started on FastAPI startup:
audit ingestion must survive API restarts/deploys, the consumer workload
scales independently of API request volume, and API request latency must
never depend on a database write happening on the ingestion side.
"""
import sys

from audit.config import AuditConfig
from consumers.processor import parse_audit_event
from consumers.sink import Sink
from consumers.stream_reader import StreamReader
from db.session import SessionLocal


def handle_message(reader: StreamReader, message_id: str, fields: dict) -> bool:
    """Process one Redis Streams message. Returns True if it was acked.

    Deserialize -> validate -> persist -> ack, in that order, and only ack
    after a successful DB commit. Any failure along the way leaves the
    message unacknowledged in the consumer group's pending entries list so
    it can be retried -- it is never dropped.
    """
    try:
        event = parse_audit_event(fields["data"])
    except Exception as e:
        print(f"[WORKER] failed to parse message {message_id}: {e}")
        return False

    db = SessionLocal()
    try:
        Sink(db).write(event.model_dump())
    except Exception as e:
        print(f"[WORKER] failed to persist message {message_id}: {e}")
        return False
    finally:
        db.close()

    reader.ack(message_id)
    return True


def run(max_iterations=None):
    """Main consumer loop.

    max_iterations bounds the loop for tests; production (the __main__
    entrypoint below) leaves it None to run forever.
    """
    reader = StreamReader()
    reader.ensure_group()

    iterations = 0
    while max_iterations is None or iterations < max_iterations:
        response = reader.read_group(AuditConfig.CONSUMER_NAME)
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
