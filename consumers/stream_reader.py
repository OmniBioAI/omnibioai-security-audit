import redis
import json
from redis.exceptions import ResponseError
from audit.config import AuditConfig


class StreamReader:
    def __init__(self):
        self.redis = redis.from_url(AuditConfig.REDIS_URL, decode_responses=True)
        self.stream = AuditConfig.STREAM_NAME

    def read(self, last_id="0-0"):
        return self.redis.xread({self.stream: last_id}, block=5000)

    # -----------------------------------------------------------------
    # PR4.2: consumer-group reads for durable persistence. `read()` above
    # (offset-less xread) is left untouched for backward compatibility --
    # these are additive.
    # -----------------------------------------------------------------

    def ensure_group(self, group=None):
        """Create the consumer group if it doesn't exist yet (idempotent).

        Starts the group at "0-0" (not "$") so a brand-new group also picks
        up any events already sitting in the stream before the worker's
        first run, rather than silently skipping them.
        """
        group = group or AuditConfig.CONSUMER_GROUP
        try:
            self.redis.xgroup_create(self.stream, group, id="0-0", mkstream=True)
        except ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

    def read_group(self, consumer_name, group=None, count=10, block=5000):
        """Read undelivered ("new") messages for this consumer group."""
        group = group or AuditConfig.CONSUMER_GROUP
        return self.redis.xreadgroup(
            group, consumer_name, {self.stream: ">"}, count=count, block=block
        )

    def ack(self, message_id, group=None):
        group = group or AuditConfig.CONSUMER_GROUP
        self.redis.xack(self.stream, group, message_id)