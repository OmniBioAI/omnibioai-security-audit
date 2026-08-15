import redis
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

    # -----------------------------------------------------------------
    # HIPAA P0: abandoned Pending Entries List recovery. read_group()
    # above only ever asks Redis for ">" -- strictly new, never-before-
    # delivered messages -- so a message that was delivered but never
    # acked (worker crash, transient persistence failure) is otherwise
    # invisible to every future read_group() call, from this consumer
    # identity or any other, forever. See worker/main.py::sweep_pending
    # for the caller that makes this reachable from the main loop.
    # -----------------------------------------------------------------

    def claim_stale(self, consumer_name, group=None, min_idle_ms=None, max_deliveries=None, batch=None):
        """Reclaims entries abandoned by a crashed or stuck consumer.

        Two Redis calls (XPENDING's extended form, then XCLAIM), not the
        newer single-call XAUTOCLAIM: XPENDING's extended form is the
        only way to read each entry's `times_delivered`, which is what
        distinguishes "abandoned, still worth retrying" from "poison --
        has already failed this many times, stop retrying it" (see
        AuditConfig.PEL_MAX_DELIVERIES). XAUTOCLAIM's combined
        claim-in-one-call doesn't expose that count.

        Concurrency-safe for multiple worker replicas without any extra
        coordination: XCLAIM only reassigns an entry that is *still*
        idle >= min_idle_ms at the exact moment it runs. Two workers
        racing to reclaim the same entry each issue XCLAIM for it, but
        Redis processes them serially -- whichever runs second finds the
        entry already claimed (idle time just reset to ~0 by the first),
        so XCLAIM returns nothing for that id, never a duplicate
        delivery to both. See
        tests/test_worker_pel_recovery_integration.py::
        test_real_concurrent_workers_racing_for_the_same_entry_only_one_wins
        for a real-Redis proof (two live consumers racing to reclaim the
        same entry).

        Returns (claimed, poison_ids):
          claimed -- list of (message_id, fields) tuples now owned by
            `consumer_name`, ready for the normal handle_message() path,
            exactly like a message just read via read_group().
          poison_ids -- message ids that exceeded max_deliveries and were
            ACKed directly here (removed from the PEL, never handed back
            for reprocessing) -- returned only so the caller can log them,
            not for further action.
        """
        group = group or AuditConfig.CONSUMER_GROUP
        min_idle_ms = AuditConfig.PEL_MIN_IDLE_MS if min_idle_ms is None else min_idle_ms
        max_deliveries = AuditConfig.PEL_MAX_DELIVERIES if max_deliveries is None else max_deliveries
        batch = AuditConfig.PEL_SWEEP_BATCH if batch is None else batch

        stale = self.redis.xpending_range(
            self.stream, group, min="-", max="+", count=batch, idle=min_idle_ms
        )
        if not stale:
            return [], []

        poison_ids = [e["message_id"] for e in stale if e["times_delivered"] >= max_deliveries]
        reclaimable_ids = [e["message_id"] for e in stale if e["times_delivered"] < max_deliveries]

        if poison_ids:
            self.redis.xack(self.stream, group, *poison_ids)

        claimed = []
        if reclaimable_ids:
            claimed = self.redis.xclaim(self.stream, group, consumer_name, min_idle_ms, reclaimable_ids)
        return claimed, poison_ids