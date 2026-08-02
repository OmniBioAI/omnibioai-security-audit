import json
import redis.asyncio as redis
from typing import Optional
from audit.config import AuditConfig
from audit.models import AuditEvent


class AuditLogger:
    def __init__(self):
        self.redis = redis.from_url(AuditConfig.REDIS_URL, decode_responses=True)

    async def log(self, event: AuditEvent):
        try:
            # mode="json" recursively converts non-JSON-native types (e.g. the
            # datetime timestamp) to their JSON-safe form (ISO-8601 string),
            # so json.dumps below never sees a raw datetime.
            payload = event.model_dump(mode="json")

            await self.redis.xadd(
                AuditConfig.STREAM_NAME,
                {"data": json.dumps(payload)},
                maxlen=AuditConfig.MAX_STREAM_LENGTH,
                approximate=True,
            )
        except Exception as e:
            # NEVER break core system
            print(f"[AUDIT ERROR] {e}")