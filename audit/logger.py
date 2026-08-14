import json
import redis.asyncio as redis
from typing import Optional
from audit.config import AuditConfig
from audit.models import AuditEvent
from audit.signing import sign_audit_event


class AuditLogger:
    def __init__(self):
        self.redis = redis.from_url(AuditConfig.REDIS_URL, decode_responses=True)

    async def log(self, event: AuditEvent):
        try:
            # mode="json" recursively converts non-JSON-native types (e.g. the
            # datetime timestamp) to their JSON-safe form (ISO-8601 string),
            # so json.dumps below never sees a raw datetime.
            payload = event.model_dump(mode="json")

            # HIPAA PR3b: this is the one producer that lives in the same
            # repo as the consumer/audit.signing itself, so unlike every
            # other producer (api-gateway, tes, workflow-bundles,
            # control-center, rag -- all separate deployables that
            # hand-port sign_audit_event), this one imports it directly --
            # no drift risk, no parallel copy to keep in sync.
            #
            # data is computed exactly once and that exact string is both
            # signed and published, matching every other producer's
            # contract. service comes from the already-serialized payload
            # (not event.service) so a signature always covers the
            # identity actually present in the signed bytes.
            data = json.dumps(payload)
            fields = {"data": data}
            service = payload.get("service")
            if service:
                fields["sig"] = sign_audit_event(service, data, AuditConfig.EVENT_SIGNING_SECRET)

            await self.redis.xadd(
                AuditConfig.STREAM_NAME,
                fields,
                maxlen=AuditConfig.MAX_STREAM_LENGTH,
                approximate=True,
            )
        except Exception as e:
            # NEVER break core system
            print(f"[AUDIT ERROR] {e}")