import functools

from audit.config import AuditConfig
from audit.context import get_identity, get_trace_id, get_user_id
from audit.logger import AuditLogger
from audit.models import AuditEvent

logger = AuditLogger()


def audit(event_type: str, action: str):
    def wrapper(func):
        @functools.wraps(func)
        async def async_inner(*args, **kwargs):
            result = await func(*args, **kwargs)

            # PR4.4: identity is None unless inject_context() was given a
            # token that validated (audit/contexts.py), so this is `{}`
            # for every caller that predates PR4.4 -- identical to the
            # implicit AuditEvent.context default that was already in
            # effect here.
            identity = get_identity()

            await logger.log(
                AuditEvent(
                    service=AuditConfig.SERVICE_NAME,
                    event_type=event_type,
                    user_id=get_user_id(),
                    organization_id=str(identity.org_id) if identity and identity.org_id is not None else None,
                    tenant_scope="organization" if identity and identity.org_id is not None else "unknown",
                    action=action,
                    decision="success",
                    trace_id=get_trace_id(),
                    context=identity.as_context() if identity else {},
                )
            )

            return result

        return async_inner

    return wrapper
