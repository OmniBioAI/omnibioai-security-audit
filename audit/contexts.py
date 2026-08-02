from audit.context import set_trace_id, set_user_id, set_identity
from audit.identity import validate_identity_token
import uuid


def inject_context(user_id: str = None, token: str = None):
    """Establishes per-request audit context: a fresh trace_id, user_id,
    and -- PR4.4 -- a verified identity if `token` is a valid, signed
    access token.

    `token` takes precedence over `user_id` when both are given and the
    token validates: a cryptographically verified identity is trusted over
    a caller-asserted string, which is the point of "validate identity"
    rather than "trust whatever string I'm handed." If `token` is missing
    or fails validation, this falls back to the pre-PR4.4 behavior
    (`user_id` used as-is, no verified identity attached) -- every
    existing caller that only ever passes `user_id` keeps working exactly
    as before.
    """
    trace_id = str(uuid.uuid4())
    set_trace_id(trace_id)

    identity = validate_identity_token(token) if token else None
    if identity is not None:
        set_user_id(identity.sub)
    else:
        set_user_id(user_id)
    set_identity(identity)

    return trace_id
