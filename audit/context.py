from contextvars import ContextVar
from typing import Optional

trace_id_var = ContextVar("trace_id", default=None)
user_id_var = ContextVar("user_id", default=None)
# PR4.4, additive: holds a VerifiedIdentity (audit/identity.py) when
# inject_context() was given a token that validated, None otherwise.
# user_id_var/get_user_id() are untouched -- existing callers/tests that
# only ever use those two keep working exactly as before.
identity_var = ContextVar("identity", default=None)


def set_trace_id(trace_id: str):
    trace_id_var.set(trace_id)


def get_trace_id() -> Optional[str]:
    return trace_id_var.get()


def set_user_id(user_id: str):
    user_id_var.set(user_id)


def get_user_id() -> Optional[str]:
    return user_id_var.get()


def set_identity(identity) -> None:
    identity_var.set(identity)


def get_identity():
    return identity_var.get()