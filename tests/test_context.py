import jwt
import pytest
from audit.context import (
    set_trace_id, get_trace_id,
    set_user_id, get_user_id,
    get_identity,
    trace_id_var, user_id_var, identity_var,
)
from audit.contexts import inject_context
from audit import jwt_verify as jwt_verify_module

SECRET = "test-secret"


def _token(**claims):
    return jwt.encode(claims, SECRET, algorithm="HS256")


@pytest.fixture(autouse=True)
def _patch_secret(monkeypatch):
    # SSO Phase 2 PR3: decoding now happens in audit.jwt_verify, not
    # audit.identity -- identity_module no longer has its own JWT_SECRET.
    monkeypatch.setattr(jwt_verify_module, "JWT_SECRET", SECRET)


# ---------------------------------------------------------------------------
# trace_id context var
# ---------------------------------------------------------------------------

def test_trace_id_default_is_none():
    # Reset to default
    token = trace_id_var.set(None)
    try:
        assert get_trace_id() is None
    finally:
        trace_id_var.reset(token)


def test_set_and_get_trace_id():
    token = trace_id_var.set(None)
    try:
        set_trace_id("trace-abc-123")
        assert get_trace_id() == "trace-abc-123"
    finally:
        trace_id_var.reset(token)


def test_trace_id_can_be_overwritten():
    token = trace_id_var.set(None)
    try:
        set_trace_id("first")
        set_trace_id("second")
        assert get_trace_id() == "second"
    finally:
        trace_id_var.reset(token)


# ---------------------------------------------------------------------------
# user_id context var
# ---------------------------------------------------------------------------

def test_user_id_default_is_none():
    token = user_id_var.set(None)
    try:
        assert get_user_id() is None
    finally:
        user_id_var.reset(token)


def test_set_and_get_user_id():
    token = user_id_var.set(None)
    try:
        set_user_id("user-xyz")
        assert get_user_id() == "user-xyz"
    finally:
        user_id_var.reset(token)


def test_user_id_can_be_overwritten():
    token = user_id_var.set(None)
    try:
        set_user_id("user1")
        set_user_id("user2")
        assert get_user_id() == "user2"
    finally:
        user_id_var.reset(token)


# ---------------------------------------------------------------------------
# inject_context (contexts.py)
# ---------------------------------------------------------------------------

def test_inject_context_sets_trace_id():
    token_t = trace_id_var.set(None)
    token_u = user_id_var.set(None)
    try:
        trace_id = inject_context(user_id="u1")
        assert get_trace_id() == trace_id
        assert len(trace_id) == 36  # UUID4 format
    finally:
        trace_id_var.reset(token_t)
        user_id_var.reset(token_u)


def test_inject_context_sets_user_id():
    token_t = trace_id_var.set(None)
    token_u = user_id_var.set(None)
    try:
        inject_context(user_id="user-99")
        assert get_user_id() == "user-99"
    finally:
        trace_id_var.reset(token_t)
        user_id_var.reset(token_u)


def test_inject_context_returns_uuid_string():
    trace_id = inject_context()
    assert isinstance(trace_id, str)
    assert len(trace_id) == 36


def test_inject_context_generates_unique_trace_ids():
    t1 = inject_context()
    t2 = inject_context()
    assert t1 != t2


def test_inject_context_without_user_id():
    token_u = user_id_var.set(None)
    try:
        inject_context()
        assert get_user_id() is None
    finally:
        user_id_var.reset(token_u)


# ---------------------------------------------------------------------------
# PR4.4: inject_context(token=...) -- verified identity takes precedence
# ---------------------------------------------------------------------------

def test_inject_context_with_valid_token_sets_verified_identity():
    token_u = user_id_var.set(None)
    token_i = identity_var.set(None)
    try:
        access_token = _token(sub="7", email="bob@omnibioai.test", roles=["auth_service"])
        inject_context(token=access_token)

        identity = get_identity()
        assert identity is not None
        assert identity.sub == "7"
        assert identity.email == "bob@omnibioai.test"
    finally:
        user_id_var.reset(token_u)
        identity_var.reset(token_i)


def test_inject_context_valid_token_overrides_user_id_with_sub():
    """A verified token's sub is trusted over a caller-asserted user_id --
    this is the whole point of validating identity rather than accepting a
    bare string."""
    token_u = user_id_var.set(None)
    token_i = identity_var.set(None)
    try:
        access_token = _token(sub="verified-user")
        inject_context(user_id="claimed-user", token=access_token)

        assert get_user_id() == "verified-user"
    finally:
        user_id_var.reset(token_u)
        identity_var.reset(token_i)


def test_inject_context_invalid_token_falls_back_to_bare_user_id():
    """Pre-PR4.4 behavior is preserved when the token doesn't validate --
    the bare user_id is used and no verified identity is attached."""
    token_u = user_id_var.set(None)
    token_i = identity_var.set(None)
    try:
        inject_context(user_id="fallback-user", token="not-a-real-token")

        assert get_user_id() == "fallback-user"
        assert get_identity() is None
    finally:
        user_id_var.reset(token_u)
        identity_var.reset(token_i)


def test_inject_context_without_token_leaves_identity_none():
    """Every existing caller (no token param at all) must keep getting
    identity_var == None -- exactly PR4.1-PR4.3's behavior."""
    token_u = user_id_var.set(None)
    token_i = identity_var.set(None)
    try:
        inject_context(user_id="plain-user")

        assert get_user_id() == "plain-user"
        assert get_identity() is None
    finally:
        user_id_var.reset(token_u)
        identity_var.reset(token_i)


def test_inject_context_second_call_clears_stale_identity():
    """A second inject_context() call without a token must not leave a
    previous call's verified identity lingering in context."""
    token_u = user_id_var.set(None)
    token_i = identity_var.set(None)
    try:
        access_token = _token(sub="7")
        inject_context(token=access_token)
        assert get_identity() is not None

        inject_context(user_id="someone-else")
        assert get_identity() is None
        assert get_user_id() == "someone-else"
    finally:
        user_id_var.reset(token_u)
        identity_var.reset(token_i)
