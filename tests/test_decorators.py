from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from audit.context import identity_var, trace_id_var, user_id_var


@pytest.fixture(autouse=True)
def reset_context_vars():
    t1 = trace_id_var.set("test-trace")
    t2 = user_id_var.set("test-user")
    # PR4.4, additive: keeps identity_var at its None default for every
    # existing test in this file (none of them set it), and resets it for
    # any test below that does.
    t3 = identity_var.set(None)
    yield
    trace_id_var.reset(t1)
    user_id_var.reset(t2)
    identity_var.reset(t3)


# ---------------------------------------------------------------------------
# @audit decorator
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_audit_decorator_calls_wrapped_function():
    mock_logger = MagicMock()
    mock_logger.log = AsyncMock()

    with patch("audit.decorators.logger", mock_logger):
        from audit.decorators import audit

        @audit(event_type="test", action="do_thing")
        async def my_func():
            return "result"

        result = await my_func()

    assert result == "result"


@pytest.mark.asyncio
async def test_audit_decorator_logs_after_function():
    mock_logger = MagicMock()
    mock_logger.log = AsyncMock()

    with patch("audit.decorators.logger", mock_logger):
        from audit.decorators import audit

        @audit(event_type="iam", action="validate")
        async def my_func():
            return 42

        await my_func()

    mock_logger.log.assert_called_once()


@pytest.mark.asyncio
async def test_audit_decorator_log_event_has_correct_type_and_action():
    mock_logger = MagicMock()
    mock_logger.log = AsyncMock()

    with patch("audit.decorators.logger", mock_logger):
        from audit.decorators import audit

        @audit(event_type="policy", action="evaluate")
        async def my_func():
            return True

        await my_func()

    event = mock_logger.log.call_args[0][0]
    assert event.event_type == "policy"
    assert event.action == "evaluate"


@pytest.mark.asyncio
async def test_audit_decorator_attaches_trace_id():
    mock_logger = MagicMock()
    mock_logger.log = AsyncMock()

    with patch("audit.decorators.logger", mock_logger):
        from audit.decorators import audit

        @audit(event_type="auth", action="login")
        async def my_func():
            return True

        await my_func()

    event = mock_logger.log.call_args[0][0]
    assert event.trace_id == "test-trace"


@pytest.mark.asyncio
async def test_audit_decorator_attaches_user_id():
    mock_logger = MagicMock()
    mock_logger.log = AsyncMock()

    with patch("audit.decorators.logger", mock_logger):
        from audit.decorators import audit

        @audit(event_type="auth", action="login")
        async def my_func():
            return True

        await my_func()

    event = mock_logger.log.call_args[0][0]
    assert event.user_id == "test-user"


@pytest.mark.asyncio
async def test_audit_decorator_sets_decision_success():
    mock_logger = MagicMock()
    mock_logger.log = AsyncMock()

    with patch("audit.decorators.logger", mock_logger):
        from audit.decorators import audit

        @audit(event_type="auth", action="login")
        async def my_func():
            return True

        await my_func()

    event = mock_logger.log.call_args[0][0]
    assert event.decision == "success"


@pytest.mark.asyncio
async def test_audit_decorator_preserves_function_name():
    mock_logger = MagicMock()
    mock_logger.log = AsyncMock()

    with patch("audit.decorators.logger", mock_logger):
        from audit.decorators import audit

        @audit(event_type="test", action="test")
        async def named_function():
            return None

    assert named_function.__name__ == "named_function"


@pytest.mark.asyncio
async def test_audit_decorator_passes_args_to_wrapped():
    mock_logger = MagicMock()
    mock_logger.log = AsyncMock()
    captured = []

    with patch("audit.decorators.logger", mock_logger):
        from audit.decorators import audit

        @audit(event_type="test", action="test")
        async def my_func(x, y):
            captured.append((x, y))
            return x + y

        result = await my_func(1, 2)

    assert result == 3
    assert captured == [(1, 2)]


# ---------------------------------------------------------------------------
# PR4.4: identity enrichment via audit/context.py::identity_var
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_audit_decorator_context_empty_without_identity():
    """Every pre-PR4.4 caller (identity_var left at its None default, as
    the reset_context_vars fixture does) must still get context == {} --
    the exact default AuditEvent already had before this PR."""
    mock_logger = MagicMock()
    mock_logger.log = AsyncMock()

    with patch("audit.decorators.logger", mock_logger):
        from audit.decorators import audit

        @audit(event_type="auth", action="login")
        async def my_func():
            return True

        await my_func()

    event = mock_logger.log.call_args[0][0]
    assert event.context == {}


@pytest.mark.asyncio
async def test_audit_decorator_enriches_context_with_verified_identity():
    from audit.identity import VerifiedIdentity

    identity = VerifiedIdentity(
        sub="42", email="alice@omnibioai.test", roles=["org_admin"],
        org_id=7, org_role=["admin"],
    )
    token = identity_var.set(identity)

    mock_logger = MagicMock()
    mock_logger.log = AsyncMock()

    try:
        with patch("audit.decorators.logger", mock_logger):
            from audit.decorators import audit

            @audit(event_type="auth", action="login")
            async def my_func():
                return True

            await my_func()
    finally:
        identity_var.reset(token)

    event = mock_logger.log.call_args[0][0]
    assert event.context == {
        "identity": {
            "sub": "42",
            "email": "alice@omnibioai.test",
            "roles": ["org_admin"],
            "org_id": 7,
            "org_role": ["admin"],
            "verified": True,
        }
    }
    assert event.organization_id == "7"
    assert event.tenant_scope == "organization"


@pytest.mark.asyncio
async def test_audit_decorator_user_id_unaffected_by_identity_absence():
    """Sanity check that this PR didn't change how user_id itself is
    sourced -- still get_user_id(), untouched by identity_var."""
    mock_logger = MagicMock()
    mock_logger.log = AsyncMock()

    with patch("audit.decorators.logger", mock_logger):
        from audit.decorators import audit

        @audit(event_type="auth", action="login")
        async def my_func():
            return True

        await my_func()

    event = mock_logger.log.call_args[0][0]
    assert event.user_id == "test-user"
