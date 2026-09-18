"""Coverage gap: api/deps_audit.py::require_audit_read_access's
except TokenInvalid branch. Every existing exerciser of this dependency
(tests/test_routes_audit_safe.py) only ever sends a well-formed JWT (valid
or wrong-scope) or no Authorization header at all -- never a header that
parses as Bearer but fails token verification itself, so that branch was
never reached. Mirrors tests/test_deps.py::test_invalid_token_raises_401,
which covers the structurally identical branch in api/deps.py.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import pytest
from fastapi import HTTPException

from api.deps_audit import require_audit_read_access


def test_malformed_bearer_token_raises_401():
    """Reject a Bearer header that fails token verification with a 401, not just a missing header."""
    with pytest.raises(HTTPException) as exc:
        require_audit_read_access("Bearer not-a-real-token")
    assert exc.value.status_code == 401
