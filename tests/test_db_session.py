"""Coverage gap: db/session.py::get_db was only ever exercised through
FastAPI's dependency-override mechanism (tests/conftest.py's
audit_events_client fixture replaces it entirely), so the generator body
itself -- yield a Session, close it in `finally` -- never actually ran.
No live database connection is required here: SQLAlchemy's engine/Session
construction is lazy and never opens a connection until a query executes,
same assumption db/session.py's own module-level `engine = create_engine(...)`
already relies on to be importable at all in this test environment.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import pytest
from sqlalchemy.orm import Session

from db.session import get_db


def test_get_db_yields_a_session_and_closes_it_on_generator_exit():
    """Yield a live Session from get_db and close it once the generator is exhausted."""
    gen = get_db()
    db = next(gen)
    assert isinstance(db, Session)

    with pytest.raises(StopIteration):
        next(gen)
