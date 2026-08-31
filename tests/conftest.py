from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture
def mock_async_redis():
    return AsyncMock()


@pytest.fixture
def mock_sync_redis():
    return MagicMock()


@pytest.fixture
def audit_logger(mock_async_redis):
    with patch("audit.logger.redis") as mock_redis_module:
        mock_redis_module.from_url.return_value = mock_async_redis
        from audit.logger import AuditLogger
        logger = AuditLogger()
        logger.redis = mock_async_redis
        yield logger, mock_async_redis


@pytest.fixture
def stream_reader(mock_sync_redis):
    with patch("consumers.stream_reader.redis") as mock_redis_module:
        mock_redis_module.from_url.return_value = mock_sync_redis
        from consumers.stream_reader import StreamReader
        reader = StreamReader()
        reader.redis = mock_sync_redis
        yield reader, mock_sync_redis


@pytest.fixture
def db_session():
    """PR4.2: isolated in-memory SQLite database for exercising the
    audit_events table without a real MySQL instance. Mirrors the pattern
    omnibioai-auth's tests/conftest.py uses for its own SQLite test DB."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401 -- registers AuditEventRecord on Base.metadata
    from db.base import Base

    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    session = TestingSessionLocal()
    yield session
    session.close()


@pytest.fixture
def audit_events_client(monkeypatch):
    """PR4.3: TestClient for GET /audit/events, wired to an isolated
    in-memory SQLite DB and a fixed JWT_SECRET.

    Uses StaticPool (unlike the plain `db_session` fixture above) because
    starlette's TestClient dispatches requests on a separate thread from
    the test itself -- SQLite's default per-thread `:memory:` connection
    would otherwise give the request thread a fresh, tableless database.
    Yields (TestClient, SessionLocal) so tests can seed rows directly via
    the same SessionLocal the app's dependency override uses.
    """
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    import db.models  # noqa: F401
    from api.main import app
    from audit import jwt_verify as jwt_verify_module
    from db.base import Base
    from db.session import get_db

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # SSO Phase 2 PR3: decoding now happens in audit.jwt_verify, not
    # api.deps -- api.deps no longer has its own JWT_SECRET to patch.
    monkeypatch.setattr(jwt_verify_module, "JWT_SECRET", "test-secret")
    monkeypatch.setattr(jwt_verify_module._blacklist, "exists", lambda _key: 0)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        yield TestClient(app), TestingSessionLocal
    finally:
        app.dependency_overrides.pop(get_db, None)
