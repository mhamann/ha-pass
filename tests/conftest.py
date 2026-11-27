"""Shared fixtures for HAPass test suite.

Environment variables MUST be set before any app imports because:
- app.config.Settings() evaluates at import time
- app.auth._hashed is computed at import time
"""
import os
import time

# Set env vars before any app module is imported
os.environ.setdefault("ADMIN_USERNAME", "testadmin")
os.environ.setdefault("ADMIN_PASSWORD", "testpassword123")
os.environ.setdefault("HA_BASE_URL", "http://localhost:8123")
os.environ.setdefault("HA_TOKEN", "test-token")

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app import database as db
from app.config import settings
from app.models import NEVER_EXPIRES_SECONDS

# Home location reported by the mocked HA /api/config
HOME_LAT = 40.0
HOME_LON = -75.0


@pytest_asyncio.fixture
async def test_db(tmp_path):
    """Create a temp DB file, run Alembic migrations, open the async connection, yield, clean up.

    This uses a real on-disk SQLite file (not :memory:) to match production
    behavior with WAL mode and foreign keys.
    """
    db_file = tmp_path / "test.db"
    original_path = settings.db_path

    settings.db_path = str(db_file)

    # Run real Alembic migrations — verifies migrations work on every test
    db.run_migrations()

    # Open the real aiosqlite connection
    conn = await db.get_db()
    yield conn

    await db.close_db()
    settings.db_path = original_path


@pytest.fixture
def mock_ha_client():
    """Patch the Home Assistant external dependency.

    Only ha_client is mocked — we cannot run a real HA instance in tests.
    Everything else (DB, auth, routing, rate limiting, validation) is real.

    Yields the mock dict so tests can assert what was forwarded to HA
    (e.g. verify call_service received the correct domain/service/data).
    """
    mocks = {
        "init_client": MagicMock(),
        "validate_connectivity": AsyncMock(),
        "start_ws_listener": AsyncMock(),
        "stop_ws_listener": AsyncMock(),
        "close_client": AsyncMock(),
        "is_ws_healthy": MagicMock(return_value=True),
        "get_states": AsyncMock(return_value=[]),
        "get_state": AsyncMock(return_value=None),
        "get_config": AsyncMock(return_value={"latitude": HOME_LAT, "longitude": HOME_LON}),
        "call_service": AsyncMock(return_value=[]),
        "fire_event": AsyncMock(return_value={}),
        "logbook_log": AsyncMock(return_value={}),
        "broadcast_token_expired": AsyncMock(),
        "invalidate_entity_cache": AsyncMock(),
    }
    with patch.multiple("app.ha_client", **mocks):
        yield mocks


@pytest.fixture(autouse=True)
def _reset_login_limiter():
    """Reset the admin login rate limiter between tests to prevent cross-test pollution.

    Without this, failed login attempts from one test count against the
    rate limiter in subsequent tests (it's a module-level singleton).
    """
    from app.routers.admin import _login_limiter
    _login_limiter._windows.clear()


@pytest_asyncio.fixture
async def client(test_db, mock_ha_client):
    """httpx.AsyncClient using ASGITransport — bypasses lifespan.

    The lifespan connects to HA and starts the WS listener, which we don't
    want in tests. Instead, test_db handles DB init and mock_ha_client
    handles the HA dependency.
    """
    import httpx
    from main import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


@pytest_asyncio.fixture
async def admin_session(test_db):
    """Create an admin session in the real DB and return a cookie dict."""
    from app.auth import SESSION_COOKIE

    session_id = await db.create_admin_session(ttl_seconds=86400)
    return {SESSION_COOKIE: session_id}


@pytest_asyncio.fixture
async def sample_token(test_db):
    """Create a test token with one entity, valid for 1 hour, in the real DB."""
    now = int(time.time())
    token = await db.create_token(
        label="Test Token",
        slug="test-token",
        entity_ids=["light.living_room"],
        expires_at=now + 3600,
        ip_allowlist=None,
    )
    return token


@pytest.fixture(autouse=True)
def _reset_proximity_cache():
    """Proximity caches HA-derived inputs at module level; isolate tests."""
    from app import proximity
    proximity.reset_cache()
    yield
    proximity.reset_cache()


@pytest.fixture
def override_settings():
    """Temporarily set attributes on the global settings object."""
    saved: dict = {}

    def _set(**kwargs):
        for k, v in kwargs.items():
            if k not in saved:
                saved[k] = getattr(settings, k)
            setattr(settings, k, v)

    yield _set
    for k, v in saved.items():
        setattr(settings, k, v)


@pytest_asyncio.fixture
async def prox_token(test_db):
    """A proximity-gated token (150 m, home network allowed)."""
    now = int(time.time())
    return await db.create_token(
        label="Garage Guest",
        slug="garage-guest",
        entity_ids=["cover.garage_door"],
        expires_at=now + 3600,
        ip_allowlist=None,
        proximity={"proximity_required": True, "geofence_radius_m": 150, "allow_home_network": True},
    )
