"""Admin sign-in via Home Assistant OAuth, config validation, startup resilience."""
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from app import database as db
from app import ha_auth
from app.auth import SESSION_COOKIE
from app.config import Settings

HA_ONLY = dict(
    admin_auth="ha",
    ha_external_url="https://ha.example.com",
    public_url="https://pass.example.com",
)


@pytest.fixture
def ha_only(override_settings):
    override_settings(**HA_ONLY)


def _user(**over):
    base = dict(id="u1", name="Owner", is_admin=True, is_owner=True)
    base.update(over)
    return ha_auth.HAUser(**base)


async def _start(client):
    resp = await client.get("/admin/auth/ha/start")
    assert resp.status_code == 303
    state = parse_qs(urlparse(resp.headers["location"]).query)["state"][0]
    return resp, state


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

async def test_start_redirects_to_ha_authorize(client, ha_only):
    resp, state = await _start(client)
    url = urlparse(resp.headers["location"])
    q = parse_qs(url.query)
    assert f"{url.scheme}://{url.netloc}{url.path}" == "https://ha.example.com/auth/authorize"
    assert q["response_type"] == ["code"]
    assert q["client_id"] == ["https://pass.example.com/"]
    assert q["redirect_uri"] == ["https://pass.example.com/admin/auth/ha/callback"]
    assert q["code_challenge_method"] == ["S256"]
    assert q["code_challenge"] == [ha_auth._challenge(ha_auth._pending[state][0])]
    cookie = resp.headers["set-cookie"]
    assert f"{ha_auth.STATE_COOKIE}={state}" in cookie
    assert "HttpOnly" in cookie and "SameSite=lax" in cookie and "Path=/admin/auth" in cookie


async def test_routes_404_when_ha_login_disabled(client, override_settings):
    override_settings(admin_auth="password")
    assert (await client.get("/admin/auth/ha/start")).status_code == 404
    assert (await client.get("/admin/auth/ha/callback?code=x&state=y")).status_code == 404


async def test_callback_success_creates_session(client, ha_only):
    _, state = await _start(client)
    with patch.object(ha_auth, "login_with_code", AsyncMock(return_value=_user())) as login:
        resp = await client.get(f"/admin/auth/ha/callback?code=abc&state={state}")
    assert login.await_args[0][0] == "abc"
    assert len(login.await_args[0][1]) >= 43   # PKCE verifier passed through
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin/dashboard"
    session_id = resp.cookies.get(SESSION_COOKIE) or client.cookies.get(SESSION_COOKIE)
    assert session_id and await db.get_admin_session(session_id)
    # The session works against the admin API
    client.cookies.set(SESSION_COOKIE, session_id)
    assert (await client.get("/admin/tokens")).status_code == 200


async def test_callback_rejects_state_mismatch(client, ha_only):
    await _start(client)
    with patch.object(ha_auth, "login_with_code", AsyncMock()) as login:
        resp = await client.get("/admin/auth/ha/callback?code=abc&state=forged")
    assert resp.status_code == 303
    assert resp.headers["location"].endswith("login_error=bad_state")
    login.assert_not_awaited()


async def test_callback_state_is_single_use(client, ha_only):
    _, state = await _start(client)
    with patch.object(ha_auth, "login_with_code", AsyncMock(return_value=_user())):
        first = await client.get(f"/admin/auth/ha/callback?code=abc&state={state}")
        client.cookies.set(ha_auth.STATE_COOKIE, state, path="/admin/auth")
        replay = await client.get(f"/admin/auth/ha/callback?code=abc&state={state}")
    assert first.headers["location"] == "/admin/dashboard"
    assert replay.headers["location"].endswith("login_error=bad_state")


def test_pkce_verifier_expires():
    state, _ = ha_auth.begin_login(now=0)
    assert ha_auth.take_verifier(state, now=ha_auth.STATE_TTL_S + 1) is None


def test_pkce_challenge_matches_rfc7636_example():
    # RFC 7636 Appendix B
    assert ha_auth._challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == \
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


async def test_callback_rejects_missing_state_cookie(client, ha_only):
    with patch.object(ha_auth, "login_with_code", AsyncMock()) as login:
        resp = await client.get("/admin/auth/ha/callback?code=abc&state=whatever")
    assert resp.headers["location"].endswith("login_error=bad_state")
    login.assert_not_awaited()


async def test_callback_user_cancelled(client, ha_only):
    _, state = await _start(client)
    resp = await client.get(f"/admin/auth/ha/callback?error=access_denied&state={state}")
    assert resp.headers["location"].endswith("login_error=cancelled")


@pytest.mark.parametrize("code", ["not_admin", "not_allowed", "code_rejected"])
async def test_callback_surfaces_auth_errors(client, ha_only, code):
    _, state = await _start(client)
    with patch.object(ha_auth, "login_with_code", AsyncMock(side_effect=ha_auth.HAAuthError(code))):
        resp = await client.get(f"/admin/auth/ha/callback?code=abc&state={state}")
    assert resp.headers["location"].endswith(f"login_error={code}")
    assert SESSION_COOKIE not in resp.cookies


async def test_password_login_disabled_in_ha_mode(client, ha_only):
    resp = await client.post("/admin/login", json={"username": "testadmin", "password": "testpassword123"})
    assert resp.status_code == 403
    assert "Home Assistant" in resp.json()["detail"]


async def test_both_mode_allows_password(client, override_settings):
    override_settings(**{**HA_ONLY, "admin_auth": "both"})
    resp = await client.post("/admin/login", json={"username": "testadmin", "password": "testpassword123"})
    assert resp.status_code == 200


async def test_dashboard_renders_ha_button(client, ha_only):
    resp = await client.get("/admin/dashboard")
    assert 'href="/admin/auth/ha/start"' in resp.text
    assert 'id="l-pass"' not in resp.text


# ---------------------------------------------------------------------------
# login_with_code
# ---------------------------------------------------------------------------

@pytest.fixture
def ha_calls(monkeypatch):
    calls = {
        "exchange": AsyncMock(return_value={"access_token": "at", "refresh_token": "rt"}),
        "user": AsyncMock(return_value=_user()),
        "revoke": AsyncMock(),
    }
    monkeypatch.setattr(ha_auth, "exchange_code", calls["exchange"])
    monkeypatch.setattr(ha_auth, "current_user", calls["user"])
    monkeypatch.setattr(ha_auth, "revoke", calls["revoke"])
    return calls


async def test_login_revokes_refresh_token(ha_only, ha_calls):
    user = await ha_auth.login_with_code("abc", "v" * 43)
    assert user.id == "u1"
    ha_calls["exchange"].assert_awaited_once_with("abc", "v" * 43)
    ha_calls["user"].assert_awaited_once_with("at")
    ha_calls["revoke"].assert_awaited_once_with("rt")


async def test_login_rejects_non_admin_and_still_revokes(ha_only, ha_calls):
    ha_calls["user"].return_value = _user(is_admin=False, is_owner=False)
    with pytest.raises(ha_auth.HAAuthError) as e:
        await ha_auth.login_with_code("abc", "v" * 43)
    assert e.value.code == "not_admin"
    ha_calls["revoke"].assert_awaited_once_with("rt")


async def test_login_user_allowlist(ha_only, ha_calls, override_settings):
    override_settings(admin_ha_user_ids="someone-else, another")
    with pytest.raises(ha_auth.HAAuthError) as e:
        await ha_auth.login_with_code("abc", "v" * 43)
    assert e.value.code == "not_allowed"
    override_settings(admin_ha_user_ids="u1")
    assert (await ha_auth.login_with_code("abc", "v" * 43)).id == "u1"


async def test_login_revokes_even_if_user_lookup_fails(ha_only, ha_calls):
    ha_calls["user"].side_effect = OSError("ws down")
    with pytest.raises(ha_auth.HAAuthError) as e:
        await ha_auth.login_with_code("abc", "v" * 43)
    assert e.value.code == "ha_error"
    ha_calls["revoke"].assert_awaited_once_with("rt")


async def test_exchange_code_posts_form_to_ha(ha_only, override_settings):
    seen = {}

    def handler(request: httpx.Request):
        seen["url"] = str(request.url)
        seen["body"] = parse_qs(request.content.decode())
        return httpx.Response(200, json={"access_token": "at", "refresh_token": "rt"})

    transport = httpx.MockTransport(handler)
    real = httpx.AsyncClient
    with patch("app.ha_auth.httpx.AsyncClient", lambda **kw: real(transport=transport, **kw)):
        tokens = await ha_auth.exchange_code("the-code", "verifier")
    assert tokens["access_token"] == "at"
    assert seen["url"] == "http://localhost:8123/auth/token"
    assert seen["body"] == {
        "grant_type": ["authorization_code"],
        "code": ["the-code"],
        "client_id": ["https://pass.example.com/"],
        "code_verifier": ["verifier"],
    }


async def test_exchange_code_rejected(ha_only):
    transport = httpx.MockTransport(lambda r: httpx.Response(400, json={"error": "invalid_request"}))
    real = httpx.AsyncClient
    with patch("app.ha_auth.httpx.AsyncClient", lambda **kw: real(transport=transport, **kw)):
        with pytest.raises(ha_auth.HAAuthError) as e:
            await ha_auth.exchange_code("bad", "verifier")
    assert e.value.code == "code_rejected"


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------

BASE_ENV = dict(ha_base_url="http://ha:8123", ha_token="t")


def test_ha_mode_does_not_need_password():
    s = Settings(**BASE_ENV, **HA_ONLY, admin_password="")
    assert s.ha_login_enabled and not s.password_login_enabled


def test_ha_mode_requires_external_url():
    with pytest.raises(ValueError, match="ha_external_url"):
        Settings(**BASE_ENV, admin_auth="ha", public_url="https://pass.example.com")


def test_ha_mode_requires_public_url_or_guest_url():
    with pytest.raises(ValueError, match="public_url"):
        Settings(**BASE_ENV, admin_auth="ha", ha_external_url="https://ha.example.com")
    s = Settings(**BASE_ENV, admin_auth="ha", ha_external_url="https://ha.example.com",
                 guest_url="https://pass.example.com")
    assert s.ha_login_enabled


def test_password_mode_still_requires_password():
    with pytest.raises(ValueError, match="admin_password"):
        Settings(**BASE_ENV, admin_auth="password", admin_username="a", admin_password="short")


@pytest.mark.parametrize("field,value", [
    ("trusted_proxies", "not-an-ip"),
    ("home_public_ips", "1.2.3.4/99"),
    ("admin_frame_ancestors", "https://ha.example.com; script-src *"),
    ("admin_frame_ancestors", "javascript:alert(1)"),
])
def test_invalid_network_settings_rejected(field, value):
    with pytest.raises(ValueError):
        Settings(**BASE_ENV, **HA_ONLY, **{field: value})


def test_home_location_must_be_complete():
    with pytest.raises(ValueError, match="together"):
        Settings(**BASE_ENV, **HA_ONLY, home_latitude=40.0)


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------

async def test_admin_frame_ancestors(client, override_settings):
    resp = await client.get("/admin/dashboard")
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert resp.headers["x-frame-options"] == "DENY"

    override_settings(admin_frame_ancestors="https://ha.example.com")
    resp = await client.get("/admin/dashboard")
    assert "frame-ancestors https://ha.example.com" in resp.headers["content-security-policy"]
    assert "x-frame-options" not in resp.headers
    # Guest pages stay unframeable
    resp = await client.get("/g/does-not-exist")
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]


# ---------------------------------------------------------------------------
# Startup resilience
# ---------------------------------------------------------------------------

async def _run_lifespan():
    from main import app, lifespan
    async with lifespan(app):
        pass


async def test_startup_tolerates_ha_unreachable(test_db, mock_ha_client):
    mock_ha_client["validate_connectivity"].side_effect = httpx.ConnectError("refused")
    await _run_lifespan()  # must not raise
    mock_ha_client["start_ws_listener"].assert_awaited_once()


async def test_startup_fails_fast_on_rejected_token(test_db, mock_ha_client):
    resp = httpx.Response(401, request=httpx.Request("GET", "http://ha/api/"))
    mock_ha_client["validate_connectivity"].side_effect = httpx.HTTPStatusError("401", request=resp.request, response=resp)
    with pytest.raises(RuntimeError, match="rejected"):
        await _run_lifespan()
