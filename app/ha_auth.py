"""Admin sign-in through Home Assistant (OAuth2 authorization-code flow).

HA acts as the identity provider. HA needs no client registration: the
client_id is this app's public URL, and HA accepts a redirect_uri on the same
host. After login we

1. exchange the code for tokens (server-to-server, via HA_BASE_URL),
2. ask HA who the user is (WebSocket ``auth/current_user``),
3. **revoke the refresh token immediately**, so no HA credential is kept and
   none accumulates on the user's HA profile,
4. admit only HA admins (optionally only listed HA user IDs).
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode, urlparse, urlunparse

import httpx
import websockets

from app.config import settings

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 10
STATE_COOKIE = "hp_oauth_state"
CALLBACK_PATH = "/admin/auth/ha/callback"
STATE_TTL_S = 600
_MAX_PENDING = 100

# PKCE (RFC 7636, S256): verifiers stay server-side, keyed by OAuth state, so
# an intercepted authorization code is useless without this process.
_pending: dict[str, tuple[str, float]] = {}


class HAAuthError(Exception):
    """Login failed. ``code`` is a short machine-readable reason for the UI."""

    def __init__(self, code: str, message: str = ""):
        super().__init__(message or code)
        self.code = code


@dataclass(frozen=True)
class HAUser:
    id: str
    name: str
    is_admin: bool
    is_owner: bool


def public_base() -> str:
    return (settings.public_url or settings.guest_url).rstrip("/")


def client_id() -> str:
    return public_base() + "/"


def redirect_uri() -> str:
    return public_base() + CALLBACK_PATH


def _challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def begin_login(now: float | None = None) -> tuple[str, str]:
    """Start a login: returns (state, HA authorize URL)."""
    now = now if now is not None else time.monotonic()
    for k, (_, exp) in list(_pending.items()):
        if exp <= now:
            del _pending[k]
    while len(_pending) >= _MAX_PENDING:  # bound memory under abuse
        _pending.pop(next(iter(_pending)))
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)  # 86 chars, within RFC 7636's 43-128
    _pending[state] = (verifier, now + STATE_TTL_S)
    base = settings.ha_external_url.rstrip("/")
    query = urlencode({
        "response_type": "code",
        "client_id": client_id(),
        "redirect_uri": redirect_uri(),
        "state": state,
        "code_challenge": _challenge(verifier),
        "code_challenge_method": "S256",
    })
    return state, f"{base}/auth/authorize?{query}"


def take_verifier(state: str, now: float | None = None) -> str | None:
    """Single-use: return and forget the PKCE verifier for this state."""
    entry = _pending.pop(state, None)
    if entry is None:
        return None
    verifier, exp = entry
    if exp <= (now if now is not None else time.monotonic()):
        return None
    return verifier


def _ws_url() -> str:
    parsed = urlparse(settings.ha_base_url.rstrip("/"))
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return urlunparse(parsed._replace(scheme=scheme)) + "/api/websocket"


async def exchange_code(code: str, code_verifier: str) -> dict:
    async with httpx.AsyncClient(base_url=settings.ha_base_url.rstrip("/"), timeout=HTTP_TIMEOUT) as c:
        resp = await c.post("/auth/token", data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id(),
            "code_verifier": code_verifier,
        })
    if resp.status_code != 200:
        raise HAAuthError("code_rejected", f"HA token endpoint returned {resp.status_code}")
    tokens = resp.json()
    if not tokens.get("access_token"):
        raise HAAuthError("code_rejected", "no access_token in HA response")
    return tokens


async def current_user(access_token: str) -> HAUser:
    async with websockets.connect(_ws_url(), open_timeout=HTTP_TIMEOUT, close_timeout=2) as ws:
        msg = json.loads(await ws.recv())
        if msg.get("type") != "auth_required":
            raise HAAuthError("ha_error", f"unexpected WS greeting {msg.get('type')}")
        await ws.send(json.dumps({"type": "auth", "access_token": access_token}))
        msg = json.loads(await ws.recv())
        if msg.get("type") != "auth_ok":
            raise HAAuthError("ha_error", "WS auth with user token failed")
        await ws.send(json.dumps({"id": 1, "type": "auth/current_user"}))
        msg = json.loads(await ws.recv())
    if not msg.get("success") or not isinstance(msg.get("result"), dict):
        raise HAAuthError("ha_error", "auth/current_user failed")
    r = msg["result"]
    return HAUser(
        id=str(r.get("id", "")),
        name=str(r.get("name", "")),
        is_admin=bool(r.get("is_admin")),
        is_owner=bool(r.get("is_owner")),
    )


async def revoke(refresh_token: str | None) -> None:
    if not refresh_token:
        return
    try:
        async with httpx.AsyncClient(base_url=settings.ha_base_url.rstrip("/"), timeout=HTTP_TIMEOUT) as c:
            resp = await c.post("/auth/revoke", data={"token": refresh_token})
            if resp.status_code == 404:  # older HA
                resp = await c.post("/auth/token", data={"action": "revoke", "token": refresh_token})
        if resp.status_code != 200:
            logger.warning("HA refresh-token revoke returned %d", resp.status_code)
    except Exception as exc:
        logger.warning("HA refresh-token revoke failed: %s", exc)


def authorize_user(user: HAUser) -> None:
    if not user.is_admin:
        raise HAAuthError("not_admin")
    allowed = settings.admin_ha_user_id_set
    if allowed and user.id not in allowed:
        raise HAAuthError("not_allowed")


async def login_with_code(code: str, code_verifier: str) -> HAUser:
    tokens = await exchange_code(code, code_verifier)
    try:
        user = await current_user(tokens["access_token"])
    except HAAuthError:
        raise
    except Exception as exc:
        raise HAAuthError("ha_error", str(exc)) from exc
    finally:
        # Never keep HA credentials, whatever the outcome.
        await revoke(tokens.get("refresh_token"))
    authorize_user(user)
    return user
