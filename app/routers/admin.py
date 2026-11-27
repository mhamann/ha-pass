"""Admin API router."""
import ipaddress
import json
import logging
import secrets
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse

from app import database as db
from app.auth import INGRESS_SENTINEL, SESSION_COOKIE, require_admin, verify_password
from app.client_ip import client_ip, request_is_https
from app.config import settings
from app import ha_client
from app import ha_auth
from app.models import (
    AdminLoginRequest,
    NEVER_EXPIRES_SECONDS,
    ProximitySettings,
    SUPPORTED_DOMAINS,
    TokenCreateRequest,
    TokenUpdateEntitiesRequest,
    TokenUpdateExpiryRequest,
)
from app.rate_limiter import RateLimiter

router = APIRouter(prefix="/admin")
logger = logging.getLogger(__name__)

# Admin session lifetime — 24 hours, hardcoded like Uptime Kuma / Dockge.
ADMIN_SESSION_TTL = 86400
# Sessions created via Home Assistant sign-in are shorter: re-auth is one click.
HA_ADMIN_SESSION_TTL = 12 * 3600
OAUTH_STATE_TTL = ha_auth.STATE_TTL_S

# CSRF: Admin routes are protected by SameSite=strict cookie. The slug-based
# guest auth acts as a bearer token — no additional CSRF token needed.

# M-24: Rate limiting on admin login (5 failed attempts/min/IP)
_login_limiter = RateLimiter()

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@router.post("/login")
async def login(body: AdminLoginRequest, request: Request, response: Response) -> dict:
    if not settings.password_login_enabled:
        detail = "Password login disabled — sign in with Home Assistant" if settings.ha_login_enabled \
            else "Login disabled — use HA sidebar"
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)

    # Rate limit login attempts by IP
    allowed = await _login_limiter.check(f"login:{client_ip(request)}", 5)
    if not allowed:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many login attempts")

    if body.username != settings.admin_username or not await verify_password(body.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    session_id = await db.create_admin_session(ttl_seconds=ADMIN_SESSION_TTL)
    _set_session_cookie(response, request, session_id, ADMIN_SESSION_TTL)
    return {"ok": True}


def _set_session_cookie(response: Response, request: Request, session_id: str, ttl: int) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        httponly=True,
        samesite="strict",
        secure=request_is_https(request),
        max_age=ttl,
    )


def _login_error_redirect(request: Request, code: str) -> RedirectResponse:
    resp = RedirectResponse(
        url=f"{request.state.ingress_path}/admin/dashboard?login_error={code}",
        status_code=status.HTTP_303_SEE_OTHER,
    )
    resp.delete_cookie(ha_auth.STATE_COOKIE, path="/admin/auth")
    return resp


@router.get("/auth/ha/start")
async def ha_login_start(request: Request):
    if not settings.ha_login_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    state, url = ha_auth.begin_login()
    resp = RedirectResponse(url=url, status_code=status.HTTP_303_SEE_OTHER)
    # Lax (not Strict): it must survive the top-level redirect back from HA,
    # which may live on a different site.
    resp.set_cookie(
        ha_auth.STATE_COOKIE,
        state,
        httponly=True,
        samesite="lax",
        secure=request_is_https(request),
        max_age=OAUTH_STATE_TTL,
        path="/admin/auth",
    )
    return resp


@router.get("/auth/ha/callback")
async def ha_login_callback(
    request: Request,
    code: str | None = Query(default=None, max_length=512),
    state: str | None = Query(default=None, max_length=256),
    error: str | None = Query(default=None, max_length=128),
):
    if not settings.ha_login_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if not await _login_limiter.check(f"ha-login:{client_ip(request)}", 10):
        return _login_error_redirect(request, "rate_limited")
    if error:
        if state:
            ha_auth.take_verifier(state)
        return _login_error_redirect(request, "cancelled")
    expected = request.cookies.get(ha_auth.STATE_COOKIE)
    if not code or not state or not expected or not secrets.compare_digest(state, expected):
        return _login_error_redirect(request, "bad_state")
    verifier = ha_auth.take_verifier(state)
    if verifier is None:  # expired, already used, or app restarted mid-login
        return _login_error_redirect(request, "bad_state")
    try:
        user = await ha_auth.login_with_code(code, verifier)
    except ha_auth.HAAuthError as exc:
        logger.warning("HA admin login rejected: %s (%s)", exc.code, exc)
        return _login_error_redirect(request, exc.code)
    except Exception:
        logger.exception("HA admin login failed")
        return _login_error_redirect(request, "ha_error")

    logger.info("Admin signed in via Home Assistant: %s (%s)", user.name, user.id)
    session_id = await db.create_admin_session(ttl_seconds=HA_ADMIN_SESSION_TTL)
    resp = RedirectResponse(
        url=f"{request.state.ingress_path}/admin/dashboard",
        status_code=status.HTTP_303_SEE_OTHER,
    )
    resp.delete_cookie(ha_auth.STATE_COOKIE, path="/admin/auth")
    _set_session_cookie(resp, request, session_id, HA_ADMIN_SESSION_TTL)
    return resp


@router.post("/logout")
async def logout(response: Response, session_id: str = Depends(require_admin)) -> dict:
    if session_id == INGRESS_SENTINEL:
        return {"ok": True}
    await db.delete_admin_session(session_id)
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Token management
# ---------------------------------------------------------------------------

def _row_to_response(row: Any, entity_ids: list[str] | None = None) -> dict:
    ip_raw = row["ip_allowlist"]
    ip_list = json.loads(ip_raw) if ip_raw else None
    if entity_ids is not None:
        count = len(entity_ids)
    elif "entity_count" in row.keys():
        count = row["entity_count"]
    else:
        count = 0
    return {
        "id": row["id"],
        "slug": row["slug"],
        "label": row["label"],
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "revoked": bool(row["revoked"]),
        "last_accessed": row["last_accessed"],
        "ip_allowlist": ip_list,
        "proximity": {
            "proximity_required": bool(row["proximity_required"]),
            "geofence_radius_m": row["geofence_radius_m"],
            "allow_home_network": bool(row["allow_home_network"]),
        },
        "entity_count": count,
        "entity_ids": entity_ids,
    }


def _activity_row_to_response(row: Any) -> dict:
    return {
        "timestamp": row["timestamp"],
        "activity": row["event_type"],
        "token_label": row["token_label"],
        "target_entity_id": row["entity_id"],
        "service": row["service"],
        "ip_address": row["ip_address"],
        "proximity_method": row["proximity_method"],
        "distance_m": row["distance_m"],
    }


@router.get("/tokens")
async def list_tokens(_: str = Depends(require_admin)) -> list[dict]:
    rows = await db.list_tokens()
    return [_row_to_response(r) for r in rows]


@router.get("/activity")
async def list_activity(
    limit: int = Query(default=50, ge=1, le=200),
    _: str = Depends(require_admin),
) -> list[dict]:
    rows = await db.list_access_logs(limit=limit)
    return [_activity_row_to_response(r) for r in rows]


@router.post("/tokens", status_code=status.HTTP_201_CREATED)
async def create_token(
    body: TokenCreateRequest,
    request: Request,
    _: str = Depends(require_admin),
) -> dict:
    # Validate IP CIDR list if provided
    if body.ip_allowlist:
        for cidr in body.ip_allowlist:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail=f"Invalid CIDR: {cidr}",
                )

    slug = body.slug or secrets.token_hex(16)
    if body.expires_in_seconds == NEVER_EXPIRES_SECONDS:
        expires_at = NEVER_EXPIRES_SECONDS
    else:
        expires_at = int(time.time()) + body.expires_in_seconds

    # Ensure slug uniqueness
    existing = await db.get_token_by_slug(slug)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Slug '{slug}' already exists",
        )

    row = await db.create_token(
        label=body.label,
        slug=slug,
        entity_ids=body.entity_ids,
        expires_at=expires_at,
        ip_allowlist=body.ip_allowlist,
        proximity=body.proximity.model_dump() if body.proximity else None,
    )
    entity_ids = await db.get_token_entities(row["id"])
    return _row_to_response(row, entity_ids)


@router.get("/tokens/{token_id}")
async def get_token(token_id: str, _: str = Depends(require_admin)) -> dict:
    row = await db.get_token_by_id(token_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    entity_ids = await db.get_token_entities(token_id)
    return _row_to_response(row, entity_ids)


@router.patch("/tokens/{token_id}/entities")
async def update_token_entities(
    token_id: str,
    body: TokenUpdateEntitiesRequest,
    _: str = Depends(require_admin),
) -> dict:
    row = await db.get_token_by_id(token_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if row["revoked"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot edit entities on a revoked token",
        )
    await db.update_token_entities(token_id, body.entity_ids)
    await ha_client.invalidate_entity_cache(token_id)
    entity_ids = await db.get_token_entities(token_id)
    row = await db.get_token_by_id(token_id)
    return _row_to_response(row, entity_ids)


@router.patch("/tokens/{token_id}/proximity")
async def update_token_proximity(
    token_id: str,
    body: ProximitySettings,
    _: str = Depends(require_admin),
) -> dict:
    row = await db.get_token_by_id(token_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    await db.update_token_proximity(token_id, body.model_dump())
    row = await db.get_token_by_id(token_id)
    return _row_to_response(row, await db.get_token_entities(token_id))


@router.patch("/tokens/{token_id}/expiry")
async def update_token_expiry(
    token_id: str,
    body: TokenUpdateExpiryRequest,
    _: str = Depends(require_admin),
) -> dict:
    row = await db.get_token_by_id(token_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if body.expires_in_seconds == NEVER_EXPIRES_SECONDS:
        new_expires = NEVER_EXPIRES_SECONDS
    else:
        new_expires = int(time.time()) + body.expires_in_seconds
    await db.update_token_expiry(token_id, new_expires)
    # Un-revoke if the token was revoked (admin is explicitly renewing it)
    if row["revoked"]:
        await db.unrevoke_token(token_id)
    row = await db.get_token_by_id(token_id)
    return _row_to_response(row)


@router.post("/tokens/{token_id}/revoke")
async def revoke_token(token_id: str, _: str = Depends(require_admin)) -> dict:
    row = await db.get_token_by_id(token_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    await db.revoke_token(token_id)
    # Notify connected SSE clients
    if not row["revoked"]:
        await ha_client.broadcast_token_expired(token_id)
    return {"ok": True}


@router.delete("/tokens/{token_id}")
async def delete_token(token_id: str, _: str = Depends(require_admin)) -> dict:
    row = await db.get_token_by_id(token_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    await ha_client.broadcast_token_expired(token_id)
    await db.delete_token(token_id)
    return {"ok": True}


# ---------------------------------------------------------------------------
# HA entity list proxy
# ---------------------------------------------------------------------------

@router.get("/ha/entities")
async def ha_entities(_: str = Depends(require_admin)) -> list[dict]:
    try:
        states = await ha_client.get_states()
    except Exception:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Home Assistant unreachable")
    # Only return entities whose domain guests can either control or view.
    return [
        {
            "entity_id": s["entity_id"],
            "friendly_name": s.get("attributes", {}).get("friendly_name", s["entity_id"]),
            "domain": domain,
            "state": s["state"],
        }
        for s in states
        if (domain := s["entity_id"].split(".")[0]) in SUPPORTED_DOMAINS
    ]
