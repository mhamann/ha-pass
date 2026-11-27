"""Proximity ("near home") policy for guest links.

Applies to both viewing (state + live stream) and commands:

* Viewing needs the home network, or a short-lived signed *presence grant*
  cookie obtained from ``POST /g/{slug}/presence`` with a passing check.
* Commands need the home network, or a fresh GPS fix sent with the command.

A token with ``proximity_required`` only allows the gated action when one of:

* **network** — the client's (trusted) IP is the home's public IP, either
  configured statically (HOME_PUBLIC_IPS) or read from an HA entity
  (HOME_WAN_IP_ENTITY). Traffic from home Wi-Fi through a tunnel such as
  Cloudflare arrives with the home's WAN IP. This is server-observed and
  cannot be forged by the browser.
* **gps** — the browser supplies a fresh geolocation fix that lies within the
  token's radius of the home location (HA's configured location unless
  overridden). This is client-reported: it stops casual / remote misuse, not a
  determined link-holder who fakes their location. Expiry, revocation and the
  audit trail remain the primary controls.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import logging
import math
import secrets
import time
from dataclasses import dataclass
from typing import Any

from app import ha_client
from app.client_ip import parse_networks
from app.config import settings

logger = logging.getLogger(__name__)

EARTH_RADIUS_M = 6_371_008.8
MAX_ACCURACY_M = 200          # reject fixes vaguer than this
MAX_FIX_AGE_S = 60            # reject fixes older than this
MAX_FIX_FUTURE_SKEW_S = 30    # tolerate small client clock skew
MIN_RADIUS_M = 25
MAX_RADIUS_M = 5000

# A successful presence check grants view access (state + live stream) for
# this long; the page silently re-checks before it lapses.
GRANT_TTL_S = 600

HOME_LOCATION_TTL = 3600
WAN_IP_TTL = 60


@dataclass(frozen=True)
class Location:
    lat: float
    lon: float
    accuracy: float
    ts_ms: int  # GeolocationPosition.timestamp (epoch ms)


@dataclass(frozen=True)
class ProximityResult:
    method: str | None           # "network" | "gps" | None (not required)
    distance_m: int | None = None


class ProximityDenied(Exception):
    """The request is not demonstrably near home."""

    def __init__(self, reason: str, distance_m: int | None = None):
        super().__init__(reason)
        self.reason = reason
        self.distance_m = distance_m

    def detail(self) -> dict[str, Any]:
        d: dict[str, Any] = {"error": "not_near_home", "reason": self.reason}
        if self.distance_m is not None:
            d["distance_m"] = self.distance_m
        return d


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = p2 - p1
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_RADIUS_M * math.asin(min(1.0, math.sqrt(a)))


# ---------------------------------------------------------------------------
# Cached inputs from HA
# ---------------------------------------------------------------------------

_home_loc: tuple[float, float] | None = None
_home_loc_ts: float = 0.0
_wan_nets: tuple = ()
_wan_ts: float | None = None
_lock = asyncio.Lock()


def reset_cache() -> None:
    global _home_loc, _home_loc_ts, _wan_nets, _wan_ts
    _home_loc, _home_loc_ts, _wan_nets, _wan_ts = None, 0.0, (), None


async def home_location() -> tuple[float, float] | None:
    global _home_loc, _home_loc_ts
    if settings.home_latitude is not None and settings.home_longitude is not None:
        return settings.home_latitude, settings.home_longitude
    now = time.monotonic()
    if _home_loc is not None and now - _home_loc_ts < HOME_LOCATION_TTL:
        return _home_loc
    async with _lock:
        if _home_loc is not None and now - _home_loc_ts < HOME_LOCATION_TTL:
            return _home_loc
        try:
            cfg = await ha_client.get_config()
            lat, lon = cfg.get("latitude"), cfg.get("longitude")
            if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
                _home_loc, _home_loc_ts = (float(lat), float(lon)), now
        except Exception as exc:
            logger.warning("Could not read home location from HA: %s", exc)
    return _home_loc  # may be stale or None


async def home_networks() -> tuple:
    """Static HOME_PUBLIC_IPS plus the current WAN IP entity state."""
    global _wan_nets, _wan_ts
    static = parse_networks(settings.home_public_ips)
    entity = settings.home_wan_ip_entity.strip()
    if not entity:
        return static
    now = time.monotonic()
    if _wan_ts is None or now - _wan_ts >= WAN_IP_TTL:
        async with _lock:
            if _wan_ts is None or now - _wan_ts >= WAN_IP_TTL:
                nets: tuple = ()
                try:
                    st = await ha_client.get_state(entity)
                    if st:
                        addr = ipaddress.ip_address(str(st.get("state", "")).strip())
                        nets = (ipaddress.ip_network(addr),)
                except ValueError:
                    logger.warning("%s state is not an IP address", entity)
                except Exception as exc:
                    logger.warning("Could not read %s: %s", entity, exc)
                    nets = _wan_nets  # keep last known good on transient errors
                _wan_nets, _wan_ts = nets, now
    return static + _wan_nets


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

def token_requires_proximity(row) -> bool:
    return bool(row["proximity_required"])


# ---------------------------------------------------------------------------
# Presence grants (view access)
# ---------------------------------------------------------------------------

# Per-process key: grants are invalidated by a restart, after which the page
# transparently re-runs the presence check.
_GRANT_KEY = secrets.token_bytes(32)


def grant_cookie_name(slug: str) -> str:
    return "hp_presence_" + hashlib.sha256(slug.encode()).hexdigest()[:16]


def _grant_sig(token_id: str, exp: int, method: str) -> str:
    msg = f"{token_id}|{exp}|{method}".encode()
    return hmac.new(_GRANT_KEY, msg, hashlib.sha256).hexdigest()


def issue_grant(token_id: str, method: str, now: float | None = None) -> tuple[str, int]:
    """Return (cookie value, expiry epoch seconds)."""
    exp = int(now if now is not None else time.time()) + GRANT_TTL_S
    return f"{exp}.{method}.{_grant_sig(token_id, exp, method)}", exp


def verify_grant(value: str | None, token_id: str, now: float | None = None) -> int | None:
    """Return the grant's expiry if valid for this token, else None."""
    if not value:
        return None
    try:
        exp_s, method, sig = value.split(".", 2)
        exp = int(exp_s)
    except ValueError:
        return None
    if method not in ("network", "gps"):
        return None
    if not hmac.compare_digest(sig, _grant_sig(token_id, exp, method)):
        return None
    if exp <= (now if now is not None else time.time()):
        return None
    return exp


async def on_home_network(row, client_ip: str) -> bool:
    if not row["allow_home_network"]:
        return False
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    nets = await home_networks()
    return any(addr in n for n in nets)


async def check_view(row, client_ip: str, grant: str | None) -> int | None:
    """Gate viewing. Returns a deadline (epoch s) for grant-based access,
    None when no deadline applies; raises ProximityDenied otherwise."""
    if not token_requires_proximity(row):
        return None
    if await on_home_network(row, client_ip):
        return None
    exp = verify_grant(grant, row["id"])
    if exp is None:
        raise ProximityDenied("presence_required")
    return exp


def parse_location(raw: Any) -> Location | None:
    if raw is None:
        return None
    if hasattr(raw, "model_dump"):
        raw = raw.model_dump()
    if not isinstance(raw, dict):
        return None
    try:
        lat = float(raw["lat"])
        lon = float(raw["lon"])
        acc = float(raw["accuracy"])
        ts = int(raw["ts"])
    except (KeyError, TypeError, ValueError):
        return None
    if not (-90 <= lat <= 90 and -180 <= lon <= 180) or acc < 0:
        return None
    if any(math.isnan(v) or math.isinf(v) for v in (lat, lon, acc)):
        return None
    return Location(lat, lon, acc, ts)


async def check(row, client_ip: str, location: Location | None) -> ProximityResult:
    """Return how the request proved proximity, or raise ProximityDenied.

    Used for commands (location must be fresh per command) and for issuing
    presence grants that unlock viewing.
    """
    if not token_requires_proximity(row):
        return ProximityResult(method=None)

    if await on_home_network(row, client_ip):
        return ProximityResult(method="network", distance_m=0)

    if location is None:
        raise ProximityDenied("location_required")

    now_ms = int(time.time() * 1000)
    age_s = (now_ms - location.ts_ms) / 1000
    if age_s > MAX_FIX_AGE_S or age_s < -MAX_FIX_FUTURE_SKEW_S:
        raise ProximityDenied("location_stale")
    if location.accuracy > MAX_ACCURACY_M:
        raise ProximityDenied("location_inaccurate")

    home = await home_location()
    if home is None:
        # Fail closed: without a reference point GPS cannot prove anything.
        raise ProximityDenied("home_location_unavailable")

    distance = haversine_m(home[0], home[1], location.lat, location.lon)
    radius = max(MIN_RADIUS_M, min(MAX_RADIUS_M, int(row["geofence_radius_m"])))
    if distance > radius:
        raise ProximityDenied("too_far", distance_m=round(distance))
    return ProximityResult(method="gps", distance_m=round(distance))
