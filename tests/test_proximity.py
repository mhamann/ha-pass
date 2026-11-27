"""Proximity ("near home") policy: unit tests and guest endpoint integration."""
import asyncio
import math
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from app import database as db
from app import proximity
from tests.conftest import HOME_LAT, HOME_LON

# ~111 m per 0.001 deg latitude
NEAR = (HOME_LAT + 0.0005, HOME_LON)        # ~56 m north
FAR = (HOME_LAT + 0.02, HOME_LON)           # ~2.2 km north


def _loc(lat_lon=NEAR, accuracy=20.0, age_s=1.0):
    return {"lat": lat_lon[0], "lon": lat_lon[1], "accuracy": accuracy,
            "ts": int((time.time() - age_s) * 1000)}


def _row(**over):
    row = {"id": "tok-1", "slug": "s", "proximity_required": 1,
           "geofence_radius_m": 150, "allow_home_network": 1}
    row.update(over)
    return row


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def test_haversine_known_distance():
    # One degree of latitude ≈ 111.2 km
    d = proximity.haversine_m(0, 0, 1, 0)
    assert math.isclose(d, 111_195, rel_tol=1e-3)
    assert proximity.haversine_m(HOME_LAT, HOME_LON, HOME_LAT, HOME_LON) == 0


def test_parse_location_rejects_garbage():
    assert proximity.parse_location(None) is None
    assert proximity.parse_location({"lat": "x", "lon": 0, "accuracy": 1, "ts": 1}) is None
    assert proximity.parse_location({"lat": 91, "lon": 0, "accuracy": 1, "ts": 1}) is None
    assert proximity.parse_location({"lat": 0, "lon": 0, "accuracy": -1, "ts": 1}) is None
    assert proximity.parse_location({"lat": 0, "lon": 0, "accuracy": float("nan"), "ts": 1}) is None
    loc = proximity.parse_location({"lat": 1.5, "lon": 2.5, "accuracy": 10, "ts": 123})
    assert loc == proximity.Location(1.5, 2.5, 10.0, 123)


def test_grant_roundtrip_and_binding():
    value, exp = proximity.issue_grant("tok-1", "gps")
    assert proximity.verify_grant(value, "tok-1") == exp
    assert proximity.verify_grant(value, "tok-2") is None          # bound to token
    assert proximity.verify_grant(None, "tok-1") is None
    assert proximity.verify_grant("garbage", "tok-1") is None


def test_grant_expiry_and_tamper():
    value, exp = proximity.issue_grant("tok-1", "gps", now=1000)
    assert proximity.verify_grant(value, "tok-1", now=exp - 1) == exp
    assert proximity.verify_grant(value, "tok-1", now=exp) is None
    # Extending the expiry invalidates the signature
    _, method, sig = value.split(".", 2)
    assert proximity.verify_grant(f"{exp + 9999}.{method}.{sig}", "tok-1", now=exp - 1) is None
    assert proximity.verify_grant(f"{exp}.admin.{sig}", "tok-1", now=exp - 1) is None


def test_grant_cookie_name_is_per_slug_and_opaque():
    a = proximity.grant_cookie_name("garage-guest")
    b = proximity.grant_cookie_name("other-link")
    assert a != b and "garage" not in a


# ---------------------------------------------------------------------------
# check() policy
# ---------------------------------------------------------------------------

async def test_not_required_passes_without_anything(mock_ha_client):
    res = await proximity.check(_row(proximity_required=0), "203.0.113.1", None)
    assert res.method is None


async def test_home_network_static(mock_ha_client, override_settings):
    override_settings(home_public_ips="136.56.183.42")
    res = await proximity.check(_row(), "136.56.183.42", None)
    assert res == proximity.ProximityResult("network", 0)


async def test_home_network_from_entity(mock_ha_client, override_settings):
    override_settings(home_wan_ip_entity="sensor.wan_ip")
    mock_ha_client["get_state"].return_value = {"state": "136.56.183.42"}
    res = await proximity.check(_row(), "136.56.183.42", None)
    assert res.method == "network"
    mock_ha_client["get_state"].assert_awaited_with("sensor.wan_ip")


async def test_home_network_entity_cached(mock_ha_client, override_settings):
    override_settings(home_wan_ip_entity="sensor.wan_ip")
    mock_ha_client["get_state"].return_value = {"state": "136.56.183.42"}
    for _ in range(3):
        await proximity.home_networks()
    assert mock_ha_client["get_state"].await_count == 1


async def test_home_network_entity_non_ip_state(mock_ha_client, override_settings):
    override_settings(home_wan_ip_entity="sensor.wan_ip")
    mock_ha_client["get_state"].return_value = {"state": "unavailable"}
    assert await proximity.home_networks() == ()


async def test_home_network_keeps_last_good_on_transient_error(mock_ha_client, override_settings, monkeypatch):
    override_settings(home_wan_ip_entity="sensor.wan_ip")
    mock_ha_client["get_state"].return_value = {"state": "136.56.183.42"}
    good = await proximity.home_networks()
    monkeypatch.setattr(proximity, "_wan_ts", -1e9)   # force refresh
    mock_ha_client["get_state"].side_effect = RuntimeError("HA down")
    assert await proximity.home_networks() == good


async def test_home_network_disallowed_by_token(mock_ha_client, override_settings):
    override_settings(home_public_ips="136.56.183.42")
    with pytest.raises(proximity.ProximityDenied) as e:
        await proximity.check(_row(allow_home_network=0), "136.56.183.42", None)
    assert e.value.reason == "location_required"


async def test_gps_inside_radius(mock_ha_client):
    res = await proximity.check(_row(), "203.0.113.1", proximity.parse_location(_loc(NEAR)))
    assert res.method == "gps" and 40 < res.distance_m < 70


async def test_gps_too_far_reports_distance(mock_ha_client):
    with pytest.raises(proximity.ProximityDenied) as e:
        await proximity.check(_row(), "203.0.113.1", proximity.parse_location(_loc(FAR)))
    assert e.value.reason == "too_far"
    assert 2000 < e.value.distance_m < 2400


@pytest.mark.parametrize("kwargs,reason", [
    ({"age_s": 120}, "location_stale"),
    ({"age_s": -120}, "location_stale"),
    ({"accuracy": 500}, "location_inaccurate"),
])
async def test_gps_rejects_bad_fixes(mock_ha_client, kwargs, reason):
    with pytest.raises(proximity.ProximityDenied) as e:
        await proximity.check(_row(), "203.0.113.1", proximity.parse_location(_loc(NEAR, **kwargs)))
    assert e.value.reason == reason


async def test_gps_fails_closed_without_home_location(mock_ha_client):
    mock_ha_client["get_config"].return_value = {}
    with pytest.raises(proximity.ProximityDenied) as e:
        await proximity.check(_row(), "203.0.113.1", proximity.parse_location(_loc(NEAR)))
    assert e.value.reason == "home_location_unavailable"


async def test_home_location_override_skips_ha(mock_ha_client, override_settings):
    override_settings(home_latitude=10.0, home_longitude=20.0)
    assert await proximity.home_location() == (10.0, 20.0)
    mock_ha_client["get_config"].assert_not_awaited()


async def test_radius_is_clamped(mock_ha_client):
    # A stored radius below the minimum is treated as the minimum (25 m)
    loc = proximity.parse_location(_loc((HOME_LAT + 0.0002, HOME_LON)))   # ~22 m
    res = await proximity.check(_row(geofence_radius_m=1), "203.0.113.1", loc)
    assert res.method == "gps"


async def test_check_view(mock_ha_client, override_settings):
    override_settings(home_public_ips="136.56.183.42")
    row = _row()
    assert await proximity.check_view(row, "136.56.183.42", None) is None
    with pytest.raises(proximity.ProximityDenied) as e:
        await proximity.check_view(row, "203.0.113.1", None)
    assert e.value.reason == "presence_required"
    value, exp = proximity.issue_grant(row["id"], "gps")
    assert await proximity.check_view(row, "203.0.113.1", value) == exp
    assert await proximity.check_view(_row(proximity_required=0), "203.0.113.1", None) is None


# ---------------------------------------------------------------------------
# Guest endpoints
# ---------------------------------------------------------------------------

async def _log_rows(token_id):
    conn = await db.get_db()
    async with conn.execute(
        "SELECT * FROM access_log WHERE token_id = ? ORDER BY id", (token_id,)
    ) as cur:
        return await cur.fetchall()


async def test_state_requires_presence(client, prox_token):
    resp = await client.get(f"/g/{prox_token['slug']}/state")
    assert resp.status_code == 403
    assert resp.json()["detail"] == {"error": "not_near_home", "reason": "presence_required"}


async def test_stream_requires_presence(client, prox_token):
    resp = await client.get(f"/g/{prox_token['slug']}/stream")
    assert resp.status_code == 403


async def test_presence_without_location_asks_for_it_quietly(client, prox_token):
    resp = await client.post(f"/g/{prox_token['slug']}/presence", json={})
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "location_required"
    assert await _log_rows(prox_token["id"]) == []      # normal first step, not audited


async def test_presence_with_gps_unlocks_state(client, prox_token):
    resp = await client.post(f"/g/{prox_token['slug']}/presence", json={"location": _loc(NEAR)})
    assert resp.status_code == 200
    body = resp.json()
    assert body["method"] == "gps" and body["expires_in"] > 500
    cookie_name = proximity.grant_cookie_name(prox_token["slug"])
    set_cookie = resp.headers["set-cookie"]
    assert cookie_name in set_cookie
    assert "HttpOnly" in set_cookie and "SameSite=strict" in set_cookie
    assert f"Path=/g/{prox_token['slug']}" in set_cookie

    state = await client.get(f"/g/{prox_token['slug']}/state")
    assert state.status_code == 200
    assert state.json()["proximity"] == {"required": True, "radius_m": 150, "allow_home_network": True}

    rows = await _log_rows(prox_token["id"])
    assert rows[-1]["event_type"] == "presence" and rows[-1]["proximity_method"] == "gps"


async def test_grant_for_one_link_does_not_unlock_another(client, prox_token, test_db):
    other = await db.create_token(
        label="Other", slug="other-link", entity_ids=["light.x"],
        expires_at=int(time.time()) + 3600, ip_allowlist=None,
        proximity={"proximity_required": True},
    )
    value, _ = proximity.issue_grant(prox_token["id"], "gps")
    resp = await client.get(
        f"/g/{other['slug']}/state",
        cookies={proximity.grant_cookie_name(other["slug"]): value},
    )
    assert resp.status_code == 403


async def test_presence_too_far_is_denied_and_audited(client, prox_token):
    resp = await client.post(f"/g/{prox_token['slug']}/presence", json={"location": _loc(FAR)})
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert detail["reason"] == "too_far" and detail["distance_m"] > 2000
    assert "set-cookie" not in resp.headers
    rows = await _log_rows(prox_token["id"])
    assert rows[-1]["event_type"] == "presence_denied" and rows[-1]["distance_m"] > 2000


async def test_presence_rejects_invalid_location_payload(client, prox_token):
    resp = await client.post(
        f"/g/{prox_token['slug']}/presence",
        json={"location": {"lat": 999, "lon": 0, "accuracy": 5, "ts": 0}},
    )
    assert resp.status_code == 422


async def test_presence_not_required_for_ordinary_link(client, sample_token):
    resp = await client.post(f"/g/{sample_token['slug']}/presence", json={})
    assert resp.json() == {"ok": True, "required": False}
    assert (await client.get(f"/g/{sample_token['slug']}/state")).status_code == 200


async def test_home_network_unlocks_state_without_grant(client, prox_token, override_settings):
    # ASGITransport peer is 127.0.0.1
    override_settings(home_public_ips="127.0.0.1")
    assert (await client.get(f"/g/{prox_token['slug']}/state")).status_code == 200


async def test_revoked_link_rejected_even_with_grant(client, prox_token):
    value, _ = proximity.issue_grant(prox_token["id"], "gps")
    await db.revoke_token(prox_token["id"])
    resp = await client.get(
        f"/g/{prox_token['slug']}/state",
        cookies={proximity.grant_cookie_name(prox_token["slug"]): value},
    )
    assert resp.status_code == 410


async def test_command_requires_location(client, prox_token, mock_ha_client):
    resp = await client.post(
        f"/g/{prox_token['slug']}/command",
        json={"entity_id": "cover.garage_door", "service": "cover.open_cover"},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "location_required"
    mock_ha_client["call_service"].assert_not_called()


async def test_command_grant_alone_is_not_enough(client, prox_token, mock_ha_client):
    """Commands need a fresh fix every time; a view grant doesn't authorise them."""
    value, _ = proximity.issue_grant(prox_token["id"], "gps")
    resp = await client.post(
        f"/g/{prox_token['slug']}/command",
        json={"entity_id": "cover.garage_door", "service": "cover.open_cover"},
        cookies={proximity.grant_cookie_name(prox_token["slug"]): value},
    )
    assert resp.status_code == 403
    mock_ha_client["call_service"].assert_not_called()


async def test_command_far_away_denied_and_audited(client, prox_token, mock_ha_client):
    resp = await client.post(
        f"/g/{prox_token['slug']}/command",
        json={"entity_id": "cover.garage_door", "service": "cover.open_cover", "location": _loc(FAR)},
    )
    assert resp.status_code == 403
    mock_ha_client["call_service"].assert_not_called()
    rows = await _log_rows(prox_token["id"])
    assert rows[-1]["event_type"] == "command_denied_proximity"
    assert rows[-1]["entity_id"] == "cover.garage_door"


async def test_command_near_home_succeeds_and_records_distance(client, prox_token, mock_ha_client):
    resp = await client.post(
        f"/g/{prox_token['slug']}/command",
        json={"entity_id": "cover.garage_door", "service": "cover.open_cover", "location": _loc(NEAR)},
    )
    assert resp.status_code == 200
    mock_ha_client["call_service"].assert_awaited_once()
    assert mock_ha_client["call_service"].call_args[0][2] == {"entity_id": "cover.garage_door"}
    rows = await _log_rows(prox_token["id"])
    assert rows[-1]["event_type"] == "command"
    assert rows[-1]["proximity_method"] == "gps" and 40 < rows[-1]["distance_m"] < 70
    await asyncio.sleep(0)  # let background activity task run
    payload = mock_ha_client["fire_event"].call_args[0][1]
    assert payload["proximity_method"] == "gps" and payload["distance_m"] == rows[-1]["distance_m"]


async def test_command_entity_check_precedes_location_prompt(client, prox_token, mock_ha_client):
    """Out-of-scope entities are rejected outright, never 'ask for location'."""
    resp = await client.post(
        f"/g/{prox_token['slug']}/command",
        json={"entity_id": "lock.front_door", "service": "lock.unlock"},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Entity not in allowlist"


async def test_command_on_home_network(client, prox_token, mock_ha_client, override_settings):
    override_settings(home_public_ips="127.0.0.1")
    resp = await client.post(
        f"/g/{prox_token['slug']}/command",
        json={"entity_id": "cover.garage_door", "service": "cover.close_cover"},
    )
    assert resp.status_code == 200
    rows = await _log_rows(prox_token["id"])
    assert rows[-1]["proximity_method"] == "network"


async def test_stream_ends_when_grant_lapses(test_db, prox_token, monkeypatch):
    from app import ha_client
    from app.routers import guest

    q: asyncio.Queue = asyncio.Queue()
    monkeypatch.setattr(ha_client, "subscribe", AsyncMock(return_value=q))
    monkeypatch.setattr(ha_client, "unsubscribe", AsyncMock())
    monkeypatch.setattr(ha_client, "is_ws_healthy", MagicMock(return_value=True))
    request = MagicMock()
    request.is_disconnected = AsyncMock(return_value=False)

    gen = guest._event_generator(prox_token["id"], prox_token["slug"], request, deadline=int(time.time()) + 1)
    events = [chunk async for chunk in gen]
    assert events[0].startswith("event: connected")
    assert events[-1].startswith("event: proximity_expired")
    ha_client.unsubscribe.assert_awaited_once()


async def test_guest_page_flags_proximity(client, prox_token):
    resp = await client.get(f"/g/{prox_token['slug']}")
    assert resp.status_code == 200
    assert "const PROXIMITY_REQUIRED = true;" in resp.text
    assert 'id="proximity-note"' in resp.text


# ---------------------------------------------------------------------------
# Admin API
# ---------------------------------------------------------------------------

async def test_admin_create_and_update_proximity(client, admin_session):
    resp = await client.post("/admin/tokens", cookies=admin_session, json={
        "label": "Garage", "entity_ids": ["cover.garage_door"], "expires_in_seconds": 3600,
        "proximity": {"proximity_required": True, "geofence_radius_m": 200, "allow_home_network": False},
    })
    assert resp.status_code == 201
    tok = resp.json()
    assert tok["proximity"] == {"proximity_required": True, "geofence_radius_m": 200, "allow_home_network": False}

    resp = await client.patch(f"/admin/tokens/{tok['id']}/proximity", cookies=admin_session, json={
        "proximity_required": False, "geofence_radius_m": 150, "allow_home_network": True,
    })
    assert resp.status_code == 200
    assert resp.json()["proximity"]["proximity_required"] is False

    listed = (await client.get("/admin/tokens", cookies=admin_session)).json()
    assert listed[0]["proximity"]["proximity_required"] is False


async def test_admin_create_defaults_to_no_proximity(client, admin_session):
    resp = await client.post("/admin/tokens", cookies=admin_session, json={
        "label": "Lights", "entity_ids": ["light.x"], "expires_in_seconds": 3600,
    })
    assert resp.json()["proximity"]["proximity_required"] is False


@pytest.mark.parametrize("radius", [10, 10_000])
async def test_admin_rejects_out_of_range_radius(client, admin_session, radius):
    resp = await client.post("/admin/tokens", cookies=admin_session, json={
        "label": "Bad", "entity_ids": ["light.x"], "expires_in_seconds": 3600,
        "proximity": {"proximity_required": True, "geofence_radius_m": radius},
    })
    assert resp.status_code == 422


async def test_admin_proximity_requires_auth(client, prox_token):
    resp = await client.patch(f"/admin/tokens/{prox_token['id']}/proximity", json={"proximity_required": False})
    assert resp.status_code == 401


async def test_admin_activity_includes_proximity(client, admin_session, prox_token):
    await client.post(f"/g/{prox_token['slug']}/presence", json={"location": _loc(FAR)})
    activity = (await client.get("/admin/activity", cookies=admin_session)).json()
    assert activity[0]["activity"] == "presence_denied"
    assert activity[0]["distance_m"] > 2000


# ---------------------------------------------------------------------------
# Migration
# ---------------------------------------------------------------------------

async def test_migration_003_downgrade_and_upgrade(test_db, prox_token):
    from alembic import command
    from alembic.config import Config
    from app.config import settings

    await db.close_db()
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{settings.db_path}")
    command.downgrade(cfg, "002")
    conn = await db.get_db()
    async with conn.execute("PRAGMA table_info(tokens)") as cur:
        cols = {r["name"] for r in await cur.fetchall()}
    assert "proximity_required" not in cols
    await db.close_db()

    command.upgrade(cfg, "head")
    row = await db.get_token_by_id(prox_token["id"])
    # Existing rows come back with safe defaults (no proximity requirement)
    assert row["proximity_required"] == 0 and row["geofence_radius_m"] == 150


async def test_activity_events_disabled_after_non_admin_401(mock_ha_client, monkeypatch):
    import httpx
    from app.routers import guest

    monkeypatch.setattr(guest, "_activity_events_forbidden", False)
    resp = httpx.Response(401, request=httpx.Request("POST", "http://ha/api/events/x"))
    mock_ha_client["fire_event"].side_effect = httpx.HTTPStatusError("401", request=resp.request, response=resp)
    payload = {"activity": "command", "token_label": "G", "target_entity_id": "cover.g", "service": "cover.open_cover"}
    await guest._fire_activity_event(payload)
    await guest._fire_activity_event(payload)
    assert mock_ha_client["fire_event"].await_count == 1      # stopped after the 401
    assert mock_ha_client["logbook_log"].await_count == 2     # logbook still written
