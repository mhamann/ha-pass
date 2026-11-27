"""Client IP resolution must not trust client-controlled forwarding headers."""
import time

import pytest
from starlette.requests import Request

from app import database as db
from app.client_ip import client_ip, request_is_https


def _req(peer: str, headers: dict[str, str] | None = None, scheme: str = "http") -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "scheme": scheme,
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "client": (peer, 12345),
        "server": ("testserver", 80),
    }
    return Request(scope)


def test_no_trusted_proxies_ignores_forwarding_headers(override_settings):
    override_settings(trusted_proxies="", client_ip_header="X-Forwarded-For")
    r = _req("203.0.113.9", {"X-Forwarded-For": "10.0.0.5", "CF-Connecting-IP": "10.0.0.6"})
    assert client_ip(r) == "203.0.113.9"


def test_untrusted_peer_headers_ignored(override_settings):
    override_settings(trusted_proxies="127.0.0.1", client_ip_header="CF-Connecting-IP")
    r = _req("192.168.1.50", {"CF-Connecting-IP": "136.56.183.42"})
    assert client_ip(r) == "192.168.1.50"


def test_trusted_peer_uses_cf_connecting_ip(override_settings):
    override_settings(trusted_proxies="127.0.0.1", client_ip_header="CF-Connecting-IP")
    r = _req("127.0.0.1", {"CF-Connecting-IP": "198.51.100.7", "X-Forwarded-For": "10.0.0.1"})
    assert client_ip(r) == "198.51.100.7"


def test_trusted_peer_without_header_falls_back_to_peer(override_settings):
    override_settings(trusted_proxies="127.0.0.1", client_ip_header="CF-Connecting-IP")
    assert client_ip(_req("127.0.0.1")) == "127.0.0.1"


def test_xff_spoofed_leftmost_entry_is_not_selected(override_settings):
    """Cloudflare appends to XFF; the left-most entry is attacker-controlled."""
    override_settings(trusted_proxies="127.0.0.1", client_ip_header="X-Forwarded-For")
    r = _req("127.0.0.1", {"X-Forwarded-For": "136.56.183.42, 198.51.100.7"})
    assert client_ip(r) == "198.51.100.7"


def test_xff_skips_trusted_hops_right_to_left(override_settings):
    override_settings(trusted_proxies="127.0.0.1, 172.18.0.0/16", client_ip_header="X-Forwarded-For")
    r = _req("127.0.0.1", {"X-Forwarded-For": "1.1.1.1, 198.51.100.7, 172.18.0.5"})
    assert client_ip(r) == "198.51.100.7"


def test_xff_malformed_hop_falls_back_to_peer(override_settings):
    override_settings(trusted_proxies="127.0.0.1", client_ip_header="X-Forwarded-For")
    r = _req("127.0.0.1", {"X-Forwarded-For": "1.1.1.1, not-an-ip"})
    assert client_ip(r) == "127.0.0.1"


def test_ipv4_mapped_peer_is_normalised(override_settings):
    override_settings(trusted_proxies="127.0.0.1", client_ip_header="CF-Connecting-IP")
    r = _req("::ffff:127.0.0.1", {"CF-Connecting-IP": "198.51.100.7"})
    assert client_ip(r) == "198.51.100.7"


def test_ipv6_client_from_cf(override_settings):
    override_settings(trusted_proxies="127.0.0.1", client_ip_header="CF-Connecting-IP")
    r = _req("127.0.0.1", {"CF-Connecting-IP": "2001:db8::1"})
    assert client_ip(r) == "2001:db8::1"


def test_forwarded_proto_only_trusted_from_proxy(override_settings):
    override_settings(trusted_proxies="127.0.0.1")
    assert request_is_https(_req("127.0.0.1", {"X-Forwarded-Proto": "https"}))
    assert not request_is_https(_req("192.168.1.5", {"X-Forwarded-Proto": "https"}))
    assert request_is_https(_req("192.168.1.5", scheme="https"))


async def test_ip_allowlist_cannot_be_bypassed_with_spoofed_xff(client, test_db, override_settings):
    """Regression: upstream trusted the first XFF entry, so a guest could claim any IP."""
    override_settings(trusted_proxies="", client_ip_header="X-Forwarded-For")
    now = int(time.time())
    await db.create_token(
        label="LAN only", slug="lan-only", entity_ids=["light.x"],
        expires_at=now + 3600, ip_allowlist=["10.0.0.0/8"],
    )
    resp = await client.get("/g/lan-only/state", headers={"X-Forwarded-For": "10.1.2.3"})
    assert resp.status_code == 403
