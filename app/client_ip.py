"""Resolve the real client IP without trusting client-controlled headers.

Forwarding headers (X-Forwarded-For, CF-Connecting-IP, ...) are only honoured
when the TCP peer is one of the configured TRUSTED_PROXIES. Any other peer —
including a LAN client talking to the published port directly — is identified
by its socket address and its headers are ignored.

With X-Forwarded-For the chain is walked right-to-left, skipping trusted
proxies, so a client-supplied left-most entry can never be selected. (Proxies
such as Cloudflare *append* to XFF rather than replacing it, so the left-most
entry is attacker-controlled.)
"""
import ipaddress
import logging
from functools import lru_cache

from fastapi import Request

from app.config import settings

logger = logging.getLogger(__name__)

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def parse_networks(raw: str) -> tuple[IPNetwork, ...]:
    """Parse a comma/space separated list of IPs or CIDRs. Invalid entries raise ValueError."""
    nets = []
    for part in raw.replace(",", " ").split():
        nets.append(ipaddress.ip_network(part, strict=False))
    return tuple(nets)


@lru_cache(maxsize=4)
def _trusted(raw: str) -> tuple[IPNetwork, ...]:
    return parse_networks(raw)


def _parse_ip(value: str | None) -> IPAddress | None:
    if not value:
        return None
    value = value.strip()
    # Strip brackets / port from forms like "[2001:db8::1]:443" or "1.2.3.4:567"
    if value.startswith("["):
        value = value[1:].split("]", 1)[0]
    elif value.count(":") == 1:
        value = value.split(":", 1)[0]
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    # Normalise IPv4-mapped IPv6 (::ffff:1.2.3.4) so v4 CIDRs match
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return addr.ipv4_mapped
    return addr


def _is_trusted(addr: IPAddress, trusted: tuple[IPNetwork, ...]) -> bool:
    return any(addr in net for net in trusted)


def client_ip(request: Request) -> str:
    """Return the best-known client IP as a string ("unknown" if none)."""
    peer = _parse_ip(request.client.host if request.client else None)
    if peer is None:
        return "unknown"

    trusted = _trusted(settings.trusted_proxies)
    if not trusted or not _is_trusted(peer, trusted):
        return str(peer)

    header = settings.client_ip_header.strip()
    raw = request.headers.get(header)
    if not raw:
        return str(peer)

    if header.lower() == "x-forwarded-for":
        hops = [h for h in (s.strip() for s in raw.split(",")) if h]
        for hop in reversed(hops):
            addr = _parse_ip(hop)
            if addr is None:
                # Malformed hop: stop rather than trust anything to its left
                return str(peer)
            if not _is_trusted(addr, trusted):
                return str(addr)
        return str(peer)

    # Single-value headers (CF-Connecting-IP, X-Real-IP, True-Client-IP)
    addr = _parse_ip(raw.split(",")[0])
    return str(addr) if addr is not None else str(peer)


def request_is_https(request: Request) -> bool:
    """True if the original request was HTTPS (X-Forwarded-Proto only from trusted proxies)."""
    if request.url.scheme == "https":
        return True
    peer = _parse_ip(request.client.host if request.client else None)
    trusted = _trusted(settings.trusted_proxies)
    if peer is not None and trusted and _is_trusted(peer, trusted):
        proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
        return proto == "https"
    return False
