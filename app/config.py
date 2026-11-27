import ipaddress
from typing import Literal
from urllib.parse import urlparse

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    admin_username: str = ""
    admin_password: str = ""
    ha_base_url: str = Field(min_length=1, pattern=r"^https?://")
    ha_token: str = Field(min_length=1)
    db_path: str = Field(default="/data/db.sqlite", min_length=1)
    app_name: str = "Home Access"
    contact_message: str = "Please request a new link from the person who shared this one."
    access_log_retention_days: int = Field(default=90, ge=1)
    brand_bg: str = "#F2F0E9"
    brand_primary: str = "#D9523C"
    supervisor_token: str = ""
    guest_url: str = ""

    # --- Client IP resolution -------------------------------------------------
    # Comma-separated IPs/CIDRs of reverse proxies whose forwarding header is
    # trusted. Empty = never trust forwarding headers (use the socket peer).
    trusted_proxies: str = ""
    # Header carrying the client IP when the peer is a trusted proxy.
    # "X-Forwarded-For" is walked right-to-left; anything else is single-valued
    # (e.g. "CF-Connecting-IP" for Cloudflare Tunnel).
    client_ip_header: str = "X-Forwarded-For"

    # --- Proximity ("near home") checks ---------------------------------------
    # Static public IPs/CIDRs that count as "on the home network".
    home_public_ips: str = ""
    # HA entity whose state is the home WAN IP (e.g. a router external-IP sensor).
    home_wan_ip_entity: str = ""
    # Optional override of the home location; defaults to HA's configured location.
    home_latitude: float | None = Field(default=None, ge=-90, le=90)
    home_longitude: float | None = Field(default=None, ge=-180, le=180)

    # --- Admin authentication -------------------------------------------------
    # password: built-in username/password; ha: sign in with Home Assistant
    # (OAuth2, must be an HA admin); both: either.
    admin_auth: Literal["password", "ha", "both"] = "password"
    # Browser-facing HA URL used for the OAuth redirect (e.g. https://ha.example.com).
    ha_external_url: str = ""
    # This app's public base URL (OAuth client_id). Defaults to GUEST_URL.
    public_url: str = ""
    # Optional comma-separated allowlist of HA user IDs permitted to administer.
    admin_ha_user_ids: str = ""
    # Optional origin allowed to frame the admin dashboard (e.g. an HA webpage panel).
    admin_frame_ancestors: str = ""

    @model_validator(mode="after")
    def _require_credentials_in_standalone(self):
        if not self.supervisor_token:
            if self.admin_auth in ("password", "both"):
                if len(self.admin_password) < 8:
                    raise ValueError("admin_password must be at least 8 characters in standalone mode")
                if not self.admin_username:
                    raise ValueError("admin_username is required in standalone mode")
            if self.admin_auth in ("ha", "both"):
                if not self.ha_external_url.startswith(("http://", "https://")):
                    raise ValueError("ha_external_url (http/https) is required when admin_auth includes 'ha'")
                if not (self.public_url or self.guest_url).startswith(("http://", "https://")):
                    raise ValueError("public_url (or guest_url) is required when admin_auth includes 'ha'")
        for name in ("trusted_proxies", "home_public_ips"):
            for part in getattr(self, name).replace(",", " ").split():
                try:
                    ipaddress.ip_network(part, strict=False)
                except ValueError as exc:
                    raise ValueError(f"{name}: invalid IP/CIDR {part!r}") from exc
        for origin in self.admin_frame_ancestors.split():
            parsed = urlparse(origin)
            if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.path not in ("", "/") \
                    or parsed.query or ";" in origin or "," in origin:
                raise ValueError(f"admin_frame_ancestors: {origin!r} is not an http(s) origin")
        if (self.home_latitude is None) != (self.home_longitude is None):
            raise ValueError("home_latitude and home_longitude must be set together")
        return self

    @property
    def password_login_enabled(self) -> bool:
        return bool(self.admin_password) and self.admin_auth in ("password", "both")

    @property
    def ha_login_enabled(self) -> bool:
        return self.admin_auth in ("ha", "both") and bool(self.ha_external_url)

    @property
    def admin_ha_user_id_set(self) -> set[str]:
        return {u for u in self.admin_ha_user_ids.replace(",", " ").split() if u}


settings = Settings()
