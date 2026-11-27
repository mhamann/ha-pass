# HAPass

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Shareable guest links for controlling Home Assistant devices**

Create time-limited links that give guests control of specific Home Assistant
entities — lights, locks, thermostats, fans, and more. Guests get a
mobile-friendly PWA with real-time state updates. No HA accounts needed, no app
installs, just a link.

## Screenshots

<p align="center">
  <img src="docs/admin-dashboard.png" width="250" alt="Admin dashboard">
  <img src="docs/admin-dark-extend.png" width="250" alt="Extend expiry (dark mode)">
  <img src="docs/admin-entity-picker.png" width="250" alt="Entity picker">
  <img src="docs/guest-pwa.png" width="250" alt="Guest PWA">
</p>

## Features

- **Scoped guest tokens** — each token grants access to a specific set of entities
- **Time-limited access** — tokens auto-expire after a configurable duration
- **Real-time updates** — SSE-powered live state changes with automatic reconnect
- **Installable PWA** — guests can add it to their home screen for an app-like experience
- **Dark mode** — system-aware with manual override
- **Admin dashboard** — create, revoke, extend, and monitor tokens
- **Recent activity** — see guest link opens and commands in the admin dashboard
- **Service allowlist** — only safe services (toggle, set_temperature, etc.) are permitted
- **Rate limiting** — 30 req/min per token
- **IP allowlisting** — optionally restrict tokens to specific CIDRs
- **Near-home only** — optionally require guests to be at the house (home network or GPS geofence) to view or control anything — see [Proximity](#proximity-near-home-links)
- **Sign in with Home Assistant** — optional OAuth login for the admin dashboard (HA admins only, MFA respected) — see [Admin sign-in](#admin-sign-in-with-home-assistant)

## Installation

### Home Assistant Add-on (recommended)

1. Add this repository in **Settings → Add-ons → Add-on Store → ⋮ → Repositories**:

   ```
   https://github.com/rohithkadaveru/ha-pass
   ```

2. Find **HAPass** in the store and click **Install**.
3. Go to the **Configuration** tab and set your options.
4. Start the add-on.
5. Click **Open Web UI** or find HAPass in the HA sidebar.

Admin access works through the HA sidebar — no separate login needed. Guest
links use the direct port (`http://<your-ha-ip>:5880/g/{slug}`) so visitors
don't need HA accounts.

### Docker Compose

```yaml
services:
  ha-pass:
    image: ghcr.io/rohithkadaveru/ha-pass:latest
    restart: unless-stopped
    ports:
      - 5880:5880
    volumes:
      - ./data:/data
    environment:
      - ADMIN_USERNAME=admin
      - ADMIN_PASSWORD=changeme
      - HA_BASE_URL=http://homeassistant.local:8123
      - HA_TOKEN=your_long_lived_token_here
```

```bash
docker compose up -d
```

### Docker Run

```bash
docker run -d --restart unless-stopped \
  -p 5880:5880 \
  -v ./data:/data \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD=changeme \
  -e HA_BASE_URL=http://homeassistant.local:8123 \
  -e HA_TOKEN=your_long_lived_token_here \
  ghcr.io/rohithkadaveru/ha-pass:latest
```

The admin dashboard is at `http://localhost:5880/admin/dashboard`.

> **Note:** Docker deployments need a [long-lived access token](https://developers.home-assistant.io/docs/auth_api/#long-lived-access-token) from Home Assistant. Create one in your HA profile under **Security → Long-Lived Access Tokens**. The add-on handles this automatically.

## Configuration

### Add-on Options

Set these in **Settings → Add-ons → HAPass → Configuration**:

| Option | Description | Default |
|---|---|---|
| **Admin Username** | Username for direct-port admin access (not needed for sidebar) | — |
| **Admin Password** | Password for direct-port admin access (min 8 chars) | — |
| **App Name** | Display name shown to guests | `Home Access` |
| **Contact Message** | Message shown when a guest link expires | `Please request a new link...` |
| **Background Color** | Hex color for page background | `#F2F0E9` |
| **Primary Color** | Hex color for accents and buttons | `#D9523C` |
| **Guest URL** | External base URL for guest links (e.g. `https://guest.myhouse.com`) | — |

### Docker Environment Variables

| Variable | Description | Required | Default |
|---|---|---|---|
| `ADMIN_USERNAME` | Admin login username | Yes | — |
| `ADMIN_PASSWORD` | Admin login password (min 8 chars) | Yes | — |
| `HA_BASE_URL` | Home Assistant base URL | Yes | — |
| `HA_TOKEN` | HA long-lived access token | Yes | — |
| `DB_PATH` | SQLite database path | No | `/data/db.sqlite` |
| `APP_NAME` | Display name shown to guests | No | `Home Access` |
| `CONTACT_MESSAGE` | Message shown on expired pages | No | `Please request a new link...` |
| `ACCESS_LOG_RETENTION_DAYS` | Days to retain access logs | No | `90` |
| `BRAND_BG` | Background color (hex) | No | `#F2F0E9` |
| `BRAND_PRIMARY` | Primary/accent color (hex) | No | `#D9523C` |
| `GUEST_URL` | External base URL for guest links | No | — |
| `HOST` | Interface uvicorn binds to | No | `0.0.0.0` |
| `TRUSTED_PROXIES` | IPs/CIDRs of reverse proxies whose forwarding header is trusted (comma-separated). Empty = never trust forwarding headers | No | — |
| `CLIENT_IP_HEADER` | Header carrying the client IP from a trusted proxy. `X-Forwarded-For` is walked right-to-left; use `CF-Connecting-IP` behind Cloudflare Tunnel | No | `X-Forwarded-For` |
| `HOME_PUBLIC_IPS` | Static public IPs/CIDRs that count as "on the home network" | No | — |
| `HOME_WAN_IP_ENTITY` | HA entity whose state is the home's public IP (e.g. a router external-IP sensor) | No | — |
| `HOME_LATITUDE` / `HOME_LONGITUDE` | Override the home location used for GPS checks | No | HA's location |
| `ADMIN_AUTH` | `password`, `ha` (Sign in with Home Assistant only) or `both` | No | `password` |
| `HA_EXTERNAL_URL` | Browser-facing HA URL for the sign-in redirect | With `ha` | — |
| `PUBLIC_URL` | This app's public base URL (OAuth client ID) | No | `GUEST_URL` |
| `ADMIN_HA_USER_IDS` | Restrict admin sign-in to these HA user IDs (comma-separated) | No | any HA admin |
| `ADMIN_FRAME_ANCESTORS` | Origin allowed to embed the admin dashboard (e.g. an HA Webpage dashboard) | No | — |

> **Client IPs behind a proxy.** Forwarding headers are honoured only when the
> TCP peer is in `TRUSTED_PROXIES`. Without it, IP allowlists and the
> home-network check use the socket address. Upstream HAPass ≤ 0.2.4 trusted
> the *first* `X-Forwarded-For` entry, which a client can set freely.

## Home Assistant Activity Events

HAPass emits a `ha_pass_activity` event after a valid guest page load and after
a successful guest command. These events are best-effort notification hooks:
HAPass logs and drops event failures without blocking the guest. HAPass also
writes matching Home Assistant Logbook entries for the Activity view.

Event payloads do not include the guest slug, internal token ID, or client IP
address.

```json
{
  "schema_version": 1,
  "activity": "command",
  "token_label": "Cleaner",
  "target_entity_id": "lock.front_door",
  "service": "lock.unlock"
}
```

`activity` is either `page_load` or `command`. `page_load` means the guest link
URL was requested; link previews, scanners, stale bookmarks, and refreshes can
also trigger it. Use `command` for higher-signal notifications.

```yaml
alias: HAPass guest activity notification
triggers:
  - trigger: event
    event_type: ha_pass_activity
conditions:
  - condition: template
    value_template: "{{ trigger.event.data.activity == 'command' }}"
actions:
  - action: notify.mobile_app_phone
    data:
      title: "Guest access"
      message: >
        {{ trigger.event.data.token_label }} used
        {{ trigger.event.data.service }}
        on {{ trigger.event.data.target_entity_id }}
```

## Proximity (near-home links)

Tick **Only works near home** when creating a link. The link then requires,
for **viewing** (state + live stream) and for **every command**, one of:

- **Home network** — the guest's IP is the home's public IP
  (`HOME_PUBLIC_IPS` and/or `HOME_WAN_IP_ENTITY`). Through a tunnel, devices on
  home Wi-Fi arrive with the WAN IP. Server-observed; can't be forged.
- **GPS** — the browser shares a fix within the link's radius (25–5000 m) of
  home. The fix must be ≤ 60 s old and accurate to ≤ 200 m.

Viewing is unlocked by `POST /g/{slug}/presence`, which sets a 10-minute
HttpOnly cookie scoped to that one link; the page renews it silently and the
live stream closes when it lapses. Commands need a fresh fix each time (or the
home network) — a view grant alone can't operate anything.

Every check is audited (method, distance; denials too) in the activity feed.

**Limits:** browser GPS is reported by the client, so a determined link-holder
could fake it. Proximity stops casual and remote misuse; short expiry and
revocation remain the real controls.

## Admin sign-in with Home Assistant

With `ADMIN_AUTH=ha`, the dashboard sends you to your HA login page (OAuth2
authorization code + PKCE; HA needs no client registration because the client
ID is `PUBLIC_URL`). Only HA **administrators** are admitted (optionally only
`ADMIN_HA_USER_IDS`). The HA refresh token is revoked immediately after
sign-in, so HAPass never keeps HA credentials; it issues its own 12-hour admin
session instead. `ADMIN_USERNAME`/`ADMIN_PASSWORD` aren't needed.

## Supported Entity Types

### Controllable Domains

| Domain | Allowed Services |
|---|---|
| `light` | `turn_on`, `turn_off`, `toggle` |
| `switch` | `turn_on`, `turn_off`, `toggle` |
| `input_boolean` | `turn_on`, `turn_off`, `toggle` |
| `climate` | `set_temperature`, `set_hvac_mode`, `turn_on`, `turn_off` |
| `lock` | `lock`, `unlock`, `open` |
| `media_player` | `media_play`, `media_pause`, `media_stop`, `volume_set`, `media_play_pause`, `turn_on`, `turn_off` |
| `cover` | `open_cover`, `close_cover`, `stop_cover` |
| `fan` | `turn_on`, `turn_off`, `toggle`, `set_percentage` |

### Read-Only Domains

| Domain | Access |
|---|---|
| `sensor` | Real-time state display only |
| `binary_sensor` | Real-time state display only |

## Architecture

```
Browser (Guest PWA)
    │
    ├── GET  /g/{slug}          → PWA shell (HTML)
    ├── GET  /g/{slug}/state    → initial entity states
    ├── GET  /g/{slug}/stream   → SSE real-time updates
    └── POST /g/{slug}/command  → service call proxy
                                      │
                                      ▼
                                  HAPass
                                  (FastAPI)
                                      │
                                      ├── REST API → Home Assistant
                                      └── WebSocket → HA event bus
```

## Disclaimer

HAPass is not affiliated with, endorsed by, or associated with Home Assistant
or Nabu Casa Inc. "Home Assistant" is a trademark of Nabu Casa Inc.

## License

[MIT](LICENSE)
