"""Tests for top-level app routes in main.py."""


async def test_root_redirects_to_admin_dashboard(client, mock_ha_client):
    resp = await client.get("/", follow_redirects=False)
    assert resp.status_code in (301, 302, 307)
    assert "/admin/dashboard" in resp.headers["location"]


async def test_health_check_returns_503_when_ws_unhealthy(client, mock_ha_client):
    """Degraded WS returns 503 so monitoring can alert."""
    mock_ha_client["is_ws_healthy"].return_value = False
    resp = await client.get("/health")
    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "degraded"
    assert data["ws"] == "disconnected"


async def test_html_opts_out_of_cdn_script_rewriting(client, sample_token):
    """Cloudflare Rocket Loader rewrites <script> tags and re-runs inline ones
    without their CSP nonce, which the browser then blocks (page never starts).
    HTML must carry Cache-Control: no-transform and every script data-cfasync=false."""
    import re

    for path in (f"/g/{sample_token['slug']}", "/admin/dashboard", "/g/does-not-exist"):
        resp = await client.get(path)
        assert "no-transform" in resp.headers["cache-control"], path
        tags = re.findall(r"<script\b[^>]*>", resp.text)
        assert tags, path
        for tag in tags:
            assert 'data-cfasync="false"' in tag, (path, tag)
