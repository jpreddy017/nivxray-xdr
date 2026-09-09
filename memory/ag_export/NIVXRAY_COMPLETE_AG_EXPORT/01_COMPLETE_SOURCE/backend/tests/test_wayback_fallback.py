"""P1-10 regression lock · Wayback Machine fallback.

The Sophos community URL (and many other analyst-reference URLs) is
Imperva-protected — direct httpx.get() returns a ~1 KB anti-bot
challenge instead of the article. Playwright with a real Chromium UA
often works, but not always.

This session added a `_wayback_fetch` cascade so acquisition falls
through to `web.archive.org` when the primary fetch returns an
anti-bot wall.

This suite locks:
  · _looks_like_antibot_wall recognises the common wall markers
  · _wayback_fetch has the expected shape (skips non-http URLs,
      returns "" on all failures, never raises)
  · The cascade actually calls Wayback when the primary is a wall
"""
from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from services.ida.acquisition import (
    _looks_like_antibot_wall,
    _wayback_fetch,
    acquire_url,
)


# ── Anti-bot wall detection ───────────────────────────────────────
@pytest.mark.parametrize("html", [
    "<html><body>Checking your browser before you access</body></html>",
    "<html><meta name=noindex, nofollow></html>",
    '<iframe id="main-iframe" src="/incapsula"></iframe>',
    "<title>Attention Required! | Cloudflare</title>",
    "<script>_Incapsula_Resource</script>",
    "<html>please enable cookies</html>",
])
def test_detects_common_antibot_walls(html):
    assert _looks_like_antibot_wall(html) is True


def test_empty_html_is_treated_as_wall():
    assert _looks_like_antibot_wall("") is True
    assert _looks_like_antibot_wall(None) is True  # type: ignore[arg-type]


def test_real_article_is_not_flagged():
    real = "<html>" + ("<p>Long-form threat report content. " * 500) + "</html>"
    assert _looks_like_antibot_wall(real) is False


# ── _wayback_fetch guardrails ─────────────────────────────────────
def test_wayback_rejects_non_http_url():
    assert _wayback_fetch("") == ""
    assert _wayback_fetch("ftp://x") == ""
    assert _wayback_fetch("javascript:alert(1)") == ""


def test_wayback_returns_empty_on_all_failures():
    """When every year snapshot 404s, function must return "" (not raise)."""
    fake_resp = MagicMock()
    fake_resp.status_code = 404
    fake_resp.content = b""
    with patch("services.ida.acquisition.httpx.get", return_value=fake_resp):
        assert _wayback_fetch("https://community.sophos.com/x") == ""


def test_wayback_returns_html_when_snapshot_found():
    long_html = b"<html>" + (b"<p>archived article content " * 500) + b"</html>"
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.content = long_html
    with patch("services.ida.acquisition.httpx.get", return_value=fake_resp):
        out = _wayback_fetch("https://community.sophos.com/x")
    assert "archived article content" in out
    assert len(out) > 4000


def test_wayback_swallows_httpx_errors():
    import httpx
    with patch(
        "services.ida.acquisition.httpx.get",
        side_effect=httpx.HTTPError("boom"),
    ):
        # Must return empty, never raise
        assert _wayback_fetch("https://community.sophos.com/x") == ""


# ── Cascade wiring: antibot wall triggers Wayback path ────────────
def test_acquire_url_falls_through_to_wayback_on_antibot_wall():
    """When the primary fetch returns an anti-bot wall AND Playwright
    also returns nothing meaningful, acquisition must attempt the
    Wayback path. We verify the Wayback function is invoked."""
    antibot = "<html>Checking your browser</html>"
    long_html = "<html>" + ("<p>archived reader " * 500) + "</html>"

    fake_primary = MagicMock()
    fake_primary.status_code = 200
    fake_primary.content = antibot.encode()
    fake_primary.headers = {"Content-Type": "text/html"}
    fake_primary.text = antibot

    with patch("services.ida.acquisition.httpx.get", return_value=fake_primary), \
             patch("services.ida.acquisition._playwright_render", return_value=""), \
             patch("services.ida.acquisition._wayback_fetch",
                       return_value=long_html) as mock_wb:
        try:
            acquire_url("https://community.sophos.com/some-article")
        except Exception:
            # We only care that Wayback was consulted; downstream
            # extraction failures are irrelevant to this regression.
            pass
        assert mock_wb.called, "Wayback fallback was not invoked on antibot wall"
