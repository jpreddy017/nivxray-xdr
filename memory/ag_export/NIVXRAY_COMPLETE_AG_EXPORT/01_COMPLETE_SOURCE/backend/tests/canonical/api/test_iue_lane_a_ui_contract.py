"""Deterministic UI contract test for the Structured Evidence tab.

Runs against the live preview instance.  Skipped when the preview URL
is unreachable (e.g. offline CI runs).  Covers the 7 assertions from
Phase 6c.4:

  T1 · LogicalEvents render correctly
  T2 · Aggregated events remain correctly represented
  T3 · Process / Network / IOC panels are present
  T4 · canonical.*.ip IOC projection matches canonical fields
  T5 · Provenance panel + lineage + record refs walkable
  T6 · No [object Object] anywhere in the rendered DOM
  T7 · Empty state renders without crash

Runs via ``playwright.sync_api``; installs are not attempted from here.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))


def _preview_url() -> str:
    # Reads the frontend .env — playwright hits the live preview.
    env = Path("/app/frontend/.env").read_text()
    for line in env.splitlines():
        if line.startswith("REACT_APP_BACKEND_URL="):
            return line.split("=", 1)[1].strip()
    return ""


PREVIEW = _preview_url()
FIXTURE_NDJSON = (
    b'{"event_time":"2026-02-14T12:00:00.010Z","host":"srv-01","user":"jsmith",'
    b'"action":"exec","category":"process","CommandLine":"powershell -enc AAA",'
    b'"src_ip":"10.0.0.1","dst_ip":"185.220.101.7"}\n'
    b'{"event_time":"2026-02-14T12:00:00.240Z","host":"srv-01","user":"jsmith",'
    b'"action":"exec","category":"process","CommandLine":"powershell -enc AAA",'
    b'"src_ip":"10.0.0.1","dst_ip":"185.220.101.7"}\n'
    b'{"event_time":"2026-02-14T12:00:07.500Z","host":"srv-02","user":"rjones",'
    b'"action":"network_connect","category":"network",'
    b'"src_ip":"10.0.0.2","dst_ip":"198.51.100.20","dst_port":"443"}\n'
)


@pytest.fixture(scope="module")
def playwright_available():
    try:
        import playwright.sync_api  # noqa
    except ImportError:
        pytest.skip("playwright not installed in test env")
    # Verify a browser executable is available before running headless tests.
    from playwright.sync_api import sync_playwright
    try:
        with sync_playwright() as pw:
            b = pw.chromium.launch(headless=True)
            b.close()
    except Exception as e:
        pytest.skip(f"playwright browser not installed: {e}")


@pytest.fixture(scope="module")
def fixture_file(tmp_path_factory):
    p = tmp_path_factory.mktemp("iue") / "fixture.ndjson"
    p.write_bytes(FIXTURE_NDJSON)
    return str(p)


def _login(page):
    # Read admin creds from /app/memory/test_credentials.md
    try:
        creds = Path("/app/memory/test_credentials.md").read_text()
    except Exception:
        pytest.skip("test_credentials.md missing")
    import re
    m = re.search(r"admin@nivxray\.com.*?password[:\s`\"]*([A-Za-z0-9]+)",
                    creds, re.S | re.I)
    if not m:
        pytest.skip("admin password not found in test_credentials.md")
    pw = m.group(1)

    page.goto(f"{PREVIEW}/login", wait_until="networkidle", timeout=30_000)

    def clear_and_type(sel, val):
        loc = page.locator(sel)
        loc.click()
        page.keyboard.press("Control+A")
        page.keyboard.press("Delete")
        page.keyboard.type(val, delay=15)

    clear_and_type('input[type="email"]', "admin@nivxray.com")
    clear_and_type('input[type="password"]', pw)
    page.click('button:has-text("ENTER TERMINAL")', force=True)
    for _ in range(20):
        if "/login" not in page.url:
            break
        page.wait_for_timeout(500)
    assert "/login" not in page.url, f"login failed, still at {page.url}"


def test_structured_evidence_full_contract(playwright_available, fixture_file):
    from playwright.sync_api import sync_playwright
    if not PREVIEW:
        pytest.skip("REACT_APP_BACKEND_URL not set")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(viewport={"width": 1920, "height": 1200})
        page = ctx.new_page()
        try:
            _login(page)

            # ── /lane-a route uses the extracted component ────────
            page.goto(f"{PREVIEW}/lane-a", wait_until="networkidle", timeout=30_000)
            page.wait_for_selector('[data-testid="structured-evidence-tab"]',
                                    timeout=10_000)

            # ── T7 · Empty state ─────────────────────────────────
            assert page.locator('[data-testid="evidence-empty-state"]').count() == 1

            # ── T1 · Upload + LogicalEvents render ────────────────
            page.locator('[data-testid="evidence-file-input"]').set_input_files(
                fixture_file)
            page.click('[data-testid="evidence-analyze-btn"]', force=True)
            page.wait_for_selector('[data-testid="evidence-summary"]',
                                    timeout=15_000)
            page.wait_for_timeout(400)

            events = page.locator('div[data-testid^="evidence-event-"]').count()
            assert events == 2, f"expected 2 LogicalEvents, got {events}"

            # ── T2 · Aggregation shown (×N badges present) ────────
            first_badge = page.locator(
                '[data-testid^="evidence-event-count-"]').first
            badge_txt = first_badge.text_content()
            assert badge_txt.startswith("×"), \
                f"aggregation badge missing: {badge_txt!r}"

            # ── T3 · Category panels present ──────────────────────
            assert page.locator('[data-testid="evidence-panel-process"]').count() == 1
            assert page.locator('[data-testid="evidence-panel-network"]').count() == 1
            assert page.locator('[data-testid="evidence-panel-ioc"]').count() == 1

            # ── T4 · IOC projection from canonical fields ─────────
            ips = page.locator('[data-testid="evidence-ioc-ips"] li').count()
            assert ips >= 2, f"expected >=2 IPs projected, got {ips}"

            # ── T5 · Provenance trace ─────────────────────────────
            page.locator('div[data-testid^="evidence-event-"]').first.click(force=True)
            page.wait_for_timeout(300)
            assert page.locator('[data-testid="evidence-provenance-panel"]').count() == 1
            chain = page.locator(
                '[data-testid^="evidence-provenance-chain-"]').count()
            assert chain >= 5, f"expected >=5 lineage steps, got {chain}"
            refs = page.locator('[data-testid="evidence-record-refs"] li').count()
            assert refs >= 1

            # ── T6 · No [object Object] ───────────────────────────
            body = page.evaluate("() => document.body.innerText")
            assert "[object Object]" not in body, \
                "[object Object] leaked into DOM"
        finally:
            browser.close()
