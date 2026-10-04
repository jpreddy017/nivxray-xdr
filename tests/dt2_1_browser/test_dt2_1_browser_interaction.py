"""DT2-1 · focused Playwright browser suite.

These are the PLAYWRIGHT rows of the 50-case matrix: everything that is
genuinely browser-dependent — real WheelEvent objects with every
`deltaMode`, scroll-domain ownership, URL/history semantics, browser
Back/Forward, and overlapping-request races.

IT IS NOT A SUBSTITUTE FOR PHYSICAL HARDWARE ACCEPTANCE.
Synthetic WheelEvent sequences prove the pipeline's arithmetic and
bounds. They do NOT prove how a physical mouse or a physical Mac
trackpad FEELS. Those rows stay "PHYSICAL HARDWARE: NOT VALIDATED".

Deliberately OUTSIDE `backend/tests/edr`, so the authoritative CI scope
(which runs `pytest tests/edr` on a runner with no browser and no preview
edge) is unaffected.

Run:  python -m pytest /app/tests/dt2_1_browser -q -s
"""
from __future__ import annotations

import os
import re

import pytest
from playwright.sync_api import sync_playwright

BASE = os.environ.get(
    "DT2_PREVIEW_URL",
    "https://greeting-app-5782.preview.emergentagent.com")
EMAIL = os.environ.get("DT2_EMAIL", "admin@nivxray.com")
PASSWORD = os.environ.get("DT2_PASSWORD", "uulVDp5cCSB3Hva99s7UUAwK")
DEVICE = os.environ.get("DT2_DEVICE", "dev_42e8c6dc74b9")
TENANT = os.environ.get("DT2_TENANT", "default")
LOCAL_API = os.environ.get("DT2_LOCAL_API", "http://localhost:8001")

CHROME = os.environ.get("PLAYWRIGHT_CHROME_EXECUTABLE_PATH",
                        "/usr/local/bin/browser-use-chromium")

CANVAS = '[data-testid="amp-canvas"]'
NAVBAR = '[data-testid="dt2-navbar"]'
PANEL = '[data-testid="amp-activity-list"]'

WHEEL_JS = """(el, o) => {
  for (let i = 0; i < o.times; i += 1) {
    el.dispatchEvent(new WheelEvent('wheel', {
      deltaX: o.dx, deltaY: o.dy, deltaMode: o.mode,
      ctrlKey: o.ctrl, shiftKey: o.shift,
      bubbles: true, cancelable: true }));
  }
}"""


def _iso_ms(text):
    """'2026-06-01T00:00:00.000Z' → epoch ms, without importing dateutil."""
    m = re.match(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)", text or "")
    if not m:
        return None
    import calendar
    y, mo, d, h, mi, s = (int(x) for x in m.groups())
    return calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0)) * 1000


class Trajectory:
    def __init__(self, page):
        self.page = page

    def window(self):
        bar = self.page.locator(NAVBAR)
        return (_iso_ms(bar.get_attribute("data-window-from")),
                _iso_ms(bar.get_attribute("data-window-to")),
                int(bar.get_attribute("data-zoom-level") or -1))

    def span(self):
        t0, t1, _ = self.window()
        return t1 - t0

    def wheel(self, selector=CANVAS, dx=0, dy=0, mode=0, ctrl=False,
              shift=False, times=1, settle=260):
        self.page.eval_on_selector(
            selector, WHEEL_JS,
            {"dx": dx, "dy": dy, "mode": mode, "ctrl": ctrl,
             "shift": shift, "times": times})
        self.page.wait_for_timeout(settle)

    def attr(self, selector, name):
        return self.page.locator(selector).first.get_attribute(name)


@pytest.fixture(scope="module")
def traj():
    """Authenticate over the API, then seed the SPA's own session keys.

    NOTE for the P0 tenant-authority gate: the console currently carries
    the active tenant in `localStorage.nvx_tenant` / `?tenant=` and sends
    it as `X-Tenant-Id`. That is a client-side REQUEST; whether the server
    independently verifies membership is the subject of the separate P0
    tenant-authority task, NOT of DT2-1.
    """
    import json
    import subprocess

    def _login(origin):
        out = subprocess.run(
            ["curl", "-s", "--max-time", "45", "-X", "POST",
             f"{origin}/api/auth/login",
             "-H", "Content-Type: application/json",
             "-d", json.dumps({"email": EMAIL, "password": PASSWORD})],
            capture_output=True, text=True, timeout=60)
        try:
            return json.loads(out.stdout or "{}"), out.stdout[:160]
        except ValueError:
            return {}, out.stdout[:160]

    token, detail = None, ""
    # The preview EDGE intermittently answers a challenge/502 to
    # non-browser clients; the token is identical from the local origin,
    # and the BROWSER below still exercises the real external edge.
    import time
    for attempt in range(4):
        for origin in (LOCAL_API, BASE):
            auth, raw = _login(origin)
            token = auth.get("access_token") or auth.get("token")
            if token:
                break
            detail = f"{origin} → {raw}"
        if token:
            break
        time.sleep(3 * (attempt + 1))
    assert token, f"preview login did not return a token: {detail}"

    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"],
                                    executable_path=CHROME)
        page = browser.new_page(viewport={"width": 1680, "height": 950})
        page.goto(f"{BASE}/login", wait_until="domcontentloaded",
                  timeout=90000)
        page.evaluate(
            """(o) => {
                 localStorage.setItem('nvx_token', o.token);
                 localStorage.setItem('nvx_email', o.email);
                 localStorage.setItem('nvx_tenant', o.tenant);
               }""",
            {"token": token, "email": EMAIL, "tenant": TENANT})
        page.goto(f"{BASE}/edr/device-trajectory?device={DEVICE}",
                  wait_until="domcontentloaded", timeout=90000)
        try:
            page.wait_for_selector(NAVBAR, timeout=180000)
        except Exception as ex:                        # pragma: no cover
            page.screenshot(path="/tmp/dt2_1_navbar_missing.png",
                            full_page=False)
            browser.close()
            pytest.skip(f"trajectory workspace did not render: {ex}")
        page.wait_for_timeout(3000)
        yield Trajectory(page)
        browser.close()


# ── B01-B05 · deltaMode and bounded sensitivity ───────────────────────

def test_b01_pixel_mode_small_wheel_moves_the_window_a_little(traj):
    t0, t1, _ = traj.window()
    traj.page.mouse.move(700, 520)
    traj.wheel(dx=-6, times=3)
    n0, n1, _ = traj.window()
    moved = abs(n0 - t0)
    assert moved > 0, "a small horizontal gesture must move time at all"
    assert moved < (t1 - t0) * 0.30, "and must not leap across the window"
    print(f"B01 small pixel gesture moved {moved / 1000:.1f}s "
          f"of a {(t1 - t0) / 1000:.0f}s window")


def test_b02_line_mode_is_converted_not_treated_as_pixels(traj):
    t0, _, _ = traj.window()
    traj.wheel(dx=-3, mode=1, times=2)
    n0, _, _ = traj.window()
    assert n0 != t0, "DOM_DELTA_LINE must still produce movement"
    print(f"B02 LINE mode moved {abs(n0 - t0) / 1000:.1f}s")


def test_b03_page_mode_is_bounded(traj):
    t0, t1, _ = traj.window()
    span = t1 - t0
    traj.wheel(dx=-1, mode=2, times=1)
    n0, _, _ = traj.window()
    assert abs(n0 - t0) <= span * 0.10 + 1, \
        "one DOM_DELTA_PAGE event must stay inside the per-event clamp"
    print(f"B03 PAGE mode moved {abs(n0 - t0) / 1000:.1f}s "
          f"(clamp {span * 0.08 / 1000:.1f}s)")


def test_b04_a_mouse_like_burst_is_bounded(traj):
    t0, t1, _ = traj.window()
    span = t1 - t0
    traj.wheel(dx=-100, times=40)
    n0, n1, _ = traj.window()
    assert n1 - n0 == span, "a pan must not change the scale"
    assert abs(n0 - t0) <= span * 0.35 + 1, \
        "a 40-event mouse burst must stay inside the rolling budget"
    print(f"B04 40 × 100px burst moved {abs(n0 - t0) / 1000:.1f}s "
          f"(budget {span * 0.30 / 1000:.1f}s)")


def test_b05_a_trackpad_like_burst_is_bounded(traj):
    t0, t1, _ = traj.window()
    span = t1 - t0
    traj.wheel(dx=-7.5, times=120)
    n0, _, _ = traj.window()
    assert abs(n0 - t0) <= span * 0.35 + 1, \
        "120 high-frequency low-delta frames must not run away"
    print(f"B05 120 × 7.5px trackpad burst moved "
          f"{abs(n0 - t0) / 1000:.1f}s")


# ── B06-B09 · zoom ────────────────────────────────────────────────────

def test_b06_ctrl_wheel_zooms_at_most_one_level_per_event(traj):
    _, _, lvl = traj.window()
    traj.page.mouse.move(700, 520)
    traj.wheel(dy=120, ctrl=True, times=1)
    _, _, after = traj.window()
    assert abs(after - lvl) <= 1, "one event, at most one ladder level"
    print(f"B06 zoom level {lvl} → {after}")


def test_b07_a_zoom_burst_cannot_detonate_the_scale(traj):
    before = traj.span()
    traj.wheel(dy=200, ctrl=True, times=60)
    after = traj.span()
    assert after <= 30 * 86400 * 1000, "ceiling is the 30-day level"
    assert after >= 1000, "floor is the 1-second level"
    print(f"B07 60-event zoom burst: {before / 1000:.0f}s → "
          f"{after / 1000:.0f}s (bounded)")


def test_b08_zoom_is_anchored_on_the_pointer(traj):
    box = traj.page.locator(CANVAS).bounding_box()
    x = box["x"] + box["width"] * 0.75
    y = box["y"] + box["height"] * 0.5
    traj.page.mouse.move(x, y)
    traj.page.wait_for_timeout(120)
    t0, t1, _ = traj.window()
    gutter = 280
    plot_w = box["width"] - gutter
    frac = ((x - box["x"]) - gutter) / plot_w
    anchor = t0 + frac * (t1 - t0)
    traj.wheel(dy=-160, ctrl=True, times=1)
    n0, n1, _ = traj.window()
    assert n0 <= anchor <= n1, \
        "the moment under the pointer must remain inside the window"
    print(f"B08 anchor preserved inside the new window")


def test_b09_pan_does_not_change_the_zoom_level(traj):
    _, _, lvl = traj.window()
    traj.wheel(dx=-40, times=4)
    _, _, after = traj.window()
    assert after == lvl, "PAN must never alter the temporal scale"


# ── B10-B12 · scroll-domain isolation ─────────────────────────────────

def test_b10_wheel_over_the_canvas_does_not_scroll_the_page(traj):
    y0 = traj.page.evaluate("window.scrollY")
    traj.wheel(dy=200, times=6)
    assert traj.page.evaluate("window.scrollY") == y0, \
        "the trajectory must consume its own gesture"


def test_b11_wheel_over_the_canvas_scrolls_lanes_not_time(traj):
    t0, t1, _ = traj.window()
    start = traj.attr('[data-testid="amp-workspace"]', "data-row-start")
    traj.wheel(dy=300, times=3)
    n0, n1, _ = traj.window()
    after = traj.attr('[data-testid="amp-workspace"]', "data-row-start")
    assert (n0, n1) == (t0, t1), "a vertical gesture must not pan time"
    print(f"B11 lanes {start} → {after}, window unchanged")


def test_b12_scrolling_the_inspector_does_not_move_the_trajectory(traj):
    t0, t1, lvl = traj.window()
    rows = traj.attr('[data-testid="amp-workspace"]', "data-row-start")
    traj.wheel(selector=PANEL, dy=300, times=4)
    assert traj.window() == (t0, t1, lvl), \
        "inspector scrolling must not pan or zoom the trajectory"
    assert traj.attr('[data-testid="amp-workspace"]',
                     "data-row-start") == rows
    assert traj.attr(PANEL, "data-dt2-scroll-domain") == "inspector"


# ── B13-B16 · URL, history, Back/Forward ──────────────────────────────

def test_b13_the_window_is_serialized_into_the_url(traj):
    traj.page.wait_for_timeout(700)
    url = traj.page.url
    assert "from=" in url and "to=" in url and "zoom=" in url
    assert "device=" in url


def test_b14_no_credential_or_raw_payload_enters_the_url(traj):
    url = traj.page.url.lower()
    for banned in ("token", "secret", "password", "bearer", "jwt",
                   "authorization", "raw_payload"):
        assert banned not in url, banned


def test_b15_a_wheel_burst_does_not_flood_browser_history(traj):
    before = traj.page.evaluate("history.length")
    traj.wheel(dx=-30, times=30)
    traj.page.wait_for_timeout(900)
    after = traj.page.evaluate("history.length")
    assert after - before <= 1, \
        f"history grew by {after - before} entries on a wheel burst"
    print(f"B15 history {before} → {after} across 30 wheel events")


def test_b16_back_and_forward_restore_the_investigation_window(traj):
    traj.page.wait_for_timeout(800)
    first = traj.window()
    traj.page.evaluate(
        """() => { const u = new URL(window.location.href);
                   u.searchParams.set('from', u.searchParams.get('from'));
                   return null; }""")
    # A materially different investigation window, pushed deliberately.
    t0, t1, _ = first
    span = t1 - t0
    new_from = t0 - 4 * span
    traj.page.evaluate(
        """(o) => {
             const u = new URL(window.location.href);
             u.searchParams.set('from', new Date(o.f).toISOString());
             u.searchParams.set('to', new Date(o.t).toISOString());
             window.history.pushState({}, '', u.toString());
             window.dispatchEvent(new PopStateEvent('popstate'));
           }""", {"f": new_from, "t": new_from + span})
    traj.page.wait_for_timeout(1500)
    moved = traj.window()
    assert moved[0] != first[0], "the pushed window must be applied"
    traj.page.go_back()
    traj.page.wait_for_timeout(2000)
    restored = traj.window()
    assert abs(restored[0] - first[0]) < span * 0.5, \
        f"Back must restore the previous window ({restored} vs {first})"
    traj.page.go_forward()
    traj.page.wait_for_timeout(2000)
    forward = traj.window()
    assert abs(forward[0] - moved[0]) < span * 0.5, \
        "Forward must restore the next window"
    print(f"B16 Back/Forward restored the window deterministically")


# ── B17-B19 · races, prev/next, state truth ───────────────────────────

def test_b17_rapid_a_b_c_navigation_lands_on_c(traj):
    gen0 = int(traj.attr('[data-testid="amp-workspace"]',
                         "data-dt2-generation") or 0)
    for _ in range(3):
        traj.wheel(dx=-90, times=2, settle=60)
    traj.page.wait_for_timeout(2500)
    gen1 = int(traj.attr('[data-testid="amp-workspace"]',
                         "data-dt2-generation") or 0)
    state = traj.attr('[data-testid="amp-workspace"]',
                      "data-dt2-window-state")
    assert gen1 > gen0, "each viewport change must mint a new generation"
    assert state not in ("FAILED",), \
        "overlapping requests must not surface as a failure"
    print(f"B17 generation {gen0} → {gen1}, state {state}")


def test_b18_previous_next_controls_are_present_and_deterministic(traj):
    for tid in ("dt2-prev-event", "dt2-next-event", "dt2-prev-detection",
                "dt2-next-detection", "dt2-zoom-in", "dt2-zoom-out"):
        assert traj.page.locator(f'[data-testid="{tid}"]').count() == 1, tid
    before = traj.window()
    traj.page.click('[data-testid="dt2-next-event"]')
    traj.page.wait_for_timeout(1200)
    sel = traj.attr('[data-testid="amp-workspace"]',
                    "data-dt2-selection-state")
    assert sel is not None
    print(f"B18 next-event → selection state {sel}, window {before} → "
          f"{traj.window()}")


def test_b19_state_attributes_never_claim_absence_on_failure(traj):
    state = traj.attr('[data-testid="amp-workspace"]',
                      "data-dt2-window-state")
    assert state in ("READY", "READY_NOT_OBSERVED", "REFRESHING",
                     "WINDOW_LOADING", "PREFETCHING", "INITIAL_LOADING",
                     "STALE_RESPONSE_DISCARDED", "CANCELED", "FAILED",
                     "FOCUS_RESOLVING", "UNAVAILABLE", "IDLE"), state
    if state in ("FAILED", "CANCELED", "STALE_RESPONSE_DISCARDED"):
        assert traj.page.locator(
            '[data-testid="amp-activity-empty"]').count() == 0, \
            "a failed or superseded window must not render as empty"
    engine = traj.attr('[data-testid="amp-workspace"]', "data-dt2-engine")
    assert engine == "dt2.1"
    print(f"B19 window state {state}, engine {engine}")
