"""Navigator OWNER FIX: pinned day popover, dot/time-link jump, hour bar parity. Preview shell only."""
import asyncio, json, sys, urllib.parse as up
from playwright.async_api import async_playwright

HOST = "https://edr-forge-complete.preview.emergentagent.com"
D = sys.argv[1] if len(sys.argv) > 1 else open("/tmp/shell_dir").read().strip()
TAG = sys.argv[2] if len(sys.argv) > 2 else "after"
B = f"{HOST}/{D}/index.html"
OUT = "/app/.e3ui-harness/shots_nav"
R, ERR = {}, []


def ok(n, c, d=""):
    R[n] = {"pass": bool(c), "detail": str(d)[:200]}


def qp(pg):
    return dict(up.parse_qsl(up.urlparse(pg.url).query))


async def main():
    import os
    os.makedirs(OUT, exist_ok=True)
    async with async_playwright() as p:
        b = await p.chromium.launch(executable_path="/usr/bin/chromium", args=["--no-sandbox"])
        pg = await (await b.new_context(viewport={"width": 2000, "height": 1300})).new_page()
        pg.on("pageerror", lambda e: ERR.append(str(e)[:300]))
        await pg.goto(B)
        await pg.wait_for_selector('[data-testid^="v3-marker-"]', timeout=45000)
        await pg.wait_for_selector('[data-testid="v3-loading"]', state="detached", timeout=30000)
        nav = pg.locator('[data-testid="v3-navigator"]')
        await nav.screenshot(path=f"{OUT}/{TAG}_01_navigator.png")
        if TAG == "before":
            await b.close(); return
        cells = pg.locator('[data-testid^="v3-day-cell-"]')
        ok("thirty_days", await cells.count() == 30)
        # hover preview then click pins
        await cells.last.hover()
        await pg.wait_for_selector('[data-testid="v3-day-tooltip"]')
        ok("hover_preview_unpinned", await pg.get_attribute('[data-testid="v3-day-tooltip"]', "data-pinned") == "0")
        await cells.last.click()
        await pg.wait_for_selector('[data-testid="v3-day-tooltip"][data-pinned="1"]')
        await pg.mouse.move(10, 1250)
        await pg.wait_for_timeout(600)
        ok("pinned_stays_after_leave", await pg.locator('[data-testid="v3-day-tooltip"][data-pinned="1"]').count() == 1)
        await nav.screenshot(path=f"{OUT}/after_02_day_pinned.png")
        await pg.screenshot(path=f"{OUT}/after_02b_day_pinned_page.jpeg", quality=70)
        await pg.keyboard.press("Escape")
        ok("esc_closes", await pg.locator('[data-testid="v3-day-tooltip"]').count() == 0)
        # day with detections -> click time link jumps
        dots = pg.locator('[data-testid^="v3-day-dot-"]')
        ok("day_dots_present", await dots.count() > 0, await dots.count())
        day_cell = dots.first.locator("xpath=ancestor::*[starts-with(@data-testid,'v3-day-cell-')]")
        await day_cell.click()
        await pg.wait_for_selector('[data-testid="v3-day-tooltip"][data-pinned="1"]')
        await pg.mouse.move(10, 1250)
        await pg.wait_for_timeout(400)
        await pg.click('[data-testid="v3-tip-jump-0"]')
        await pg.wait_for_function("()=>new URLSearchParams(location.search).get('event')", timeout=15000)
        ok("time_link_sets_event", "event" in qp(pg), qp(pg))
        ok("time_link_closes_popover", await pg.locator('[data-testid="v3-day-tooltip"]').count() == 0)
        await pg.wait_for_selector('[data-testid="v3-activity-details"]', timeout=20000)
        ok("time_link_opens_details", True)
        await pg.screenshot(path=f"{OUT}/after_03_jumped.jpeg", quality=70)
        # red dot click navigates directly
        await pg.goto(B)
        await pg.wait_for_selector('[data-testid^="v3-marker-"]', timeout=45000)
        await pg.click('[data-testid^="v3-day-dot-"] >> nth=-1')
        await pg.wait_for_function("()=>new URLSearchParams(location.search).get('event')", timeout=15000)
        ok("red_dot_jumps", "event" in qp(pg))
        ok("red_dot_pins", await pg.locator('[data-testid="v3-day-tooltip"][data-pinned="1"]').count() == 1)
        await pg.keyboard.press("Escape")
        # hour bar parity
        hs = pg.locator('[data-testid^="v3-hour-cell-"]')
        ok("24_hour_cells", await hs.count() == 24)
        ok("hour_cursor_pointer", await hs.nth(3).evaluate("e=>getComputedStyle(e).cursor") == "pointer")
        await pg.wait_for_timeout(800)
        ok("hour_activity_markers", await pg.locator('[data-testid^="v3-hour-activity-"]').count() > 0)
        await hs.nth(3).hover()
        await pg.wait_for_selector('[data-testid="v3-day-tooltip"][data-pinned="0"]')
        ok("hour_hover_preview", True)
        before = qp(pg)
        await hs.nth(3).click()
        await pg.wait_for_selector('[data-testid="v3-day-tooltip"][data-pinned="1"]')
        a = qp(pg)
        ok("hour_click_zooms_1h", a.get("t0") and int(a["t1"]) - int(a["t0"]) <= 3_600_000, a)
        await pg.mouse.move(10, 1250)
        await pg.wait_for_timeout(500)
        ok("hour_pinned_stays", await pg.locator('[data-testid="v3-day-tooltip"][data-pinned="1"]').count() == 1)
        await nav.screenshot(path=f"{OUT}/after_04_hour_pinned.png")
        await pg.mouse.click(1000, 1250)
        ok("outside_click_closes", await pg.locator('[data-testid="v3-day-tooltip"]').count() == 0)
        hd = pg.locator('[data-testid="v3-hour-det"]')
        if await hd.count():
            await pg.click('[data-testid="v3-last24"]')
            await pg.wait_for_timeout(800)
            await pg.locator('[data-testid="v3-hour-det"]').first.click()
            await pg.wait_for_function("()=>new URLSearchParams(location.search).get('event')", timeout=15000)
            ok("hour_dot_jumps", "event" in qp(pg))
        # owner clarification: every time link in every day popover
        await pg.goto(B)
        await pg.wait_for_selector('[data-testid^="v3-marker-"]', timeout=45000)
        await pg.wait_for_selector('[data-testid="v3-loading"]', state="detached", timeout=30000)
        days = await pg.eval_on_selector_all('[data-testid^="v3-day-dot-"]', "e=>e.map(x=>x.dataset.testid.slice(11))")
        n_links, seq = 0, 0
        for day in days:
            for i in range(5):
                await pg.click(f'[data-testid="v3-day-cell-{day}"]')
                await pg.wait_for_selector('[data-testid="v3-day-tooltip"][data-pinned="1"]')
                await pg.wait_for_selector('[data-testid="v3-loading"]', state="detached", timeout=30000)
                link = pg.locator(f'[data-testid="v3-tip-jump-{i}"]')
                if not await link.count():
                    await pg.keyboard.press("Escape"); break
                hhmm = (await link.inner_text()).strip()
                prior = qp(pg)
                if seq < 1:
                    await pg.screenshot(path=f"{OUT}/after_seq_1_popover.jpeg", quality=70)
                await link.click()
                await pg.wait_for_selector('[data-testid="v3-hour-det"][data-selected="1"]', timeout=20000)
                await pg.wait_for_selector('[data-testid="v3-loading"]', state="detached", timeout=30000)
                q = qp(pg)
                at = await pg.get_attribute('[data-testid="v3-hour-det"][data-selected="1"]', "data-at")
                ok(f"link_{day}_{i}_dot_time", at[:10] == day and at[11:16] == hhmm, f"{at} vs {day} {hhmm}")
                mk = pg.locator('[data-testid^="v3-marker-"][data-selected="1"]')
                await mk.first.wait_for(timeout=10000)
                ok(f"link_{day}_{i}_grid_marker", await mk.first.get_attribute("data-event-iid") == q.get("event"), q.get("event"))
                dt = await pg.inner_text('[data-testid="v3-details-time"]')
                ok(f"link_{day}_{i}_details", f"{day} {hhmm}" in dt, dt)
                ok(f"link_{day}_{i}_window", int(q["t0"]) <= int(q["t1"]) and int(q["t1"]) - int(q["t0"]) <= 3_600_000, q)
                ok(f"link_{day}_{i}_popover_closed", await pg.locator('[data-testid="v3-day-tooltip"]').count() == 0)
                if seq < 1:
                    await pg.screenshot(path=f"{OUT}/after_seq_2_result.jpeg", quality=70)
                    await nav.screenshot(path=f"{OUT}/after_seq_3_timebar_selected.png")
                await pg.go_back()
                await pg.wait_for_timeout(500)
                b2 = qp(pg)
                ok(f"link_{day}_{i}_back", b2.get("t0") == prior.get("t0") and b2.get("t1") == prior.get("t1") and b2.get("event") == prior.get("event"), (prior, b2))
                n_links += 1; seq += 1
        ok("links_tested", n_links > 0, n_links)
        ok("no_page_errors", not ERR, ERR)
        await b.close()
    print(json.dumps(R, indent=1))
    print("PASS", sum(v["pass"] for v in R.values()), "/", len(R))


asyncio.run(main())
