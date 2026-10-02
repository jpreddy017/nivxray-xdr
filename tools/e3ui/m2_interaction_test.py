"""M2 Playwright: interaction assertions + 2000x1300 acceptance screenshots. Preview shell only; no production contact."""
import asyncio, json, re, sys, urllib.parse as up
from playwright.async_api import async_playwright

D = open("/tmp/shell_dir").read().strip()
HOST = "https://edr-forge-complete.preview.emergentagent.com"
B = f"{HOST}/{D}/index.html"
OUT = "/app/.e3ui-harness/shots_m2"
R, ERR = {}, []


def ok(name, cond, detail=""):
    R[name] = {"pass": bool(cond), "detail": str(detail)[:200]}


def qp(page):
    return dict(up.parse_qsl(up.urlparse(page.url).query))


async def ready(pg, url=B):
    await pg.goto(url)
    await pg.wait_for_selector('[data-testid^="v3-marker-"]', timeout=45000)
    await pg.wait_for_selector('[data-testid="v3-loading"]', state="detached", timeout=30000)


async def shot(pg, name):
    await pg.screenshot(path=f"{OUT}/{name}.jpeg", quality=72)


async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch(executable_path="/usr/bin/chromium", args=["--no-sandbox"])
        ctx = await b.new_context(viewport={"width": 2000, "height": 1300})
        pg = await ctx.new_page()
        pg.on("pageerror", lambda e: ERR.append(str(e)[:300]))
        pg.on("console", lambda m: m.type == "error" and ERR.append(m.text[:200]))
        await ready(pg)
        await shot(pg, "01_full_page")
        ok("markers_render", await pg.locator('[data-testid^="v3-marker-"]').count() > 20)
        ok("shapes_are_disposition", set(await pg.eval_on_selector_all('[data-testid^="v3-marker-"]', "e=>e.map(x=>x.dataset.shape)")) <= {"square", "circle", "hexagon"})
        ok("sticky_section", await pg.locator('[data-testid="v3-sticky-section"]').count() == 1)
        # navigator tooltip
        cells = pg.locator('[data-testid^="v3-day-cell-"]')
        ok("thirty_day_cells", await cells.count() == 30, await cells.count())
        await cells.last.hover()
        await pg.wait_for_selector('[data-testid="v3-day-tooltip"]')
        tip = await pg.inner_text('[data-testid="v3-day-tooltip"]')
        ok("day_tooltip_compromise", "Compromise events" in tip, tip)
        await shot(pg, "02_navigator_day_tooltip")
        await pg.click('[data-testid="v3-tip-jump-0"]')
        await pg.wait_for_selector('[data-testid="v3-activity-details"]', timeout=20000)
        ok("tooltip_time_jumps_to_details", "Detected" in await pg.inner_text('[data-testid="v3-narrative"]'))
        await shot(pg, "05_activity_details_detection")
        ok("severity_badge", (await pg.inner_text('[data-testid="v3-severity"]')) in ("High", "Medium"))
        ok("hash_or_token_interactive", await pg.locator('[data-testid="v3-token"]').count() > 0)
        # back keeps list
        await pg.click('[data-testid="v3-details-back"]')
        ok("back_to_activity_list", await pg.locator('[data-testid="v3-activity"]').is_visible())
        ok("selected_row_kept", await pg.locator('[data-testid^="v3-activity-row-"][data-selected="1"]').count() == 1)
        # grid + activity, execute details
        await ready(pg)
        await shot(pg, "03_grid_and_activity")
        exe = pg.locator('[data-testid^="v3-marker-"][data-glyph="exec"]').first
        await exe.click()
        await pg.wait_for_selector('[data-testid="v3-narrative"]')
        nar = await pg.inner_text('[data-testid="v3-narrative"]')
        ok("execute_narrative", "was Executed by" in nar and "Unknown disposition" in nar, nar[:120])
        ok("selected_column_glow", await pg.locator('[data-testid="v3-selected-column"]').count() == 1)
        ok("event_in_url", "event" in qp(pg))
        await shot(pg, "04_activity_details_execute")
        # hover tooltip
        await pg.locator('[data-testid^="v3-marker-"]').nth(3).hover()
        ok("marker_hover_tooltip", await pg.locator('[data-testid="v3-tooltip"]').count() == 1)
        # return to activity
        grid = pg.locator('[data-testid="v3-grid"]')
        await grid.evaluate("g=>g.scrollLeft=g.scrollWidth")
        await pg.wait_for_timeout(300)
        rta = pg.locator('[data-testid="v3-return-to-activity"]')
        ok("return_to_activity_shown", await rta.count() == 1)
        if await rta.count():
            await rta.click(); await pg.wait_for_timeout(300)
            ok("return_to_activity_recenters", await rta.count() == 0)
        # zoom +/- and wheel
        w0 = await grid.evaluate("g=>g.scrollWidth")
        await pg.click('[data-testid="v3-zin"]'); await pg.wait_for_timeout(200)
        w1 = await grid.evaluate("g=>g.scrollWidth")
        ok("plus_zooms_in", w1 > w0, f"{w0}->{w1}")
        await pg.click('[data-testid="v3-zout"]'); await pg.click('[data-testid="v3-zout"]'); await pg.wait_for_timeout(200)
        ok("minus_zooms_out", await grid.evaluate("g=>g.scrollWidth") < w1)
        box = await grid.bounding_box()
        await pg.mouse.move(box["x"] + 700, box["y"] + 40)
        wb = await grid.evaluate("g=>g.scrollWidth")
        await pg.mouse.wheel(0, -300); await pg.wait_for_timeout(300)
        ok("wheel_zoom_on_header", await grid.evaluate("g=>g.scrollWidth") != wb)
        await pg.click('[data-testid="v3-fit"]'); await pg.wait_for_timeout(300)
        ok("fit_to_evidence", await grid.evaluate("g=>g.scrollWidth <= g.clientWidth + 400"))
        await pg.click('[data-testid="v3-reset"]'); await pg.wait_for_timeout(300)
        # drag pan
        await grid.evaluate("g=>g.scrollLeft=600")
        s0 = await grid.evaluate("g=>g.scrollLeft")
        await pg.mouse.move(box["x"] + 900, box["y"] + 500); await pg.mouse.down()
        await pg.mouse.move(box["x"] + 700, box["y"] + 500, steps=5); await pg.mouse.up()
        ok("drag_pan", await grid.evaluate("g=>g.scrollLeft") > s0, s0)
        # determinism: 3 repeats each of wheel-zoom (header + ctrl over body) and drag-pan
        det = []
        for i in range(3):
            z0 = float(await grid.get_attribute("data-colw"))
            await pg.mouse.move(box["x"] + 800, box["y"] + 40); await pg.mouse.wheel(0, -200); await pg.wait_for_timeout(150)
            z1 = float(await grid.get_attribute("data-colw"))
            await pg.mouse.move(box["x"] + 800, box["y"] + 500); await pg.keyboard.down("Control"); await pg.mouse.wheel(0, 200)
            await pg.keyboard.up("Control"); await pg.wait_for_timeout(150)
            z2 = float(await grid.get_attribute("data-colw"))
            await grid.evaluate("g=>g.scrollLeft=500"); a = await grid.evaluate("g=>g.scrollLeft")
            await pg.mouse.move(box["x"] + 900, box["y"] + 600); await pg.mouse.down()
            await pg.mouse.move(box["x"] + 600, box["y"] + 600, steps=6); await pg.mouse.up()
            c = await grid.evaluate("g=>g.scrollLeft")
            det.append(z1 > z0 and z2 < z1 and c - a >= 250)
        ok("wheel_zoom_and_drag_pan_deterministic_x3", all(det), det)
        # search filters rows
        n_rows = await pg.locator('[data-testid^="v3-row-"]').count()
        await pg.fill('[data-testid="v3-search"]', "upd.exe"); await pg.press('[data-testid="v3-search"]', "Enter"); await pg.wait_for_timeout(400)
        n_hit = await pg.locator('[data-testid^="v3-row-"]').count()
        labels = await pg.eval_on_selector_all('[data-testid^="v3-row-"]', "e=>e.map(x=>x.title.toLowerCase())")
        ok("search_filters_rows", 0 < n_hit < n_rows and any("upd.exe" in t for t in labels), f"{n_rows}->{n_hit}")
        await pg.click('[data-testid="v3-search-clear"]'); await pg.wait_for_timeout(300)
        # expand instances
        exp = pg.locator('[data-testid^="v3-expand-"]').first
        if await exp.count():
            await exp.click(); await pg.wait_for_timeout(200)
            ok("expand_instances", await pg.locator('[data-testid^="v3-subrow-"]').count() > 0)
            await exp.click(); await pg.wait_for_timeout(200)
            ok("collapse_instances", await pg.locator('[data-testid^="v3-subrow-"]').count() == 0)
        # search
        await pg.fill('[data-testid="v3-search"]', "powershell")
        await pg.press('[data-testid="v3-search"]', "Enter"); await pg.wait_for_timeout(500)
        ok("search_in_url", qp(pg).get("q") == "powershell")
        ok("search_count", "results" in await pg.inner_text('[data-testid="v3-search-count"]'))
        ok("search_hit_red_label", await pg.locator('[data-testid="v3-search-hit-label"]').count() > 0)
        await pg.click('[data-testid="v3-search-next"]'); await pg.wait_for_timeout(400)
        ok("search_next_selects", await pg.locator('[data-testid="v3-activity-details"]').count() == 1)
        await shot(pg, "07_search")
        await pg.click('[data-testid="v3-details-back"]')
        await pg.click('[data-testid="v3-search-clear"]'); await pg.wait_for_timeout(400)
        ok("search_clear", "q" not in qp(pg))
        # filters
        await pg.click('[data-testid="v3-filters"]')
        await pg.wait_for_selector('[data-testid="v3-filters-panel"]')
        ok("not_collected_disabled", await pg.locator('[data-testid="v3-filter-copy"] input').is_disabled())
        await shot(pg, "06_filters_panel")
        await pg.click('[data-testid="v3-filter-dns"] input')
        ok("filters_apply_only_on_apply", "f" not in qp(pg))
        await pg.click('[data-testid="v3-filters-apply"]'); await pg.wait_for_timeout(400)
        ok("filters_in_url", "f" in qp(pg))
        ok("filtered_indicator", " of " in await pg.inner_text('[data-testid="v3-filter-indicator"]'))
        await pg.click('[data-testid="v3-filter-reset"]'); await pg.wait_for_timeout(300)
        # context menu + approval
        m = pg.locator('[data-testid^="v3-marker-"][data-glyph="exec"]').first
        await m.click(button="right")
        await pg.wait_for_selector('[data-testid="v3-context-menu"]')
        await shot(pg, "08a_context_menu")
        await pg.click('[data-testid="v3-ctx-QUARANTINE_FILE"]')
        await pg.wait_for_selector('[data-testid="v3-approval-dialog"]')
        await shot(pg, "08b_approval_dialog")
        await pg.click('[data-testid="v3-approval-confirm"]')
        await pg.wait_for_selector('[data-testid="v3-notice"]')
        ok("approval_requested_not_executed", "not executed" in await pg.inner_text('[data-testid="v3-notice"]'))
        # isolate lineage
        await pg.locator('[data-testid^="v3-marker-"][data-glyph="exec"]').nth(2).click(button="right")
        await pg.click('[data-testid="v3-ctx-isolate-lineage"]'); await pg.wait_for_timeout(500)
        ok("isolate_lineage", await pg.locator('[data-testid="v3-isolate-banner"]').count() == 1 and "iso" in qp(pg))
        await shot(pg, "09_isolate_lineage")
        await pg.click('[data-testid="v3-isolate-restore"]'); await pg.wait_for_timeout(300)
        ok("isolate_restore", "iso" not in qp(pg))
        # day click, prev/next/now/last24, back/forward
        await pg.locator('[data-testid^="v3-day-cell-"]').nth(20).click()
        await pg.wait_for_selector('[data-testid="v3-loading"]', state="detached", timeout=30000)
        t0 = qp(pg).get("t0")
        ok("day_click_sets_range", t0 is not None)
        await pg.click('[data-testid="v3-prev"]'); await pg.wait_for_timeout(300)
        ok("prev_shifts", qp(pg).get("t0") != t0)
        await pg.go_back(); await pg.wait_for_timeout(500)
        ok("browser_back_restores", qp(pg).get("t0") == t0)
        await pg.go_forward(); await pg.wait_for_timeout(500)
        ok("browser_forward", qp(pg).get("t0") != t0)
        await pg.click('[data-testid="v3-next"]'); await pg.click('[data-testid="v3-now"]'); await pg.click('[data-testid="v3-last24"]')
        ok("last24_clears_range", "t0" not in qp(pg))
        strip = await pg.locator('[data-testid="v3-hour-strip"]').bounding_box()
        await pg.mouse.move(strip["x"] + strip["width"] * 0.10, strip["y"] + 10); await pg.mouse.down()
        await pg.mouse.move(strip["x"] + strip["width"] * 0.25, strip["y"] + 10, steps=6); await pg.mouse.up()
        await pg.wait_for_timeout(300)
        ok("hour_strip_drag_range", "t0" in qp(pg))
        # load older
        await pg.click('[data-testid="v3-last24"]')
        await pg.wait_for_selector('[data-testid="v3-loading"]', state="detached", timeout=30000)
        c0 = await pg.inner_text('[data-testid="v3-loaded-count"]')
        await pg.click('[data-testid="v3-load-older"]')
        await pg.wait_for_timeout(2500)
        ok("load_older", await pg.inner_text('[data-testid="v3-loaded-count"]') != c0)
        # debug drawer hidden by default
        ok("debug_hidden_default", await pg.locator('[data-testid="v3-debug-drawer"]').count() == 0)
        await pg.click('[data-testid="v3-debug-toggle"]')
        ok("debug_drawer_opens", await pg.locator('[data-testid="v3-debug-drawer"]').count() == 1)
        # deep links
        cases = json.loads(await (await pg.request.get(f"{HOST}/api/e3/preview/deeplink-cases")).text())
        for name, eid in cases.items():
            await pg.goto(f"{B}?device=dev_f22d20b97b6d&event={eid.replace('#', '%23')}")
            try:
                await pg.wait_for_selector('[data-testid="v3-activity-details"], [data-testid="v3-deeplink-state"]:has-text("not found")', timeout=30000)
            except Exception:
                pass
            got = await pg.locator('[data-testid="v3-activity-details"]').count() == 1
            ok(f"deeplink_{name}", got if name != "nonexistent" else not got)
        await shot(pg, "10_deeplink_nonexistent")
        # linux + mac devices
        for dev, tag in (("dev_syn_lnx01", "ELF"), ("dev_fix_mac01", "MachO")):
            await pg.goto(f"{B}?device={dev}&t0=1&t1=9999999999999")
            await pg.wait_for_selector('[data-testid^="v3-marker-"]', timeout=30000)
            types = await pg.eval_on_selector_all('[data-testid^="v3-row-"]', "e=>[...new Set(e.map(x=>x.dataset.rowType))]")
            ok(f"{dev}_{tag}_rows", tag in types, types)
            await shot(pg, f"11_{dev}")
        # light theme toggle
        await ready(pg)
        await pg.get_by_role("button", name="Light").click(); await pg.wait_for_timeout(400)
        ok("light_toggle", await pg.evaluate("getComputedStyle(document.querySelector('.v3amp')).getPropertyValue('--v3-page').trim()") == "#f3f4f6")
        await shot(pg, "12_light_theme")
        await pg.get_by_role("button", name="Dark").click()
        R["console_errors"] = ERR[:10]
        await b.close()
    json.dump(R, open(f"{OUT}/results.json", "w"), indent=1)
    fails = {k: v for k, v in R.items() if isinstance(v, dict) and not v["pass"]}
    print(f"{sum(1 for v in R.values() if isinstance(v, dict) and v['pass'])} pass / {len(fails)} fail")
    print(json.dumps(fails, indent=1)[:3000]); print("errors", ERR[:5])

asyncio.run(main())
