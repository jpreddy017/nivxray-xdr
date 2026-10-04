"""Owner UI pass: sidebar rail collapse, Activity divider, M2 partials. Preview shell only; no production contact."""
import asyncio, json
from playwright.async_api import async_playwright

D = open("/tmp/shell_dir").read().strip()
HOST = "https://edr-forge-complete.preview.emergentagent.com"
B = f"{HOST}/{D}/index.html"
OUT = "/app/.e3ui-harness/shots_ui3"
R, ERR = {}, []


def ok(name, cond, detail=""):
    R[name] = {"pass": bool(cond), "detail": str(detail)[:200]}


async def ready(pg, url=B):
    await pg.goto(url)
    await pg.wait_for_selector('[data-testid^="v3-marker-"]', timeout=45000)
    await pg.wait_for_selector('[data-testid="v3-loading"]', state="detached", timeout=30000)
    await pg.wait_for_timeout(300)


async def widths(pg):
    return await pg.evaluate("""() => ({ side: document.querySelector('[data-testid="nvf-sidebar"]').getBoundingClientRect().width,
      grid: document.querySelector('[data-testid="v3-grid"]').clientWidth,
      sticky: document.querySelector('[data-testid="v3-sticky-section"]')?.getBoundingClientRect().width,
      panel: document.querySelector('[data-testid="v3-activity-panel"]').getBoundingClientRect().width,
      ws: document.querySelector('[data-testid="v3-workspace"]').clientWidth })""")


async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch(executable_path="/usr/bin/chromium", args=["--no-sandbox"])
        for vw, vh in ((2000, 1300), (1440, 900)):
            ctx = await b.new_context(viewport={"width": vw, "height": vh})
            pg = await ctx.new_page()
            pg.on("pageerror", lambda e: ERR.append(str(e)[:300]))
            tag = f"{vw}x{vh}"
            await ready(pg)
            await pg.evaluate("localStorage.removeItem('nvx.sidebar.collapsed'); sessionStorage.removeItem('nvx.dt.panelW')")
            await ready(pg)
            w0 = await widths(pg)
            ok(f"{tag}_expanded_labels", await pg.locator('[data-testid="nvf-sidebar"] .nav-title').count() == 4 and await pg.locator('[data-testid="nvf-brand-wordmark"]').count() == 1)
            ok(f"{tag}_panel_default_336", abs(w0["panel"] - 336) <= 1, w0)
            tg = pg.locator('[data-testid="nvf-sidebar-toggle"]')
            ok(f"{tag}_toggle_aria_expanded_true", await tg.get_attribute("aria-expanded") == "true")
            await pg.screenshot(path=f"{OUT}/{tag}_expanded.jpeg", quality=72)
            await tg.click(); await pg.wait_for_timeout(450)
            w1 = await widths(pg)
            ok(f"{tag}_rail_width_60_68", 60 <= w1["side"] <= 68, w1["side"])
            ok(f"{tag}_toggle_aria_expanded_false", await tg.get_attribute("aria-expanded") == "false")
            ok(f"{tag}_all_icons_visible", await pg.locator('[data-testid="nvf-sidebar"] .nav-item .ic svg').count() == 17)
            ok(f"{tag}_labels_hidden", await pg.locator('[data-testid="nvf-sidebar"] .nav-title').count() == 0 and await pg.locator('[data-testid="nvf-nav-sep"]').count() == 3)
            ok(f"{tag}_n_mark_only", await pg.locator('[data-testid="nvf-brand-wordmark"]').count() == 0)
            act = pg.locator('[data-testid="nvf-nav-device-trajectory"]')
            ok(f"{tag}_active_kept_with_accent", await act.get_attribute("data-active") == "true"
               and await act.evaluate("e=>getComputedStyle(e).borderLeftColor") != "rgba(0, 0, 0, 0)")
            ok(f"{tag}_grid_relayout_wider", w1["grid"] > w0["grid"] + 200, f'{w0["grid"]}->{w1["grid"]}')
            ok(f"{tag}_no_stale_width", abs((w1["sticky"] or 0) - w1["grid"]) <= 12, w1)
            await pg.hover('[data-testid="nvf-nav-hunting"]')
            ok(f"{tag}_ni_tooltip", (await pg.inner_text('[data-testid="nvf-rail-tooltip"]')) == "Hunt — not implemented")
            ok(f"{tag}_ni_not_clickable", await pg.locator('[data-testid="nvf-nav-hunting"]').get_attribute("aria-disabled") == "true")
            await pg.hover('[data-testid="nvf-nav-detections"]')
            ok(f"{tag}_tooltip_hover", (await pg.inner_text('[data-testid="nvf-rail-tooltip"]')) == "Detections")
            await pg.mouse.move(vw / 2, vh / 2)
            await pg.focus('[data-testid="nvf-nav-events"]')
            ok(f"{tag}_tooltip_focus", (await pg.inner_text('[data-testid="nvf-rail-tooltip"]')) == "Events")
            await pg.screenshot(path=f"{OUT}/{tag}_collapsed.jpeg", quality=72)
            await ready(pg, pg.url)
            ok(f"{tag}_collapsed_persists_reload", await pg.locator('[data-testid="nvf-sidebar"]').get_attribute("data-collapsed") == "1")
            await pg.keyboard.press("Tab")
            await pg.focus('[data-testid="nvf-sidebar-toggle"]'); await pg.keyboard.press("Enter"); await pg.wait_for_timeout(450)
            ok(f"{tag}_keyboard_expand", await pg.locator('[data-testid="nvf-sidebar"]').get_attribute("data-collapsed") == "0")
            # divider drag + clamps
            dv = await pg.locator('[data-testid="v3-panel-divider"]').bounding_box()
            await pg.mouse.move(dv["x"] + 3, dv["y"] + 200); await pg.mouse.down(); await pg.mouse.move(dv["x"] + 600, dv["y"] + 200, steps=6); await pg.mouse.up()
            wmin = await widths(pg)
            ok(f"{tag}_divider_clamp_min_320", abs(wmin["panel"] - 320) <= 1, wmin["panel"])
            await pg.screenshot(path=f"{OUT}/{tag}_divider_min.jpeg", quality=72)
            dv = await pg.locator('[data-testid="v3-panel-divider"]').bounding_box()
            await pg.mouse.move(dv["x"] + 3, dv["y"] + 200); await pg.mouse.down(); await pg.mouse.move(dv["x"] - 1500, dv["y"] + 200, steps=8); await pg.mouse.up()
            wmax = await widths(pg)
            ok(f"{tag}_divider_clamp_max_40pct", abs(wmax["panel"] - max(320, int(wmax["ws"] * 0.4))) <= 2 and wmax["grid"] > 300, wmax)
            await pg.screenshot(path=f"{OUT}/{tag}_divider_max.jpeg", quality=72)
            await ready(pg, pg.url)
            ok(f"{tag}_panel_width_session_persist", abs((await widths(pg))["panel"] - wmax["panel"]) <= 2)
            await pg.focus('[data-testid="v3-panel-divider"]'); await pg.keyboard.press("ArrowRight"); await pg.wait_for_timeout(100)
            ok(f"{tag}_divider_keyboard", (await widths(pg))["panel"] < wmax["panel"])
            # maximum workspace mode
            await pg.click('[data-testid="v3-workspace-mode"]'); await pg.wait_for_timeout(450)
            wm = await widths(pg)
            ok(f"{tag}_max_workspace_mode", wm["side"] <= 68 and abs(wm["panel"] - 320) <= 1, wm)
            await pg.click('[data-testid="v3-workspace-mode"]'); await pg.wait_for_timeout(450)
            ok(f"{tag}_standard_mode", (await widths(pg))["side"] > 100)
            await ctx.close()
        ctx = await b.new_context(viewport={"width": 2000, "height": 1300})
        pg = await ctx.new_page()
        await ready(pg)
        # long command line wraps in Activity Details
        await pg.fill('[data-testid="v3-search"]', "powershell.exe"); await pg.press('[data-testid="v3-search"]', "Enter"); await pg.wait_for_timeout(500)
        await pg.click('[data-testid="v3-search-next"]'); await pg.wait_for_selector('[data-testid="v3-activity-details"]')
        nar = await pg.inner_text('[data-testid="v3-narrative"]')
        await pg.click('[data-testid="v3-evidence"] summary')
        ov = await pg.evaluate("(()=>{const d=document.querySelector('[data-testid=\"v3-activity-details\"]');return d.scrollWidth-d.clientWidth})()")
        ok("details_long_cmdline_wraps_no_overflow", "Command line" in nar and ov <= 1, f"overflow={ov}")
        await pg.screenshot(path=f"{OUT}/details_long_cmdline_wrap.jpeg", quality=72)
        # partials: 18px sections, no-data hatch, glyph legend
        fs = await pg.evaluate("getComputedStyle(document.querySelector('[data-testid=\"v3-sticky-section\"] span')).fontSize")
        ok("section_text_18px", fs == "18px", fs)
        await pg.click('[data-testid="v3-search-clear"]')
        await pg.locator('[data-testid^="v3-day-cell-"]').nth(25).click()
        await pg.wait_for_selector('[data-testid="v3-loading"]', state="detached", timeout=30000)
        await pg.wait_for_timeout(800)
        nd = await pg.locator('[data-testid="v3-nodata-hour"]').count()
        h = json.loads(await (await pg.request.get(f"{HOST}/api/edr/endpoints/dev_f22d20b97b6d/trajectory/hours?day=" +
                       (await pg.locator('[data-testid^="v3-day-cell-"]').nth(25).get_attribute("data-testid"))[12:])).text())
        ok("nodata_hours_match_coverage", nd == sum(1 for n in h["hours"] if n == 0), f"{nd} vs {h['hours']}")
        await pg.click('[data-testid="v3-legend-toggle"]')
        ok("legend_exec_blocked_and_audit_eye", await pg.locator('[data-testid="v3-glyph-exec-blocked"]').count() >= 1 and await pg.locator('[data-testid="v3-flag-audit"]').count() == 1)
        await pg.screenshot(path=f"{OUT}/legend_and_nodata_hatch.jpeg", quality=72)
        await pg.click('[data-testid="v3-legend-toggle"]')
        await pg.click('[data-testid="v3-filters"]')
        ok("filters_still_not_collected", await pg.locator('[data-testid="v3-filter-exec_blocked"] input').is_disabled() and await pg.locator('[data-testid="v3-filter-f_audit"] input').is_disabled())
        await b.close()
    R["page_errors"] = ERR[:10]
    json.dump(R, open(f"{OUT}/results.json", "w"), indent=1)
    fails = {k: v for k, v in R.items() if isinstance(v, dict) and not v["pass"]}
    print(f"{sum(1 for v in R.values() if isinstance(v, dict) and v['pass'])} pass / {len(fails)} fail")
    print(json.dumps(fails, indent=1)[:3000]); print("errors", ERR[:5])

asyncio.run(main())
