"""Search bar, device Actions (approval-only), Isolation chip, Details drawer, Product/Version narrative. Preview shell only."""
import asyncio, json, os, sys, urllib.parse as up
from playwright.async_api import async_playwright

HOST = "https://edr-forge-complete.preview.emergentagent.com"
D = sys.argv[1] if len(sys.argv) > 1 else open("/tmp/shell_dir").read().strip()
B = f"{HOST}/{D}/index.html"
OUT = "/app/.e3ui-harness/shots_actions"
R, ERR = {}, []


def ok(n, c, d=""):
    R[n] = {"pass": bool(c), "detail": str(d)[:200]}


async def main():
    os.makedirs(OUT, exist_ok=True)
    async with async_playwright() as p:
        b = await p.chromium.launch(executable_path="/usr/bin/chromium", args=["--no-sandbox"])
        pg = await (await b.new_context(viewport={"width": 2000, "height": 1300})).new_page()
        pg.on("pageerror", lambda e: ERR.append(str(e)[:300]))
        await pg.goto(B)
        await pg.wait_for_selector('[data-testid^="v3-marker-"]', timeout=45000)
        await pg.wait_for_selector('[data-testid="v3-loading"]', state="detached", timeout=30000)
        # search
        ok("search_icon", await pg.locator('[data-testid="v3-search-icon"]').count() == 1)
        ok("no_clear_when_empty", await pg.locator('[data-testid="v3-search-clear"]').count() == 0)
        await pg.fill('[data-testid="v3-search"]', "powershell")
        ok("clear_visible_while_typing", await pg.locator('[data-testid="v3-search-clear"]').count() == 1)
        await pg.press('[data-testid="v3-search"]', "Enter")
        await pg.wait_for_selector('[data-testid="v3-search-count"]')
        cnt = await pg.inner_text('[data-testid="v3-search-count"]')
        ok("result_count_text", cnt.endswith("result") or cnt.endswith("results"), cnt)
        await pg.screenshot(path=f"{OUT}/01_search_hits.jpeg", quality=70)
        await pg.fill('[data-testid="v3-search"]', "zz-no-such-thing-qq")
        await pg.press('[data-testid="v3-search"]', "Enter")
        await pg.wait_for_selector('[data-testid="v3-search-empty"]', timeout=10000)
        em = await pg.inner_text('[data-testid="v3-search-empty"]')
        ok("empty_state_text", "No events match" in em and "zz-no-such-thing-qq" in em, em)
        ok("zero_results_count", (await pg.inner_text('[data-testid="v3-search-count"]')).startswith("0 results"))
        await pg.screenshot(path=f"{OUT}/02_search_empty.jpeg", quality=70)
        await pg.click('[data-testid="v3-search-clear"]')
        await pg.wait_for_timeout(400)
        ok("clear_resets", await pg.input_value('[data-testid="v3-search"]') == "" and "q=" not in pg.url
           and await pg.locator('[data-testid="v3-search-empty"]').count() == 0)
        # actions menu
        chip = pg.locator('[data-testid="v3-isolation-chip"]')
        ok("isolation_chip", await chip.count() == 1, await chip.inner_text())
        await pg.click('[data-testid="v3-actions"]')
        await pg.wait_for_selector('[data-testid="dt-device-actions-menu"]')
        menu = await pg.inner_text('[data-testid="dt-device-actions-menu"]')
        for w in ["Events", "Process Tree", "Campaign Story", "Live Query", "View Changes", "Take Forensic Snapshot", "Start Isolation", "Scan", "Diagnose Sensor", "Move to Group"]:
            ok(f"menu_has_{w.replace(' ', '_')}", w in menu, menu)
        ok("pivot_chevrons", menu.count("›") >= 5)
        await pg.screenshot(path=f"{OUT}/03_actions_menu.jpeg", quality=70)
        await pg.click('[data-testid="v3-ctx-ISOLATE_DEVICE"]')
        await pg.wait_for_selector('[data-testid="v3-approval-dialog"]')
        ok("dialog_approval_only", "request" in (await pg.inner_text('[data-testid="v3-approval-dialog"]')))
        await pg.click('[data-testid="v3-approval-confirm"]')
        await pg.wait_for_selector('[data-testid="dt-approval-result"]', timeout=10000)
        res = await pg.inner_text('[data-testid="dt-approval-result"]')
        ok("approval_requested_state", "APPROVAL_REQUESTED" in res and "not executed" in res, res)
        ok("chip_requested", await chip.get_attribute("data-state") == "REQUESTED_ISOLATE_DEVICE", await chip.inner_text())
        await pg.screenshot(path=f"{OUT}/04_isolation_requested.jpeg", quality=70)
        await pg.click('[data-testid="v3-actions"]')
        await pg.wait_for_selector('[data-testid="v3-ctx-STOP_ISOLATION"]')
        ok("stop_isolation_offered", True)
        await pg.click('[data-testid="v3-ctx-MOVE_TO_GROUP"]')
        await pg.wait_for_selector('[data-testid="v3-approval-group"]')
        ok("move_group_needs_name", await pg.is_disabled('[data-testid="v3-approval-confirm"]'))
        await pg.fill('[data-testid="v3-approval-group"]', "Quarantine-Hosts")
        await pg.click('[data-testid="v3-approval-confirm"]')
        await pg.wait_for_selector('[data-testid="dt-approval-result"]')
        await pg.click('[data-testid="v3-actions"]')
        await pg.click('[data-testid="v3-ctx-dev-events"]')
        await pg.wait_for_selector('[data-testid="v3-notice"]')
        ok("pivot_notice", "Events" in await pg.inner_text('[data-testid="v3-notice"]'))
        # details drawer
        await pg.click('[data-testid="v3-show-details"]')
        await pg.wait_for_selector('[data-testid="v3-details-pop"]')
        dp = await pg.inner_text('[data-testid="v3-details-pop"]')
        ok("details_sensor_label", "Sensor version" in dp and "Connector" not in dp, dp)
        lt = await pg.inner_text('[data-testid="v3-details-row-last-telemetry"]')
        ok("details_utc", "UTC" in lt or "not collected" in lt, lt)
        ok("details_related_events", "Related compromise events" in dp)
        await pg.screenshot(path=f"{OUT}/05_details.jpeg", quality=70)
        if await pg.locator('[data-testid="v3-details-det-0"]').count():
            await pg.click('[data-testid="v3-details-det-0"]')
            await pg.wait_for_function("()=>new URLSearchParams(location.search).get('event')", timeout=15000)
            await pg.wait_for_selector('[data-testid="v3-activity-details"]', timeout=20000)
            ok("details_event_jumps", True)
            nar = await pg.inner_text('[data-testid="v3-narrative"]')
            ok("narrative_product_version", "Product:" in nar and "Version:" in nar, nar)
            await pg.screenshot(path=f"{OUT}/06_narrative.jpeg", quality=70)
        ok("no_page_errors", not ERR, ERR)
        await b.close()
    print(json.dumps({k: v for k, v in R.items() if not v["pass"]}, indent=1))
    print("PASS", sum(v["pass"] for v in R.values()), "/", len(R))


asyncio.run(main())
