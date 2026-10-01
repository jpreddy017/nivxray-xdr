"""Frontend-only tests for XDR X1 (context bar / IA), X2 (search), X3 (linked incidents / pivots)."""
import asyncio, os, json

BASE = "https://greeting-app-5782.preview.emergentagent.com"

async def login(page, email, password):
    await page.goto(f"{BASE}/login", wait_until="domcontentloaded")
    await page.wait_for_load_state("networkidle")
    await page.fill('input[type="email"], input[name="email"]', email)
    await page.fill('input[type="password"], input[name="password"]', password)
    await page.click('button[type="submit"]')
    await page.wait_for_load_state("networkidle")
    await page.wait_for_timeout(1500)

async def logout(page):
    # try clicking a logout affordance; fallback to clearing storage
    await page.goto(f"{BASE}/logout", wait_until="domcontentloaded")
    await page.evaluate("() => { try { localStorage.clear(); sessionStorage.clear(); } catch(e){} }")
    await page.context.clear_cookies()

async def get_attr(page, sel, attr):
    el = await page.query_selector(sel)
    if not el: return None
    return await el.get_attribute(attr)

async def text_of(page, sel):
    el = await page.query_selector(sel)
    if not el: return None
    return (await el.text_content() or "").strip()

results = []
def rec(name, ok, detail=""):
    results.append({"test": name, "status": "PASS" if ok else "FAIL", "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'} :: {name} :: {detail[:400]}")

console_errors = []

async def attach_console(page, label):
    def handler(msg):
        if msg.type == "error":
            console_errors.append(f"[{label}] {msg.text[:300]}")
    page.on("console", handler)

async def run():
    from playwright.async_api import async_playwright
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        ctx = await browser.new_context(viewport={"width":1600,"height":1000})
        page = await ctx.new_page()
        await attach_console(page, "admin")

        # ===== ADMIN LOGIN =====
        await login(page, "admin@nivxray.com", "uulVDp5cCSB3Hva99s7UUAwK")

        # ===== TEST 1: Context bar on all pages =====
        pages_to_check = [
            ("/xdr/incidents", "NIVXRAY_XDR"),
            ("/xdr/search?q=bash", "NIVXRAY_XDR"),
            ("/xdr/endpoints", "NIVXRAY_XDR"),
            ("/xdr/edr/device-trajectory?device=dev_42e8c6dc74b9", "NIVXFORGE_EDR"),
        ]
        for path, expected_plane in pages_to_check:
            try:
                await page.goto(f"{BASE}{path}", wait_until="domcontentloaded")
                await page.wait_for_load_state("networkidle")
                if "device-trajectory" in path:
                    await page.wait_for_timeout(16000)
                else:
                    await page.wait_for_timeout(2500)
                bar = await page.query_selector('[data-testid="xdr-context-bar"]')
                bc = await text_of(page, '[data-testid="xdr-breadcrumbs"]')
                cust = await text_of(page, '[data-testid="xdr-ctx-customer"]')
                plane = await get_attr(page, '[data-testid="xdr-context-bar"]', 'data-plane')
                ok = bar is not None and bc and bc.startswith("NivXRay XDR") and cust and "ALL CUSTOMERS" in cust and plane == expected_plane
                detail = f"bar={bar is not None} bc='{bc}' cust='{cust}' plane={plane} expected={expected_plane}"
                if "device-trajectory" in path and "Device Trajectory" not in (bc or ""):
                    ok = False
                    detail += " (missing 'Device Trajectory' in breadcrumb)"
                if "endpoints" in path and "Endpoints" not in (bc or ""):
                    detail += " (endpoints breadcrumb: check)"
                rec(f"X1 context bar on {path}", ok, detail)
            except Exception as e:
                rec(f"X1 context bar on {path}", False, str(e))

        # ===== TEST 2: Context chips on pivot =====
        try:
            url = f"{BASE}/xdr/edr/device-trajectory?device=dev_42e8c6dc74b9&raw_event_id=raw_fac9185acde4f8ccebef7a3b&incident_id=inc_2305c71cd8f54dc38e55"
            await page.goto(url, wait_until="domcontentloaded")
            await page.wait_for_timeout(16000)
            data_device = await get_attr(page, '[data-testid="xdr-context-bar"]', 'data-device')
            data_inc = await get_attr(page, '[data-testid="xdr-context-bar"]', 'data-incident')
            ep = await page.query_selector('[data-testid="xdr-ctx-endpoint"]')
            inc_chip = await page.query_selector('[data-testid="xdr-ctx-incident"]')
            ev_chip = await page.query_selector('[data-testid="xdr-ctx-evidence"]')
            plane_chip = await page.query_selector('[data-testid="xdr-ctx-plane"]')
            all_present = all([ep, inc_chip, ev_chip, plane_chip])
            ok = data_device == "dev_42e8c6dc74b9" and data_inc == "inc_2305c71cd8f54dc38e55" and all_present
            detail = f"data-device={data_device} data-incident={data_inc} chips ep={bool(ep)} inc={bool(inc_chip)} ev={bool(ev_chip)} plane={bool(plane_chip)}"
            rec("X1 pivot context chips", ok, detail)
            # click incident chip
            if inc_chip:
                await inc_chip.click()
                await page.wait_for_timeout(2500)
                cur = page.url
                nav_ok = "/xdr/incidents/inc_2305c71cd8f54dc38e55" in cur
                rec("X1 incident chip navigates", nav_ok, f"url={cur}")
        except Exception as e:
            rec("X1 pivot context chips", False, str(e))

        # ===== TEST 3: Capability-honest IA =====
        ia_targets = [
            ("xdr-nav-assets-identity", "Assets: Identity"),
            ("xdr-nav-assets-network", "Assets: Network"),
            ("xdr-nav-attack-paths", "Attack Paths"),
            ("xdr-nav-critical-assets", "Critical Assets"),
        ]
        try:
            await page.goto(f"{BASE}/xdr/incidents", wait_until="domcontentloaded")
            await page.wait_for_timeout(2500)
            for tid, label in ia_targets:
                try:
                    sel = f'[data-testid="{tid}"]'
                    btn = await page.query_selector(sel)
                    if not btn:
                        # try opening sidebar
                        tog = await page.query_selector('[data-testid="xdr-sidebar-toggle"]')
                        if tog:
                            await tog.click()
                            await page.wait_for_timeout(500)
                        btn = await page.query_selector(sel)
                    if not btn:
                        rec(f"X1 IA nav {tid}", False, "nav item not found")
                        continue
                    await btn.click()
                    await page.wait_for_timeout(2000)
                    ni_el = await page.query_selector('[data-testid^="xdr-not-implemented-"]')
                    cap_state = await text_of(page, '[data-testid="xdr-capability-state"]')
                    ok = ni_el is not None and cap_state and "NOT_IMPLEMENTED" in cap_state
                    rec(f"X1 IA {tid} NOT_IMPLEMENTED", ok, f"present={ni_el is not None} state='{cap_state}' url={page.url}")
                except Exception as e:
                    rec(f"X1 IA {tid}", False, str(e))
        except Exception as e:
            rec("X1 IA nav suite", False, str(e))

        # ===== TEST 4: Global search from top bar =====
        try:
            await page.goto(f"{BASE}/xdr/incidents", wait_until="domcontentloaded")
            await page.wait_for_timeout(2000)
            search = await page.query_selector('[data-testid="xdr-topbar-search"]')
            if not search:
                rec("X2 topbar search present", False, "xdr-topbar-search not found")
            else:
                await search.fill("EDR-LNX-002")
                await search.press("Enter")
                await page.wait_for_timeout(3000)
                cur = page.url
                url_ok = "/xdr/search" in cur and "EDR-LNX-002" in cur
                results_el = await page.query_selector('[data-testid="xdr-search-results"]')
                data_state = await get_attr(page, '[data-testid="xdr-search-results"]', 'data-state')
                total_str = await get_attr(page, '[data-testid="xdr-search-results"]', 'data-total')
                total = int(total_str) if total_str and total_str.isdigit() else 0
                classif = await text_of(page, '[data-testid="xdr-search-classification"]')
                grp_inc = await page.query_selector('[data-testid="xdr-search-group-INCIDENT"]')
                grp_det = await page.query_selector('[data-testid="xdr-search-group-DETECTION"]')
                ok = url_ok and data_state == "RESULTS" and total >= 14 and classif and "RULE_ID" in classif and grp_inc and grp_det
                rec("X2 search EDR-LNX-002 results", ok,
                    f"url={cur} state={data_state} total={total} classif={classif} inc={bool(grp_inc)} det={bool(grp_det)}")
                # click a DETECTION result
                if grp_det:
                    link = await grp_det.query_selector('a, button, [data-testid^="xdr-search-result-"]')
                    if link:
                        await link.click()
                        await page.wait_for_timeout(16000)
                        handoff = await text_of(page, '[data-testid="amp-handoff-resolved"]')
                        rec("X2 DETECTION opens trajectory + handoff", bool(handoff), f"handoff='{handoff[:200] if handoff else None}'")
        except Exception as e:
            rec("X2 top bar search", False, str(e))

        # ===== TEST 5: Other search terms and honesty =====
        async def do_search(q):
            await page.goto(f"{BASE}/xdr/search?q={q}", wait_until="domcontentloaded")
            await page.wait_for_timeout(3500)

        try:
            # endpoint term
            await do_search("agent-env-630704a1")
            grp_ep = await page.query_selector('[data-testid="xdr-search-group-ENDPOINT"]')
            rec("X2 search endpoint term has ENDPOINT group", bool(grp_ep), f"grp={bool(grp_ep)}")

            # incident term
            await do_search("INC000000293")
            grp_inc = await page.query_selector('[data-testid="xdr-search-group-INCIDENT"]')
            total = await get_attr(page, '[data-testid="xdr-search-results"]', 'data-total')
            rec("X2 search INC000000293", bool(grp_inc), f"grp={bool(grp_inc)} total={total}")

            # no match
            await do_search("zzz-no-such-entity-zzz")
            state = await get_attr(page, '[data-testid="xdr-search-results"]', 'data-state')
            nm = await text_of(page, '[data-testid="xdr-search-no-match"]')
            ok = state == "NO_MATCH" and nm and ("absence" in nm.lower() or "not proof" in nm.lower() or "not a record" in nm.lower())
            rec("X2 NO_MATCH honesty", ok, f"state={state} no_match_text='{(nm or '')[:200]}'")

            # not searchable listing
            ns_el = await page.query_selector('[data-testid="xdr-search-not-searchable"]')
            if ns_el:
                # try expanding if it's a details/summary
                try:
                    await ns_el.click()
                    await page.wait_for_timeout(500)
                except Exception:
                    pass
                html = await ns_el.inner_html()
                cnt = html.count("NOT_SEARCHABLE_NO_INDEX")
                rec("X2 not-searchable lists >=7 entity types", cnt >= 7, f"count={cnt}")
            else:
                rec("X2 not-searchable region present", False, "xdr-search-not-searchable missing")
        except Exception as e:
            rec("X2 other terms", False, str(e))

        # ===== TEST 6: Linked XDR Incidents in EDR =====
        try:
            await page.goto(f"{BASE}/xdr/edr/device-trajectory?device=dev_42e8c6dc74b9", wait_until="domcontentloaded")
            await page.wait_for_timeout(16000)
            toggle = await page.query_selector('[data-testid="edr-linked-xdr-toggle"]')
            count = await get_attr(page, '[data-testid="edr-linked-xdr-toggle"]', 'data-count')
            state = await get_attr(page, '[data-testid="edr-linked-xdr-toggle"]', 'data-state')
            ok_t = toggle is not None and count == "4" and state == "LINKED"
            rec("X3 linked-xdr toggle count=4 LINKED", ok_t, f"count={count} state={state}")
            if toggle:
                await toggle.click()
                await page.wait_for_timeout(1500)
                menu = await page.query_selector('[data-testid="edr-linked-xdr-menu"]')
                if menu:
                    txt = await menu.text_content() or ""
                    has_all = all(x in txt for x in ["INC000000293","INC000000232","INC000000231","INC000000230"])
                    rec("X3 linked-xdr menu lists 4 incidents", has_all, f"contains 4 nums={has_all}")
                    # click INC000000293 entry
                    item = await menu.query_selector('a, button')
                    if item:
                        await item.click()
                        await page.wait_for_timeout(2500)
                        rec("X3 linked-xdr click navigates", "/xdr/incidents/" in page.url, f"url={page.url}")
                else:
                    rec("X3 linked-xdr menu opens", False, "menu not present after toggle")
        except Exception as e:
            rec("X3 linked-xdr", False, str(e))

        # ===== TEST 7: Regression handoff + attribution =====
        try:
            await page.goto(f"{BASE}/edr/detections?endpoint_id=ep_2d57cbe6f80152062109", wait_until="domcontentloaded")
            await page.wait_for_timeout(4000)
            links = await page.query_selector_all('[data-testid^="edr-detection-trajectory-"]')
            if not links:
                rec("X3 regression handoff link found", False, "no edr-detection-trajectory-* links")
            else:
                first = links[0]
                tid = await first.get_attribute("data-testid")
                raw_id = tid.replace("edr-detection-trajectory-","") if tid else ""
                await first.click()
                await page.wait_for_timeout(16000)
                handoff = await text_of(page, '[data-testid="amp-handoff-resolved"]')
                det = await page.query_selector('[data-testid="amp-detection-record"]')
                ok = handoff and raw_id in handoff and ("rule" in handoff.lower()) and ("verdict" in handoff.lower()) and det is not None
                rec("X3 regression handoff + attribution", ok, f"raw={raw_id} handoff='{(handoff or '')[:200]}' det={bool(det)}")
        except Exception as e:
            rec("X3 regression handoff", False, str(e))

        # ===== TEST 8: Tenant isolation as analyst =====
        await ctx.close()
        ctx2 = await browser.new_context(viewport={"width":1600,"height":1000})
        page2 = await ctx2.new_page()
        await attach_console(page2, "analyst")
        await login(page2, "analyst@nivx-live.com", "NivxLive!Analyst2026")
        try:
            await page2.goto(f"{BASE}/xdr/search?q=agent-env-630704a1", wait_until="domcontentloaded")
            await page2.wait_for_timeout(4000)
            body = (await page2.text_content("body")) or ""
            grp_ep = await page2.query_selector('[data-testid="xdr-search-group-ENDPOINT"]')
            grp_det = await page2.query_selector('[data-testid="xdr-search-group-DETECTION"]')
            grp_ev = await page2.query_selector('[data-testid="xdr-search-group-EVIDENCE"]')
            no_hostname = "agent-env-630704a1" not in body
            ok = not grp_ep and not grp_det and not grp_ev and no_hostname
            rec("Tenant iso: search cross-tenant has no results", ok,
                f"ep={bool(grp_ep)} det={bool(grp_det)} ev={bool(grp_ev)} host_hidden={no_hostname}")
        except Exception as e:
            rec("Tenant iso search", False, str(e))

        try:
            await page2.goto(f"{BASE}/xdr/edr/device-trajectory?device=dev_42e8c6dc74b9", wait_until="domcontentloaded")
            await page2.wait_for_timeout(16000)
            state = await get_attr(page2, '[data-testid="amp-handoff-state"]', 'data-state')
            toggle = await page2.query_selector('[data-testid="edr-linked-xdr-toggle"]')
            # menu should not have content
            menu_content = None
            if toggle:
                await toggle.click()
                await page2.wait_for_timeout(1000)
                menu = await page2.query_selector('[data-testid="edr-linked-xdr-menu"]')
                if menu:
                    menu_content = (await menu.text_content() or "").strip()
            body = (await page2.text_content("body")) or ""
            hidden = "inc_2305c71cd8f54dc38e55" not in body and "INC000000293" not in body
            ok = state == "ENDPOINT_NOT_RESOLVED" or hidden
            rec("Tenant iso: trajectory ENDPOINT_NOT_RESOLVED / no linked-incident content", ok,
                f"handoff_state={state} menu_content='{(menu_content or '')[:120]}' hidden={hidden}")
        except Exception as e:
            rec("Tenant iso trajectory", False, str(e))

        try:
            cust = await text_of(page2, '[data-testid="xdr-ctx-customer"]')
            ok = cust and "nivx-live" in cust and "default" not in cust
            rec("Tenant iso: customer chip nivx-live", ok, f"cust='{cust}'")
        except Exception as e:
            rec("Tenant iso chip", False, str(e))

        await browser.close()

    print("\n=== SUMMARY ===")
    passed = sum(1 for r in results if r["status"]=="PASS")
    print(f"{passed}/{len(results)} passed")
    print(f"Console errors: {len(console_errors)}")
    for e in console_errors[:20]:
        print(" ", e)
    with open("/app/test_reports/x1_x2_x3_frontend_results.json","w") as f:
        json.dump({"results":results,"console_errors":console_errors},f,indent=2)

asyncio.run(run())
