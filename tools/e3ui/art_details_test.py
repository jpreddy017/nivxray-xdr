"""Activity Details artifacts: 5 event types, network summary, real-mouse right-click -> Quarantine -> approval. Preview only."""
import asyncio, json
from urllib.parse import quote
from playwright.async_api import async_playwright

D = open("/tmp/shell_dir").read().strip()
HOST = "https://edr-forge-complete.preview.emergentagent.com"
B = f"{HOST}/{D}/index.html"
OUT = "/app/.e3ui-harness/shots_art"
DEV = "dev_f22d20b97b6d"
R, ERR = {}, []


def ok(name, cond, detail=""):
    R[name] = {"pass": bool(cond), "detail": str(detail)[:240]}


async def open_event(pg, iid):
    await pg.goto(f"{B}?device={DEV}&event={quote(iid, safe='')}")
    await pg.wait_for_selector('[data-testid="dt-artifacts"]', timeout=45000)
    await pg.wait_for_selector('[data-testid="v3-loading"]', state="detached", timeout=30000)
    await pg.wait_for_timeout(700)


async def sec_text(pg, sid):
    loc = pg.locator(f'[data-testid="dt-sec-{sid}"]')
    return await loc.inner_text() if await loc.count() else ""


async def common(pg, tag, need):
    for sid in need:
        loc = pg.locator(f'[data-testid="dt-sec-{sid}"] [data-testid="{"dt-mitre-link" if sid == "mitre" else "dt-field-row"}"]')
        ok(f"{tag}_section_{sid}_has_values", await loc.count() > 0, await loc.count())
    await pg.screenshot(path=f"{OUT}/{tag}_top.jpeg", quality=72)
    nc = pg.locator('[data-testid="dt-not-collected"]')
    await nc.locator("summary").click()
    rows = await pg.locator('[data-testid="dt-not-collected-row"]').all_inner_texts()
    ok(f"{tag}_not_collected_lists_reasons", rows and all(any(k in r for k in ("not collected by sensor", "not provided by source", "provider not configured", "not emitted")) for r in rows), rows[:3])
    ok(f"{tag}_no_clean_without_evidence", "Clean" not in await pg.inner_text('[data-testid="v3-activity-details"]'))
    await pg.screenshot(path=f"{OUT}/{tag}.jpeg", quality=72)


async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch(executable_path="/usr/bin/chromium", args=["--no-sandbox"])
        pg = await b.new_page(viewport={"width": 2000, "height": 1300})
        pg.on("pageerror", lambda e: ERR.append(str(e)[:300]))
        ev = json.loads(await (await pg.request.get(f"{HOST}/api/edr/endpoints/{DEV}/trajectory?limit=4000&lane_end=100000")).text())["events"]
        pick = lambda f: next((e["event_iid"] for e in reversed(ev) if f(e)), None)  # noqa: E731
        ids = {"detection": pick(lambda e: (e.get("e3_detection") or {}).get("rule_id") == "BHV-OFFICE-CHAIN-001"),
               "execution": pick(lambda e: e.get("e3_disposition")),
               "network": pick(lambda e: e["event_type"] == "network_connect" and e.get("e3_ti")) or pick(lambda e: e["event_type"] == "network_connect"),
               "dns": pick(lambda e: e["event_type"] == "dns_query"), "registry": pick(lambda e: e["event_type"] == "registry_value_set"),
               "quarantined": pick(lambda e: (e.get("e3_enforcement") or {}).get("outcome") == "QUARANTINED")}
        ok("fixture_events_present", all(ids.values()), ids)
        await open_event(pg, ids["detection"])
        await common(pg, "01_detection", ["detection", "mitre", "action", "process", "file", "ioc"])
        hrefs = await pg.eval_on_selector_all('[data-testid="dt-mitre-link"]', "e=>e.map(x=>x.href)")
        attrs = await pg.eval_on_selector_all('[data-testid="dt-mitre-link"]', "e=>e.map(x=>[x.target,x.rel])")
        ok("mitre_links_new_tab_noopener", attrs and all(t == "_blank" and "noopener" in r for t, r in attrs), attrs)
        tac = await pg.eval_on_selector_all('[data-testid="dt-mitre-tactic-link"]', "e=>e.map(x=>x.href)")
        ok("mitre_tactic_links", "https://attack.mitre.org/tactics/TA0001/" in tac and "https://attack.mitre.org/tactics/TA0002/" in tac and "https://attack.mitre.org/tactics/TA0011/" in tac, tac)
        ok("mitre_domain_visible", "attack.mitre.org/techniques/T1059/001/" in await sec_text(pg, "mitre"))
        ok("mitre_links_correct", "https://attack.mitre.org/techniques/T1059/001/" in hrefs and "https://attack.mitre.org/techniques/T1566/001/" in hrefs, hrefs)
        ok("detection_rule_and_engine", "BHV-OFFICE-CHAIN-001" in await sec_text(pg, "detection") and "Behavioral Protection" in await sec_text(pg, "detection"))
        ok("action_none_without_evidence", "No enforcement/response evidence recorded." in await sec_text(pg, "action"))
        await open_event(pg, ids["execution"])
        await common(pg, "02_execution", ["file", "disposition", "process", "parent", "children"])
        disp = await sec_text(pg, "disposition")
        ok("disposition_with_provenance_and_history", "MALICIOUS" in disp and "synthetic TI fixture" in disp and "Provenance" in disp and "retrospective" in disp, disp[:200])
        ok("exec_sha256_full", len([t for t in (await sec_text(pg, "file")).split() if len(t) == 64]) >= 1)
        await open_event(pg, ids["network"])
        await common(pg, "03_network", ["network", "process"])
        net = await sec_text(pg, "network")
        ok("network_fields", "Remote IP:port" in net and "Connections from this process" in net, net[:200])
        await open_event(pg, ids["dns"])
        await common(pg, "04_dns", ["dns"])
        ok("dns_fields", "Query name" in await sec_text(pg, "dns"))
        await open_event(pg, ids["registry"])
        await common(pg, "05_registry", ["registry"])
        ok("registry_fields", "Key path" in await sec_text(pg, "registry"))
        await open_event(pg, ids["quarantined"])
        ok("action_quarantined_only_with_evidence", "quarantined" in (await sec_text(pg, "action")).lower() and "synthetic enforcement fixture" in await sec_text(pg, "action"))
        await pg.screenshot(path=f"{OUT}/06_quarantined_action.jpeg", quality=72)
        cases = json.loads(await (await pg.request.get(f"{HOST}/api/e3/preview/deeplink-cases")).text())
        ok("deeplink_cases_enforcement", cases.get("quarantined") and cases.get("quarantine_failed"), cases)
        await open_event(pg, cases["quarantined"])
        ok("deeplink_quarantined_action", "Quarantined" in await sec_text(pg, "action") and "moved to quarantine store" in await sec_text(pg, "action"), await sec_text(pg, "action"))
        await open_event(pg, cases["quarantine_failed"])
        ok("deeplink_quarantine_failed_action", "Quarantine Failed — file in use by running process (sharing violation)" in await sec_text(pg, "action"), await sec_text(pg, "action"))
        ok("quarantine_failed_reason_row", "Reason" in await sec_text(pg, "action"))
        await pg.screenshot(path=f"{OUT}/06b_quarantine_failed_action.jpeg", quality=72)
        ok("deeplink_not_quarantined_case", cases.get("not_quarantined"), cases)
        await open_event(pg, cases["not_quarantined"])
        ok("not_quarantined_audit_mode", "Not Quarantined — audit mode" in await sec_text(pg, "action"), await sec_text(pg, "action"))
        await pg.screenshot(path=f"{OUT}/06c_not_quarantined_action.jpeg", quality=72)
        # real-mouse click on a network-row marker -> Activity Details (Network section)
        await pg.goto(f"{B}?device={DEV}")
        await pg.wait_for_selector('[data-testid="dt-marker"]', timeout=45000)
        await pg.wait_for_selector('[data-testid="v3-loading"]', state="detached", timeout=30000)
        center = """(sel) => { for (const m of document.querySelectorAll(sel)) { const r = m.getBoundingClientRect(), x = r.x + r.width / 2, y = r.y + r.height / 2;
            if (y > 0 && y < innerHeight && m.contains(document.elementFromPoint(x, y))) return [x, y]; } return null; }"""
        pt = await pg.evaluate(center, '[data-testid^="v3-marker-"][data-glyph="net"] [data-testid="dt-marker"]')
        ok("net_marker_visible", pt, pt)
        await pg.mouse.click(pt[0], pt[1])
        await pg.wait_for_selector('[data-testid="dt-sec-network"]', timeout=8000)
        ok("net_marker_real_click_opens_details", await pg.locator('[data-testid="dt-sec-network"] [data-testid="dt-field-row"]').count() > 0)
        await pg.mouse.click(pt[0] + 3, pt[1] + 4)
        ok("net_marker_offcenter_click_still_selects", await pg.locator('[data-testid="dt-sec-network"]').count() == 1)
        await pg.click('[data-testid="v3-details-back"]')
        # real-mouse click on a Network row label -> Network summary
        pt = await pg.evaluate(center, '[data-row-type="Network"] [data-testid="dt-row-label"]')
        ok("net_label_visible", pt, pt)
        await pg.mouse.click(pt[0], pt[1])
        await pg.wait_for_selector('[data-testid="dt-network-summary"]')
        ok("network_summary_tld_groups", await pg.locator('[data-testid="dt-net-group-tld"]').count() > 0)
        ok("network_summary_rows", await pg.locator('[data-testid="dt-net-row"]').count() > 0 and "unique destinations" in await pg.inner_text('[data-testid="dt-net-totals"]'))
        await pg.screenshot(path=f"{OUT}/07_network_summary.jpeg", quality=72)
        await pg.click('[data-testid="dt-network-summary-back"]')
        # real-mouse right-click on a marker -> Quarantine -> approval
        await pg.wait_for_selector('[data-testid="v3-activity"]')
        pt = await pg.evaluate("""() => { for (const m of document.querySelectorAll('[data-testid="dt-marker"]')) {
            const r = m.getBoundingClientRect(), x = r.x + r.width / 2, y = r.y + r.height / 2;
            if (m.contains(document.elementFromPoint(x, y))) return [x, y]; } return null; }""")
        ok("visible_marker_found", pt, pt)
        await pg.mouse.click(pt[0], pt[1], button="right")
        await pg.wait_for_selector('[data-testid="dt-context-menu"]', timeout=5000)
        ok("rightclick_marker_menu", all([await pg.locator(f'[data-testid="{t}"]').count() == 1 for t in ("dt-ctx-copy-hash", "dt-ctx-isolate-lineage", "dt-ctx-quarantine")]))
        await pg.mouse.move(pt[0] + 40, pt[1] + 60)
        await pg.wait_for_function("getComputedStyle(document.querySelector('[data-testid=\"v3-context-menu\"]')).opacity === '1'")
        ok("menu_not_covered_by_tooltip", await pg.locator('[data-testid="v3-tooltip"]').count() == 0)
        await pg.screenshot(path=f"{OUT}/08_rightclick_menu.jpeg", quality=72)
        await pg.locator('[data-testid="dt-ctx-quarantine"]').click()
        await pg.wait_for_selector('[data-testid="dt-approval-dialog"]')
        await pg.screenshot(path=f"{OUT}/09_approval_dialog.jpeg", quality=72)
        await pg.click('[data-testid="v3-approval-confirm"]')
        await pg.wait_for_selector('[data-testid="dt-approval-result"]')
        ok("approval_requested_not_executed", "Approval Requested — not executed" in await pg.inner_text('[data-testid="dt-approval-result"]'))
        await pg.screenshot(path=f"{OUT}/10_approval_result.jpeg", quality=72)
        for name, sel in (("row_label", '[data-testid="dt-row-label"]'), ("activity_row", '[data-testid^="v3-activity-row-"]')):
            bb = await pg.locator(sel).nth(2).bounding_box()
            await pg.mouse.click(bb["x"] + 8, bb["y"] + bb["height"] / 2, button="right")
            ok(f"rightclick_{name}_menu", await pg.locator('[data-testid="dt-context-menu"]').count() == 1)
            await pg.mouse.click(5, 5)
        g = await pg.locator('[data-testid="v3-grid-body"]').bounding_box()
        await pg.mouse.click(g["x"] + 300, g["y"] + 200, button="right")
        ok("rightclick_grid_space_hit_test", await pg.locator('[data-testid="dt-context-menu"]').count() == 1)
        r = await pg.request.get(f"{HOST}/edr/device-trajectory?device={DEV}")
        await pg.goto(f"{HOST}/edr/device-trajectory?device={DEV}")
        await pg.wait_for_url(f"**/{D}/index.html?device={DEV}*", timeout=20000)
        ok("preview_root_redirect", D in pg.url, pg.url)
        await b.close()
    R["page_errors"] = ERR[:10]
    json.dump(R, open(f"{OUT}/results.json", "w"), indent=1)
    fails = {k: v for k, v in R.items() if isinstance(v, dict) and not v["pass"]}
    print(f"{sum(1 for v in R.values() if isinstance(v, dict) and v['pass'])} pass / {len(fails)} fail")
    print(json.dumps(fails, indent=1)[:3000]); print("errors", ERR[:5])

asyncio.run(main())
