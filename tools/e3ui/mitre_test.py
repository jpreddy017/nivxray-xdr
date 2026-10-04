"""ATT&CK mapping (E1 attribution adapter + vendored STIX catalogue): MITRE box, strip, filters, search, badge, hover,
HeatMap pivots both ways, Navigator layer export, old-vs-new box regression. Preview only."""
import asyncio, json
from urllib.parse import quote
from playwright.async_api import async_playwright

D = open("/tmp/shell_dir").read().strip()
HOST = "https://edr-forge-complete.preview.emergentagent.com"
B = f"{HOST}/{D}/index.html"
OUT = "/app/.e3ui-harness/shots_mitre"
DEV = "dev_f22d20b97b6d"
R, ERR = {}, []
DAY = 86400000


def ok(name, cond, detail=""):
    R[name] = {"pass": bool(cond), "detail": str(detail)[:300]}


async def ready(pg, sel='[data-testid="dt-marker"]'):
    await pg.wait_for_selector(sel, timeout=45000)
    await pg.wait_for_selector('[data-testid="v3-loading"]', state="detached", timeout=30000)
    await pg.wait_for_timeout(600)


async def spa(pg, path):
    await pg.evaluate("(p) => { history.pushState({}, '', p); dispatchEvent(new PopStateEvent('popstate')); }", path)


async def main():
    import os
    os.makedirs(OUT, exist_ok=True)
    async with async_playwright() as p:
        b = await p.chromium.launch(executable_path="/usr/bin/chromium", args=["--no-sandbox"])
        ctx = await b.new_context(viewport={"width": 2000, "height": 1300}, accept_downloads=True)
        pg = await ctx.new_page()
        pg.on("console", lambda m: m.type == "error" and ERR.append(m.text))
        api = f"{HOST}/api/edr/endpoints/{DEV}/trajectory"
        import time
        t1 = int(time.time() * 1000) + DAY
        iso = lambda ms: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ms / 1000))
        allev = json.loads(await (await pg.request.get(f"{api}?limit=4000&lane_end=100000&time_start={iso(t1 - 8 * DAY)}&time_end={iso(t1)}")).text())["events"]
        office = next(e for e in allev if (e.get("e3_attack") or {}).get("type") == "Rule-mapped" and "T1059.001" in e["mitre"])
        dl_iid = json.loads(await (await pg.request.get(f"{HOST}/api/edr/attack/techniques/T1003.001/devices")).text())["devices"][0]["events"][0]["event_iid"]
        w = json.loads(await (await pg.request.get(f"{api}/focus?event_iid={quote(dl_iid, safe='')}")).text())["focus"]["window"]
        dump = next(e for e in json.loads(await (await pg.request.get(f"{api}?limit=4000&lane_end=100000&time_start={w['time_start']}&time_end={w['time_end']}")).text())["events"] if e["event_iid"] == dl_iid)
        recent = [e for e in allev if e["timestamp_instant_ms"] > office["timestamp_instant_ms"] - 3600000]
        plain = next(e for e in recent if e["event_type"] == "process_create" and not e.get("mitre") and not e.get("e3_detection"))
        heur = next(e for e in recent if (e.get("e3_attack") or {}).get("type") == "Heuristic" and e["event_type"].startswith("network"))
        ok("e1_attribution_rows", office["mitre_basis"] == "RULE_DECLARED_BY_MATCHED_DETECTION" and office.get("findings"), office["mitre_basis"])

        # ---------- strip ----------
        await pg.goto(f"{B}?device={DEV}")
        await ready(pg)
        await pg.wait_for_selector('[data-testid="dt-attack-strip"]', timeout=20000)
        cols = await pg.locator('[data-testid^="dt-attack-tactic-"][data-observed]').count()
        ok("strip_15_tactic_columns_v19", cols == 15, cols)
        lbl = await pg.inner_text('[data-testid="dt-attack-strip-label"]')
        ok("strip_label", "Observed on this device (from detections and behavioral matches)" in lbl and "v19.2" in lbl, lbl)
        ok("strip_attribution_footer", "© The MITRE Corporation" in await pg.inner_text('[data-testid="dt-attack-attribution"]'))
        ok("strip_dim_unobserved", await pg.get_attribute('[data-testid="dt-attack-tactic-reconnaissance"]', "data-observed") == "0")
        ok("strip_t1027_under_stealth_v19", await pg.locator('[data-testid="dt-attack-tactic-stealth"] [data-testid="dt-attack-tech-T1027"]').count() == 1)
        ok("strip_default_range_excludes_5d_old_dump", await pg.locator('[data-testid="dt-attack-tech-T1003.001"]').count() == 0)
        ok("strip_detections_only_by_default", await pg.locator('[data-testid="dt-attack-tech-T1071.001"]').count() == 0)
        await pg.screenshot(path=f"{OUT}/01_attack_strip.jpeg", quality=72)
        # export Navigator layer
        async with pg.expect_download() as dl:
            await pg.click('[data-testid="dt-attack-export-layer"]')
        layer = json.loads(open(await (await dl.value).path()).read())
        ok("layer_versions", layer["versions"] == {"attack": "19", "navigator": "5.1.0", "layer": "4.5"} and layer["domain"] == "enterprise-attack", layer["versions"])
        ok("layer_techniques", {t["techniqueID"] for t in layer["techniques"]} >= {"T1059.001", "T1105", "T1027"}
           and all(isinstance(t["score"], int) and t["tactic"] for t in layer["techniques"]), [t["techniqueID"] for t in layer["techniques"]])
        json.dump(layer, open(f"{OUT}/navigator_layer.json", "w"), indent=1)
        # technique click filters, click again clears
        total = await pg.locator('[data-testid="dt-marker"]').count()
        await pg.click('[data-testid="dt-attack-tech-T1059.001"]')
        await pg.wait_for_selector('[data-testid="dt-attack-filter-banner"]')
        await pg.wait_for_timeout(500)
        n = await pg.locator('[data-testid="dt-marker"]').count()
        ind = await pg.inner_text('[data-testid="v3-filter-indicator"]')
        ok("technique_click_filters", n < total and ind.split(" of ")[0].strip().isdigit() and 0 < int(ind.split(" of ")[0]) < 20, (n, total, ind))
        await pg.screenshot(path=f"{OUT}/02_technique_filtered.jpeg", quality=72)
        await pg.click('[data-testid="dt-attack-tech-T1059.001"]')
        await pg.wait_for_timeout(500)
        ok("technique_click_again_clears", await pg.locator('[data-testid="dt-attack-filter-banner"]').count() == 0 and "att=" not in pg.url)
        # range: widen to 7 days -> lateral dump appears
        now = office["timestamp_instant_ms"] + 10 * 60000
        await pg.goto(f"{B}?device={DEV}&t0={now - 7 * DAY}&t1={now}")
        await ready(pg)
        await pg.wait_for_selector('[data-testid="dt-attack-tech-T1003.001"]', timeout=20000)
        ok("strip_follows_range_7d_shows_cred_lateral", await pg.locator('[data-testid="dt-attack-tactic-lateral-movement"] [data-testid="dt-attack-tech-T1021.002"]').count() == 1)
        await pg.screenshot(path=f"{OUT}/03_attack_strip_7d.jpeg", quality=72)
        await pg.click('[data-testid="dt-attack-include-heuristic"]')
        await pg.wait_for_selector('[data-testid="dt-attack-tech-T1071.001"]', timeout=15000)
        ok("heuristic_toggle_labelled", "heuristic" in await pg.inner_text('[data-testid="dt-attack-tech-T1071.001"]'))

        # ---------- badge / tactic filter / search ----------
        await pg.goto(f"{B}?device={DEV}")
        await ready(pg)
        await pg.goto(f"{B}?device={DEV}&event={quote(office['event_iid'], safe='')}")
        await ready(pg)
        badges, markers = await pg.locator('[data-testid="dt-attack-badge"]').count(), await pg.locator('[data-testid="dt-marker"]').count()
        ok("badge_on_rule_mapped_markers_only", 0 < badges < 20 and badges < markers, (badges, markers))
        await pg.click('[data-testid="v3-details-back"]')
        await pg.click('[data-testid="v3-filters"]')
        await pg.wait_for_selector('[data-testid="v3-filter-group-ATTCK"]')
        ok("filters_group_all_attack_tactics", "All ATT&CK tactics" in await pg.locator('[data-testid="v3-filter-group-ATTCK"]').locator("xpath=..").inner_text())
        for k in ("initial-access", "execution", "stealth", "command-and-control"):
            await pg.click(f'[data-testid="v3-filter-ta_{k}"] input')
        await pg.click('[data-testid="v3-filters-apply"]')
        await pg.wait_for_timeout(600)
        ok("tactic_filter_hides_mapped_only", await pg.locator('[data-testid="dt-attack-badge"]').count() == 0
           and await pg.locator('[data-testid="dt-marker"]').count() >= markers - badges, (await pg.locator('[data-testid="dt-marker"]').count(), markers))
        await pg.click('[data-testid="v3-filter-reset"]')
        await pg.wait_for_timeout(400)
        for q, name in (("T1059", "search_T1059"), ("T1059.001", "search_T1059_001"), ("PowerShell", "search_name_powershell")):
            await pg.fill('[data-testid="v3-search"]', q)
            await pg.press('[data-testid="v3-search"]', "Enter")
            await pg.wait_for_timeout(600)
            ind = await pg.inner_text('[data-testid="v3-filter-indicator"]') if await pg.locator('[data-testid="v3-filter-indicator"]').count() else ""
            ok(name, " of " in ind and await pg.locator('[data-testid="dt-attack-badge"]').count() >= 1, ind)
        await pg.screenshot(path=f"{OUT}/04_search_T1059.jpeg", quality=72)

        # ---------- MITRE box (rule-mapped) + hover + pivot to HeatMap ----------
        await pg.goto(f"{B}?device={DEV}&event={quote(office['event_iid'], safe='')}")
        await ready(pg, '[data-testid="dt-sec-mitre"]')
        box = pg.locator('[data-testid="dt-sec-mitre"]')
        txt = await box.inner_text()
        ok("box_header_and_attributed", "MITRE | ATT&CK" in txt and await box.get_attribute("data-attributed") == "true")
        ok("box_rule_mapped_source", "Rule-mapped" in await pg.inner_text('[data-testid="dt-attack-type"]') and "BHV-OFFICE-CHAIN-001" in await pg.inner_text('[data-testid="dt-attack-source"]'))
        ok("box_version_stamp", "ATT&CK Enterprise v19.2" in await pg.inner_text('[data-testid="dt-attack-version"]'))
        ok("box_note", "Mapped by rule metadata. A MITRE mapping is not a verdict." in txt)
        hrefs = await pg.eval_on_selector_all('[data-testid="dt-mitre-link"]', "e=>e.map(x=>[x.href,x.target,x.rel])")
        ok("box_technique_links", any(h == "https://attack.mitre.org/techniques/T1059/001/" for h, _, _ in hrefs) and all(t == "_blank" and "noopener" in r for _, t, r in hrefs), hrefs)
        tac = await pg.eval_on_selector_all('[data-testid="dt-mitre-tactic-link"]', "e=>e.map(x=>x.href)")
        ok("box_tactic_links_kill_chain", tac == ["https://attack.mitre.org/tactics/TA0001/", "https://attack.mitre.org/tactics/TA0002/",
           "https://attack.mitre.org/tactics/TA0005/", "https://attack.mitre.org/tactics/TA0011/"], tac)
        ok("box_v19_stealth_not_defense_evasion", "Stealth" in txt and "Defense Evasion" not in txt)
        await pg.hover('[data-testid="dt-mitre-link"] >> nth=0')
        await pg.wait_for_selector('[data-testid="dt-attack-hovercard"]', timeout=5000)
        ok("hover_card_description", len(await pg.inner_text('[data-testid="dt-attack-hovercard"]')) > 60)
        await pg.screenshot(path=f"{OUT}/05_mitre_box_rule_mapped.jpeg", quality=72)
        idx = [h for h, _, _ in hrefs].index("https://attack.mitre.org/techniques/T1059/001/")
        await pg.mouse.move(5, 5)
        await pg.locator('[data-testid="dt-open-heatmap"]').nth(idx).click()
        await pg.wait_for_selector('[data-testid="xdr-mitre-dt-context"]', timeout=30000)
        ok("pivot_to_heatmap_url", "/xdr/intelligence/mitre" in pg.url and "technique=T1059.001" in pg.url and f"device={DEV}" in pg.url, pg.url)
        await pg.wait_for_selector('[data-testid="xdr-mitre-detail-body"]', timeout=20000)
        ok("heatmap_preselected_technique", "T1059.001" in await pg.inner_text('[data-testid="xdr-mitre-detail-body"]'))
        ok("heatmap_attribution_footer", "© The MITRE Corporation" in await pg.inner_text('[data-testid="xdr-mitre-attribution"]'))
        await pg.wait_for_selector('[data-testid^="xdr-mitre-open-dt-event-"]', timeout=20000)
        await pg.screenshot(path=f"{OUT}/06_heatmap_pivot.jpeg", quality=72)
        await pg.click(f'[data-testid="xdr-mitre-open-dt-event-{office["observation_id"]}"]')
        await pg.wait_for_selector('[data-testid="v3-activity-details"]', timeout=45000)
        ok("pivot_back_deeplink", "/edr/device-trajectory" in pg.url and "%23" in pg.url and f"device={DEV}" in pg.url, pg.url)
        ok("pivot_back_selects_event", office["observation_id"] in (await pg.text_content('[data-testid="v3-evidence"]') or ""))
        await pg.screenshot(path=f"{OUT}/07_back_in_trajectory.jpeg", quality=72)

        # ---------- empty-state precedent + heuristic ----------
        await pg.goto(f"{B}?device={DEV}&event={quote(plain['event_iid'], safe='')}")
        await ready(pg, '[data-testid="dt-sec-mitre"]')
        ok("empty_tactics_verbatim", (await pg.inner_text('[data-testid="dt-mitre-tactics-none"]')).strip() == "◇ no tactic attributed")
        ok("empty_techniques_verbatim", (await pg.inner_text('[data-testid="dt-mitre-techniques-none"]')).strip()
           == "◇ no technique attributed to this observation. Absence of an attribution is not evidence that no technique was used.")
        ok("badge_unknown_not_assessed", (await pg.inner_text('[data-testid="dt-assessment-badge"]')).startswith("Unknown ·"))
        line = await pg.inner_text('[data-testid="dt-no-detection-line"]')
        ok("no_detection_line", line.startswith("No detection engine claimed this observation — it is telemetry reported by") and line.endswith("Absence of a detection is not a verdict of clean."), line)
        ok("observables_none", "◇ no file artefact was reported with this observation." in await pg.inner_text('[data-testid="dt-observables"]'))
        ok("observed_activity_cmdline", (plain.get("command_line") or "")[:40] in await pg.inner_text('[data-testid="dt-observed-activity-text"]'))
        await pg.screenshot(path=f"{OUT}/08_unattributed_precedent.jpeg", quality=72)
        await pg.goto(f"{B}?device={DEV}&event={quote(heur['event_iid'], safe='')}")
        await ready(pg, '[data-testid="dt-sec-mitre"]')
        ok("heuristic_labelled_not_detection", "Heuristic — ingest keyword tag, not a detection" in await pg.inner_text('[data-testid="dt-attack-type"]'))
        await pg.screenshot(path=f"{OUT}/09_heuristic_tag.jpeg", quality=72)

        # ---------- AMP deltas: header, narrative, signature hexagon, past tense, search view ----------
        cases = json.loads(await (await pg.request.get(f"{HOST}/api/e3/preview/deeplink-cases")).text())
        await pg.goto(f"{B}?device={DEV}&event={quote(cases['quarantined'], safe='')}")
        await ready(pg, '[data-testid="v3-activity-details"]')
        ok("header_label_under_time_detected", (await pg.inner_text('[data-testid="dt-event-type"]')).strip() == "Detected"
           and await pg.locator('[data-testid="v3-details-time"]').count() == 1, await pg.inner_text('[data-testid="dt-event-type-row"]'))
        ok("header_severity_badge_right", (await pg.inner_text('[data-testid="v3-severity"]')).strip() == "Medium")
        narr = await pg.inner_text('[data-testid="v3-narrative"]')
        ok("narrative_detected_pattern", narr.startswith("Detected eicar") and "[" in narr and " as EICAR-Test-Signature." in narr, narr[:200])
        ok("narrative_actor_line_past_tense", any([x for x in narr.split("\n") if x.strip()][1].startswith(v) for v in ("Created by", "Moved by", "Executed by", "Modified by")), narr)
        ok("narrative_outcome_from_evidence", "The file was quarantined." in narr)
        ok("narrative_process_disposition", "Process disposition Malicious." in narr, narr)
        col = await pg.eval_on_selector('[data-testid="v3-detection-name"]', "e=>getComputedStyle(e).color")
        ok("detection_name_red", col == "rgb(229, 83, 75)", col)
        ok("signature_disposition_hexagon", await pg.locator('[data-testid^="v3-marker-"][data-shape="hexagon"]').count() >= 1)
        await pg.screenshot(path=f"{OUT}/11_amp_detection_header_narrative.jpeg", quality=72)
        hashed = next((e for e in allev if e.get("file_sha256")), None)
        if hashed:
            await pg.goto(f"{B}?device={DEV}&event={quote(hashed['event_iid'], safe='')}")
            await ready(pg, '[data-testid="v3-hash-chip"]')
            ok("hash_chip_dashed", "dashed" in await pg.eval_on_selector('[data-testid="v3-hash-chip"]', "e=>getComputedStyle(e).borderBottomStyle"))
        await pg.goto(f"{B}?device={DEV}&event={quote(office['event_iid'], safe='')}")
        await ready(pg, '[data-testid="v3-narrative"]')
        ok("office_narrative_pattern", (await pg.inner_text('[data-testid="v3-narrative"]')).startswith("Detected powershell.exe"))
        await pg.goto(f"{B}?device={DEV}&event={quote(cases['quarantine_failed'], safe='')}")
        await ready(pg, '[data-testid="v3-activity-details"]')
        ok("narrative_quarantine_failed_reason", "Quarantine failed — file in use by running process (sharing violation)." in await pg.inner_text('[data-testid="v3-narrative"]')
           or "Quarantine Failed — file in use by running process (sharing violation)" in await pg.inner_text('[data-testid="dt-artifacts"]'))
        await pg.goto(f"{B}?device={DEV}&event={quote(plain['event_iid'], safe='')}")
        await ready(pg, '[data-testid="v3-activity-details"]')
        ok("chip_past_tense_executed", (await pg.inner_text('[data-testid="dt-event-type"]')).strip() == "Executed")
        bad = [x for x in await pg.eval_on_selector_all('[data-testid="v3-legend"] *, [data-testid="dt-event-type"]', "e=>e.map(x=>x.textContent.trim())")
               if x in ("Execute", "Create", "Move", "Delete", "Scan", "Quarantine")]
        ok("no_present_tense_rendered", not bad, bad)
        wq = json.loads(await (await pg.request.get(f"{api}/focus?event_iid={quote(cases['quarantined'], safe='')}")).text())["focus"]["window"]
        eic = next(e for e in json.loads(await (await pg.request.get(f"{api}?limit=4000&lane_end=100000&time_start={wq['time_start']}&time_end={wq['time_end']}")).text())["events"] if e["event_iid"] == cases["quarantined"])
        sha = eic.get("file_sha256") or "eicar_test_file.com"  # S-3: preview file events carry no hash; search by name
        if sha:
            from datetime import datetime
            ms = lambda v: int(datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp() * 1000)
            await pg.goto(f"{B}?device={DEV}&q={sha}&t0={ms(wq['time_start'])}&t1={ms(wq['time_end'])}")
            await ready(pg)
            res = await pg.inner_text('[data-testid="v3-search-count"]')
            labels = await pg.eval_on_selector_all('[data-testid="dt-row-label"]', "e=>e.map(x=>x.textContent.trim())")
            ok("search_view_results_and_rows", res.endswith("results") or res.endswith("result"), (res, labels))
            ok("search_view_two_rows", 1 <= len(labels) <= 3, labels)
            await pg.screenshot(path=f"{OUT}/12_search_sha256.jpeg", quality=72)
        else:
            ok("search_view_results_and_rows", False, "eicar sha not found")

        # ---------- IOC / ATT&CK strip at scale ----------
        await pg.goto(f"{B}?device={DEV}")
        await ready(pg)
        await pg.click('[data-testid="dt-tab-ioc"]')
        await pg.wait_for_selector('[data-testid="dt-ioc-summary"]')
        ok("ioc_grouped_small_case", await pg.locator('button[data-testid^="dt-ioc-group-"]').count() >= 1 and "distinct" in await pg.inner_text('[data-testid="dt-ioc-total"]'))
        ok("ioc_no_raw_iso", "T0" not in await pg.inner_text('[data-testid="dt-ioc-list"]') and "UTC" in await pg.inner_text('[data-testid="dt-ioc-list"]'))
        await pg.screenshot(path=f"{OUT}/13_ioc_strip_small.jpeg", quality=72)
        await pg.goto(f"{B}?device={DEV}&scenario=high_detection_volume")
        await ready(pg)
        await pg.click('[data-testid="dt-tab-ioc"]')
        await pg.wait_for_selector('[data-testid="dt-ioc-summary"]')
        await pg.wait_for_timeout(400)
        ms = await pg.evaluate("window.__e3StripMs")
        ok("hdv_strip_render_under_100ms", ms is not None and ms < 100, ms)
        tot = await pg.inner_text('[data-testid="dt-ioc-total"]')
        ok("hdv_grouping_counts", "distinct" in tot and int(tot.split(" detections")[0]) >= 100, tot)
        ok("hdv_top5_collapsed", await pg.locator('button[data-testid^="dt-ioc-group-"]').count() == 5)
        grid_y = (await pg.locator('[data-testid="v3-grid"]').bounding_box())["y"]
        await pg.click('[data-testid="dt-ioc-show-all"]')
        await pg.wait_for_timeout(300)
        h = (await pg.locator('[data-testid="dt-ioc-groups"]').bounding_box())["height"]
        rendered = await pg.locator('button[data-testid^="dt-ioc-group-"]').count()
        ok("hdv_show_all_bounded_virtualized", h <= 221 and rendered < 30, (h, rendered))
        grid_y2 = (await pg.locator('[data-testid="v3-grid"]').bounding_box())["y"]
        ok("hdv_no_grid_displacement_beyond_strip_max", grid_y2 - grid_y <= 230 and grid_y2 < 900, (grid_y, grid_y2))
        await pg.screenshot(path=f"{OUT}/14_ioc_strip_high_volume.jpeg", quality=72)
        await pg.click('[data-testid="dt-sev-pill-CRITICAL"]')
        await pg.wait_for_timeout(500)
        ok("sev_pill_filters_list_and_trajectory", "sev=CRITICAL" in pg.url and await pg.locator('[data-testid="v3-filter-indicator"]').count() == 1)
        await pg.click('[data-testid="dt-sev-pill-CRITICAL"]')
        await pg.wait_for_timeout(300)
        ok("sev_pill_click_again_clears", "sev=" not in pg.url)
        await pg.fill('[data-testid="dt-strip-quickfilter"]', "HDV-RULE-007")
        await pg.wait_for_timeout(200)
        ok("strip_quick_filter", await pg.locator('button[data-testid^="dt-ioc-group-"]').count() == 1)
        await pg.locator('button[data-testid^="dt-ioc-group-"]').first.click()
        await pg.wait_for_selector('[data-testid="dt-strip-stepper"]', timeout=10000)
        pos = await pg.inner_text('[data-testid="dt-strip-step-pos"]')
        await pg.click('[data-testid="dt-strip-next"]')
        await pg.wait_for_timeout(1500)
        ok("stepper_navigates", pos.startswith("1 of ") and (await pg.inner_text('[data-testid="dt-strip-step-pos"]')).startswith("2 of ")
           and "event=" in pg.url and await pg.locator('[data-testid="v3-activity-details"]').count() == 1, (pos, pg.url[-80:]))
        await pg.keyboard.press("Escape")
        await pg.wait_for_timeout(400)
        ok("esc_restores_full_view", "ioc=" not in pg.url)
        await pg.click('[data-testid="dt-tab-attack"]')
        await pg.wait_for_selector('[data-testid="dt-attack-strip"]')
        more = pg.locator('[data-testid^="dt-attack-more-"]')
        ok("attack_plus_n_more", await more.count() >= 1)
        if await more.count():
            await more.first.click()
            ok("attack_more_expands", (await more.first.inner_text()) == "less")
        await pg.click('[data-testid="dt-attack-matrix-toggle"]')
        await pg.wait_for_selector('[data-testid="dt-attack-matrix"]')
        cells = await pg.locator('[data-testid="dt-attack-cell"]').count()
        mh = (await pg.locator('[data-testid="dt-attack-matrix"]').bounding_box())["height"]
        ok("matrix_toggle_hundreds", cells >= 200 and mh <= 221, (cells, mh))
        await pg.screenshot(path=f"{OUT}/15_attack_matrix_high_volume.jpeg", quality=72)

        # ---------- old vs new regression ----------
        for e, tag in ((office, "rule"), (dump, "dump"), (heur, "heur")):
            await pg.goto(f"{B}?device={DEV}")
            await ready(pg)
            await spa(pg, f"/e3/mitre-compare?device={DEV}&event={quote(e['event_iid'], safe='')}")
            await pg.wait_for_selector('[data-testid="mitre-compare"]', timeout=45000)
            old = await pg.eval_on_selector_all('[data-testid="mitre-compare-old"] [data-testid^="amp-mitre-T"]', "e=>e.map(x=>x.textContent.trim())")
            new = await pg.eval_on_selector_all('[data-testid="mitre-compare-new"] [data-testid="dt-mitre-link"] b', "e=>e.map(x=>x.textContent.trim())")
            old_t = sorted(x for x in old if not x.startswith("TA"))
            ok(f"old_vs_new_identical_techniques_{tag}", old_t == sorted(new) and old_t == sorted(e["mitre"]), (old, new, e["mitre"]))
            if tag == "rule":
                await pg.screenshot(path=f"{OUT}/10_old_vs_new_box.jpeg", quality=72)
        await b.close()
    passed = sum(v["pass"] for v in R.values())
    json.dump(R, open(f"{OUT}/results.json", "w"), indent=1)
    print(f"{passed} pass / {len(R) - passed} fail")
    print(json.dumps({k: v for k, v in R.items() if not v["pass"]}, indent=1))
    print("errors", ERR[:5])

asyncio.run(main())
