"""S3-D · ANCHOR-TO-EVIDENCE — programmatic DOM proof (no screenshots).

Proves: an evidence-backed causal anchor hands the analyst to the records that
CITE it, with the provenance chain and the shared inspector reachable; an
anchor with no citation offers no evidence action; an unmapped reference gets
an explicit truthful state with no nearest-match fallback; cross-tenant
exposes nothing; every incident tab still works.
"""
import asyncio
import sys

from playwright.async_api import async_playwright

BASE = ""
with open("/app/frontend/.env") as f:
    for line in f:
        if line.startswith("REACT_APP_BACKEND_URL="):
            BASE = line.split("=", 1)[1].strip().rstrip("/")

OWN = ("analyst@default.com", "DefaultCo!Analyst2026")
INC_ASSOC = "inc_c1edae99d4e541c58552"
INC_UNASSOC = "inc_r381_promote"
INC_OTHER_TENANT = "inc_7742fe7120174204be36"

_p = _f = 0


def check(name, cond, detail=""):
    global _p, _f
    if cond:
        _p += 1
        print(f"PASS · {name} {detail}")
    else:
        _f += 1
        print(f"FAIL · {name} {detail}")


async def login(page, cred):
    await page.goto(f"{BASE}/login", wait_until="domcontentloaded")
    await page.fill('input[type="email"]', cred[0])
    await page.fill('input[type="password"]', cred[1])
    await page.click('button[type="submit"]')
    await page.wait_for_timeout(3500)


async def open_tab(page, incident_id, tab, extra=""):
    for _ in (1, 2):
        await page.goto(f"{BASE}/xdr/incidents/{incident_id}?tab={tab}{extra}",
                        wait_until="domcontentloaded")
        try:
            await page.wait_for_selector(
                '[data-testid="incident-generate-report"]', timeout=25000)
        except Exception:                                      # noqa: BLE001
            pass
        await page.wait_for_timeout(5500)
        if len(await page.inner_text("body")) > 1000:
            return


async def main():
    async with async_playwright() as pw:
        b = await pw.chromium.launch(args=["--no-sandbox"])
        page = await b.new_page(viewport={"width": 1680, "height": 1100})
        await login(page, OWN)

        # ── 1 · the anchor table states its evidence ───────────────
        await open_tab(page, INC_ASSOC, "story")
        rows = page.locator('[data-testid^="incident-story-depth-anchors-row-"]')
        n = await rows.count()
        check("causal anchors render", n > 0, f"{n} anchors")

        cited = page.locator('[data-testid^="incident-story-depth-anchors-view-evidence-"]')
        n_cited = await cited.count()
        counts = page.locator('[data-testid^="incident-story-depth-anchors-evcount-"]')
        ctxt = (await counts.first.inner_text()) if await counts.count() else ""
        check("an evidence-backed anchor states how many records cite it",
              n_cited > 0 and "supporting record" in ctxt,
              f"{n_cited} actionable · {ctxt!r}")

        none = page.locator('[data-testid^="incident-story-depth-anchors-noevidence-"]')
        n_none = await none.count()
        ntxt = (await none.first.inner_text()) if n_none else ""
        check("an anchor with no citation offers NO evidence action",
              n_none == 0 or "NO EVENT CITED" in ntxt.upper(),
              f"{n_none} uncited · {ntxt.strip()!r}")
        # the action must never be rendered for an uncited anchor
        check("actionable anchors + uncited anchors account for every anchor",
              n_cited + n_none == n, f"{n_cited}+{n_none} vs {n}")

        # ── 2 · anchor → evidence ──────────────────────────────────
        await cited.first.click()
        await page.wait_for_timeout(7000)
        check("the hand-off lands on Evidence focused on that anchor",
              "tab=evidence" in page.url and "focus=" in page.url,
              f"url={page.url.split('?')[-1]}")

        sec = page.locator('[data-testid="xdr-record-evidence-anchor"]')
        check("Evidence opens a focused anchor section (not a new screen)",
              await sec.count() == 1
              and await page.locator(
                  '[data-testid="xdr-record-evidence"]').count() == 1,
              f"sections={await sec.count()}")

        cnt = page.locator('[data-testid="xdr-record-evidence-anchor-count"]')
        unmatched = page.locator('[data-testid="xdr-record-evidence-anchor-unmatched"]')
        matched = await cnt.count() > 0
        check("the citing records resolve for an evidence-backed anchor",
              matched, f"count_block={await cnt.count()} "
                       f"unmatched={await unmatched.count()}")

        if matched:
            ctext = await cnt.first.inner_text()
            check("multiple evidence is represented truthfully, none chosen "
                  "as 'the' evidence",
                  "none is chosen" in ctext.lower(), f"{ctext[:90]!r}")
            erows = page.locator('[data-testid^="xdr-record-evidence-anchor-table-row-"]')
            n_er = await erows.count()
            check("every citing record is listed", n_er > 0, f"{n_er} row(s)")
            detail = await page.locator('[data-open="true"]').first.evaluate(
                "el => el.nextElementSibling?.innerText || ''")
            check("the provenance chain is shown",
                  "Provenance chain" in detail
                  and "canonical" in detail.lower()
                  and "normalizer" in detail.lower(), f"{detail[:100]!r}")
            check("the shared inspector is reachable for the cited reference",
                  await page.locator(
                      '[data-testid^="xdr-record-evidence-anchor-inspect-"]'
                  ).count() > 0)
            check("the incident evidence table is still present underneath",
                  await page.locator(
                      '[data-testid="xdr-record-evidence-grid"]').count() == 1)

        # ── 3 · an unmapped reference is stated, never substituted ──
        await open_tab(page, INC_ASSOC, "evidence",
                       "&focus=proc_s3d_does_not_exist")
        um = page.locator('[data-testid="xdr-record-evidence-anchor-unmatched"]')
        utxt = (await um.first.inner_text()) if await um.count() else ""
        check("an unmapped reference gets an explicit truthful state",
              await um.count() == 1 and "NOT MATCHED" in utxt.upper(),
              f"{utxt[:70]!r}")
        check("no nearest-match fallback is offered",
              "nearest similar record" in utxt.lower()
              and await page.locator(
                  '[data-testid^="xdr-record-evidence-anchor-table-row-"]'
              ).count() == 0)
        check("an absent citation is not a benign finding",
              "not a finding" in utxt.lower())

        # ── 4 · NOT_ASSOCIATED incident ────────────────────────────
        await open_tab(page, INC_UNASSOC, "story")
        check("no anchor evidence action without causal analysis",
              await page.locator(
                  '[data-testid^="incident-story-depth-anchors-view-evidence-"]'
              ).count() == 0)

        # ── 5 · cross-tenant ───────────────────────────────────────
        await open_tab(page, INC_OTHER_TENANT, "evidence",
                       "&focus=proc_2926e8542ed7")
        body = await page.inner_text("body")
        check("another tenant's incident exposes no citing records",
              await page.locator(
                  '[data-testid^="xdr-record-evidence-anchor-table-row-"]'
              ).count() == 0 and "powershell" not in body.lower())

        # ── 6 · every tab still works ──────────────────────────────
        for tab in ("overview", "story", "timeline", "evidence", "detections",
                    "response", "activity"):
            txt = ""
            for _ in (1, 2):
                await open_tab(page, INC_ASSOC, tab)
                txt = await page.inner_text("body")
                if len(txt) > 1000:
                    break
            check(f"tab still renders · {tab}",
                  len(txt) > 1000 and "SURFACE ERROR" not in txt.upper(),
                  f"{len(txt)} chars")

        await b.close()

    print(f"\nS3-D DOM PROOF · {_p} PASS · {_f} FAIL")
    return 0 if _f == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
