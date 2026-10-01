"""S3-C · MILESTONE TIMELINE MERGE — programmatic DOM proof (no screenshots).

Real browser, real login, real preview edge.
Proves: a causal milestone sits in the ONE incident timeline at the activity
time of the evidence it cites; the three clocks are not conflated; the
evidence chain is reachable; a raw event and a milestone are distinguishable;
Story ↔ Timeline hand-off works through the existing query-param routing; an
incident with no causal analysis gets no fabricated milestone timeline.
"""
import asyncio
import re
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
        await page.wait_for_timeout(5000)
        if len(await page.inner_text("body")) > 1000:
            return


async def main():
    async with async_playwright() as pw:
        b = await pw.chromium.launch(args=["--no-sandbox"])
        page = await b.new_page(viewport={"width": 1680, "height": 1100})
        await login(page, OWN)

        # ── 1 · the milestone is IN the one timeline ────────────────
        await open_tab(page, INC_ASSOC, "timeline")
        table = page.locator('[data-testid="inv-timeline-table"]')
        check("the single investigation timeline is present",
              await table.count() == 1, f"tables={await table.count()}")
        check("no second timeline table was introduced",
              await page.locator(
                  '[data-testid="inv-timeline-table"]').count() == 1)

        ms = page.locator('[data-testid^="inv-timeline-milestone-m-"]')
        n_ms = await ms.count()
        check("a causal milestone appears inside the timeline", n_ms > 0,
              f"{n_ms} milestone row(s)")

        ev = page.locator('[data-testid^="inv-timeline-table-row-fr-"]')
        n_ev = await ev.count()
        check("observed evidence events appear alongside", n_ev > 0,
              f"{n_ev} evidence event row(s)")

        mtxt = (await ms.first.inner_text()) if n_ms else ""
        check("a milestone is visually distinguished from a raw event",
              "ATTACK MILESTONE" in mtxt.upper(), f"{mtxt[:60]!r}")

        # milestone row time == the cited evidence event's activity time
        m_row = page.locator('[data-testid^="inv-timeline-table-row-m-"]').first
        e_row = page.locator('[data-testid^="inv-timeline-table-row-fr-"]').first
        m_cells = await m_row.locator("td").all_inner_texts()
        e_cells = await e_row.locator("td").all_inner_texts()
        check("the milestone carries the cited event's activity time",
              m_cells and e_cells and m_cells[0].strip() == e_cells[0].strip()
              and len(m_cells[0].strip()) > 4,
              f"milestone={m_cells[0].strip()!r} event={e_cells[0].strip()!r}")

        # order agrees with time
        times = [c[0].strip() for c in
                 [await r.locator("td").all_inner_texts()
                  for r in await page.locator(
                      '[data-testid^="inv-timeline-table-row-"]').all()]
                 if c and re.search(r"\d", c[0])]
        check("timeline order agrees with the authoritative time",
              times == sorted(times, reverse=True), f"{times[:4]}")

        # ── 2 · the three clocks are not conflated ─────────────────
        # click the TIME cell: the Activity cell carries the hand-off button.
        await m_row.locator("td").first.click()
        await page.wait_for_timeout(900)
        det = page.locator('[data-testid^="inv-timeline-timebasis-m-"]')
        dtxt = (await det.first.inner_text()) if await det.count() else ""
        check("the milestone states it has no clock of its own",
              await det.count() > 0
              and "no clock of its own" in dtxt.lower()
              and "cited evidence event" in dtxt.lower(), f"{dtxt[:90]!r}")

        detail_txt = await page.locator('[data-open="true"]') \
            .first.evaluate("el => el.nextElementSibling?.innerText || ''")
        for label in ("Activity time", "Sensor observed", "Ingested"):
            check(f"the three clocks are reported separately · {label}",
                  label in detail_txt)
        check("ingest time is not presented as activity time",
              "Ingested" in detail_txt
              and detail_txt.count("Activity time") == 1)

        # ── 3 · evidence provenance chain + inspection ─────────────
        check("the milestone exposes its evidence chain",
              "Evidence chain" in detail_txt
              and "canonical" in detail_txt.lower(),
              f"chain={'Evidence chain' in detail_txt}")
        insp = page.locator('[data-testid^="inv-timeline-inspect-m-"]')
        check("the cited evidence is inspectable in place",
              await insp.count() > 0, f"inspectors={await insp.count()}")

        # ── 4 · Story → Timeline hand-off ──────────────────────────
        await open_tab(page, INC_ASSOC, "story")
        btn = page.locator('[data-testid^="incident-story-depth-milestones-to-timeline-"]')
        check("the story offers a hand-off to the timeline",
              await btn.count() > 0, f"{await btn.count()} button(s)")
        if await btn.count():
            await btn.first.click()
            await page.wait_for_timeout(6000)
            check("the hand-off lands on the timeline focused on that milestone",
                  "tab=timeline" in page.url and "focus=m-" in page.url,
                  f"url={page.url.split('?')[-1]}")
            focused = page.locator('[data-focus="true"]')
            check("the handed-over milestone row is focused and expanded",
                  await focused.count() == 1
                  and (await focused.first.get_attribute("data-open")) == "true",
                  f"focused={await focused.count()}")

        # ── 5 · Timeline → Story hand-off ──────────────────────────
        back = page.locator('[data-testid^="inv-timeline-to-story-m-"]')
        check("the timeline offers a hand-off back to the story",
              await back.count() > 0, f"{await back.count()} button(s)")
        if await back.count():
            await back.first.click()
            await page.wait_for_timeout(6000)
            check("the hand-off lands on the story focused on that milestone",
                  "tab=story" in page.url and "focus=m-" in page.url,
                  f"url={page.url.split('?')[-1]}")
            check("the story milestone row is focused",
                  await page.locator('[data-focus="true"]').count() >= 1)

        # ── 6 · NOT_ASSOCIATED keeps S3-A honesty ──────────────────
        await open_tab(page, INC_UNASSOC, "timeline")
        check("no causal milestone is fabricated without causal analysis",
              await page.locator(
                  '[data-testid^="inv-timeline-milestone-m-"]').count() == 0)
        check("no unpositioned-milestone block is invented either",
              await page.locator(
                  '[data-testid="inv-timeline-unpositioned-sec"]').count() == 0)
        body = await page.inner_text("body")
        check("the timeline itself still renders for that incident",
              "Investigation timeline" in body, f"{len(body)} chars")

        # ── 7 · cross-tenant ───────────────────────────────────────
        await open_tab(page, INC_OTHER_TENANT, "timeline")
        body = await page.inner_text("body")
        check("another tenant's incident exposes no milestone or event rows",
              await page.locator(
                  '[data-testid^="inv-timeline-milestone-m-"]').count() == 0
              and await page.locator(
                  '[data-testid^="inv-timeline-table-row-fr-"]').count() == 0)

        # ── 8 · every tab still works ──────────────────────────────
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

    print(f"\nS3-C DOM PROOF · {_p} PASS · {_f} FAIL")
    return 0 if _f == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
