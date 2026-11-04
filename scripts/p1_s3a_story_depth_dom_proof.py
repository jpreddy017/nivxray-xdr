"""S3-A · INCIDENT STORY DEPTH — programmatic DOM proof (no screenshots).

Real browser, real login, real preview edge. Verifies the promoted surface on
an ASSOCIATED incident, the honest state on a NOT_ASSOCIATED incident, tenant
isolation, and that the existing incident tabs still render.
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

INC_ASSOC = "inc_c1edae99d4e541c58552"      # default   · causal analysis exists
INC_UNASSOC = "inc_r381_promote"            # default   · none recorded
INC_OTHER_TENANT = "inc_7742fe7120174204be36"   # nivx-live

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


async def story(page, incident_id):
    await page.goto(f"{BASE}/xdr/incidents/{incident_id}?tab=story",
                    wait_until="domcontentloaded")
    await page.wait_for_timeout(6000)


async def main():
    async with async_playwright() as pw:
        b = await pw.chromium.launch(args=["--no-sandbox"])
        page = await b.new_page(viewport={"width": 1680, "height": 1000})
        await login(page, OWN)

        # ── 1 · ASSOCIATED incident ─────────────────────────────────
        await story(page, INC_ASSOC)
        root = page.locator('[data-testid="incident-story-depth"]')
        check("surface mounted", await root.count() == 1,
              f"count={await root.count()}")
        st = await root.first.get_attribute("data-nx-state") \
            if await root.count() else None
        check("association state is ASSOCIATED", st == "ASSOCIATED", f"→ {st}")

        rows = page.locator('[data-testid^="incident-story-depth-milestones-row-"]')
        n_rows = await rows.count()
        check("milestones render", n_rows > 0, f"{n_rows} milestone rows")

        metrics = page.locator('[data-testid="incident-story-depth-metrics"]')
        check("metric strip renders", await metrics.count() == 1)

        stages = page.locator('[data-testid^="incident-story-depth-stages-"]')
        n_st = await stages.count()
        covered = await page.locator(
            '[data-testid^="incident-story-depth-stages-"][data-covered="true"]'
        ).count()
        not_obs = await page.locator(
            '[data-testid^="incident-story-depth-stages-"][data-covered="false"]'
        ).count()
        check("attack stages render with evidence-placed vs NOT OBSERVED",
              n_st >= 14 and covered > 0 and not_obs > 0,
              f"{n_st} stages · {covered} placed · {not_obs} not observed")

        anchors = page.locator('[data-testid^="incident-story-depth-anchors-row-"]')
        n_a = await anchors.count()
        ents = await page.locator(
            '[data-testid^="incident-story-depth-anchors-entity-"]').count()
        check("causal anchors render as entities", n_a > 0 and ents > 0,
              f"{n_a} anchors · {ents} entity refs")

        rels = page.locator('[data-testid^="incident-story-depth-relationships-rel-"],'
                            '[data-testid^="incident-story-depth-relationships-struct-"]')
        n_r = await rels.count()
        cited = await page.locator('[data-nx-state="EVIDENCE_CITED"]').count()
        derived = await page.locator('[data-nx-state="ENGINE_DERIVED"]').count()
        check("relationships render, each classified",
              n_r > 0 and (cited + derived) >= n_r,
              f"{n_r} relationships · {cited} evidence-cited · "
              f"{derived} derived")

        # provenance is reachable (L3): open the first milestone row
        if n_rows:
            await rows.first.click()
            await page.wait_for_timeout(800)
            det = page.locator('[data-testid^="incident-story-depth-milestones-detail-"]')
            txt = (await det.first.inner_text()) if await det.count() else ""
            check("milestone provenance is reachable",
                  await det.count() > 0 and "Supporting evidence" in txt,
                  f"detail rows={await det.count()}")

        # no engine implementation vocabulary in primary content
        body = await page.inner_text("body")
        leaks = [w for w in ("v2_cases", "shadow_observation", "case_authz",
                             "IKG engine") if w in body]
        check("no implementation vocabulary in the analyst surface",
              not leaks, f"leaks={leaks}")

        # ── 2 · NOT_ASSOCIATED incident ─────────────────────────────
        await story(page, INC_UNASSOC)
        na = page.locator('[data-testid="incident-story-depth-not-associated"]')
        check("unassociated incident states it explicitly",
              await na.count() == 1, f"count={await na.count()}")
        if await na.count():
            t = await na.first.inner_text()
            check("the statement carries the server's reason and the "
                  "NOT BENIGN distinction",
                  "not available" in t.lower()
                  and "benign" in t.lower(),
                  f"text={t[:90]!r}")
        check("no fabricated zero metrics on an unassociated incident",
              await page.locator(
                  '[data-testid="incident-story-depth-metrics"]').count() == 0)
        check("no milestone table on an unassociated incident",
              await page.locator(
                  '[data-testid^="incident-story-depth-milestones-row-"]'
              ).count() == 0)
        check("no attack stage strip on an unassociated incident",
              await page.locator(
                  '[data-testid^="incident-story-depth-stages-"]').count() == 0)

        # ── 3 · tenant isolation ────────────────────────────────────
        await story(page, INC_OTHER_TENANT)
        check("another tenant's incident exposes no causal analysis",
              await page.locator(
                  '[data-testid="incident-story-depth"][data-nx-state="ASSOCIATED"]'
              ).count() == 0)
        body = await page.inner_text("body")
        check("another tenant's incident discloses no engine content",
              "Attack milestones" not in body)

        # ── 4 · the existing tabs still render ──────────────────────
        # The preview edge throttles rapid sequential navigation (429 /
        # bot challenge), so each tab waits for a real anchor element and
        # is retried once — a slow edge is not a product defect.
        for tab in ("overview", "story", "timeline", "evidence", "detections",
                    "response", "activity"):
            txt = ""
            for attempt in (1, 2):
                await page.goto(f"{BASE}/xdr/incidents/{INC_ASSOC}?tab={tab}",
                                wait_until="domcontentloaded")
                try:
                    await page.wait_for_selector(
                        '[data-testid="incident-generate-report"]',
                        timeout=25000)
                except Exception:                              # noqa: BLE001
                    pass
                await page.wait_for_timeout(4000)
                txt = await page.inner_text("body")
                if len(txt) > 1000:
                    break
                await page.wait_for_timeout(6000)
            ok = len(txt) > 1000 and "SURFACE ERROR" not in txt.upper()
            check(f"tab still renders · {tab}", ok, f"{len(txt)} chars")

        await b.close()

    print(f"\nS3-A DOM PROOF · {_p} PASS · {_f} FAIL")
    return 0 if _f == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
