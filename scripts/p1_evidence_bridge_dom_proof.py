"""P1 · EVIDENCE NAMESPACE BRIDGE — programmatic DOM proof (no screenshots).

Real browser, real login, real preview edge. Proves the S3-D path the owner
asked for, in the console:

  Causal anchor → View Evidence → the EXACT canonical evidence record of THIS
  incident → EvidenceInspector → original source / provenance

and that an unbridged or unretained reference keeps its own namespace and is
never replaced by a nearby record.

The incident used is the one the real pipeline promoted during
`scripts/p1_evidence_namespace_bridge_e2e_proof.py` (TEST/SYNTHETIC tenant,
preview only).
"""
import asyncio
import sys

from playwright.async_api import async_playwright

BASE = ""
with open("/app/frontend/.env") as f:
    for line in f:
        if line.startswith("REACT_APP_BACKEND_URL="):
            BASE = line.split("=", 1)[1].strip().rstrip("/")

ADMIN = ("admin@nivxray.com", "uulVDp5cCSB3Hva99s7UUAwK")

# The freshly ingested, BRIDGED incident (proof tenant) and its anchor.
BRIDGED_INC = "inc_f2760485f3da40e6879e"
BRIDGED_ANCHOR = "proc_fd2bf0768346"
BRIDGED_CANONICAL = "sysmon-1-dffefe701c0245318ebc9166d4f0bd93"
# An incident whose canonical reference exists but whose canonical record is
# not retained → REFERENCED_RECORD_ABSENT.
ABSENT_INC = "inc_a4ba2ecf80b14f398547"

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
        await page.wait_for_timeout(5000)
        if len(await page.inner_text("body")) > 800:
            return


async def main():
    async with async_playwright() as pw:
        b = await pw.chromium.launch(args=["--no-sandbox"])
        page = await b.new_page(viewport={"width": 1680, "height": 1100})
        await login(page, ADMIN)

        # ── 1 · the canonical evidence records are a real, identified row ──
        await open_tab(page, BRIDGED_INC, "evidence")
        sec = page.locator('[data-testid="xdr-record-canonical-evidence"]')
        check("canonical evidence section renders", await sec.count() > 0)
        table = page.locator(
            '[data-testid="xdr-record-canonical-evidence-table"]')
        check("canonical evidence table renders", await table.count() > 0)
        text = await sec.inner_text() if await sec.count() else ""
        check("the row is identified by the canonical evidence id",
              BRIDGED_CANONICAL in text, BRIDGED_CANONICAL)
        check("its bridge state is stated as BRIDGED", "BRIDGED" in text)
        row = page.locator(
            f'[data-testid="xdr-record-canonical-evidence-row-'
            f'{BRIDGED_CANONICAL}"]')
        check("the exact record row is addressable", await row.count() > 0)
        if await row.count():
            rtext = await row.inner_text()
            check("  it names where the incident references it",
                  "incident_pipeline" in rtext or "case_observation" in rtext,
                  rtext[:120].replace("\n", " "))
            check("  it reports the raw source of the evidence",
                  "Raw source" in rtext or "edr_raw_events" in rtext
                  or "retained on the canonical record" in rtext)
        insp = page.locator(
            f'[data-testid="xdr-record-canonical-evidence-inspect-'
            f'{BRIDGED_CANONICAL}"]')
        check("the shared inspector is reachable from the record",
              await insp.count() > 0)
        if await insp.count():
            itext = await insp.inner_text()
            check("  and it RESOLVES the record (not NOT PRESENT)",
                  "NOT PRESENT" not in itext.upper(),
                  itext[:120].replace("\n", " "))
            check("  reporting the normalizer / source provenance",
                  "NORMALIZER" in itext.upper() or "SOURCE" in itext.upper())

        # ── 2 · anchor → View Evidence → that same exact record ───────────
        await open_tab(page, BRIDGED_INC, "evidence",
                       f"&focus={BRIDGED_ANCHOR}")
        anchor = page.locator('[data-testid="xdr-record-evidence-anchor"]')
        check("the anchor evidence section renders",
              await anchor.count() > 0)
        atext = await anchor.inner_text() if await anchor.count() else ""
        check("the anchor is named, not guessed", BRIDGED_ANCHOR in atext,
              BRIDGED_ANCHOR)
        check("the cited record carries its canonical evidence id",
              BRIDGED_CANONICAL in atext)
        check("and the anchor row states BRIDGED", "BRIDGED" in atext)
        ainsp = page.locator(
            f'[data-testid="xdr-record-evidence-anchor-inspect-'
            f'{BRIDGED_CANONICAL}"]')
        check("the anchor inspects the CANONICAL record, not the frame id",
              await ainsp.count() > 0)
        if await ainsp.count():
            itext = await ainsp.inner_text()
            check("  the inspector resolves it",
                  "NOT PRESENT" not in itext.upper(),
                  itext[:120].replace("\n", " "))
        sel = page.locator(
            '[data-testid="xdr-record-canonical-evidence"]')
        check("the same record is marked as the selected anchor's evidence",
              "SELECTED ANCHOR" in (await sel.inner_text()
                                    if await sel.count() else ""))

        # ── 3 · an unretained reference is truthful, never substituted ────
        await open_tab(page, ABSENT_INC, "evidence")
        sec2 = page.locator('[data-testid="xdr-record-canonical-evidence"]')
        t2 = await sec2.inner_text() if await sec2.count() else ""
        check("the unretained-reference incident renders its own state",
              await sec2.count() > 0)
        check("it is reported as REFERENCED_RECORD_ABSENT",
              "REFERENCED_RECORD_ABSENT" in t2, t2[:160].replace("\n", " "))
        check("it does NOT claim the record was found",
              "BRIDGED" not in t2.replace("REFERENCED_RECORD_ABSENT", ""))
        check("and it states that this is not an absence of evidence",
              "not an absence of evidence" in t2)

        await b.close()
    print(f"\n{_p} passed · {_f} failed")
    return 1 if _f else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
