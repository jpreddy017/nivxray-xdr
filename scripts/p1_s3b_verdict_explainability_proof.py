"""S3-B · VERDICT EXPLAINABILITY — authorization matrix + DOM proof.

Part 1 (API, real JWTs): the ONE backend change — the engine's negative
explainability read now carries the same authority as the other engine-depth
reads (S2-mini). Anonymous denied · own-tenant analyst allowed · cross-tenant
404 · engine-native case analyst-denied / admin-allowed · fabricated identity
cannot elevate · the analyst still cannot mutate or administer the engine.

Part 2 (real browser): the analyst-facing surface on the Individual Incident.
"""
import asyncio
import json
import sys
import urllib.error
import urllib.request

from playwright.async_api import async_playwright

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
      "Gecko) Chrome/125.0 Safari/537.36")
BASE = ""
with open("/app/frontend/.env") as f:
    for line in f:
        if line.startswith("REACT_APP_BACKEND_URL="):
            BASE = line.split("=", 1)[1].strip().rstrip("/")

ADMIN = ("admin@nivxray.com", "uulVDp5cCSB3Hva99s7UUAwK")
OWN = ("analyst@default.com", "DefaultCo!Analyst2026")
OTHER = ("analyst@nivx-live.com", "NivxLive!Analyst2026")

INC_ASSOC = "inc_c1edae99d4e541c58552"       # default · causal analysis exists
INC_UNASSOC = "inc_r381_promote"             # default · none recorded
ENGINE_NATIVE = "case_dfir_bumblebee_akira_2026"
EXPLAIN = "/investigation/explain/ransomware"

_p = _f = 0


def check(name, cond, detail=""):
    global _p, _f
    if cond:
        _p += 1
        print(f"PASS · {name} {detail}")
    else:
        _f += 1
        print(f"FAIL · {name} {detail}")


def call(method, path, token=None, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{BASE}{path}", data=data, method=method)
    req.add_header("User-Agent", UA)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def login(cred):
    st, b = call("POST", "/api/auth/login",
                 body={"email": cred[0], "password": cred[1]})
    if st != 200:
        print(f"ABORT · login {cred[0]} → {st}")
        sys.exit(2)
    return json.loads(b)["access_token"]


def api_matrix():
    t_admin, t_own, t_other = login(ADMIN), login(OWN), login(OTHER)
    p = f"/api/v2/cases/{INC_ASSOC}{EXPLAIN}"

    st, _ = call("GET", p)
    check("anonymous negative explainability", st in (401, 403), f"→ {st}")

    st, b = call("GET", p, t_own)
    d = json.loads(b) if st == 200 else {}
    check("own-tenant analyst reads negative explainability",
          st == 200 and "verdict_line" in d
          and isinstance(d.get("missing_required"), list), f"→ {st}")

    st, _ = call("GET", p, t_other)
    check("cross-tenant negative explainability", st == 404, f"→ {st}")

    st, _ = call("GET", p, t_admin)
    check("admin negative explainability unchanged", st == 200, f"→ {st}")

    st, _ = call("GET", f"/api/v2/cases/{ENGINE_NATIVE}{EXPLAIN}", t_admin)
    check("admin reads the engine-native case", st == 200, f"→ {st}")
    st, _ = call("GET", f"/api/v2/cases/{ENGINE_NATIVE}{EXPLAIN}", t_own)
    check("analyst CANNOT read the engine-native case", st == 404, f"→ {st}")

    for q, h in ((f"?tenant_id=default", {}), (f"?customer=default", {}),
                 ("", {"X-Tenant-Id": "default"}),
                 ("", {"X-Principal-Id": "admin@nivxray.com"})):
        st, _ = call("GET", f"{p}{q}", t_other, headers=h)
        check(f"fabricated identity cannot elevate {q or h}", st == 404,
              f"→ {st}")

    # profile is a read parameter, never a configuration write
    st, _ = call("POST", "/api/v2/cases", t_own, body={"name": "refused"})
    check("analyst cannot create an engine case", st in (401, 403), f"→ {st}")
    st, _ = call("GET", "/api/v2/cases", t_own)
    check("analyst cannot list the engine registry", st in (401, 403),
          f"→ {st}")


async def login_ui(page, cred):
    await page.goto(f"{BASE}/login", wait_until="domcontentloaded")
    await page.fill('input[type="email"]', cred[0])
    await page.fill('input[type="password"]', cred[1])
    await page.click('button[type="submit"]')
    await page.wait_for_timeout(3500)


async def overview(page, incident_id):
    for _ in (1, 2):
        await page.goto(f"{BASE}/xdr/incidents/{incident_id}?tab=overview",
                        wait_until="domcontentloaded")
        try:
            await page.wait_for_selector(
                '[data-testid="incident-generate-report"]', timeout=25000)
        except Exception:                                      # noqa: BLE001
            pass
        await page.wait_for_timeout(5000)
        if len(await page.inner_text("body")) > 1000:
            return


async def dom_proof():
    async with async_playwright() as pw:
        b = await pw.chromium.launch(args=["--no-sandbox"])
        page = await b.new_page(viewport={"width": 1680, "height": 1000})
        await login_ui(page, OWN)

        await overview(page, INC_ASSOC)
        root = page.locator('[data-testid="incident-verdict-explainability"]')
        check("surface mounted on the incident overview",
              await root.count() == 1, f"count={await root.count()}")

        vd = page.locator('[data-testid="incident-verdict-explainability-verdict"]')
        vtxt = (await vd.first.inner_text()) if await vd.count() else ""
        check("authoritative verdict displayed", await vd.count() == 1
              and len(vtxt) > 3, f"text={vtxt[:60]!r}")

        m = page.locator('[data-testid="incident-verdict-explainability-metrics"]')
        mtxt = (await m.first.inner_text()) if await m.count() else ""
        check("confidence and analysis completeness stay independent",
              "CONFIDENCE" in mtxt.upper()
              and "ANALYSIS COMPLETENESS" in mtxt.upper()
              and "NOT AVAILABLE" in mtxt.upper(), f"text={mtxt[:140]!r}")

        sup = page.locator('[data-testid^="incident-verdict-explainability-supports-row-"]')
        n_sup = await sup.count()
        check("supporting reasons displayed", n_sup > 0, f"{n_sup} reasons")

        cited = await page.locator('[data-nx-state="EVIDENCE_CITED"]').count()
        uncited = await page.locator('[data-nx-state="NO_EVENT_CITED"]').count()
        check("each reason declares its basis", (cited + uncited) >= n_sup,
              f"{cited} evidence-cited · {uncited} stated without an event")

        if n_sup:
            await sup.first.click()
            await page.wait_for_timeout(700)
            det = page.locator('[data-testid^="incident-verdict-explainability-supports-detail-"]')
            dtxt = (await det.first.inner_text()) if await det.count() else ""
            check("evidence provenance reachable",
                  await det.count() > 0 and "Supporting evidence" in dtxt,
                  f"detail={await det.count()}")

        hyp = page.locator('[data-testid^="incident-verdict-explainability-hypothesis-"][data-testid$="-toggle"]')
        n_h = await hyp.count()
        check("engine hypotheses offered under progressive disclosure",
              n_h > 0, f"{n_h} hypotheses")
        if n_h:
            await hyp.first.click()
            await page.wait_for_timeout(2500)
            line = page.locator('[data-testid$="-line"]')
            absent = page.locator('[data-testid$="-absent"]')
            ltxt = (await line.first.inner_text()) if await line.count() else ""
            atxt = (await absent.first.inner_text()) if await absent.count() else ""
            check("limiting evidence displayed for a hypothesis",
                  await line.count() > 0 and len(ltxt) > 5
                  and "NOT OBSERVED" in atxt.upper(),
                  f"line={ltxt[:70]!r}")

        gaps = page.locator('[data-testid="incident-verdict-explainability-gaps"]')
        gtxt = (await gaps.first.inner_text()) if await gaps.count() else ""
        n_no = await page.locator(
            '[data-testid^="incident-verdict-explainability-gaps-notobserved-"]').count()
        n_un = await page.locator(
            '[data-testid^="incident-verdict-explainability-gaps-unavailable-"]').count()
        check("missing visibility is separated from negative evidence",
              n_no > 0 and n_un > 0
              and "Searched · not observed" in gtxt
              and "telemetry not available" in gtxt.lower(),
              f"{n_no} searched-not-observed · {n_un} visibility gaps")
        check("the two absence semantics are stated, not implied",
              "not evidence of absence" in gtxt.lower()
              and "not negative evidence" in gtxt.lower())

        body = await page.inner_text("body")
        leaks = [w for w in ("v2_cases", "shadow_observation", "case_authz",
                             "soc_balanced") if w in body]
        check("no implementation vocabulary in primary content", not leaks,
              f"leaks={leaks}")
        check("no engine profile selector is exposed to the analyst",
              "profile" not in body.lower().split("technical details")[0])

        # ── NOT_ASSOCIATED ──────────────────────────────────────────
        await overview(page, INC_UNASSOC)
        na = page.locator('[data-testid="incident-verdict-explainability-not-associated"]')
        check("unassociated incident states the causal explanation is absent",
              await na.count() == 1, f"count={await na.count()}")
        if await na.count():
            t = await na.first.inner_text()
            check("the statement keeps NOT ASSOCIATED ≠ BENIGN",
                  "benign" in t.lower(), f"text={t[:80]!r}")
        check("no hypothesis block on an unassociated incident",
              await page.locator(
                  '[data-testid^="incident-verdict-explainability-hypothesis-"]'
              ).count() == 0)
        check("no fabricated supporting reasons on an unassociated incident",
              await page.locator(
                  '[data-testid^="incident-verdict-explainability-supports-row-"]'
              ).count() == 0)

        # ── the existing tabs still render ──────────────────────────
        for tab in ("overview", "story", "evidence", "activity"):
            txt = ""
            for _ in (1, 2):
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
            check(f"tab still renders · {tab}",
                  len(txt) > 1000 and "SURFACE ERROR" not in txt.upper(),
                  f"{len(txt)} chars")

        await b.close()


def main():
    print(f"edge: {BASE}\n--- PART 1 · authorization matrix ---")
    api_matrix()
    print("\n--- PART 2 · DOM proof ---")
    asyncio.run(dom_proof())
    print(f"\nS3-B PROOF · {_p} PASS · {_f} FAIL")
    return 0 if _f == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
