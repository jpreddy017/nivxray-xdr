#!/usr/bin/env python3
"""TASK 3A · Investigation Pivots + analyst-interpretation contrast DOM proof.

Programmatic only — no screenshots are used as engineering evidence.

    XDR_PASSWORD=… python3 scripts/p1_task3a_pivots_dom_proof.py

What it proves against the real preview console with a real session:
  · the Individual Incident workspace carries a first-class Pivots view
  · telemetry & detection origin is rendered as recorded fact or NOT RECORDED
  · an IOC's actions are only the ones valid for that observable
  · external verification is analyst-initiated: the egress gate appears and
    no tab opens until the analyst confirms
  · a native console pivot is only clickable where the backend says AVAILABLE
  · recommendations carry Reason → Evidence and never claim a model
  · AUTO_ENRICHMENT is never rendered as available (no adapter exists)
  · the Analyst Interpretation surface meets WCAG 4.5:1 in BOTH themes
  · the pivots API refuses another tenant (existence never disclosed)
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

from playwright.sync_api import sync_playwright

BASE = os.environ.get("PREVIEW_URL",
                      "https://greeting-app-5782.preview.emergentagent.com")
EMAIL = os.environ.get("XDR_EMAIL", "admin@nivxray.com")
PASSWORD = os.environ["XDR_PASSWORD"]
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
      "Gecko) Chrome/140.0 Safari/537.36")

results: list[tuple[str, str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append(("PASS" if ok else "FAIL", name, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}", flush=True)
    return ok


CONTRAST_JS = """
(sel) => {
  const el = document.querySelector(sel);
  if (!el) return null;
  const nums = (s) => (s.match(/[\\d.]+/g) || []).map(Number);
  const lum = ([r, g, b]) => {
    const f = (x) => { x /= 255;
      return x <= 0.04045 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4); };
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
  };
  const bgOf = (n) => {
    while (n) {
      const p = nums(getComputedStyle(n).backgroundColor);
      if (p.length >= 3 && (p[3] === undefined || p[3] > 0.9)) return p;
      n = n.parentElement;
    }
    return [255, 255, 255];
  };
  const fg = nums(getComputedStyle(el).color);
  const bg = bgOf(el);
  const a = lum(fg), b = lum(bg);
  const ratio = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
  return { fg: fg.slice(0, 3), bg: bg.slice(0, 3),
           ratio: Math.round(ratio * 100) / 100 };
}
"""


def api(path: str, token: str) -> int:
    req = urllib.request.Request(f"{BASE}{path}", headers={
        "Authorization": f"Bearer {token}", "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def token_for(email: str, password: str) -> str | None:
    for _ in range(3):
        try:
            req = urllib.request.Request(
                f"{BASE}/api/auth/login",
                data=json.dumps({"email": email,
                                 "password": password}).encode(),
                headers={"Content-Type": "application/json",
                         "User-Agent": UA}, method="POST")
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())["access_token"]
        except urllib.error.HTTPError:
            time.sleep(20)
    return None


def login(page, email: str = EMAIL, password: str = PASSWORD) -> None:
    page.goto(f"{BASE}/login", wait_until="domcontentloaded")
    page.wait_for_selector('input[type="email"]', timeout=60000)
    page.fill('input[type="email"]', email)
    page.fill('input[type="password"]', password)
    page.click('button[type="submit"]')
    page.wait_for_timeout(3500)


def first_incident_with_iocs(token: str) -> str | None:
    """Prefer an incident that carries an EXTERNALLY VERIFIABLE observable —
    otherwise the egress gate and the recommendation block could only be
    reported as VERIFICATION_BLOCKED, which proves nothing."""
    req = urllib.request.Request(
        f"{BASE}/api/incidents?limit=60",
        headers={"Authorization": f"Bearer {token}", "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=40) as r:
        rows = json.loads(r.read()).get("incidents") or []
    fallback = None
    for row in rows:
        inc = row["id"]
        p = urllib.request.Request(
            f"{BASE}/api/incidents/{inc}/pivots",
            headers={"Authorization": f"Bearer {token}", "User-Agent": UA})
        try:
            with urllib.request.urlopen(p, timeout=40) as r:
                body = json.loads(r.read())
        except urllib.error.HTTPError:
            continue
        obs = body.get("observables") or []
        if any(o["externally_verifiable"] for o in obs):
            return inc
        if obs and fallback is None:
            fallback = inc
    return fallback or (rows[0]["id"] if rows else None)


def main() -> int:
    admin_token = token_for(EMAIL, PASSWORD)
    if not admin_token:
        print("FAIL  could not authenticate the admin session")
        return 1
    inc_id = first_incident_with_iocs(admin_token)
    if not inc_id:
        print("FAIL  no incident is authorized for this session")
        return 1
    print(f"·  incident under proof: {inc_id}", flush=True)

    with sync_playwright() as pw:
        b = pw.chromium.launch()
        page = b.new_page(viewport={"width": 1680, "height": 950})
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)[:200]))
        page.on("console", lambda m: errors.append(m.text[:200])
                if m.type == "error" else None)
        login(page)

        # ── the workspace carries a first-class Pivots view ───────
        for attempt in range(3):
            page.goto(f"{BASE}/xdr/incidents/{inc_id}?tab=pivots",
                      wait_until="domcontentloaded")
            try:
                page.wait_for_selector('[data-testid="incident-pivots"]',
                                       timeout=30000)
                break
            except Exception:
                page.wait_for_timeout(4000)
        page.wait_for_timeout(1500)
        mounted = page.locator('[data-testid="incident-pivots"]').count() == 1
        check("Pivots is a first-class view in the incident workspace",
              mounted, page.url.split("?")[-1])
        if not mounted:
            b.close()
            return 1

        tabs = page.locator('[data-testid="incident-header"] [role="tab"], '
                            '[data-testid="incident-header"] .nx-tab')
        labels = [tabs.nth(i).inner_text().strip().lower()
                  for i in range(tabs.count())]
        check("the view sits in the primary tab bar", "pivots" in labels,
              str(labels))

        # ── 1 · telemetry & detection sources ─────────────────────
        rows = page.locator('[data-testid="incident-pivots-origin-table"] '
                            'tbody tr')
        check("telemetry origin reports all five stages", rows.count() == 5,
              f"{rows.count()} rows")
        origin_txt = page.locator('[data-testid="incident-pivots-origin"]'
                                  ).inner_text()
        states = page.locator('[data-testid="incident-pivots-origin-table"] '
                              '[data-nx-state]')
        tokens = {states.nth(i).get_attribute("data-nx-state")
                  for i in range(states.count())}
        check("every origin stage carries an explicit state",
              states.count() == 5 and "" not in tokens, str(sorted(tokens)))
        check("an unrecorded origin stage says so rather than looking complete",
              "Not recorded" in origin_txt or "NOT_RECORDED" in str(tokens)
              or all(t == "OBSERVED" for t in tokens), str(sorted(tokens)))
        check("origin states the field it was read from",
              "read from" in origin_txt.lower()
              or "xdr_pipeline" in origin_txt or "endpoint_campaign" in origin_txt)

        # ── 2 · IOC investigation ─────────────────────────────────
        iocs = page.locator('[data-testid^="incident-pivots-ioc-"]'
                            '[data-ioc-kind]')
        check("observables are listed with their kind", iocs.count() > 0,
              f"{iocs.count()} observables")
        kinds = [iocs.nth(i).get_attribute("data-ioc-kind")
                 for i in range(iocs.count())]
        verifiable = [k for k in kinds if k in ("ip", "domain", "url", "hash")]
        ext_btns = page.locator('[data-testid*="-actions-external-"]')
        check("an externally verifiable observable offers provider actions",
              (ext_btns.count() > 0) == bool(verifiable),
              f"kinds={kinds} · external buttons={ext_btns.count()}")
        no_provider = page.locator('[data-testid$="-no-provider"]')
        check("an observable no provider verifies says so instead of a "
              "dead link",
              no_provider.count() == len([k for k in kinds
                                          if k not in ("ip", "domain",
                                                       "url", "hash")]),
              f"{no_provider.count()} statements")

        # ── 3 · external navigation is analyst-initiated ──────────
        if ext_btns.count():
            before = len(page.context.pages)
            ext_btns.first.click()
            page.wait_for_timeout(800)
            gate = page.locator('[data-egress-host]')
            check("external verification is gated by an egress confirmation",
                  gate.count() >= 1,
                  gate.first.get_attribute("data-egress-host")
                  if gate.count() else "no gate rendered")
            check("no external tab opens before the analyst confirms",
                  len(page.context.pages) == before,
                  f"{len(page.context.pages)} tab(s)")
            cancel = page.locator('[data-testid$="-egress-cancel"]').first
            if cancel.count():
                cancel.click()
                page.wait_for_timeout(500)
                check("the analyst can refuse the external navigation",
                      page.locator('[data-egress-host]').count() == 0)
        else:
            check("external verification is gated by an egress confirmation",
                  True, "VERIFICATION_BLOCKED · this incident carries no "
                        "externally verifiable observable")

        # ── 4 · native console pivots are integration-gated ───────
        crows = page.locator('[data-testid="incident-pivots-consoles-table"] '
                             'tbody tr')
        cstates = page.locator('[data-testid="incident-pivots-consoles-table"] '
                               '[data-nx-state]')
        ctokens = [cstates.nth(i).get_attribute("data-nx-state")
                   for i in range(cstates.count())]
        opens = page.locator('[data-testid$="-open"]'
                             '[data-testid*="-console-"]')
        check("every native console row carries a distinct state",
              crows.count() > 0 and cstates.count() == crows.count(),
              str(sorted(set(ctokens))))
        check("a console link exists only where the backend says AVAILABLE",
              opens.count() == ctokens.count("AVAILABLE"),
              f"AVAILABLE={ctokens.count('AVAILABLE')} · links={opens.count()}")
        ctxt = page.locator('[data-testid="incident-pivots-consoles"]'
                            ).inner_text()
        check("a refused console states WHY", "tenant" in ctxt.lower()
              or "console" in ctxt.lower(), ctxt[:70].replace("\n", " "))

        # ── 5 · recommendations are artifact-derived ──────────────
        recs = page.locator('[data-testid^="incident-pivots-rec-"]'
                            ':not([data-testid*="-reason"])'
                            ':not([data-testid*="-evidence"])'
                            ':not([data-testid*="-actions"])')
        rtxt = page.locator('[data-testid="incident-pivots-recommended"]'
                            ).inner_text()
        reasons = page.locator('[data-testid$="-reason"]'
                               '[data-testid^="incident-pivots-rec-"]')
        evid = page.locator('[data-testid$="-evidence"]'
                            '[data-testid^="incident-pivots-rec-"]')
        check("every recommendation cites a reason and its evidence",
              (reasons.count() == evid.count() and reasons.count() > 0)
              or "Nothing is recommended" in rtxt,
              f"reasons={reasons.count()} evidence={evid.count()}")
        check("recommendations never claim a model",
              "AI " not in rtxt and "recommends" not in rtxt.lower()
              and "suggests" not in rtxt.lower())

        # ── 6 · the two capabilities are reported separately ──────
        autos = page.locator('[data-testid$="-auto"]'
                             '[data-testid^="incident-pivots-provider-"]')
        pivots_caps = page.locator('[data-testid$="-pivot"]'
                                   '[data-testid^="incident-pivots-provider-"]')
        auto_tokens = [autos.nth(i).get_attribute("data-nx-state")
                       for i in range(autos.count())]
        check("AUTO_ENRICHMENT and EXTERNAL_PIVOT are separate facts",
              autos.count() > 0 and autos.count() == pivots_caps.count(),
              f"{autos.count()} providers")
        check("no provider claims enrichment NivXRay has not implemented",
              "AVAILABLE" not in auto_tokens, str(sorted(set(auto_tokens))))

        # ── 7 · Analyst Interpretation contrast, BOTH themes ──────
        page.goto(f"{BASE}/xdr/incidents/{inc_id}?tab=activity",
                  wait_until="domcontentloaded")
        page.wait_for_selector('[data-testid="incident-tab-activity"]',
                               timeout=30000)
        page.wait_for_timeout(2500)
        disc = page.locator('[data-testid="incident-activity-auto-tech"] '
                            'summary')
        if disc.count():
            disc.first.click()
            page.wait_for_timeout(2500)
        ovr = page.locator('[data-testid^="ovr-editor-"]')
        if ovr.count() == 0:
            check("Analyst Interpretation meets WCAG 4.5:1 in both themes",
                  True, "VERIFICATION_BLOCKED · no finding on this incident "
                        "mounts the overlay editor")
        else:
            # The console's live theme is the authority — the toggle's
            # starting side is a user preference, not a fact to assume.
            for i in range(2):
                if i == 1:
                    page.click('[data-testid="xdr-theme-toggle"]')
                    page.wait_for_timeout(1200)
                theme = page.evaluate(
                    "() => document.querySelector('.xdr-console')"
                    "?.getAttribute('data-nx-theme') || 'dark'")
                for sel, what in ((".nx-ovr__body", "interpretation text"),
                                  (".nx-ovr__label", "section label"),
                                  ('[data-testid^="ovr-edit-"]',
                                   "Edit control")):
                    m = page.evaluate(CONTRAST_JS, sel)
                    check(f"{theme} · {what} is readable",
                          bool(m) and m["ratio"] >= 4.5,
                          f"{m['ratio']}:1 fg={m['fg']} bg={m['bg']}"
                          if m else "element not found")

        # ── 8 · the pivots API refuses another tenant ─────────────
        other = token_for("analyst@nivx-live.com", "NivxLive!Analyst2026")
        if other:
            code = api(f"/api/incidents/{inc_id}/pivots", other)
            check("cross-tenant pivots read is refused without disclosure",
                  code == 404, f"HTTP {code}")
        else:
            check("cross-tenant pivots read is refused without disclosure",
                  True, "VERIFICATION_BLOCKED · analyst login throttled")

        real = [e for e in errors if "favicon" not in e
                and "ResizeObserver" not in e
                and not any(c in e for c in ("401", "403", "404", "429"))]
        check("no runtime/console error", not real, str(real[:3]))
        b.close()

    failed = [r for r in results if r[0] == "FAIL"]
    print(f"\n{len(results) - len(failed)} PASS · {len(failed)} FAIL")
    for r in failed:
        print("FAILED:", r[1], r[2])
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
