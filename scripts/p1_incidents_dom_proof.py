#!/usr/bin/env python3
"""TASK 2 · Incidents DOM proof — programmatic, no screenshots.

Drives the real preview console with a real session and asserts the analyst
workflow: queue → search/filter → contextual pane → investigation pivot,
in BOTH themes, plus overflow and console-error gates.

    python3 scripts/p1_incidents_dom_proof.py
"""
from __future__ import annotations

import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("PREVIEW_URL",
                      "https://greeting-app-5782.preview.emergentagent.com")
EMAIL = os.environ.get("XDR_EMAIL", "admin@nivxray.com")
PASSWORD = os.environ["XDR_PASSWORD"]

PANE_SECTIONS = ["flyout-verdict-section", "flyout-entities",
                 "flyout-detections", "flyout-assets", "flyout-mitre",
                 "flyout-evidence", "flyout-progression", "flyout-worklog"]

results: list[tuple[str, str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append(("PASS" if ok else "FAIL", name, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}", flush=True)
    return ok


def main() -> int:
    with sync_playwright() as pw:
        b = pw.chromium.launch()
        page = b.new_page(viewport={"width": 1680, "height": 950})
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("console", lambda m: errors.append(m.text)
                if m.type == "error" else None)

        page.goto(f"{BASE}/login", wait_until="domcontentloaded")
        page.fill('input[type="email"]', EMAIL)
        page.fill('input[type="password"]', PASSWORD)
        page.click('button[type="submit"]')
        page.wait_for_timeout(3500)

        page.goto(f"{BASE}/xdr/incidents", wait_until="domcontentloaded")
        page.wait_for_selector('[data-testid="incidents-table"]', timeout=30000)
        page.wait_for_timeout(2000)
        nrows = page.locator('[data-testid="incidents-table"] tbody tr').count()
        check("queue mounts", True, f"rows={nrows}")

        rows = page.locator('[data-testid="incidents-table"] tbody tr')
        first_text = rows.first.inner_text().replace("\n", " ")[:80]

        # ── contextual pane ────────────────────────────────────────
        rows.first.click()
        page.wait_for_selector('[data-testid="incident-flyout"]', timeout=15000)
        check("row click opens contextual pane", True)
        body = page.locator('[data-testid="incident-flyout-body"]')
        check("pane body present", body.count() == 1)
        for sec in PANE_SECTIONS:
            check(f"pane section {sec}",
                  page.locator(f'[data-testid="{sec}"]').count() == 1)

        eyebrow = page.locator('[data-testid="incident-flyout"] .nx-fly-eyebrow'
                               ).inner_text()
        inc_no = eyebrow.split("·")[-1].strip()
        check("pane identity matches clicked row", inc_no in first_text,
              f"{inc_no!r} in {first_text!r}")

        # absence wording is words, never a fabricated 0
        pane_text = body.inner_text()
        check("absence stated in words",
              any(p in pane_text for p in (
                  "No technique is mapped", "No contributing detection",
                  "cites no entity", "No evidence pointer",
                  "No correlation match", "Not available", "Not recorded")),
              "")

        # overflow gate on the pane and its facts
        overflow = page.evaluate("""() => {
          const out = [];
          const b = document.querySelector('[data-testid=incident-flyout-body]');
          if (b && b.scrollWidth > b.clientWidth + 1) out.push('flyout-body');
          document.querySelectorAll('[data-testid=incident-flyout-body] '
            + '.nx-fact-value, [data-testid=incident-flyout-body] .nx-chip, '
            + '[data-testid=incident-flyout-body] .nx-metric-value')
            .forEach((e, i) => {
              if (e.scrollWidth > e.clientWidth + 2) out.push(
                (e.className || 'el') + '#' + i + ':' + e.scrollWidth + '>'
                + e.clientWidth);
            });
          return out;
        }""")
        check("no overflow in pane", not overflow, str(overflow[:5]))

        # ── investigation pivot preserves identity ────────────────
        href_id = page.evaluate("""() => document.querySelector(
          '[data-testid=incident-flyout-fullpage]')?.getAttribute('href')""")
        page.click('[data-testid="incident-pivot-detections"]')
        page.wait_for_timeout(2500)
        url = page.url
        check("pivot keeps incident identity",
              bool(href_id) and href_id.split("/")[-1] in url
              and "tab=detections" in url, f"{href_id} → {url}")

        # ── search / empty-state column contract ──────────────────
        page.goto(f"{BASE}/xdr/incidents", wait_until="domcontentloaded")
        page.wait_for_selector('[data-testid="incidents-table"]')
        page.wait_for_timeout(2000)
        search = page.locator('[data-testid="incidents-table"] input').first
        search.fill("zzzz-no-such-incident")
        page.wait_for_timeout(1200)
        heads = page.locator('[data-testid="incidents-table"] thead th').count()
        check("table structure survives an empty result", heads >= 10,
              f"{heads} columns")
        check("empty state is truthful",
              "authorized empty set" in page.locator(
                  '[data-testid="incidents-table"]').inner_text())

        # ── both themes ───────────────────────────────────────────
        search.fill("")
        page.wait_for_timeout(800)
        for want in ("dark", "light"):
            state = page.get_attribute('[data-testid="xdr-theme-toggle"]',
                                       "data-theme-state")
            if state != want:
                page.click('[data-testid="xdr-theme-toggle"]')
                page.wait_for_timeout(700)
            applied = page.get_attribute('[data-testid="xdr-shell"]',
                                         "data-nx-theme")
            check(f"theme switches to {want}", applied == want, str(applied))
            page.locator('[data-testid="incidents-table"] tbody tr'
                         ).first.click()
            page.wait_for_selector('[data-testid="incident-flyout-body"]')
            bad = page.evaluate("""() => {
              const same = [];
              const sel = ['[data-testid=incidents-table] thead th',
                '[data-testid=incidents-table] tbody td',
                '[data-testid=incident-flyout-body] .nx-fact-value',
                '[data-testid=incident-flyout-body] .nx-chip',
                '[data-testid=incident-flyout-body] .nx-sec-title'];
              const bg = (el) => {
                let n = el;
                while (n) {
                  const c = getComputedStyle(n).backgroundColor;
                  if (c && c !== 'rgba(0, 0, 0, 0)' && c !== 'transparent')
                    return c;
                  n = n.parentElement;
                }
                return 'rgb(255, 255, 255)';
              };
              sel.forEach((s) => document.querySelectorAll(s).forEach((e) => {
                if (!e.textContent.trim()) return;
                if (getComputedStyle(e).color === bg(e)) same.push(s);
              }));
              return [...new Set(same)];
            }""")
            check(f"{want}: no text painted on its own colour", not bad,
                  str(bad))
            clipped = page.evaluate("""() => {
              const out = [];
              document.querySelectorAll(
                '[data-testid=incident-flyout-body] .nx-chip,'
                + '[data-testid=incidents-table] thead th').forEach((e) => {
                if (e.scrollWidth > e.clientWidth + 2) out.push(e.className);
              });
              return [...new Set(out)];
            }""")
            check(f"{want}: nothing clipped", not clipped, str(clipped))
            page.click('[data-testid="incident-flyout-close"]')
            page.wait_for_timeout(400)

        real_errors = [e for e in errors
                       if "favicon" not in e and "ResizeObserver" not in e]
        check("no runtime/console error", not real_errors,
              str(real_errors[:3]))
        b.close()

    failed = [r for r in results if r[0] == "FAIL"]
    print(f"\n{len(results) - len(failed)} PASS · {len(failed)} FAIL")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
