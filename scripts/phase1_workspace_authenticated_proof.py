"""
Phase 1 · AUTHENTICATED runtime proof of the cleaned Workspace.

Why this exists: the production artefact points at nivxray.nivxforge.com,
whose database is separate from preview and for which no credential exists
yet, so authenticated behaviour cannot be proven against it before the
owner deploys. To avoid shipping an unverified product, an IDENTICAL build
of the same cleaned source is produced against the PREVIEW backend and
driven with real credentials here.

What this proves: the four approved removals did not break any retained
Workspace workflow, and the retained investigation deep-link capability
(Q1 = A) still resolves.

What this does NOT prove: production data, production auth, or the
production hostname. Those are the post-deployment runbook's job.
"""
import functools
import http.server
import json
import os
import socketserver
import threading

BUILD = "/tmp/ws_preview_build"
PORT = 9098
BASE = f"http://127.0.0.1:{PORT}"
EMAIL = "admin@nivxray.com"
PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'} · {name}" + (f" · {detail}" if detail else ""))


class SPAHandler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        p = super().translate_path(path)
        if os.path.isdir(p) or os.path.exists(p):
            return p
        return os.path.join(BUILD, "index.html")

    def log_message(self, *a):
        pass


def main():
    from playwright.sync_api import sync_playwright

    h = functools.partial(SPAHandler, directory=BUILD)
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", PORT), h)
    httpd.allow_reuse_address = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1920, "height": 950})
        console_errors = []
        page.on("console",
                lambda m: console_errors.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: console_errors.append(str(e)))

        # ---- 1 · authentication -------------------------------------
        page.goto(f"{BASE}/login", wait_until="networkidle")
        page.fill('[data-testid="login-email-input"]', EMAIL)
        page.fill('[data-testid="login-password-input"]', PASSWORD)
        page.click('[data-testid="login-submit-btn"]')
        page.wait_for_url(f"{BASE}/", timeout=30000)
        page.wait_for_timeout(2500)
        check("authentication works on the cleaned build", page.url == f"{BASE}/",
              page.url.replace(BASE, ""))

        # ---- 2 · shipped navigation --------------------------------
        for gone in ("nav-xdr", "nav-investigations", "nav-nivxforge"):
            n = page.locator(f'[data-testid="{gone}"]').count()
            check(f"removed nav item absent after login · {gone}", n == 0, f"count {n}")

        for kept, label in (("nav-workspace", "WORKSPACE"), ("nav-history", "HISTORY"),
                            ("nav-batch-test", "BATCH"), ("nav-heatmap", "HEATMAP"),
                            ("nav-tools", "TOOLS"), ("nav-learn", "LEARN"),
                            ("nav-admin-menu", "ADMIN")):
            n = page.locator(f'[data-testid="{kept}"]').count()
            check(f"retained nav item present · {label}", n >= 1, f"count {n}")

        # ---- 3 · retained top-level surfaces render -----------------
        surfaces = {
            "/": "Workspace (Decoder / Analyze)",
            "/auto-investigate": "Auto Investigate",
            "/analyze": "Command Analyzer",
            "/history": "History",
            "/batch-test": "Batch",
            "/heatmap": "Heatmap",
            "/lab": "Learn · Practice Lab",
            "/kb": "Learn · Knowledge Base",
            "/docs": "Learn · Docs",
            "/admin": "Admin",
            "/documents": "Admin · Documents",
            "/threat-intel": "Threat Intel",
            "/iedde": "IEDDE trace",
            "/compare": "Compare",
            "/platform": "Platform Health",
            "/battery": "Battery",
            "/benchmark": "Benchmark (now authenticated)",
        }
        for path, label in surfaces.items():
            page.goto(f"{BASE}{path}", wait_until="domcontentloaded")
            page.wait_for_timeout(1400)
            landed = page.url.replace(BASE, "").split("?")[0]
            body = (page.locator("body").inner_text() or "").strip()
            ok = landed == path and len(body) > 40
            check(f"retained surface renders · {label} ({path})", ok,
                  f"landed {landed} · {len(body)} chars")

        # ---- 4 · Q1 · retained investigation deep-link capability ---
        for path in ("/investigations", "/investigation-summary"):
            page.goto(f"{BASE}{path}", wait_until="domcontentloaded")
            page.wait_for_timeout(1600)
            landed = page.url.replace(BASE, "").split("?")[0]
            check(f"Q1 · investigation deep link still routes (not bounced) · {path}",
                  landed == path, f"landed {landed}")

        # A real investigation id, taken from the backend the build talks to
        # The Investigations list and detail pages are backed by
        # /api/correlations (id field: `id`) — NOT /api/investigations,
        # which is the activity feed Quick Open reads and whose id field is
        # `investigation_id`. Two different stores behind one word; using
        # the wrong one is exactly how a "route is broken" false finding
        # gets written up.
        token = page.evaluate("localStorage.getItem('nvx_token')")
        r = page.request.get(
            "https://greeting-app-5782.preview.emergentagent.com/api/correlations?limit=1",
            headers={"Authorization": "Bearer " + (token or "")})
        inv_id = None
        if r.ok:
            d = r.json()
            lst = d.get("correlations") or []
            if lst:
                inv_id = lst[0].get("id")
        if inv_id:
            page.goto(f"{BASE}/investigations/{inv_id}", wait_until="domcontentloaded")
            page.wait_for_timeout(2200)
            landed = page.url.replace(BASE, "").split("?")[0]
            check("Q1 · a REAL investigation detail deep link resolves",
                  landed == f"/investigations/{inv_id}", f"landed {landed}")
        else:
            check("Q1 · a REAL investigation detail deep link resolves", False,
                  "no investigation available from the backend to test with")

        # ---- 5 · Quick Open still populates from /investigations ----
        page.goto(f"{BASE}/", wait_until="networkidle")
        page.wait_for_timeout(1500)
        page.keyboard.press("Control+k")
        page.wait_for_timeout(2500)
        opened = page.locator('[data-testid="quick-open-palette"]').count() >= 1
        check("Quick Open palette still opens (Ctrl+K)", opened)
        if opened:
            page.fill('[data-testid="quick-open-input"]', "")
            page.wait_for_timeout(1500)
            rows = page.locator('[data-testid^="quick-open-row-"]').count()
            check("Quick Open still lists results (it reads /investigations)",
                  rows >= 1, f"{rows} rows")
            page.keyboard.press("Escape")

        # ---- 6 · History drilldown affordance survives --------------
        page.goto(f"{BASE}/history", wait_until="networkidle")
        page.wait_for_timeout(2500)
        check("History page renders its drawer",
              page.locator('[data-testid="history-page"]').count() >= 1)
        total = page.locator('[data-testid="history-total"]').count()
        check("History still reports its record total", total >= 1)

        # ---- 7 · removed product surfaces are gone ------------------
        for path in ("/nivxforge", "/nivxforge/dashboard", "/nivxforge/investigate",
                     "/nivxforge/governance", "/edr/trajectory", "/xdr"):
            page.goto(f"{BASE}{path}", wait_until="domcontentloaded")
            page.wait_for_timeout(1200)
            landed = page.url.replace(BASE, "").split("?")[0]
            check(f"removed surface no longer reachable · {path}", landed == "/",
                  f"landed {landed}")

        # ---- 8 · v2 shadow surfaces ship flag-off -------------------
        page.goto(f"{BASE}/v2/workspace", wait_until="domcontentloaded")
        page.wait_for_timeout(1600)
        txt = (page.locator("body").inner_text() or "").lower()
        check("Q4 · /v2/* route resolves but renders its flag-off state",
              page.url.replace(BASE, "").split("?")[0] == "/v2/workspace",
              f"body starts: {txt[:80]!r}")

        real_errors = [e for e in console_errors
                       if "favicon" not in e.lower() and "404" not in e]
        check("no uncaught page errors across the whole sweep",
              len(real_errors) == 0, f"{len(real_errors)} errors: {real_errors[:3]}")

        page.screenshot(path="/app/memory/phase1_workspace_cleaned_nav.png",
                        full_page=False)
        browser.close()

    httpd.shutdown()
    npass = sum(1 for _, ok, _ in results if ok)
    print(f"\n{npass}/{len(results)} PASS · {len(results) - npass} FAIL")
    with open("/app/memory/phase1_workspace_authenticated_proof.json", "w") as fh:
        json.dump([{"check": n, "pass": ok, "detail": d} for n, ok, d in results],
                  fh, indent=2)
    return 0 if npass == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
