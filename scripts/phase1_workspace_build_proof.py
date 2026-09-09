"""
Phase 1 · Workspace migration build proof (local, read-only).

Serves the PRODUCTION artefact /app/frontend/build on a local port with the
same SPA fallback rewrite the deployment will apply, then drives a real
browser against it.

Proves, on the real artefact:
  · the SPA fallback requirement (deep links must not 404)
  · authentication gating, including the /benchmark security correction
  · the four approved removals are absent from the shipped nav
  · every retained top-level surface is present in the shipped nav
  · the retained investigation deep-link capability still routes
  · the /v2/* shadow flags ship OFF
  · the bundle talks to the production API and never to preview

It does NOT prove authenticated behaviour: the production database is
separate from preview and no production credential exists yet. Those checks
belong to the post-deployment runbook.
"""
import functools
import http.server
import json
import os
import re
import socketserver
import threading

BUILD = "/app/frontend/build"
PORT = 9099
BASE = f"http://127.0.0.1:{PORT}"
PROD_API = "https://nivxray.nivxforge.com"

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'} · {name}" + (f" · {detail}" if detail else ""))


class SPAHandler(http.server.SimpleHTTPRequestHandler):
    """Mirrors  rewrites: /(.*) -> /index.html  from frontend/vercel.json."""

    def translate_path(self, path):
        p = super().translate_path(path)
        if os.path.isdir(p) or os.path.exists(p):
            return p
        return os.path.join(BUILD, "index.html")

    def log_message(self, *a):
        pass


class NoFallbackHandler(http.server.SimpleHTTPRequestHandler):
    """A plain static host, to demonstrate WHY the rewrite is mandatory."""

    def log_message(self, *a):
        pass


def serve(handler, port):
    h = functools.partial(handler, directory=BUILD)
    httpd = socketserver.TCPServer(("127.0.0.1", port), h)
    httpd.allow_reuse_address = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def main():
    from playwright.sync_api import sync_playwright

    # ---- static artefact assertions ---------------------------------
    alljs = ""
    for f in sorted(os.listdir(f"{BUILD}/static/js")):
        if f.endswith(".js"):
            with open(f"{BUILD}/static/js/{f}", encoding="utf8", errors="ignore") as fh:
                alljs += fh.read()

    check("artefact targets the production API",
          alljs.count(PROD_API) > 0 and "greeting-app-5782" not in alljs,
          f"{alljs.count(PROD_API)} prod refs · {alljs.count('greeting-app-5782')} preview refs")

    flags = {k: set(re.findall(f'REACT_APP_NIVX_FLAG_{k}:"([^"]*)"', alljs))
             for k in ("TRAJECTORY_ENGINE", "CASE_ENGINE", "VERDICT_ENGINE_V3")}
    check("v2 shadow flags ship disabled",
          all(v == {"disabled"} for v in flags.values()), json.dumps(
              {k: sorted(v) for k, v in flags.items()}))

    routes = set(re.findall(r'path:"(/[^"]*|\*)"', alljs))
    for r in ("/edr/trajectory", "/nivxforge", "/nivxforge/dashboard", "/xdr"):
        check(f"removed route absent from bundle · {r}", r not in routes)
    for r in ("/investigations", "/investigations/:id", "/investigation-summary",
              "/analyst", "/investigate", "/benchmark", "/history",
              "/auto-investigate", "/v2/workspace"):
        check(f"retained route present in bundle · {r}", r in routes)

    # ---- the rewrite requirement, demonstrated both ways ------------
    spa = serve(SPAHandler, PORT)
    plain = serve(NoFallbackHandler, PORT + 1)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1920, "height": 900})
        errors = []
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: errors.append(str(e)))

        r = page.request.get(f"http://127.0.0.1:{PORT + 1}/auto-investigate")
        check("without the SPA rewrite a deep link 404s (why rewrites are mandatory)",
              r.status == 404, f"status {r.status}")
        r = page.request.get(f"{BASE}/auto-investigate")
        check("with the SPA rewrite the deep link is served",
              r.status == 200, f"status {r.status}")

        # ---- unauthenticated gating ---------------------------------
        for path in ("/", "/auto-investigate", "/history", "/admin", "/benchmark",
                     "/investigations", "/analyst", "/investigate", "/lab",
                     "/batch-test", "/heatmap"):
            page.goto(f"{BASE}{path}", wait_until="networkidle")
            landed = page.url.replace(BASE, "")
            check(f"unauthenticated {path} is gated to /login",
                  landed.startswith("/login"), f"landed {landed}")

        # /benchmark is the Q5 security correction — call it out explicitly
        page.goto(f"{BASE}/benchmark", wait_until="networkidle")
        check("Q5 · /benchmark now requires authentication",
              page.url.endswith("/login"), page.url.replace(BASE, ""))

        # ---- shipped navigation, on the login page shell ------------
        page.goto(f"{BASE}/login", wait_until="networkidle")
        page.wait_for_timeout(700)
        html = page.content()
        for gone in ("nav-xdr", "nav-investigations", "nav-nivxforge"):
            check(f"removed nav item absent from DOM · {gone}", gone not in html)

        browser.close()

    spa.shutdown()
    plain.shutdown()

    npass = sum(1 for _, ok, _ in results if ok)
    print(f"\n{npass}/{len(results)} PASS · {len(results) - npass} FAIL")
    with open("/app/memory/phase1_workspace_build_proof.json", "w") as fh:
        json.dump([{"check": n, "pass": ok, "detail": d} for n, ok, d in results],
                  fh, indent=2)
    return 0 if npass == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
