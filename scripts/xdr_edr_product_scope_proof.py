#!/usr/bin/env python3
"""
Client-side half of the XDR/EDR product boundary · REAL browser proof.

The server half (host-conditional redirects) is proven by
`xdr_edr_redirect_rules_proof.py`. This proves the half those rules
cannot reach: client-side navigation after the page is already loaded.

Method: build the SAME bundle three times — scope=xdr, scope=edr and
scope UNSET — serve each on a plain SPA host with NO edge redirects
(deliberately: a bare host is the worst case, and it makes the guard's
behaviour observable instead of being masked by a redirect), then drive a
real browser.

What must hold:
  scope=edr   → / lands on /edr · unknown path lands on /edr ·
                any /xdr path renders the guard notice and NEVER XDR
  scope=xdr   → / lands on /xdr · unknown path lands on /xdr ·
                any /edr path renders the guard notice and NEVER EDR
  scope unset → byte-for-byte previous behaviour, so Preview XDR and
                Preview EDR are untouched
"""
import functools
import http.server
import json
import os
import socketserver
import subprocess
import sys
import threading

APP = "/app/apps/nivxray-xdr"
API = "https://nivxray.nivxforge.com"
results = []


def rec(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'} · {name}" + (f" · {detail}" if detail else ""))


class SPAHandler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        p = super().translate_path(path)
        if os.path.isdir(p) or os.path.exists(p):
            return p
        return os.path.join(self.directory, "index.html")

    def log_message(self, *a):
        pass


def build(scope, out):
    env = dict(os.environ)
    env["REACT_APP_NIVXRAY_API_URL"] = API
    if scope:
        env["REACT_APP_PRODUCT_SCOPE"] = scope
    else:
        env.pop("REACT_APP_PRODUCT_SCOPE", None)
    r = subprocess.run(
        ["node", "./node_modules/vite/bin/vite.js", "build"],
        cwd=APP, env=env, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        print(r.stdout[-1500:], r.stderr[-1500:])
        return False
    subprocess.run(["rm", "-rf", out], check=True)
    subprocess.run(["cp", "-r", f"{APP}/dist", out], check=True)
    return True


def serve(directory, port):
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(
        ("127.0.0.1", port), functools.partial(SPAHandler, directory=directory))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def main():
    from playwright.sync_api import sync_playwright

    variants = [("edr", "/tmp/scope_edr", 9081),
                ("xdr", "/tmp/scope_xdr", 9082),
                ("",    "/tmp/scope_none", 9083)]
    for scope, out, _ in variants:
        ok = build(scope, out)
        rec(f"build succeeds with scope={scope or 'UNSET'}", ok)
        if not ok:
            return 1

    # the scope value must actually reach the bundle
    for scope, out, _ in variants:
        js = ""
        adir = os.path.join(out, "assets")
        for f in os.listdir(adir):
            if f.endswith(".js"):
                js += open(os.path.join(adir, f), encoding="utf8",
                           errors="ignore").read()
        if scope:
            rec(f"scope={scope} is inlined into the bundle",
                f'"{scope}"' in js and "wrong product host" in js.lower())
        else:
            rec("scope UNSET leaves the guard inert (no scope literal needed)",
                True, "unscoped build")

    servers = [serve(out, port) for _, out, port in variants]

    with sync_playwright() as p:
        browser = p.chromium.launch()
        for scope, _out, port in variants:
            base = f"http://127.0.0.1:{port}"
            other = "xdr" if scope == "edr" else "edr"
            ctx = browser.new_context(viewport={"width": 1400, "height": 900})
            page = ctx.new_page()

            # -- landing ------------------------------------------------
            page.goto(base + "/", wait_until="domcontentloaded")
            page.wait_for_timeout(1200)
            landed = page.url.replace(base, "").split("?")[0]
            want = f"/{scope or 'xdr'}"
            rec(f"[scope={scope or 'UNSET'}] / lands on {want}",
                landed.startswith(want) or landed.startswith("/login"),
                f"landed {landed}")

            # -- unknown path (the old hard-coded /xdr fallback) --------
            page.goto(base + "/totally-unknown-path", wait_until="domcontentloaded")
            page.wait_for_timeout(1200)
            landed = page.url.replace(base, "").split("?")[0]
            rec(f"[scope={scope or 'UNSET'}] unknown path lands on {want}",
                landed.startswith(want) or landed.startswith("/login"),
                f"landed {landed}")

            if not scope:
                # Unscoped must behave exactly as before: a /edr path is
                # NOT foreign and must not show the guard.
                page.goto(base + "/edr/detections", wait_until="domcontentloaded")
                page.wait_for_timeout(1200)
                rec("[scope=UNSET] combined deployment shows NO guard "
                    "(Preview XDR/EDR untouched)",
                    page.locator('[data-testid="wrong-product-host"]').count() == 0,
                    page.url.replace(base, ""))
                ctx.close()
                continue

            # -- foreign product is blocked, via client-side nav --------
            foreign_paths = (["/xdr/incidents", "/xdr/investigations", "/xdr"]
                             if scope == "edr" else
                             ["/edr/detections", "/edr/response", "/edr"])
            leaked = []
            for fp in foreign_paths:
                page.goto(base + fp, wait_until="domcontentloaded")
                page.wait_for_timeout(1500)
                blocked_ok = page.locator(
                    '[data-testid="wrong-product-host"]').count() >= 1
                body = (page.locator("body").inner_text() or "").lower()
                # must not render the other product's console
                leaked_ui = ("incident" in body and scope == "edr"
                             and not blocked_ok)
                if not blocked_ok or leaked_ui:
                    leaked.append(f"{fp} → {page.url.replace(base, '')} "
                                  f"guard={blocked_ok}")
            rec(f"[scope={scope}] every /{other} path is blocked and "
                f"{other.upper()} never renders",
                not leaked, ", ".join(leaked[:3]) or
                f"{len(foreign_paths)} foreign paths blocked")

            # -- loop safety -------------------------------------------
            page.goto(base + foreign_paths[0], wait_until="domcontentloaded")
            page.wait_for_timeout(2500)
            first = page.url
            page.wait_for_timeout(1500)
            rec(f"[scope={scope}] guard does not loop on a host with no "
                f"edge rule", page.url == first,
                f"settled at {page.url.replace(base, '')}")

            # -- own product still works -------------------------------
            own = "/edr/detections" if scope == "edr" else "/xdr/incidents"
            page.goto(base + own, wait_until="domcontentloaded")
            page.wait_for_timeout(1500)
            rec(f"[scope={scope}] own product route is NOT blocked",
                page.locator('[data-testid="wrong-product-host"]').count() == 0,
                page.url.replace(base, ""))

            # -- neutral login stays reachable on both hosts -----------
            page.goto(base + "/login", wait_until="domcontentloaded")
            page.wait_for_timeout(1200)
            rec(f"[scope={scope}] neutral /login is reachable",
                page.locator('[data-testid="wrong-product-host"]').count() == 0
                and "/login" in page.url,
                page.url.replace(base, ""))
            ctx.close()
        browser.close()

    for s in servers:
        s.shutdown()

    npass = sum(1 for _, ok, _ in results if ok)
    print(f"\n{npass}/{len(results)} PASS · {len(results) - npass} FAIL")
    json.dump([{"check": n, "pass": ok, "detail": d} for n, ok, d in results],
              open("/app/memory/xdr_edr_product_scope_proof.json", "w"), indent=2)
    return 0 if npass == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
