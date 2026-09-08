#!/usr/bin/env python3
"""
XDR / EDR production acceptance sweep · Phase 2 and Phase 3.

PREPARED, NOT RUN — the hostnames do not exist yet and, per the owner
lock, XDR/EDR must not be deployed until Workspace Phase 1 is verified.

    python3 scripts/xdr_edr_live_acceptance.py --product xdr
    python3 scripts/xdr_edr_live_acceptance.py --product edr

Each product is verified INDEPENDENTLY, which is the whole point of the
two-project topology: Phase 2 (XDR) and Phase 3 (EDR) are separate gates
with separate rollbacks.

Authenticated checks are reported BLOCKED_BY_PRODUCTION_CREDENTIAL, never
skipped and never satisfied with preview credentials.
"""
import argparse
import json
import re
import sys
import urllib.request

XDR_HOST = "https://xdr.nivxforge.com"
EDR_HOST = "https://edr.nivxforge.com"
WORKSPACE = "https://workspace.nivxmachines.com"
LEGACY = "https://nivxray.nivxforge.com"
PREVIEW = "https://greeting-app-5782.preview.emergentagent.com"
APPROVED_API = "https://nivxray.nivxforge.com"   # TEMPORARY_MIGRATION_DEPENDENCY
UA = "Mozilla/5.0 (NivXRay acceptance sweep)"

# Cross-product origin variables MUST stay unset until each product is
# runtime-verified (owner decision 4a) — a launcher must never point at
# an unverified product.
LAUNCHER_VARS = ["REACT_APP_XDR_URL", "REACT_APP_EDR_URL",
                 "REACT_APP_WORKSPACE_URL"]

results = []


def rec(section, name, ok, detail=""):
    results.append({"section": section, "check": name, "pass": bool(ok),
                    "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'} · [{section}] {name}"
          + (f" · {detail}" if detail else ""))


def blocked(section, name, reason):
    results.append({"section": section, "check": name, "pass": None,
                    "detail": reason})
    print(f"BLOCKED · [{section}] {name} · {reason}")


def fetch(url, follow=True, timeout=25):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    op = (urllib.request.build_opener() if follow
          else urllib.request.build_opener(NoRedirect))
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with op.open(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf8", "ignore"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, "", dict(e.headers or {})
    except Exception as e:
        return 0, f"__ERROR__ {e}", {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--product", required=True, choices=["xdr", "edr"])
    args = ap.parse_args()

    product = args.product
    other = "edr" if product == "xdr" else "xdr"
    base = XDR_HOST if product == "xdr" else EDR_HOST
    other_base = EDR_HOST if product == "xdr" else XDR_HOST

    print(f"\n{product.upper()} production acceptance · {base}\n" + "-" * 72)

    # -- A · reachable and TLS ---------------------------------------
    st, body, _ = fetch(base + "/")
    rec("A", "host answers over https", st == 200, f"HTTP {st}")
    rec("A", "serves the SPA index document",
        '<div id="root"' in body or "<script" in body)

    # -- B · product boundary · landing ------------------------------
    st, _, hdrs = fetch(base + "/", follow=False)
    loc = hdrs.get("location", "")
    rec("B", f"/ redirects to /{product} (own product landing)",
        st in (301, 302, 307, 308) and loc.rstrip("/").endswith(f"/{product}"),
        f"HTTP {st} → {loc or 'no redirect'}")

    # -- C · product boundary · containment --------------------------
    st, _, hdrs = fetch(f"{base}/{other}", follow=False)
    loc = hdrs.get("location", "")
    rec("C", f"/{other} on the {product.upper()} host redirects to the "
             f"{other.upper()} host",
        st in (301, 302, 307, 308) and loc.startswith(other_base),
        f"HTTP {st} → {loc or 'NOT REDIRECTED — product leak'}")

    deep = "/edr/detections" if other == "edr" else "/xdr/incidents"
    st, _, hdrs = fetch(base + deep, follow=False)
    loc = hdrs.get("location", "")
    rec("C", f"deep link {deep} also leaves the {product.upper()} host",
        st in (301, 302, 307, 308) and loc.startswith(other_base),
        f"HTTP {st} → {loc or 'NOT REDIRECTED — product leak'}")

    own_deep = "/xdr/incidents" if product == "xdr" else "/edr/detections"
    st, _, hdrs = fetch(base + own_deep, follow=False)
    rec("C", f"own deep link {own_deep} is NOT redirected away",
        st == 200, f"HTTP {st} {hdrs.get('location', '')}")

    # -- D · SPA rewrite + hard refresh ------------------------------
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1600, "height": 900})
        errors = []
        page.on("console", lambda m: errors.append(m.text)
                if m.type == "error" else None)
        page.on("pageerror", lambda e: errors.append(str(e)))

        own_routes = (["/xdr/incidents", "/xdr/investigations", "/xdr/search",
                       "/xdr/endpoints", "/xdr/kb", "/xdr/docs"]
                      if product == "xdr" else
                      ["/edr", "/edr/detections", "/edr/process-tree",
                       "/edr/response", "/edr/hunting", "/edr/files"])
        broken = []
        for r in own_routes:
            try:
                page.goto(base + r, wait_until="domcontentloaded")
                page.reload(wait_until="domcontentloaded")
                page.wait_for_timeout(500)
                if page.url.replace(base, "").split("?")[0] not in (
                        r, "/login", f"/{product}/login"):
                    broken.append(f"{r}→{page.url.replace(base, '')}")
            except Exception as e:
                broken.append(f"{r}: {type(e).__name__}")
        rec("D", "own deep links survive a hard refresh", not broken,
            ", ".join(broken[:4]) or f"{len(own_routes)} routes ok")

        # -- E · unauthenticated gating -----------------------------
        ungated = []
        for r in own_routes:
            page.goto(base + r, wait_until="domcontentloaded")
            page.wait_for_timeout(500)
            if "login" not in page.url:
                ungated.append(f"{r}→{page.url.replace(base, '')}")
        rec("E", "protected surfaces gate to a login route", not ungated,
            ", ".join(ungated[:4]) or "all gated")

        real = [e for e in errors if "favicon" not in e.lower()
                and "401" not in e and "Failed to load resource" not in e]
        rec("H", "no uncaught console / runtime errors", not real,
            f"{len(real)}: {real[:3]}")
        browser.close()

    # -- F · the shipped artefact -----------------------------------
    st, html, _ = fetch(base + "/")
    assets = re.findall(r'src="(/assets/[^"]+\.js)"', html)
    alljs = ""
    for a in assets:
        _, b, _ = fetch(base + a)
        alljs += b
    rec("F", "javascript bundle downloadable", bool(alljs),
        f"{len(assets)} entry chunk(s), {len(alljs)} bytes")
    if alljs:
        prev = re.findall(r"https://[a-z0-9-]+\.preview\.emergentagent\.com",
                          alljs)
        rec("F", "NO preview origin embedded", not prev,
            f"{len(prev)} hits" if prev else "0 hits")
        rec("F", "approved production API embedded",
            APPROVED_API in alljs, f"{alljs.count(APPROVED_API)} refs")
        lit = [v for v in (XDR_HOST, EDR_HOST, WORKSPACE) if v in alljs]
        rec("F", "cross-product launcher origins still UNSET (owner 4a)",
            not lit, f"found {lit}" if lit else "no sibling origin baked in")

    # -- G · zero damage --------------------------------------------
    for url, label in ((LEGACY + "/", "legacy Workspace host"),
                       (LEGACY + "/api/health", "legacy API"),
                       (PREVIEW + "/xdr/incidents", "Preview XDR"),
                       (PREVIEW + "/edr", "Preview EDR"),
                       (other_base + "/", f"sibling product {other.upper()}")):
        st, _, _ = fetch(url)
        expected = st == 200
        if label.startswith("sibling") and st == 0:
            blocked("G", f"{label} still serving",
                    "sibling product not deployed yet — expected before its phase")
            continue
        rec("G", f"{label} still serving", expected, f"HTTP {st}")

    blocked("I", "sign in with a production administrator",
            "BLOCKED_BY_PRODUCTION_CREDENTIAL — provisioning requires an env "
            "change that would rebuild the FROZEN legacy project")
    for name in ("Incident queue loads real data" if product == "xdr"
                 else "Detections load real data",
                 "Process tree / investigation views render",
                 "Response actions surface", "Cross-product pivot with context"):
        blocked("I", name, "BLOCKED_BY_PRODUCTION_CREDENTIAL")

    ran = [r for r in results if r["pass"] is not None]
    npass = sum(1 for r in ran if r["pass"])
    print("-" * 72)
    print(f"{npass}/{len(ran)} PASS · {len(ran) - npass} FAIL · "
          f"{len(results) - len(ran)} BLOCKED")
    out = f"/app/memory/{product}_live_acceptance_result.json"
    json.dump({"product": product, "base_url": base, "results": results,
               "classification": (
                   f"{product.upper()}_PRODUCTION_UNAUTHENTICATED_VERIFIED"
                   if npass == len(ran) else "NOT_VERIFIED")},
              open(out, "w"), indent=2)
    print(f"written → {out}")
    return 0 if npass == len(ran) else 1


if __name__ == "__main__":
    sys.exit(main())
