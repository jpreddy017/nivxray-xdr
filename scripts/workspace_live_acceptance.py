#!/usr/bin/env python3
"""
Workspace LIVE production acceptance sweep · OWNER LOCK · Phase 1.

Run this against the real hostname the moment it resolves:

    python3 scripts/workspace_live_acceptance.py --base-url https://workspace.nivxmachines.com

Sections
  A  DNS / TLS / the index document is actually served
  B  SPA rewrite at the HTTP layer — every retained deep link
  C  the LIVE artefact re-checked with the build guard's own rules
  D  deep-link HARD REFRESH sweep in a real browser
  E  the four approved removals, confirmed on the live host
  F  unauthenticated gating, including the /benchmark security correction
  G  zero damage — legacy host and both preview products, side by side
  H  console / runtime errors and failed network requests

Authenticated checks are NOT attempted and NOT silently skipped: they are
reported as BLOCKED_BY_PRODUCTION_CREDENTIAL, which is an owner-accepted
temporary blocker. A pass here therefore classifies as
WORKSPACE_MIGRATION_UNAUTHENTICATED_VERIFIED and NOTHING stronger.

`--base-url` also accepts a local SPA-fallback server, which is how the
script itself is validated before the domain exists.
"""
import argparse
import json
import re
import sys
import urllib.request

# Routes retained for direct navigation. Every one must survive a direct
# URL + hard refresh; none may 404 at the hosting layer.
RETAINED_STATIC = [
    "/", "/login", "/analyze", "/auto-investigate", "/threat-intel",
    "/threat-model", "/history", "/batch-test", "/heatmap", "/lab",
    "/learner", "/kb", "/docs", "/admin", "/admin/corrections",
    "/admin/models", "/admin/samples", "/admin/training-inbox", "/documents",
    "/platform", "/iedde", "/compare", "/battery", "/benchmark",
    "/evidence-explorer", "/investigations", "/investigation-summary",
    "/analyst", "/analyst/rc5", "/investigate",
]
# Parameterised retained routes — sample ids; the point is the HOST must
# not 404 and React must take over, not that the record exists.
RETAINED_PARAM = [
    "/investigations/sample-id-acceptance",
    "/investigations/sample-id-acceptance/replay",
    "/compare/case-a-acceptance/case-b-acceptance",
    "/workspace/session/sample-session-acceptance",
    "/workspace/session/sample-session-acceptance/input/sample-input",
    "/investigate/sample-case-acceptance",
]
# Retained but deliberately flag-OFF. Must still not 404 at the host.
RETAINED_V2 = [
    "/v2/workspace", "/v2/workspace/sample", "/v2/trajectory",
    "/v2/trajectory/sample", "/v2/irg", "/v2/irg/sample", "/v2/compare",
    "/v2/compare/a/b", "/v2/ancestry/sample/pid-1", "/v2/case/sample",
    "/v2/ingest", "/v2/validation",
]
REMOVED = [
    "/xdr", "/nivxforge", "/nivxforge/dashboard", "/nivxforge/investigate",
    "/nivxforge/threat-intel", "/nivxforge/hunting", "/nivxforge/knowledge",
    "/nivxforge/reports", "/nivxforge/history", "/nivxforge/governance",
    "/edr/trajectory",
]

ALLOWED_API_ORIGINS = ["https://nivxray.nivxforge.com"]
FLAGS = [
    "REACT_APP_NIVX_FLAG_TRAJECTORY_ENGINE",
    "REACT_APP_NIVX_FLAG_CASE_ENGINE",
    "REACT_APP_NIVX_FLAG_VERDICT_ENGINE_V3",
]
UA = "Mozilla/5.0 (NivXRay acceptance sweep)"

LEGACY = "https://nivxray.nivxforge.com"
PREVIEW = "https://greeting-app-5782.preview.emergentagent.com"

results = []


def rec(section, name, ok, detail=""):
    results.append({"section": section, "check": name, "pass": bool(ok),
                    "detail": detail})
    flag = "PASS" if ok else "FAIL"
    print(f"{flag} · [{section}] {name}" + (f" · {detail}" if detail else ""))


def blocked(section, name, reason):
    results.append({"section": section, "check": name, "pass": None,
                    "detail": reason})
    print(f"BLOCKED · [{section}] {name} · {reason}")


def fetch(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf8", "ignore"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf8", "ignore"), dict(e.headers or {})
    except Exception as e:
        return 0, f"__ERROR__ {e}", {}


# ---------------------------------------------------------------- A
def section_a(base):
    status, body, headers = fetch(base + "/")
    rec("A", "root document is served", status == 200, f"HTTP {status}")
    rec("A", "response is the SPA index document",
        '<div id="root"' in body and "static/js/main." in body,
        "index.html markers present" if '<div id="root"' in body else body[:90])
    if base.startswith("https://"):
        rec("A", "TLS certificate valid (request completed over https)",
            status == 200)
    else:
        blocked("A", "TLS certificate valid",
                "base-url is not https — local validation run")
    return body


# ---------------------------------------------------------------- B
def section_b(base):
    """The failure this catches: a static host serving 404 for deep links."""
    all_paths = RETAINED_STATIC + RETAINED_PARAM + RETAINED_V2
    bad_status, not_index = [], []
    for p in all_paths:
        status, body, _ = fetch(base + p)
        if status != 200:
            bad_status.append(f"{p}→{status}")
        elif '<div id="root"' not in body:
            not_index.append(p)
    rec("B", f"all {len(all_paths)} retained deep links return HTTP 200",
        not bad_status, ", ".join(bad_status[:6]) or "no 404s")
    rec("B", "every retained deep link is served the SPA index document",
        not not_index, ", ".join(not_index[:6]) or "rewrite active on all")


# ---------------------------------------------------------------- C
def section_c(base):
    """Re-apply the build guard's rules to the artefact that is ACTUALLY live."""
    status, manifest_raw, _ = fetch(base + "/asset-manifest.json")
    if status != 200:
        rec("C", "asset-manifest.json reachable", False, f"HTTP {status}")
        return
    rec("C", "asset-manifest.json reachable", True)
    try:
        files = json.loads(manifest_raw)["files"]
    except Exception as e:
        rec("C", "asset-manifest.json parses", False, str(e))
        return
    js_paths = [v for v in files.values()
                if v.endswith(".js") and not v.endswith(".map")]
    rec("C", "manifest lists javascript chunks", len(js_paths) > 0,
        f"{len(js_paths)} chunks")

    alljs, unreachable = "", []
    for u in js_paths:
        st, body, _ = fetch(base + u if u.startswith("/") else f"{base}/{u}")
        if st != 200:
            unreachable.append(f"{u}→{st}")
        else:
            alljs += body + "\n"
    rec("C", "every chunk in the manifest is downloadable",
        not unreachable, ", ".join(unreachable[:4]) or f"{len(js_paths)} ok")

    preview_hits = re.findall(
        r"https://[a-z0-9-]+\.preview\.emergentagent\.com", alljs)
    rec("C", "NO preview Emergent origin embedded in the live bundle",
        not preview_hits,
        f"{len(preview_hits)} hits" if preview_hits else "0 hits")

    inlined = sorted(set(re.findall(r'REACT_APP_BACKEND_URL:"([^"]*)"', alljs)))
    rec("C", "production API origin embedded and approved",
        len(inlined) == 1 and inlined[0] in ALLOWED_API_ORIGINS,
        f"{inlined or 'ABSENT'} · approved {ALLOWED_API_ORIGINS}")

    for flag in FLAGS:
        vals = sorted(set(re.findall(flag + r':"([^"]*)"', alljs)))
        on = [v for v in vals if v in ("shadow", "enabled")]
        rec("C", f"shadow flag OFF · {flag}", not on,
            f"{vals or 'absent (→ disabled)'}")

    routes = set(re.findall(r'path:"(/[^"]*|\*)"', alljs))
    for r_ in ("/xdr", "/nivxforge", "/nivxforge/dashboard", "/edr/trajectory"):
        rec("C", f"removed route absent from the live bundle · {r_}",
            r_ not in routes)
    missing = [r_ for r_ in ("/investigations", "/investigations/:id",
                             "/investigation-summary", "/history",
                             "/auto-investigate", "/benchmark")
               if r_ not in routes]
    rec("C", "retained routes present in the live bundle", not missing,
        ", ".join(missing) or "all present")


# ---------------------------------------------------------------- D–H
def browser_sections(base):
    from playwright.sync_api import sync_playwright

    console_errors, failed_requests = [], []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1600, "height": 900})
        page.on("console", lambda m: console_errors.append(m.text)
                if m.type == "error" else None)
        page.on("pageerror", lambda e: console_errors.append(str(e)))
        page.on("requestfailed",
                lambda r: failed_requests.append(f"{r.method} {r.url}"))
        page.on("response", lambda r: failed_requests.append(
            f"{r.status} {r.url}") if r.status >= 500 else None)

        # -- D · direct URL then HARD REFRESH -------------------------
        bounced, errored = [], []
        for path in RETAINED_STATIC + RETAINED_PARAM + RETAINED_V2:
            try:
                page.goto(base + path, wait_until="domcontentloaded")
                page.reload(wait_until="domcontentloaded")
                page.wait_for_timeout(500)
                landed = page.url.replace(base, "").split("?")[0] or "/"
                # Unauthenticated: a Protected route legitimately lands on
                # /login. Landing on "/" instead means the catch-all ate it,
                # which for a RETAINED route indicates a hosting/rewrite fault.
                if landed not in (path, "/login", "/") :
                    bounced.append(f"{path}→{landed}")
                elif landed == "/" and path not in ("/", "/login"):
                    bounced.append(f"{path}→/ (catch-all bounce)")
            except Exception as e:
                errored.append(f"{path}: {type(e).__name__}")
        rec("D", "every retained deep link survives a HARD REFRESH",
            not bounced and not errored,
            ", ".join((bounced + errored)[:6]) or
            f"{len(RETAINED_STATIC + RETAINED_PARAM + RETAINED_V2)} routes ok")

        # -- E · the four approved removals ---------------------------
        still_there = []
        for path in REMOVED:
            page.goto(base + path, wait_until="domcontentloaded")
            page.wait_for_timeout(400)
            landed = page.url.replace(base, "").split("?")[0] or "/"
            if landed not in ("/", "/login"):
                still_there.append(f"{path}→{landed}")
        rec("E", f"all {len(REMOVED)} removed surfaces are unreachable",
            not still_there, ", ".join(still_there[:6]) or "all bounce away")

        page.goto(base + "/login", wait_until="domcontentloaded")
        page.wait_for_timeout(900)
        html = page.content()
        for gone, label in (("nav-xdr", "XDR top nav"),
                            ("nav-investigations", "Investigations top nav"),
                            ("nav-nivxforge", "embedded NivXForge console nav")):
            rec("E", f"{label} absent from the DOM", gone not in html)

        # -- F · unauthenticated gating -------------------------------
        ungated = []
        for path in ("/", "/auto-investigate", "/history", "/admin",
                     "/investigations", "/analyst", "/investigate",
                     "/batch-test", "/heatmap", "/documents"):
            page.goto(base + path, wait_until="domcontentloaded")
            page.wait_for_timeout(500)
            if not page.url.replace(base, "").startswith("/login"):
                ungated.append(f"{path}→{page.url.replace(base, '')}")
        rec("F", "protected surfaces gate to /login when unauthenticated",
            not ungated, ", ".join(ungated[:5]) or "all gated")

        page.goto(base + "/benchmark", wait_until="domcontentloaded")
        page.wait_for_timeout(900)
        body = (page.locator("body").inner_text() or "")
        rec("F", "Q5 · /benchmark requires authentication",
            page.url.replace(base, "").startswith("/login"),
            page.url.replace(base, ""))
        rec("F", "Q5 · /benchmark leaks neither benchmark data nor product nav",
            "nav-workspace" not in page.content() and "BENCHMARK" not in body.upper(),
            f"{len(body)} chars rendered")

        # -- H · hygiene ----------------------------------------------
        real_errors = [e for e in console_errors
                       if "favicon" not in e.lower()
                       and "401" not in e and "Failed to load resource" not in e]
        rec("H", "no uncaught console / runtime errors", not real_errors,
            f"{len(real_errors)}: {real_errors[:3]}")
        server_errors = [f for f in failed_requests if f.startswith("5")]
        rec("H", "no 5xx responses during the sweep", not server_errors,
            f"{len(server_errors)}: {server_errors[:3]}")
        browser.close()


# ---------------------------------------------------------------- G
def section_g():
    """Zero damage — nothing already live may have changed."""
    st, body, _ = fetch(LEGACY + "/")
    rec("G", "legacy nivxray.nivxforge.com STILL SERVING", st == 200,
        f"HTTP {st}")
    st2, _, _ = fetch(LEGACY + "/auto-investigate")
    rec("G", "legacy deep link still works", st2 == 200, f"HTTP {st2}")

    # The legacy Workspace must still be the OLD one, nav intact.
    # NOTE: every chunk is fetched, not a prefix. Header.jsx is imported by
    # lazily-loaded pages, so `nav-investigations` lands in a shared chunk
    # that is NOT among the first entries of the manifest — sampling the
    # first N chunks produced a false FAIL during validation.
    st3, man, _ = fetch(LEGACY + "/asset-manifest.json")
    legacy_ok, legacy_detail = False, f"manifest HTTP {st3}"
    if st3 == 200:
        try:
            js = [v for v in json.loads(man)["files"].values()
                  if v.endswith(".js") and not v.endswith(".map")]
            blob = ""
            for u in js:
                _, b, _ = fetch(LEGACY + u)
                blob += b
            found = [t for t in ("nav-xdr", "nav-investigations")
                     if t in blob]
            legacy_ok = bool(found)
            legacy_detail = (f"{len(js)} chunks scanned · found {found}"
                             if found else
                             f"{len(js)} chunks scanned · NEITHER nav testid "
                             f"found — the legacy bundle may have been replaced")
        except Exception as e:
            legacy_detail = f"{type(e).__name__}: {e}"
    rec("G", "legacy Workspace is UNCHANGED (still ships its original nav)",
        legacy_ok, legacy_detail)

    st4, _, _ = fetch(LEGACY + "/api/")
    rec("G", "legacy API (the temporary dependency) still answering",
        st4 == 200, f"HTTP {st4}")

    for path, label in (("/xdr/incidents", "Preview NivXRay XDR"),
                        ("/edr", "Preview NivXForge EDR")):
        st5, _, _ = fetch(PREVIEW + path)
        rec("G", f"{label} still serving", st5 == 200, f"HTTP {st5}")

    for host in ("https://nivxmachines.com", "https://www.nivxmachines.com"):
        st6, _, _ = fetch(host)
        rec("G", f"marketing site untouched · {host}", st6 == 200, f"HTTP {st6}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True,
                    help="e.g. https://workspace.nivxmachines.com")
    ap.add_argument("--skip-zero-damage", action="store_true")
    args = ap.parse_args()
    base = args.base_url.rstrip("/")

    print(f"\nWorkspace live acceptance sweep · {base}\n" + "-" * 72)
    section_a(base)
    section_b(base)
    section_c(base)
    browser_sections(base)
    if args.skip_zero_damage:
        blocked("G", "zero-damage side-by-side", "skipped by flag")
    else:
        section_g()

    blocked("C-auth", "sign in with a production administrator",
            "BLOCKED_BY_PRODUCTION_CREDENTIAL — owner-accepted; provisioning "
            "requires an env change that rebuilds the legacy project")
    for name in ("Workspace decode", "Auto Investigate", "Analyze",
                 "History list", "History → investigation detail",
                 "Find Related", "Correlate", "Quick Open",
                 "Share / Copy Link"):
        blocked("D-auth", name, "BLOCKED_BY_PRODUCTION_CREDENTIAL")

    ran = [r for r in results if r["pass"] is not None]
    npass = sum(1 for r in ran if r["pass"])
    nblocked = len(results) - len(ran)
    print("-" * 72)
    print(f"{npass}/{len(ran)} PASS · {len(ran) - npass} FAIL · "
          f"{nblocked} BLOCKED (credential)")
    out = "/app/memory/workspace_live_acceptance_result.json"
    with open(out, "w") as fh:
        json.dump({"base_url": base, "results": results,
                   "passed": npass, "ran": len(ran),
                   "blocked": nblocked,
                   "classification": (
                       "WORKSPACE_MIGRATION_UNAUTHENTICATED_VERIFIED"
                       if npass == len(ran) else "NOT_VERIFIED")}, fh, indent=2)
    print(f"written → {out}")
    if npass == len(ran):
        print("\nCLASSIFICATION · WORKSPACE_MIGRATION_UNAUTHENTICATED_VERIFIED")
        print("NOT full runtime verification: the authenticated half is "
              "BLOCKED_BY_PRODUCTION_CREDENTIAL.\n")
        return 0
    print("\nCLASSIFICATION · NOT_VERIFIED\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
