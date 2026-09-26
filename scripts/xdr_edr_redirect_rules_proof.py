#!/usr/bin/env python3
"""
Proof for the XDR/EDR host-aware product boundary rules.

The rules live in `apps/nivxray-xdr/vercel.json` and cannot be exercised
locally, because host-conditional redirects are evaluated by Vercel's
edge. So this reads the ACTUAL rule set from that file, re-implements
Vercel's matching semantics for the patterns used, and drives a matrix of
(host, path) cases against it.

What it proves, before anything is deployed:
  · each production host lands on its OWN product
  · neither host can serve the other product on a real navigation
  · the rules terminate — no redirect loops, no ping-pong between hosts
  · preview / *.vercel.app hosts are untouched (Preview XDR + EDR safe)
  · every /edr/* route in the app is covered on the XDR host, and every
    /xdr/* route is covered on the EDR host

Owner decisions applied: 1a · 2a · 3a · 4a · 5a. PREPARE ONLY.
"""
import json
import re
import sys

VERCEL_JSON = "/app/apps/nivxray-xdr/vercel.json"
APP_JSX = "/app/apps/nivxray-xdr/src/App.jsx"
XDR_HOST = "xdr.nivxforge.com"
EDR_HOST = "edr.nivxforge.com"

results = []


def rec(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'} · {name}" + (f" · {detail}" if detail else ""))


def compile_source(source):
    """Vercel/path-to-regexp subset actually used: literals + /:name*."""
    m = re.fullmatch(r"(?P<lit>/[^:]*?)/:(?P<name>\w+)\*", source)
    if m:
        lit = re.escape(m.group("lit").rstrip("/"))
        return re.compile(rf"^{lit}(?:/(?P<tail>.*))?$"), m.group("name")
    return re.compile(rf"^{re.escape(source)}$"), None


def apply_rules(rules, host, path):
    """Vercel evaluates redirects in order; first match wins."""
    for r in rules:
        conds = r.get("has") or []
        if any(c.get("type") == "host" and c.get("value") != host for c in conds):
            continue
        rx, param = compile_source(r["source"])
        m = rx.match(path)
        if not m:
            continue
        dest = r["destination"]
        if param:
            tail = m.groupdict().get("tail") or ""
            dest = dest.replace(f"/:{param}*", f"/{tail}" if tail else "")
        return dest, r["source"]
    return None, None


def resolve(rules, host, path, max_hops=6):
    """Follow redirects across hosts to prove termination."""
    seen, hops = set(), []
    cur_host, cur_path = host, path
    for _ in range(max_hops):
        key = (cur_host, cur_path)
        if key in seen:
            return None, hops, "LOOP"
        seen.add(key)
        dest, rule = apply_rules(rules, cur_host, cur_path)
        if dest is None:
            return (cur_host, cur_path), hops, "SETTLED"
        hops.append(f"{cur_host}{cur_path} -[{rule}]-> {dest}")
        m = re.match(r"^https://([^/]+)(/.*)?$", dest)
        if m:
            cur_host, cur_path = m.group(1), m.group(2) or "/"
        else:
            cur_path = dest
    return None, hops, "MAX_HOPS"


def main():
    cfg = json.load(open(VERCEL_JSON))
    rules = cfg.get("redirects") or []
    rec("vercel.json parses and declares redirects", bool(rules),
        f"{len(rules)} rules")
    rec("SPA rewrite present (deep links must not 404)",
        cfg.get("rewrites") == [{"source": "/(.*)", "destination": "/index.html"}])
    rec("no permanent (308) redirects while the topology is moving",
        all(r.get("permanent") is False for r in rules))

    # -- landing behaviour -------------------------------------------
    for host, want in ((XDR_HOST, "/xdr"), (EDR_HOST, "/edr")):
        end, hops, why = resolve(rules, host, "/")
        ok = why == "SETTLED" and end == (host, want)
        rec(f"{host}/ lands on its own product ({want})", ok,
            f"{why} → {end} · {hops}")

    # -- cross-host containment, driven off the REAL route table -----
    app = open(APP_JSX, encoding="utf8").read()
    routes = re.findall(r'path="(/(?:xdr|edr)[^"]*)"', app)
    xdr_routes = sorted({r for r in routes if r.startswith("/xdr")})
    edr_routes = sorted({r for r in routes if r.startswith("/edr")})
    rec("route table read from App.jsx", bool(xdr_routes and edr_routes),
        f"{len(xdr_routes)} /xdr · {len(edr_routes)} /edr")

    def concrete(p):
        return re.sub(r":([A-Za-z]\w*)\*?", "sample", p)

    leaked = []
    for r in edr_routes:                      # EDR routes on the XDR host
        p = concrete(r)
        end, hops, why = resolve(rules, XDR_HOST, p)
        if why != "SETTLED" or not end or end[0] != EDR_HOST:
            leaked.append(f"{XDR_HOST}{p} → {end} ({why})")
    rec(f"all {len(edr_routes)} /edr routes leave the XDR host",
        not leaked, ", ".join(leaked[:4]) or "every /edr route redirects to the EDR host")

    leaked = []
    for r in xdr_routes:                      # XDR routes on the EDR host
        p = concrete(r)
        end, hops, why = resolve(rules, EDR_HOST, p)
        if why != "SETTLED" or not end or end[0] != XDR_HOST:
            leaked.append(f"{EDR_HOST}{p} → {end} ({why})")
    rec(f"all {len(xdr_routes)} /xdr routes leave the EDR host",
        not leaked, ", ".join(leaked[:4]) or "every /xdr route redirects to the XDR host")

    # -- own product must NOT be redirected away ---------------------
    stolen = []
    for host, own in ((XDR_HOST, xdr_routes), (EDR_HOST, edr_routes)):
        for r in own:
            p = concrete(r)
            end, _, why = resolve(rules, host, p)
            if why != "SETTLED" or end != (host, p):
                stolen.append(f"{host}{p} → {end} ({why})")
    rec("each host keeps its OWN product routes (no self-redirect)",
        not stolen, ", ".join(stolen[:4]) or "own routes served locally")

    # -- termination -------------------------------------------------
    loops = []
    for host in (XDR_HOST, EDR_HOST):
        for p in ("/", "/xdr", "/edr", "/xdr/incidents", "/edr/detections",
                  "/xdr/incidents/abc/domain/xyz", "/edr/live-query",
                  "/anything-unknown"):
            _, hops, why = resolve(rules, host, p)
            if why != "SETTLED":
                loops.append(f"{host}{p}: {why} · {hops}")
    rec("every rule chain terminates (no loops, no ping-pong)",
        not loops, ", ".join(loops[:3]) or "16 host/path combinations settle")

    # -- preview hosts untouched -------------------------------------
    untouched = []
    for host in ("nivxray-xdr-git-conflict3108262116-jpreddy017.vercel.app",
                 "nivxray-xdr.vercel.app",
                 "greeting-app-5782.preview.emergentagent.com"):
        for p in ("/", "/xdr/incidents", "/edr"):
            dest, _ = apply_rules(rules, host, p)
            if dest is not None:
                untouched.append(f"{host}{p} → {dest}")
    rec("preview / *.vercel.app hosts are NOT redirected (Preview XDR+EDR safe)",
        not untouched, ", ".join(untouched[:3]) or "no rule matches a non-production host")

    npass = sum(1 for _, ok, _ in results if ok)
    print(f"\n{npass}/{len(results)} PASS · {len(results) - npass} FAIL")
    with open("/app/memory/xdr_edr_redirect_rules_proof.json", "w") as fh:
        json.dump([{"check": n, "pass": ok, "detail": d} for n, ok, d in results],
                  fh, indent=2)
    return 0 if npass == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
