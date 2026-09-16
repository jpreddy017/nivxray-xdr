#!/usr/bin/env python3
"""MASTER AUDIT · frontend → backend wiring reconciliation.

Extracts every /api/... string literal from both product shells and
tests it against the LIVE OpenAPI route table.  Answers, per UI call:
does the endpoint the console asks for actually exist in the running
backend?  A UI control wired to a non-existent route is a dead control.

READ-ONLY / static + one OpenAPI read.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections import defaultdict

SRC = "/app/apps/nivxray-xdr/src"
OPENAPI = "/tmp/openapi.json"

LITERAL = re.compile(r"/api/[A-Za-z0-9_./{}$:-]+")


def load_routes() -> list[str]:
    d = json.load(open(OPENAPI))
    return sorted(d["paths"])


def route_regex(route: str) -> re.Pattern:
    # /api/incidents/{incident_id}/state  →  ^/api/incidents/[^/]+/state$
    pat = re.sub(r"\{[^}]+\}", "[^/]+", re.escape(route)
                 .replace(r"\{", "{").replace(r"\}", "}"))
    return re.compile("^" + pat + "$")


def normalise(call: str) -> str:
    call = call.split("?")[0].rstrip(".,)`'\"")
    # template / param placeholders → single segment
    call = re.sub(r"\$\{[^}]*\}", "X", call)
    call = re.sub(r"\{[^}]*\}", "X", call)
    call = re.sub(r"/:[A-Za-z0-9_]+", "/X", call)
    call = re.sub(r"/+$", "", call)
    return call


def main() -> int:
    routes = load_routes()
    regexes = [(r, route_regex(r)) for r in routes]

    out = subprocess.run(
        ["grep", "-rhoE", LITERAL.pattern, "--include=*.jsx", "--include=*.js", SRC],
        capture_output=True, text=True, check=False)
    raw = sorted({ln for ln in out.stdout.splitlines() if ln.strip()})

    # where is each call site
    sites = defaultdict(list)
    out2 = subprocess.run(
        ["grep", "-rnoE", LITERAL.pattern, "--include=*.jsx", "--include=*.js", SRC],
        capture_output=True, text=True, check=False)
    for ln in out2.stdout.splitlines():
        try:
            path, lineno, hit = ln.split(":", 2)
        except ValueError:
            continue
        sites[hit].append(f"{path.replace(SRC + '/', '')}:{lineno}")

    matched, dead = [], []
    for call in raw:
        n = normalise(call)
        if n in ("/api", "/api/"):
            continue
        hit = None
        for route, rx in regexes:
            if rx.match(n) or rx.match(n + "/"):
                hit = route
                break
        if hit:
            matched.append({"call": call, "normalised": n, "route": hit})
        else:
            # prefix tolerance: the literal may be a base that is
            # concatenated at runtime (e.g. `${API}/api/edr/` + id)
            prefix = [r for r in routes if r.startswith(n + "/") or r == n]
            dead.append({"call": call, "normalised": n,
                         "prefix_of_existing_routes": prefix[:4],
                         "sites": sites.get(call, [])[:4]})

    res = {"routes_in_running_backend": len(routes),
           "frontend_api_literals": len(raw),
           "matched": len(matched), "unmatched": len(dead),
           "unmatched_detail": dead}
    with open("/app/memory/master_audit_frontend_wiring.json", "w") as fh:
        json.dump({"matched": matched, **res}, fh, indent=2)

    print(f"routes in running backend : {len(routes)}")
    print(f"frontend /api literals    : {len(raw)}")
    print(f"  matched a live route    : {len(matched)}")
    print(f"  NO live route           : {len(dead)}\n")
    for d in dead:
        tag = "BASE_PREFIX_ONLY" if d["prefix_of_existing_routes"] else "DEAD_CALL"
        print(f"{tag:17} {d['normalised']:52} {','.join(d['sites'][:2])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
