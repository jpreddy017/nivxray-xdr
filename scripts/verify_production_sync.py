#!/usr/bin/env python3
"""Production Sync verification — READ-ONLY.

Run this immediately after a backend Republish:

    python3 scripts/verify_production_sync.py \
        --prod https://nivxray.nivxforge.com \
        --source http://localhost:8001

It compares the deployed OpenAPI route inventory against the source
inventory, proves the previously-absent planes are now ROUTED (401/403 =
present and refusing; 404 = still absent), and checks that destructive
response is still fail-closed.

It sends only unauthenticated GET/POST probes with no body, touches no
database, and holds no credential. A `200` on a protected route would be a
FAILURE, not a success, and is reported as such.
"""
from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# Planes that were absent from production before the republish. Every one
# of these must stop returning 404.
PREVIOUSLY_ABSENT = [
    "/api/edr/policies", "/api/edr/policies/audit",
    "/api/edr/policies/deployment", "/api/edr/groups",
    "/api/edr/agent/policy", "/api/edr/agent/policy-ack",
    "/api/edr/exclusions", "/api/edr/exclusions/sets",
    "/api/edr/exclusions/taxonomy", "/api/edr/exclusions/enforcement-proof",
    "/api/edr/agent/exclusion-enforcement",
    "/api/edr/findings", "/api/edr/findings/evaluation-state",
    "/api/edr/findings/taxonomy",
    "/api/edr/audit", "/api/edr/audit/facets",
    "/api/edr/events", "/api/edr/events/facets",
    "/api/edr/onboarding/computers", "/api/edr/onboarding/packages",
    "/api/edr/connector/releases", "/api/edr/connector/deployments",
    "/api/edr/saved-views", "/api/edr/endpoint-commands",
    "/api/edr/enrollment/tokens/tok_probe/revoke",
    "/api/xdr/rbac/me/effective", "/api/xdr/scope/authorized",
    "/api/xdr/scope/select", "/api/xdr/windows/configuration",
]

#: Must remain protected. A 200 here means authentication weakened.
MUST_STAY_PROTECTED = [
    "/api/edr/enrollment/tokens", "/api/edr/enrollment/endpoints",
    "/api/edr/endpoints", "/api/edr/findings", "/api/edr/exclusions",
    "/api/edr/policies", "/api/edr/audit", "/api/edr/response/actions",
    "/api/edr/agent/whoami", "/api/edr/agent/heartbeat",
]

PRESENT_CODES = (400, 401, 403, 405, 409, 422, 503)


def probe(base: str, path: str, method: str = "GET") -> int | str:
    req = urllib.request.Request(base.rstrip("/") + path, method=method)
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:                                    # noqa: BLE001
        return f"ERR {type(e).__name__}"


def openapi_paths(base: str) -> set[str]:
    for suffix in ("/api/openapi.json", "/openapi.json"):
        try:
            with urllib.request.urlopen(base.rstrip("/") + suffix,
                                        timeout=40) as r:
                return set(json.load(r)["paths"])
        except Exception:                                     # noqa: BLE001
            continue
    return set()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prod", required=True)
    ap.add_argument("--source", default="http://localhost:8001")
    a = ap.parse_args()

    failures: list[str] = []

    health = probe(a.prod, "/api/health")
    print(f"health                     {health}")
    if health != 200:
        failures.append(f"health returned {health}")

    prod = openapi_paths(a.prod)
    src = openapi_paths(a.source)
    print(f"source routes              {len(src)}")
    print(f"production routes          {len(prod)}")
    missing = sorted(src - prod)
    extra = sorted(prod - src)
    print(f"missing in production      {len(missing)}")
    print(f"in production only         {len(extra)}")
    if missing:
        failures.append(f"{len(missing)} source routes absent in production")
        for p in missing[:40]:
            print(f"   MISSING {p}")

    print("\n── previously absent planes ──")
    with ThreadPoolExecutor(10) as ex:
        codes = list(ex.map(lambda p: probe(a.prod, p), PREVIOUSLY_ABSENT))
    for path, code in zip(PREVIOUSLY_ABSENT, codes):
        state = ("ROUTED" if code in PRESENT_CODES
                 else "STILL ABSENT" if code == 404 else f"UNEXPECTED {code}")
        print(f"   {str(code):>5}  {state:<13} {path}")
        if state != "ROUTED":
            failures.append(f"{path} -> {code}")

    print("\n── authority (unauthenticated must be refused) ──")
    with ThreadPoolExecutor(10) as ex:
        codes = list(ex.map(lambda p: probe(a.prod, p), MUST_STAY_PROTECTED))
    for path, code in zip(MUST_STAY_PROTECTED, codes):
        # 405 = the route exists but not for this verb; nothing is
        # disclosed, so it is a refusal too.
        ok = code in (401, 403, 405)
        print(f"   {str(code):>5}  {'REFUSED' if ok else 'NOT REFUSED'} {path}")
        if not ok:
            failures.append(f"{path} unauthenticated -> {code}")

    print("\n── destructive response must stay fail-closed ──")
    code = probe(a.prod, "/api/edr/response/actions", "POST")
    print(f"   POST /api/edr/response/actions -> {code} "
          f"(401/403/422/503 expected; 200 would be a failure)")
    if code == 200:
        failures.append("response dispatch accepted an unauthenticated POST")

    print("\n" + ("PRODUCTION SYNC VERIFICATION: PASS" if not failures else
                  "PRODUCTION SYNC VERIFICATION: FAIL"))
    for f in failures:
        print("  - " + f)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
