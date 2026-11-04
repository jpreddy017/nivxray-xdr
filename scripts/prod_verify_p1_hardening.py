#!/usr/bin/env python3
"""Production verification harness for nivxray.nivxforge.com.

Read-only. No credential is used, nothing is written, no tenant is touched.

    python3 scripts/prod_verify_p1_hardening.py --mode baseline   # BEFORE deploy
    python3 scripts/prod_verify_p1_hardening.py --mode verify     # AFTER deploy

`baseline` records the current production behaviour to
`test_reports/prod_baseline_p1.json`. `verify` asserts every owner-required
gate and prints PASS/FAIL per gate plus a final verdict.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

BASE = "https://nivxray.nivxforge.com"
REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "test_reports")
BASELINE = os.path.join(REPORT_DIR, "prod_baseline_p1.json")
UNKNOWN_KEY = "nvx_" + "0" * 48
EMPTY_BATCH = json.dumps({"envelopes": []}).encode()
_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
       "Chrome/126.0 Safari/537.36 nivxray-prod-verify")


def req(path, method="GET", headers=None, body=None):
    # Cloudflare fronts this host and blocks the default urllib UA (403),
    # which would otherwise be misread as an application failure.
    hdrs = {"User-Agent": _UA, "Accept": "*/*", **(headers or {})}
    r = urllib.request.Request(BASE + path, method=method, data=body,
                               headers=hdrs)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)
    except Exception as e:                                        # noqa: BLE001
        return 0, str(e).encode(), {}


def probe():
    out = {}
    st, body, _ = req("/api/health")
    out["health"] = {"status": st, "body": body.decode()[:200]}

    st, body, _ = req("/api/openapi.json")
    out["openapi_status"] = st
    if st == 200:
        d = json.loads(body)
        out["paths"] = len(d.get("paths", {}))
        schemas = d.get("components", {}).get("schemas", {})
        out["schemas"] = len(schemas)
        out["create_key_body_props"] = list(
            schemas.get("CreateKeyBody", {}).get("properties", {}))
        out["telemetry_receipt_props"] = list(
            schemas.get("TelemetryReceipt", {}).get("properties", {}))

    hdrs = {"Content-Type": "application/json"}
    st, body, h = req("/api/xdr/ingest/telemetry", "POST",
                      {**hdrs, "X-XDR-API-Key": UNKNOWN_KEY,
                       "X-Tenant-Id": "verify-probe"}, EMPTY_BATCH)
    out["ingest_unknown_key"] = {
        "status": st, "body": body.decode()[:250],
        "ratelimit_headers": {k: v for k, v in h.items()
                              if k.lower().startswith("ratelimit")
                              or k.lower() == "retry-after"}}

    st, body, _ = req("/api/xdr/ingest/telemetry", "POST", hdrs, EMPTY_BATCH)
    out["ingest_anonymous"] = {"status": st, "body": body.decode()[:200]}

    st, body, _ = req("/api/xdr/collectors", "GET",
                      {"X-Tenant-Id": "verify-probe",
                       "X-Principal-Id": "verify@probe"})
    out["legacy_header_rbac"] = {"status": st, "body": body.decode()[:200]}

    st, body, _ = req("/api/auth/login", "POST", hdrs,
                      json.dumps({"email": "verify-probe@example.com",
                                  "password": "not-a-real-password"}).encode())
    out["auth_alive"] = {"status": st, "body": body.decode()[:150]}

    st, body, _ = req("/")
    html = body.decode(errors="replace")
    bundle = ""
    if "static/js/main." in html:
        bundle = html.split("static/js/main.")[1].split('"')[0]
    out["workspace_root"] = {
        "status": st, "bundle": "static/js/main." + bundle if bundle else None,
        "html_sha256": hashlib.sha256(body).hexdigest()[:16]}

    st, _, _ = req("/auto-investigate")
    out["workspace_auto_investigate"] = {"status": st}
    return out


GATES = [
    ("health 200",
     lambda p: p["health"]["status"] == 200),
    ("CreateKeyBody has confirm_tenant_id",
     lambda p: "confirm_tenant_id" in p.get("create_key_body_props", [])),
    ("CreateKeyBody has allow_new_tenant",
     lambda p: "allow_new_tenant" in p.get("create_key_body_props", [])),
    ("TelemetryReceipt has duplicates (idempotency live)",
     lambda p: "duplicates" in p.get("telemetry_receipt_props", [])),
    ("unknown API key -> 401 (machine auth path live)",
     lambda p: p["ingest_unknown_key"]["status"] == 401),
    ("unknown API key -> unknown-api-key reason",
     lambda p: "unknown-api-key" in p["ingest_unknown_key"]["body"]),
    ("anonymous ingest -> 403",
     lambda p: p["ingest_anonymous"]["status"] == 403),
    ("legacy-header RBAC still fail-closed (403)",
     lambda p: p["legacy_header_rbac"]["status"] == 403),
    ("production auth alive (bad creds -> 401)",
     lambda p: p["auth_alive"]["status"] == 401),
    ("Workspace root 200 + CRA bundle present",
     lambda p: p["workspace_root"]["status"] == 200
     and bool(p["workspace_root"]["bundle"])),
    ("Workspace /auto-investigate 200",
     lambda p: p["workspace_auto_investigate"]["status"] == 200),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("baseline", "verify"), required=True)
    args = ap.parse_args()
    p = probe()
    os.makedirs(REPORT_DIR, exist_ok=True)

    if args.mode == "baseline":
        with open(BASELINE, "w") as f:
            json.dump(p, f, indent=2)
        print(json.dumps(p, indent=2))
        print(f"\nbaseline written -> {BASELINE}")
        return 0

    print(json.dumps(p, indent=2))
    print("\n── GATES ──")
    failed = []
    for name, fn in GATES:
        try:
            ok = bool(fn(p))
        except Exception:                                         # noqa: BLE001
            ok = False
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            failed.append(name)

    if os.path.exists(BASELINE):
        b = json.load(open(BASELINE))
        print("\n── BASELINE DELTA ──")
        for k in ("paths", "schemas"):
            print(f"{k}: {b.get(k)} -> {p.get(k)}")
        print(f"workspace bundle: {b['workspace_root']['bundle']} -> "
              f"{p['workspace_root']['bundle']}")

    print("\nVERDICT: " + ("PRODUCTION HARDENING PASS" if not failed
                           else f"FAIL ({len(failed)} gate(s)) — ROLL BACK"))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
