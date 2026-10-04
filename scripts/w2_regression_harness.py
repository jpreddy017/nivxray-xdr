"""W2-0 · executable regression harness.

One command, one report, no interpretation: each gate is a subprocess, its exit
code is the verdict, and the report says PASS/FAIL per gate plus the evidence
file to read.  Preview/local only — it never contacts production.

    python scripts/w2_regression_harness.py
    python scripts/w2_regression_harness.py --only dedupe_contract
    python scripts/w2_regression_harness.py --fast     # skip long ASGI suites

Report: /app/test_reports/w2_regression_latest.json (+ a timestamped copy).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

BACKEND = "/app/backend"
REPORTS = "/app/test_reports"

# name, description, gate ids it defends, command, cwd, slow?
GATES: list[dict] = [
    {
        "name": "dedupe_contract",
        "description": "delivery-identity + idempotency contract on the "
                       "deployed module (Sysmon-shaped identities)",
        "defends": ["W1-E2", "W2-D"],
        "cmd": [sys.executable, "scripts/w1e_dedupe_contract_probe.py"],
        "cwd": "/app",
        "slow": False,
    },
    {
        "name": "ingest_idempotency",
        "description": "end-to-end replay: no second raw row, canonical event, "
                       "detection or incident; retention bounded",
        "defends": ["W2-D", "W2-F"],
        "cmd": [sys.executable, "-m", "pytest",
                "tests/test_p0_ingest_idempotency.py", "-q"],
        "cwd": BACKEND,
        "slow": True,
    },
    {
        "name": "dedupe_hardening",
        "description": "fault injection: the idempotency store must not fail "
                       "open and must not permit an extra chain after a crash",
        "defends": ["W2-D", "W2-F"],
        "cmd": [sys.executable, "-m", "pytest",
                "tests/test_p0_dedupe_hardening.py", "-q"],
        "cwd": BACKEND,
        "slow": True,
    },
    {
        "name": "collector_plane_auth",
        "description": "collector plane is authenticated, RBAC-gated and "
                       "tenant-isolated (fail-closed route classification)",
        "defends": ["W2-A", "W2-G"],
        "cmd": [sys.executable, "-m", "pytest",
                "tests/test_collector_plane_auth.py", "-q"],
        "cwd": BACKEND,
        "slow": True,
    },
    {
        "name": "tenant_registry_authority",
        "description": "tenancy exists only via the registry; data-plane "
                       "writes never create a tenant",
        "defends": ["W2-A"],
        "cmd": [sys.executable, "-m", "pytest",
                "tests/test_b4b5_tenant_registry_authority.py", "-q"],
        "cwd": BACKEND,
        "slow": True,
    },
]


def run(gate: dict, timeout: int) -> dict:
    started = time.time()
    try:
        proc = subprocess.run(gate["cmd"], cwd=gate["cwd"], timeout=timeout,
                              capture_output=True, text=True)
        out = (proc.stdout or "") + (proc.stderr or "")
        status = "PASS" if proc.returncode == 0 else "FAIL"
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        out, status, rc = f"TIMEOUT after {timeout}s", "FAIL", None
    return {
        "gate": gate["name"],
        "description": gate["description"],
        "defends": gate["defends"],
        "status": status,
        "returncode": rc,
        "seconds": round(time.time() - started, 1),
        "tail": "\n".join(out.strip().splitlines()[-12:]),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", action="append", default=[],
                    help="run only these gate names")
    ap.add_argument("--fast", action="store_true", help="skip slow suites")
    ap.add_argument("--timeout", type=int, default=600)
    args = ap.parse_args()

    selected = [g for g in GATES
                if (not args.only or g["name"] in args.only)
                and not (args.fast and g["slow"])]
    if not selected:
        print("no gates selected")
        return 2

    results = [run(g, args.timeout) for g in selected]
    passed = sum(1 for r in results if r["status"] == "PASS")
    report = {
        "harness": "w2_regression",
        "at": datetime.now(timezone.utc).isoformat(),
        "scope": "PREVIEW/LOCAL ONLY — production is never contacted",
        "selected": [g["name"] for g in selected],
        "skipped": [g["name"] for g in GATES if g not in selected],
        "summary": {"total": len(results), "passed": passed,
                    "failed": len(results) - passed},
        "verdict": "PASS" if passed == len(results) else "FAIL",
        "gates": results,
    }

    os.makedirs(REPORTS, exist_ok=True)
    stamp = report["at"].replace(":", "").replace("-", "")[:15]
    for path in (f"{REPORTS}/w2_regression_latest.json",
                 f"{REPORTS}/w2_regression_{stamp}.json"):
        with open(path, "w") as fh:
            json.dump(report, fh, indent=2)

    width = max(len(r["gate"]) for r in results)
    print(f"\nW2 REGRESSION HARNESS · {report['at']}")
    for r in results:
        print(f"  {r['status']:4}  {r['gate']:<{width}}  {r['seconds']:>6}s  "
              f"defends {','.join(r['defends'])}")
    for r in results:
        if r["status"] == "FAIL":
            print(f"\n--- {r['gate']} tail ---\n{r['tail']}")
    print(f"\nVERDICT {report['verdict']}  "
          f"({passed}/{len(results)})  -> {REPORTS}/w2_regression_latest.json")
    return 0 if report["verdict"] == "PASS" else 1


sys.exit(main())
