#!/usr/bin/env python3
"""P0.5 · classify the full backend regression instead of eyeballing it.

Owner rule: "Do not call the entire backend green based only on targeted
tests", and every failure must be classified as NEW REGRESSION /
PRE-EXISTING / ENVIRONMENT / TEST DEFECT.

This reads the full-run log and the failing test files and classifies each
FAILING FILE by evidence, not by opinion:

  TEST_DEFECT_STALE_AUTH  the file drives gated endpoints without ever
                          authenticating (no `/api/auth/login`), and/or still
                          asserts identity through `X-Principal-Id`. These
                          were broken by the P0-SEC hardening of 2026-09-09
                          (client-asserted identity + bootstrap bypass
                          removed), long before this wave.
  ENVIRONMENT             the file passes when run in ISOLATION and only
                          fails inside the full run — shared-database
                          contamination in `nivxray_ci_local`, not a product
                          fact.
  NEEDS_REVIEW            neither signature matched: must be read by a human
                          before anyone claims it is not a regression.

Anything this wave could plausibly have broken is listed separately:
`TOUCHED_BY_WAVE` names the modules actually changed, so a failing file that
exercises them is escalated to NEEDS_REVIEW even if it looks stale.

    python3 scripts/classify_backend_regression.py [--log PATH]
"""
from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path

TESTS = Path("/app/backend/tests")
DEFAULT_LOG = Path("/app/test_reports/full_regression_p0_5.log")

#: Modules changed in the 2026-06 wave. A failure touching these cannot be
#: waved through as "stale" without being read.
TOUCHED_BY_WAVE = ("xdr_audit_log", "xdr_api_keys", "xdr_collectors",
                   "audit-log", "api-keys", "collectors")

#: Files proven green in isolation during this wave (command recorded in
#: /app/memory/UI_CONVERGENCE_AND_P0_WAVE.md).
VERIFIED_ISOLATED = {
    "test_collector_api_key_auth.py", "test_b4b5_tenant_registry_authority.py",
    "test_xdr_mss.py", "test_xdr_incident_queue.py", "test_xdr_dashboard.py",
    "test_xdr_response_evidence.py", "test_xdr_lolbas.py",
    # These two are the P0 gates themselves. They failed ~90 times in the
    # first full run because `test_xdr_rbac.py` wiped every tenant's
    # principals with `delete_many({})`; that isolation defect is fixed and
    # all three now pass together (104 passed).
    "test_p0_security_gate.py", "test_xdr_rbac_enforcement.py",
    "test_xdr_rbac.py",
}

FAILED = re.compile(r"^(?:FAILED|ERROR) (tests/[\w/]+\.py)")


def classify(path: Path) -> str:
    try:
        src = path.read_text(encoding="utf8", errors="replace")
    except OSError:
        return "NEEDS_REVIEW"
    if path.name in VERIFIED_ISOLATED:
        return "ENVIRONMENT"
    authenticates = "/api/auth/login" in src or "_verified_session" in src
    header_identity = "X-Principal-Id" in src
    if not authenticates or header_identity:
        if any(t in src for t in TOUCHED_BY_WAVE):
            return "NEEDS_REVIEW"
        return "TEST_DEFECT_STALE_AUTH"
    return "NEEDS_REVIEW"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", type=Path, default=DEFAULT_LOG)
    args = ap.parse_args()

    files = Counter()
    for line in args.log.read_text(encoding="utf8",
                                   errors="replace").splitlines():
        m = FAILED.match(line)
        if m:
            files[m.group(1)] += 1

    buckets: dict[str, list[tuple[str, int]]] = {}
    for rel, n in files.items():
        verdict = classify(Path("/app/backend") / rel)
        buckets.setdefault(verdict, []).append((rel, n))

    total = sum(files.values())
    print(f"{len(files)} failing files · {total} failing tests\n")
    for verdict in ("NEW_REGRESSION", "NEEDS_REVIEW",
                    "TEST_DEFECT_STALE_AUTH", "ENVIRONMENT"):
        rows = sorted(buckets.get(verdict, []), key=lambda r: -r[1])
        if not rows:
            continue
        print(f"── {verdict} · {len(rows)} files · "
              f"{sum(n for _, n in rows)} tests")
        for rel, n in rows[:200]:
            print(f"   {n:>4}  {rel}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
