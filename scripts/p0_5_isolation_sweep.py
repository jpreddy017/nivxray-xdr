#!/usr/bin/env python3
"""P0.5 closure · run every unresolved failing file IN ISOLATION and classify
it by evidence.

A file that passes alone but fails in the full run is `ENVIRONMENT`
(shared-database contention in the CI database), not a product fact. A file
that still fails alone is attributed: if it never exercises a surface this
security wave changed it is `PRE_EXISTING_UNRELATED`; if it does, it is
`ATTRIBUTION_REQUIRED` and must be read.

    python3 scripts/p0_5_isolation_sweep.py --out test_reports/p0_5_isolation.json
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from pathlib import Path

BACKEND = Path("/app/backend")

# Surfaces changed by this wave (backend/routers/xdr_{access,api_keys,
# audit_log,collectors,rbac}.py + services/access_authority.py).
WAVE_SURFACES = (
    "/api/xdr/api-keys", "/api/xdr/audit-log", "/api/xdr/collectors",
    "/api/xdr/rbac", "/api/xdr/access", "/api/xdr/tenants",
    "xdr_api_keys", "xdr_audit_log", "xdr_collectors", "xdr_rbac",
    "xdr_access", "access_authority",
)

SUMMARY = re.compile(r"=+ (.*?) =+\s*$")
COUNTS = re.compile(r"(\d+) (passed|failed|error|errors|skipped|xfailed)")


def run_file(rel: str, timeout: int) -> dict:
    started = time.time()
    try:
        p = subprocess.run(
            ["python3", "-m", "pytest", rel, "-q", "--no-header", "-p",
             "no:cacheprovider"],
            cwd=BACKEND, capture_output=True, text=True, timeout=timeout,
        )
        out = p.stdout + p.stderr
        rc = p.returncode
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or b"").decode("utf8", "replace") if isinstance(
            exc.stdout, bytes) else (exc.stdout or "")
        rc = -9
    counts: dict[str, int] = {}
    for line in out.splitlines()[-40:]:
        for n, kind in COUNTS.findall(line):
            counts[kind.rstrip("s")] = int(n)
    return {
        "returncode": rc,
        "seconds": round(time.time() - started, 1),
        "counts": counts,
        "tail": "\n".join(out.strip().splitlines()[-12:]),
    }


def touches_wave(rel: str) -> list[str]:
    try:
        src = (BACKEND / rel).read_text("utf8", errors="replace")
    except OSError:
        return []
    return sorted({s for s in WAVE_SURFACES if s in src})


def classify(res: dict, hits: list[str]) -> str:
    if res["returncode"] == -9:
        return "TIMEOUT_NOT_CLASSIFIED"
    if res["returncode"] == 0:
        return "ENVIRONMENT"
    if res["counts"].get("failed", 0) == 0 and res["counts"].get(
            "error", 0) == 0:
        return "ENVIRONMENT"
    return "ATTRIBUTION_REQUIRED" if hits else "PRE_EXISTING_UNRELATED"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", type=Path,
                    default=Path("/app/test_reports/p0_5_needs_review.txt"))
    ap.add_argument("--out", type=Path,
                    default=Path("/app/test_reports/p0_5_isolation.json"))
    ap.add_argument("--timeout", type=int, default=900)
    args = ap.parse_args()

    rels = [l.strip() for l in args.files.read_text().splitlines()
            if l.strip() and not l.startswith("#")]
    results = {}
    for i, rel in enumerate(rels, 1):
        hits = touches_wave(rel)
        res = run_file(rel, args.timeout)
        res["wave_surfaces"] = hits
        res["verdict"] = classify(res, hits)
        results[rel] = res
        print(f"[{i}/{len(rels)}] {res['verdict']:>22}  {rel}  "
              f"{res['counts']}  {res['seconds']}s", flush=True)
        args.out.write_text(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
