"""G1 Step 2 · generate and verify the reviewed-code manifest.

`Save to Github` may rewrite commit SHAs, so a commit id cannot anchor "the
Windows host is running the reviewed code". Content hashes can.

    python3 scripts/g1_step2_manifest.py generate
    python3 scripts/g1_step2_manifest.py verify-remote \
        [https://raw.githubusercontent.com/<owner>/<repo>/<branch>]

The Step 1 manifest (`G1_REVIEWED_CODE_MANIFEST.md`, 10 files) stays exactly
as it is: it is the historical evidence for the read-only pre-flight. This
is a SECOND, wider manifest for Step 2, including the S1–S5 closure.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(
    ROOT, "scripts/windows/g1/G1_STEP2_REVIEWED_CODE_MANIFEST.md")
DEFAULT_RAW = ("https://raw.githubusercontent.com/jpreddy017/nivxray-xdr/"
               "feature/rc2-alignment")

#: Every file G1 Step 2 depends on, grouped by why it is in the proof.
GROUPS: list[tuple[str, list[str]]] = [
    ("Windows pre-flight (Step 1 code, unchanged)", [
        "scripts/windows/g1/Get-NivXRayG1Preflight.ps1",
        "scripts/windows/g1/README_G1_STEP1_PREFLIGHT.md",
    ]),
    ("Native Windows acquisition (NivXForge EDR)", [
        "apps/nivxray-xdr-collector/framework/windows_eventlog.py",
        "apps/nivxray-xdr-collector/framework/windows_bookmarks.py",
        "apps/nivxray-xdr-collector/framework/collector_identity.py",
        "apps/nivxray-xdr-collector/framework/runtime.py",
        "apps/nivxray-xdr-collector/framework/scheduler.py",
        "apps/nivxray-xdr-collector/framework/outbox.py",
        "apps/nivxray-xdr-collector/framework/delivery.py",
        "apps/nivxray-xdr-collector/framework/delivery_worker.py",
        "apps/nivxray-xdr-collector/framework/store.py",
        "apps/nivxray-xdr-collector/framework/authz.py",
        "apps/nivxray-xdr-collector/main.py",
        "apps/nivxray-xdr-collector/routes/connectors.py",
    ]),
    ("S3/S4/S5 · Windows runtime + state contract", [
        "apps/nivxray-xdr-collector/framework/state_paths.py",
        "apps/nivxray-xdr-collector/requirements.txt",
        "apps/nivxray-xdr-collector/requirements-windows.txt",
        "apps/nivxray-xdr-collector/WINDOWS_RUNTIME.md",
        "apps/nivxray-xdr-collector/tests/test_g1_windows_runtime_contract.py",
    ]),
    ("S1 · three-clock independence (server)", [
        "backend/services/ingest_provenance.py",
        "backend/tests/test_g1_s1_clock_independence.py",
    ]),
    ("S2 · windows-eventlog protocol identity (server)", [
        "backend/routers/xdr_collectors.py",
        "backend/routers/xdr_data_sources.py",
        "backend/lib/collector_catalog.py",
        "backend/tests/test_g1_s2_windows_eventlog_protocol.py",
    ]),
]

FILES = [p for _label, paths in GROUPS for p in paths]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def local_hash(rel: str) -> str:
    with open(os.path.join(ROOT, rel), "rb") as f:
        return sha256_bytes(f.read())


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                          text=True).stdout.strip()


def generate() -> None:
    now = datetime.now(timezone.utc).isoformat()
    rows = {rel: local_hash(rel) for rel in FILES}
    lines = [
        "# G1 · STEP 2 reviewed-code manifest (content identity)",
        "",
        "`Save to Github` does not guarantee that local commit SHAs survive,",
        "so a commit id is not a reliable anchor for \"the Windows host is",
        "running the reviewed code\". These SHA-256 content hashes are.",
        "",
        "**This manifest supersedes nothing.** The Step 1 manifest",
        "(`G1_REVIEWED_CODE_MANIFEST.md`, 10 files) remains the historical",
        "evidence for the read-only pre-flight that already ran. This one",
        f"covers the {len(FILES)} files G1 **Step 2** depends on, including the",
        "owner-accepted S1-S5 correctness closure.",
        "",
        f"Generated {now} · local branch `{git('rev-parse', '--abbrev-ref', 'HEAD')}`",
        f"· local HEAD `{git('rev-parse', 'HEAD')}`.",
        "",
    ]
    for label, paths in GROUPS:
        lines += [f"## {label}", "", "| SHA-256 | Path |", "|---|---|"]
        lines += [f"| `{rows[p]}` | `{p}` |" for p in paths]
        lines.append("")
    lines += [
        "## Verify on the Windows host (read-only, before anything runs)",
        "",
        "The handoff block does this automatically and STOPS on any MISSING",
        "or MISMATCH. The machine-readable form used there:",
        "",
        "```json",
        json.dumps(rows, indent=2),
        "```",
        "",
        "Line endings: these hashes are of the bytes Git stores (LF). Run",
        "`git config --global core.autocrlf false` BEFORE cloning, or every",
        "`.py`/`.ps1` hash will differ legitimately and the gate will stop",
        "you for the wrong reason.",
        "",
        "A proof taken on unreviewed code is not a proof.",
        "",
    ]
    with open(MANIFEST, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"wrote {MANIFEST} ({len(FILES)} files)")
    for p in FILES:
        print(f"  {rows[p]}  {p}")


def verify_remote(base: str) -> int:
    rows = {rel: local_hash(rel) for rel in FILES}
    bad = 0
    for rel, expected in rows.items():
        req = urllib.request.Request(f"{base}/{rel}",
                                     headers={"User-Agent": "curl/8.5.0"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                actual = sha256_bytes(r.read())
                code = r.status
        except urllib.error.HTTPError as e:
            print(f"ABSENT    [{e.code}] {rel}")
            bad += 1
            continue
        if actual == expected:
            print(f"MATCH     [{code}] {rel}")
        else:
            print(f"MISMATCH  [{code}] {rel}\n  local  {expected}"
                  f"\n  remote {actual}")
            bad += 1
    print(f"\n{len(rows) - bad}/{len(rows)} match byte-for-byte")
    return 1 if bad else 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "generate"
    if cmd == "generate":
        generate()
    elif cmd == "verify-remote":
        sys.exit(verify_remote(sys.argv[2] if len(sys.argv) > 2
                               else DEFAULT_RAW))
    else:
        sys.exit(f"unknown command {cmd!r}")
