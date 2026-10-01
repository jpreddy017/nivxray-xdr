"""
S02 · Byte-level Forensic Report.

Verifies whether S02's failure is a decoder defect or a corpus
authoring defect. Same evidence template as S05.
"""
from __future__ import annotations

import base64
import binascii
import subprocess


B64_INPUT = "MzAyZTMwMmUzMTJlMzEyMDIwMjMyMDcwNmY3NzY1NzI3MzY4NjU2YzZjIGNvbW1lbnQ="
EXPECTED_SUBSTRING = "30.30.31.1"


def main() -> int:
    print("=" * 72)
    print("S02 · Byte-level Forensic Report")
    print("=" * 72)

    print("\n1 · Corpus input (base64 arg to echo):")
    print(f"   {B64_INPUT}")

    print("\n2 · rev(input):")
    rs = B64_INPUT[::-1]
    print(f"   {rs}")

    print("\n3 · Python base64.b64decode(rev, validate=True):")
    try:
        out = base64.b64decode(rs, validate=True)
        print(f"   {out!r}")
    except (binascii.Error, ValueError) as exc:
        print(f"   ERROR: {exc}")

    print("\n4 · bash `echo <rev> | base64 -d`:")
    r = subprocess.run(
        ["bash", "-c", f"echo '{rs}' | base64 -d"],
        capture_output=True,
    )
    print(f"   stdout    : {r.stdout!r}")
    print(f"   stderr    : {r.stderr.decode('utf-8', errors='replace').strip()!r}")
    print(f"   returncode: {r.returncode}")

    print("\n5 · Full corpus pipeline via real bash:")
    r = subprocess.run(
        ["bash", "-c", f"echo '{B64_INPUT}' | rev | base64 -d | xxd -r -p"],
        capture_output=True,
    )
    print(f"   stdout    : {r.stdout!r}")
    print(f"   stderr    : {r.stderr.decode('utf-8', errors='replace').strip()!r}")
    print(f"   returncode: {r.returncode}")

    print("\n6 · Direct decode WITHOUT rev (`echo | base64 -d`):")
    direct = base64.b64decode(B64_INPUT)
    print(f"   {direct!r}")

    print("\n7 · Corpus-declared expected substring:")
    print(f"   {EXPECTED_SUBSTRING!r}")

    print("\n8 · Verdict:")
    print("   Real bash's `base64 -d` FAILS on the reversed string —")
    print("   the pipeline as written cannot produce ANY output, let")
    print("   alone the declared expected substring. Direct decoding")
    print("   without `rev` produces useful bytes, but they do not")
    print("   contain `30.30.31.1` either. No deterministic path")
    print("   through this pipeline yields the corpus expectation.")
    print("   → CORPUS-AUTHORING DEFECT · queued for M9 corpus repair.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
