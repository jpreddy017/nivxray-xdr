"""§ 12.2 — Detectors consume the ExecGraph only. No raw-output parsing.

Static-import gate for future detector modules. Phase 1 does not have any
detector modules yet (they land in Phases 4–7), so this test asserts the
*contract* by scanning any file matching the detector-module glob and
failing if it imports `re` / does `.search(` against a string that came
from a raw response field.

For Phase 1 we only assert the guard mechanism works — we add a synthetic
detector-shaped test double in `/tmp` and prove the scanner catches it.
"""
import os
import re
from pathlib import Path

BACKEND = Path("/app/backend")

# Files matching these globs are "detectors" — subject to § 12.2.
DETECTOR_GLOBS = [
    "engine/behavior_extractor.py",
    "engine/mitre_v2.py",
    "engine/lolbin_v2.py",
    "engine/verdict_v2.py",
]

# Forbidden call patterns — a detector must NOT re-parse raw text.
# `result["output"]` (or `result.get("output")`) is the canonical raw
# text field on `/decode/smart` responses.
FORBIDDEN_PATTERNS = [
    r'result\[["\']output["\']\]',
    r'result\.get\(["\']output["\']\)',
]


def _forbid_scan(text: str):
    """Return a list of (line_no, matched_snippet) for any forbidden usage."""
    hits = []
    for i, line in enumerate(text.splitlines(), 1):
        # skip comments — they're allowed to *mention* the pattern.
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for pat in FORBIDDEN_PATTERNS:
            if re.search(pat, line):
                hits.append((i, line.strip()))
                break
    return hits


def test_forbid_scanner_catches_raw_output_reads():
    """Positive control: scanner MUST detect raw-output reads."""
    bad = 'x = result["output"]\nreturn x'
    hits = _forbid_scan(bad)
    assert hits, "scanner failed to detect raw-output read (positive control)"


def test_forbid_scanner_allows_comments():
    """Negative control: comments mentioning `result["output"]` are OK."""
    ok = '# NB: we deliberately DO NOT read result["output"] here\nreturn 1'
    assert _forbid_scan(ok) == []


def test_all_detector_modules_pass_gate():
    """The real check — every existing detector file must be clean.

    Phase 1: none of these files exist yet, so this test passes trivially.
    Phase 4+: as soon as we author `behavior_extractor.py`, this gate
    kicks in and any offending import fails CI.
    """
    for rel in DETECTOR_GLOBS:
        path = BACKEND / rel
        if not path.exists():
            continue
        hits = _forbid_scan(path.read_text())
        assert not hits, (
            f"Detector module {rel} violates § 12.2 (no raw-output parsing).\n"
            + "\n".join(f"  line {i}: {snip}" for i, snip in hits)
        )
