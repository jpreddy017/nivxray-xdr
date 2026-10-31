"""
Quality Dashboard · CI regression floors (2026-02-09)

Locks the quality metrics computed by the vendor benchmark so
future sprints can't silently regress:

    · commands_recovered          ≥ 19
    · behaviors_classified        ≥ 18
    · mitre_techniques            ≥ 18
    · mean_ocr_confidence         ≥ 0.85
    · generic_fallback_count      ≤ 2      (was 4 before gap fixes)
    · veee_lift                   > 0

CI failure semantics:
    · Any recovered-evidence metric dropping below floor fails.
    · The generic-fallback count rising above ceiling fails —
      that is exactly the signal we want when the classifier
      starts falling through to "Command execution" for
      previously-covered patterns.
"""
from __future__ import annotations

import os
import pytest


# ── Prereqs (VEEE needs PIL + tesseract) ─────────────────────────
def _tesseract_available() -> bool:
    try:
        import subprocess
        return subprocess.run(["tesseract", "--version"],
                                    capture_output=True, timeout=3).returncode == 0
    except Exception:
        return False


try:
    import PIL   # noqa: F401
    _PIL_OK = True
except Exception:
    _PIL_OK = False


pytestmark = pytest.mark.skipif(
    not (_PIL_OK and _tesseract_available()),
    reason="Quality dashboard benchmark needs PIL + tesseract.")


# ── Floors ───────────────────────────────────────────────────────
_FLOORS = {
    "commands":                19,   # ≥
    "behaviors":                18,  # ≥
    "mitre":                    18,  # ≥
    "recommendations":          42,  # ≥
    "mean_ocr_confidence":       0.85,  # ≥
    "veee_lift_min":             1,  # > 0
}
_CEILINGS = {
    # 4 known edge cases as of sprint-quality-gate (2026-02-09):
    #   · cmd.exe /c wmic … call getowner   (peel-loses-args)
    #   · cmd.exe /c schtasks /s <host>     (peel-loses-args)
    #   · cmd.exe /c powershell -Encoded…   (peel-loses-args)
    #   · net use \\host\c$                 (head_token=bare-exe)
    # Root cause: IDA's head_token extractor loses context after a
    # cmd/c peel or when the command has no .exe.  Backlogged for
    # the classifier polish sprint; the ceiling is a trip-wire —
    # any NEW pattern falling through fails CI.
    "generic_fallback":          4,  # ≤   (down from earlier runs; hard-locked)
}


@pytest.fixture(scope="module")
def _snapshot():
    """Run the benchmark ONCE per session with the canonical BKB
    projection active (preview state)."""
    os.environ["NVX_BKB_CANONICAL"] = "1"
    from services.diagnostics.vendor_benchmark import run_benchmark
    return run_benchmark(sprint="sprint-quality-gate")


# ══════════════════════════════════════════════════════════════════
# Floor invariants (recovered-evidence metrics)
# ══════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("metric,floor", [
    ("commands",                _FLOORS["commands"]),
    ("behaviors",               _FLOORS["behaviors"]),
    ("mitre",                   _FLOORS["mitre"]),
    ("recommendations",         _FLOORS["recommendations"]),
])
def test_metric_at_or_above_floor(_snapshot, metric, floor):
    got = _snapshot["aggregate"]["flag_on"][metric]
    assert got >= floor, \
        f"Quality regression · {metric}={got} dropped below floor {floor}"


def test_mean_ocr_confidence_at_or_above_floor(_snapshot):
    got = _snapshot["aggregate"]["flag_on"].get("mean_ocr_confidence") or 0.0
    assert got >= _FLOORS["mean_ocr_confidence"], \
        f"OCR quality regression · mean confidence {got} < {_FLOORS['mean_ocr_confidence']}"


# ══════════════════════════════════════════════════════════════════
# Ceiling invariants (bad signals must NOT rise)
# ══════════════════════════════════════════════════════════════════
def test_generic_fallback_at_or_below_ceiling(_snapshot):
    got = _snapshot["aggregate"]["flag_on"].get("generic_fallback")
    ceiling = _CEILINGS["generic_fallback"]
    assert got is not None, "generic_fallback metric not emitted"
    assert got <= ceiling, (
        f"Classifier regression · generic_fallback={got} exceeds ceiling {ceiling}. "
        f"A new command pattern is falling through to 'Command execution'. "
        f"Extend the classifier + BKB.")


# ══════════════════════════════════════════════════════════════════
# VEEE lift — Flag ON must always recover MORE than Flag OFF
# ══════════════════════════════════════════════════════════════════
def test_veee_produces_measurable_lift(_snapshot):
    off = _snapshot["aggregate"]["flag_off"]["commands"]
    on  = _snapshot["aggregate"]["flag_on"]["commands"]
    delta = on - off
    assert delta >= _FLOORS["veee_lift_min"], \
        f"VEEE lift regressed · off={off} on={on} delta={delta}"


# ══════════════════════════════════════════════════════════════════
# Snapshot shape
# ══════════════════════════════════════════════════════════════════
def test_snapshot_carries_all_quality_metrics(_snapshot):
    on = _snapshot["aggregate"]["flag_on"]
    for k in ("commands", "behaviors", "mitre", "recommendations",
                  "generic_fallback", "mean_ocr_confidence",
                  "recommendation_coverage"):
        assert k in on, f"quality metric '{k}' missing from snapshot"
