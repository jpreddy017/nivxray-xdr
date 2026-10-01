"""
Vendor Corpus Benchmark · CI Regression Baseline (2026-02-09)
──────────────────────────────────────────────────────────────

Locks the numbers reported by ``run_benchmark`` as the current
sprint's floor.  Every future sprint must recover AT LEAST as
many commands / behaviors / MITRE techniques on the same
14-fixture Vendor Corpus v1.

If a future change accidentally reduces recovery — a regression
in the classifier, the canonicalizer, VEEE, or the projection
layer — CI fails immediately.

Also gates the MITRE Consistency Diagnostic (P4) across every
fixture: the three ATT&CK panels (Observed Behaviour · MITRE
Summary · Attack Chain) MUST agree.  Any divergence in any
fixture fails the build.

The trend file (``corpus/vendor/v1/reports/sprint_trend.json``)
is written as a side effect so the sprint numbers move into the
append-only history log automatically.
"""
from __future__ import annotations

import pytest

# ── Floors — reviewed & signed off 2026-02-09 (sprint-baseline) ──
# Future sprints raise these; a drop below the floor fails CI.
_FLAG_OFF_FLOOR = {
    "commands":        0,
    "behaviors":       0,
    "mitre":           0,
    "recommendations": 42,
}
_FLAG_ON_FLOOR = {
    "commands":        19,
    "behaviors":       18,
    "mitre":            7,
    "recommendations": 42,
}


# Prereq gate — PIL + tesseract must be available (VEEE needs them).
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
    reason="Benchmark needs PIL + tesseract in the environment.")


@pytest.fixture(scope="module")
def _snapshot():
    """Run the benchmark ONCE per session and expose the snapshot
    to every regression assertion."""
    from services.diagnostics.vendor_benchmark import run_benchmark, persist_snapshot
    snap = run_benchmark()
    persist_snapshot(snap)
    return snap


# ══════════════════════════════════════════════════════════════════
# 1. Floor invariants
# ══════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("metric,floor", list(_FLAG_OFF_FLOOR.items()))
def test_flag_off_recovery_at_or_above_floor(_snapshot, metric, floor):
    got = _snapshot["aggregate"]["flag_off"][metric]
    assert got >= floor, \
        f"Flag-OFF {metric}={got} dropped below floor {floor} · regression"


@pytest.mark.parametrize("metric,floor", list(_FLAG_ON_FLOOR.items()))
def test_flag_on_recovery_at_or_above_floor(_snapshot, metric, floor):
    got = _snapshot["aggregate"]["flag_on"][metric]
    assert got >= floor, \
        f"Flag-ON {metric}={got} dropped below floor {floor} · regression"


# ══════════════════════════════════════════════════════════════════
# 2. VEEE lift invariant — Flag ON must always ≥ Flag OFF
# ══════════════════════════════════════════════════════════════════
def test_veee_delta_never_negative(_snapshot):
    """Contract §3.2 · Flag ON is strictly additive."""
    for metric in ("commands", "behaviors", "mitre", "recommendations"):
        d = _snapshot["aggregate"]["delta"][metric]
        assert d >= 0, f"VEEE regressed {metric} by {d}"


def test_veee_recovers_evidence_html_alone_cannot():
    """The corpus bakes commands into PNG screenshots and NOT into
    the surrounding HTML — so Flag ON must recover strictly more
    commands than Flag OFF.  If this test ever fails, VEEE is
    silently disabled."""
    from services.diagnostics.vendor_benchmark import run_benchmark
    snap = run_benchmark()
    off = snap["aggregate"]["flag_off"]["commands"]
    on  = snap["aggregate"]["flag_on"]["commands"]
    assert on > off, f"VEEE produced no measurable lift · off={off} on={on}"


# ══════════════════════════════════════════════════════════════════
# 3. MITRE Consistency Gate (P4 · CI-only)
# ══════════════════════════════════════════════════════════════════
# For each fixture we assemble a minimal case payload (only the
# fields the diagnostic reads) and require ALL six consistency
# checks to be green.  Any drift between the Attack Chain, MITRE
# Summary, and Observed Behaviour projections fails CI.
def _payload_from_pipeline(fixture, *, veee_enabled: bool):
    """Reproduce enough of the case-read payload for the MITRE
    diagnostic.  Uses the pipeline exactly as production would."""
    import os
    from services.ida.report_extractors import extract_all
    from services.ice.correlate         import correlate
    from services.diagnostics.vendor_benchmark import (
        _render_screenshot, _fixture_html,
    )
    html = _fixture_html(fixture.article_title, fixture.vendor, fixture.fixture_id)
    structured_blocks = []
    veee_records      = []
    if veee_enabled:
        os.environ["NVX_VEEE_ENABLED"] = "1"
        from services.veee import extract_from_image
        png = _render_screenshot(fixture.commands)
        for rec in extract_from_image(png,
                                            image_url=f"https://vendor.example/{fixture.fixture_id}.png"):
            veee_records.append(rec)
            if rec.get("type") != "skipped" and rec.get("text"):
                structured_blocks.append(rec["text"])
    else:
        os.environ["NVX_VEEE_ENABLED"] = "0"

    ext = extract_all("\n".join([html] + structured_blocks),
                            structured_blocks=structured_blocks)
    ssot = {"report_extraction": ext,
                "acquired_document": {"structured_blocks": structured_blocks,
                                          "veee_records":      veee_records,
                                          "final_text":        html}}
    ice = correlate(ssot)
    incident = ice.get("incident") or {}

    # Build a lightweight `summary_narrative` from the incident's
    # mitre matrix so the diagnostic has all three panels to compare.
    mitre_summary = []
    for row in incident.get("mitre") or []:
        mitre_summary.append({
            "tactic":     row.get("tactic") or row.get("tactic_label") or "",
            "techniques": row.get("techniques") or [],
        })
    return {
        "incident":          incident,
        "summary_narrative": {"behavior_summary": [b.get("label")
                                                              for b in incident.get("behaviors") or []
                                                              if b.get("label")],
                                  "mitre_summary":    mitre_summary},
    }


def _fixtures():
    from tests.test_p015c5_vendor_corpus_v1 import VENDOR_CORPUS_V1
    return VENDOR_CORPUS_V1


@pytest.mark.parametrize("fixture", _fixtures(),
                              ids=[f.fixture_id for f in _fixtures()])
def test_mitre_consistency_holds_flag_on(fixture):
    """P4 CI gate · every fixture must project a self-consistent
    ATT&CK view when VEEE is ON."""
    from services.diagnostics.mitre_consistency import check
    payload = _payload_from_pipeline(fixture, veee_enabled=True)
    r = check(payload)
    if not r["ok"]:
        failing = [c for c in r["checks"] if not c["ok"]]
        pytest.fail(f"{fixture.fixture_id} · MITRE inconsistency · "
                        f"{[c['check'] for c in failing]} · {failing}")


# ══════════════════════════════════════════════════════════════════
# 4. Trend file persistence & idempotence
# ══════════════════════════════════════════════════════════════════
def test_trend_file_is_appended_idempotently(_snapshot, tmp_path, monkeypatch):
    """Rerunning the benchmark with the SAME sprint id must not
    duplicate entries — the trend file dedupes on sprint id."""
    from services.diagnostics.vendor_benchmark import (
        persist_snapshot, _trend_path,
    )
    import copy, json
    p = _trend_path()
    before = json.loads(p.read_text())
    n_before = len(before["history"])
    # Persist the same snapshot again — count should NOT grow.
    persist_snapshot(copy.deepcopy(_snapshot))
    after = json.loads(p.read_text())
    n_after = len(after["history"])
    assert n_after == n_before


def test_snapshot_has_stable_shape(_snapshot):
    for k in ("schema_version", "sprint", "timestamp_utc",
                  "corpus", "aggregate", "per_fixture", "duration_ms"):
        assert k in _snapshot
    for mode in ("flag_off", "flag_on"):
        assert mode in _snapshot["aggregate"]
        for m in ("commands", "behaviors", "mitre", "recommendations"):
            assert m in _snapshot["aggregate"][mode]
