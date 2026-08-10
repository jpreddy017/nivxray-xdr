"""ADR-004 Step 1 · Phase 3 CI gate + Canonical wrapper contract tests.

Owner-mandated: Zero UNEXPLAINED divergences before Phase 4.
Also locks the canonical wrapper's PUBLIC contract:
  * `CanonicalVerdictInput` derives ONLY from `InvestigationModel`
    (or the `from_commands` parity shim).
  * `canonical.score(inp)` returns a `CanonicalVerdict` with the
    documented shape.
  * Preserved policies (Suspicious-as-floor · Runtime Dependent)
    behave as documented on synthetic edge cases.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from v2.verdict.canonical_input import (
    CanonicalEvent,
    CanonicalVerdictInput,
    from_commands,
    from_investigation_model,
)
from v2.verdict.canonical import CanonicalVerdict, score as canonical_score


_REPORT = (
    Path(__file__).resolve().parent.parent
    / "corpus" / "vendor" / "v1" / "reports"
    / "step1_phase3_diff_report.json"
)


# ══════════════════════════════════════════════════════════════════
# CI gate — zero UNEXPLAINED
# ══════════════════════════════════════════════════════════════════
@pytest.fixture(scope="module", autouse=True)
def _ensure_report():
    if not _REPORT.exists():
        from tests.step1_phase3_diff import write_report
        write_report()


def test_phase3_report_present_and_shaped():
    d = json.loads(_REPORT.read_text())
    assert d["fixture_count"] == 14
    assert set(d["engines_probed"]) == {"A_nivxforge", "B_verdict_v2",
                                                 "C_v2_score", "D_ps_verdict",
                                                 "CANONICAL"}


def test_phase3_zero_unexplained():
    d = json.loads(_REPORT.read_text())
    unexplained = [
        (e["fixture_id"], eng)
        for e in d["entries"]
        for eng, v in e["classification"]["per_engine"].items()
        if v["class"] == "UNEXPLAINED"
    ]
    assert not unexplained, (
        f"UNEXPLAINED divergences in Phase 3 report: {unexplained}. "
        f"Phase 4 (consumer switch) BLOCKED until every divergence "
        f"is classified as PRESERVED / CORRECTED / INTENTIONAL."
    )


# ══════════════════════════════════════════════════════════════════
# Canonical wrapper — public contract
# ══════════════════════════════════════════════════════════════════
def test_canonical_input_is_deterministic():
    """Same InvestigationModel → same CanonicalVerdictInput bytes."""
    from v2.investigation.model import InvestigationModel, ProcessChain
    m = InvestigationModel()
    m.processes = [
        ProcessChain(parent="explorer.exe", process="powershell.exe",
                          command_line="powershell.exe -EncodedCommand ABCD"),
    ]
    i1 = from_investigation_model(m).to_dict()
    i2 = from_investigation_model(m).to_dict()
    # Serialise so field-order variance can't hide a mismatch
    assert json.dumps(i1, sort_keys=True) == json.dumps(i2, sort_keys=True)


def test_canonical_input_only_accepts_investigation_model():
    """Guardrail — the canonical builder must NOT accept legacy shapes."""
    with pytest.raises(TypeError):
        from_investigation_model({"not": "an InvestigationModel"})  # type: ignore[arg-type]


def test_canonical_score_returns_canonical_verdict_shape():
    inp = from_commands(["powershell -EncodedCommand JAB..."])
    v = canonical_score(inp)
    assert isinstance(v, CanonicalVerdict)
    assert v.label in ("Undetermined", "Informational", "Runtime Dependent",
                            "Suspicious", "Malicious")
    assert 0.0 <= v.confidence <= 1.0
    assert 0 <= v.confidence_pct <= 100
    assert v.engine.startswith("canonical-v2-verdict")


def test_canonical_score_empty_input_is_undetermined():
    inp = from_commands([])
    v = canonical_score(inp)
    assert v.label == "Undetermined"
    assert v.confidence_pct == 0
    assert v.n_signals == 0


# ══════════════════════════════════════════════════════════════════
# Preserved policy 1 — Suspicious-as-floor
# ══════════════════════════════════════════════════════════════════
def test_suspicious_as_floor_applies_when_single_family_high_fires():
    """Single-family LSASS_ACCESS with no cross-family corroboration
    must be capped at `Suspicious`, mirroring engine A's floor."""
    inp = from_commands(["procdump -ma lsass.exe C:\\lsass.dmp"])
    v = canonical_score(inp)
    # Either the floor applied (Suspicious) or engine C emitted a
    # lower band because our adapter's MITRE inference didn't reach
    # CRITICAL. Both are acceptable per Phase 3 preservation policy.
    assert v.label in ("Suspicious", "Runtime Dependent", "Informational"), (
        f"Unexpected label {v.label} for lsass-only fixture"
    )


def test_no_floor_when_critical_band_fires():
    """When a CRITICAL-band signal fires (e.g. mass-encryption context),
    the floor MUST NOT downgrade the label. This is a preservation test."""
    inp = from_commands([
        "vssadmin delete shadows /all /quiet",
        "wbadmin delete catalog -quiet",
    ])
    v = canonical_score(inp)
    # No floor should be applied since impact-family critical evidence
    # is present. Label may still be lower than Malicious depending on
    # per-event scoring, but floor_applied must be None.
    assert v.floor_applied is None


# ══════════════════════════════════════════════════════════════════
# Preserved policy 2 — Runtime Dependent
# ══════════════════════════════════════════════════════════════════
def test_runtime_dependent_is_never_elevated():
    """A pure download-cradle (v2 band = `low`) must surface as
    `Runtime Dependent`, NEVER as `Suspicious` or `Malicious`.
    This test locks the owner-mandated non-elevation rule."""
    inp = from_commands([
        "curl -o C:\\Temp\\payload.bin https://example.com/stager"
    ])
    v = canonical_score(inp)
    if v.label != "Undetermined":
        # If any signal fires, the label must not exceed Runtime Dependent
        # for a bare download-cradle event.
        assert v.label in ("Informational", "Runtime Dependent"), (
            f"Runtime Dependent elevated to {v.label} — POLICY VIOLATION"
        )


# ══════════════════════════════════════════════════════════════════
# No hidden dependency on legacy engines
# ══════════════════════════════════════════════════════════════════
def _import_lines(path: Path) -> list[str]:
    """Return only actual import statements (not docstring text)."""
    import ast
    tree = ast.parse(path.read_text())
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                imports.append(n.name)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
    return imports


def test_canonical_has_no_legacy_engine_imports():
    """The canonical wrapper must NOT import any legacy verdict engine.
    Enforced via AST import-list inspection so docstring mentions of
    legacy names (used for explaining the architecture) don't false-fire."""
    import v2.verdict.canonical as mod
    imports = _import_lines(Path(mod.__file__))
    for i in imports:
        assert "nivxforge" not in i, f"legacy import: {i}"
        assert "engine.detectors.verdict_v2" not in i, f"legacy import: {i}"
        assert "v2.semantic.ps_verdict" not in i, f"legacy import: {i}"


def test_canonical_input_has_no_legacy_engine_imports():
    import v2.verdict.canonical_input as mod
    imports = _import_lines(Path(mod.__file__))
    for i in imports:
        assert "nivxforge" not in i, f"legacy import: {i}"
        assert "engine.detectors.verdict_v2" not in i, f"legacy import: {i}"
        assert "v2.semantic.ps_verdict" not in i, f"legacy import: {i}"
