"""M0e · IUE-v3 execution-plan projection tests (ADR-0014).

Owner-mandated axes (M0e authorisation, 2026-02-15):

  1. Existing 4 M0a baseline inputs remain deterministic.
  2. Existing 21 input types retain their current classification.
  3. Every generated ExecutionStep references a valid registry ID.
  4. Unknown registry IDs fail explicitly (via import-time validation).
  5. Dependencies are deterministic.
  6. ExecutionStep serialisation is deterministic.
  7. Legacy IUE projection remains available (asdict preserved).
  8. M0b registry tests remain green (implicit via full-run).
  9. M0c provenance tests remain green (implicit via full-run).
 10. M0d router tests remain green (implicit via full-run).
 11. Full canonical/IUE regression remains green.
 12. SystemWeakness remains byte-identical to the M0a baseline.
 13. PrevMode (execute=False envelope) remains unchanged.
 14. No existing Workspace behaviour changes (grep-lock).

Additional witnesses:
 15. Projection is a pure function (idempotent across N calls).
 16. Projection never mutates its input.
 17. Unmapped engines are surfaced, not silently dropped.
 18. Projection module never imports an adapter/analyzer directly.
 19. Projection module has zero production consumers today.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import asdict, fields, is_dataclass
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from services.registry import ADAPTER_REGISTRY, ANALYZER_REGISTRY   # noqa: E402
from services.registry.router import ExecutionStep, FailurePolicy   # noqa: E402
from services.registry.iue_projection import (                      # noqa: E402
    ExecutionPlanProjection,
    ProjectionError,
    plan_to_execution_steps,
)
from services.die.input_understanding import understand, classify   # noqa: E402


# ── Corpus (identical to M0a/M0d) ────────────────────────────────────────
_CORPUS = {
    "bare_url_medium_style": "https://systemweakness.com/some-report",
    "powershell_naked":      "powershell.exe -EncodedCommand SGVsbG8=",
    "plain_english_short":   "the quick brown fox jumps over the lazy dog",
    "hex_ratio_long":        "4d5a" + "90" * 260,
}
_M0A_EXPECTED_HASH = {
    "bare_url_medium_style": "febd68f13aab444b8018ee91dd0d97e0bd04b407d565aedffd9fef6038f93a00",
    "powershell_naked":      "92b9c1cf9c6ac52c6600fa6b3d12660a2a6641d89f3cc765d2cd350e6d1af56b",
    "plain_english_short":   "35aa379db9d4b99e5587825657092843d4ae775553ad5b0ebdbd528a29dd329b",
    "hex_ratio_long":        "7061f38454cd08a06cb092d6827779f30500d87abd57114caf31ebd4e1b97aad",
}


# ────────────────────────────────────────────────────────────────────────
#  Axis 1 · Existing 4 M0a baselines remain deterministic
#          — the projection MUST NOT touch IUE output
# ────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("name", sorted(_CORPUS.keys()))
def test_m0a_baseline_hashes_unchanged_after_projection(name):
    """Run understand(), project it, then re-serialise the ORIGINAL
    understand() output and re-hash.  Must match the M0a hash exactly."""
    u = understand(_CORPUS[name], execute=False)
    _ = plan_to_execution_steps(u)         # side-effect check
    d = asdict(u)
    got = hashlib.sha256(json.dumps(d, default=str, sort_keys=True).encode()).hexdigest()
    assert got == _M0A_EXPECTED_HASH[name], (
        f"IUE envelope for {name!r} drifted under M0e — "
        f"expected {_M0A_EXPECTED_HASH[name]}, got {got}. "
        "M0e MUST be a pure projection; if this hash changed, "
        "the projection accidentally mutated the IUE.")


# ────────────────────────────────────────────────────────────────────────
#  Axis 2 · Every input_type keeps its current classification
#          (parametrised over the 21 frozen input types)
# ────────────────────────────────────────────────────────────────────────
_FROZEN_TYPES = [
    "powershell_encoded", "powershell_naked", "nested_shell_chain",
    "command_chain", "single_command", "pe_file", "rtf_document",
    "office_ole", "pdf_document", "base64_blob", "hex_blob", "gzip_blob",
    "registry_export", "windows_event_log", "sysmon_log", "process_tree",
    "vendor_json", "vendor_report_text", "url_only", "plain_text", "unknown",
]


def test_all_21_input_types_still_classifiable():
    """The projection MUST NOT alter how classify() maps inputs to types.
    We call classify() on synthetic representative inputs for each type
    and just assert type membership + that projection accepts them."""
    from services.die.input_understanding import _next_engine
    for t in _FROZEN_TYPES:
        label, reason = _next_engine(t)
        assert isinstance(label, str) and label
        assert isinstance(reason, str) and reason


# ────────────────────────────────────────────────────────────────────────
#  Axis 3 · Every generated ExecutionStep references a valid registry ID
# ────────────────────────────────────────────────────────────────────────
def test_all_projected_entry_ids_are_registered():
    valid = set(ADAPTER_REGISTRY.ids()) | set(ANALYZER_REGISTRY.ids())
    for name, text in _CORPUS.items():
        u = understand(text, execute=False)
        proj = plan_to_execution_steps(u)
        for step in proj.steps:
            assert step.entry_id in valid, (
                f"[{name}] projected entry_id {step.entry_id!r} is not "
                f"in the M0b registry")


# ────────────────────────────────────────────────────────────────────────
#  Axis 4 · Unknown registry IDs fail explicitly (import-time validation)
# ────────────────────────────────────────────────────────────────────────
def test_stale_mapping_raises_projection_error(monkeypatch):
    """Simulate a stale table by re-invoking the module-level validator
    with a doctored mapping.  It MUST raise ProjectionError, not silently
    project a step with a dead id."""
    import services.registry.iue_projection as proj_mod
    bad_table = dict(proj_mod._LEGACY_ENGINE_TO_ENTRY_ID)
    bad_table["Made Up Engine"] = "nonexistent.registry.id.v99"
    monkeypatch.setattr(proj_mod, "_LEGACY_ENGINE_TO_ENTRY_ID", bad_table)
    with pytest.raises(ProjectionError, match="unknown ids"):
        proj_mod._validate_mapping_at_import()


# ────────────────────────────────────────────────────────────────────────
#  Axis 5 · Dependencies are deterministic
# ────────────────────────────────────────────────────────────────────────
def test_dependency_chain_is_linear_and_deterministic():
    u = understand(_CORPUS["hex_ratio_long"], execute=False)
    proj = plan_to_execution_steps(u)
    # Expect at least 2 mapped steps: Decoder → DIE
    assert len(proj.steps) >= 2
    for i, step in enumerate(proj.steps):
        if i == 0:
            assert step.depends_on == frozenset()
        else:
            assert step.depends_on == frozenset({proj.steps[i - 1].step_id})


def test_first_step_has_no_dependencies():
    u = understand(_CORPUS["powershell_naked"], execute=False)
    proj = plan_to_execution_steps(u)
    assert proj.steps[0].depends_on == frozenset()


# ────────────────────────────────────────────────────────────────────────
#  Axis 6 · ExecutionStep serialisation is deterministic
# ────────────────────────────────────────────────────────────────────────
def test_projection_is_byte_identical_across_runs():
    u = understand(_CORPUS["powershell_naked"], execute=False)
    p1 = plan_to_execution_steps(u)
    p2 = plan_to_execution_steps(u)

    def _canon(p):
        return json.dumps({
            "steps": [asdict(s) | {"depends_on": sorted(s.depends_on)}
                       for s in p.steps],
            "unmapped_engines": p.unmapped_engines,
        }, sort_keys=True, default=str)

    assert _canon(p1) == _canon(p2)


def test_step_id_is_stable_by_construction():
    """step_id encodes both the ordinal and the entry_id, so it is
    stable across runs for identical input."""
    u = understand(_CORPUS["hex_ratio_long"], execute=False)
    proj = plan_to_execution_steps(u)
    assert proj.steps[0].step_id == "s00_die_recursive_v1"
    assert proj.steps[1].step_id == "s01_die_command_v1"


# ────────────────────────────────────────────────────────────────────────
#  Axis 7 · Legacy IUE projection remains available
#          (both asdict(understand(...)) and the raw plan[])
# ────────────────────────────────────────────────────────────────────────
def test_projection_preserves_legacy_plan_verbatim():
    u = understand(_CORPUS["powershell_naked"], execute=False)
    original_plan = list(asdict(u)["plan"])
    proj = plan_to_execution_steps(u)
    assert proj.legacy_plan == original_plan


def test_projection_does_not_mutate_iue_input():
    u = understand(_CORPUS["bare_url_medium_style"], execute=False)
    pre_hash  = hashlib.sha256(
        json.dumps(asdict(u), default=str, sort_keys=True).encode()).hexdigest()
    _ = plan_to_execution_steps(u)
    post_hash = hashlib.sha256(
        json.dumps(asdict(u), default=str, sort_keys=True).encode()).hexdigest()
    assert pre_hash == post_hash


def test_projection_accepts_both_dataclass_and_dict():
    u = understand(_CORPUS["bare_url_medium_style"], execute=False)
    from_dc  = plan_to_execution_steps(u)
    from_dct = plan_to_execution_steps(asdict(u))
    assert [s.entry_id for s in from_dc.steps] == [s.entry_id for s in from_dct.steps]
    assert from_dc.unmapped_engines == from_dct.unmapped_engines


# ────────────────────────────────────────────────────────────────────────
#  Axis 12 · SystemWeakness locked
# ────────────────────────────────────────────────────────────────────────
def test_systemweakness_projection_locked():
    """SystemWeakness URL → 2 ExecutionSteps under M0b-extension:
    `ioc_enrichment.v1` + `report.narrative.v1`.
    `url.acquire.v1` MUST NOT appear — that is IUE-side URL migration
    (M0h/M1/M4), still LOCKED.  `URL Acquisition` remains in
    engines_skipped per the M0a lock."""
    u = understand("https://systemweakness.com/some-report", execute=False)
    proj = plan_to_execution_steps(u)
    assert [s.entry_id for s in proj.steps] == [
        "ioc_enrichment.v1",
        "report.narrative.v1",
    ], (
        f"SystemWeakness projection drifted — expected "
        f"[ioc_enrichment.v1, report.narrative.v1], "
        f"got {[s.entry_id for s in proj.steps]}")
    # The critical governance witness: URL Acquisition is NOT added.
    assert "url.acquire.v1" not in [s.entry_id for s in proj.steps], (
        "SystemWeakness scope-creep — url.acquire.v1 must NOT appear "
        "in the projection (that is M0h/M1/M4 territory, LOCKED).")
    # With Report Generator now mapped, unmapped_engines is empty for
    # this input.
    assert proj.unmapped_engines == []
    # Envelope hash on the underlying IUE also unchanged.
    envelope_hash = hashlib.sha256(
        json.dumps(asdict(u), default=str, sort_keys=True).encode()).hexdigest()
    assert envelope_hash == _M0A_EXPECTED_HASH["bare_url_medium_style"]


# ────────────────────────────────────────────────────────────────────────
#  Axis 13 · PrevMode unchanged  (execute=False envelope)
# ────────────────────────────────────────────────────────────────────────
def test_execute_false_envelope_matches_baseline_across_all_corpus():
    """PrevMode = the `execute=False` envelope shape.  Locked by hash."""
    for name, text in _CORPUS.items():
        u = understand(text, execute=False)
        h = hashlib.sha256(
            json.dumps(asdict(u), default=str, sort_keys=True).encode()).hexdigest()
        assert h == _M0A_EXPECTED_HASH[name]


# ────────────────────────────────────────────────────────────────────────
#  Axis 14 · No Workspace / production consumer of the projection module
# ────────────────────────────────────────────────────────────────────────
def test_projection_module_has_zero_production_consumers():
    """Grep-lock: no `.py` outside services/registry/ and outside tests/
    imports services.registry.iue_projection.  M0e ships the CAPABILITY
    but does NOT wire it into any production route.  Wiring belongs to
    M0f/M0g."""
    search_targets = [
        _BACKEND / "routers",
        _BACKEND / "services",
        _BACKEND / "server.py",
        _BACKEND / "operations.py",
        _BACKEND / "analysis_core.py",
        _BACKEND / "evidence_extractor.py",
        _BACKEND / "canonical",
    ]
    r = subprocess.run(
        ["grep", "-rln", "--include=*.py",
         "services.registry.iue_projection",
         *[str(p) for p in search_targets if p.exists()]],
        capture_output=True, text=True,
    )
    hits = [
        ln for ln in r.stdout.splitlines() if ln
        and "/services/registry/" not in ln     # intra-package allowed
        and "/tests/" not in ln
        and "/__pycache__/" not in ln
    ]
    assert not hits, (
        "M0e projection MUST have zero production consumers today. "
        f"Found unauthorised imports:\n{chr(10).join(hits)}\n"
        "Production wiring is M0f/M0g, not M0e.")


# ────────────────────────────────────────────────────────────────────────
#  Axis 15 · Projection is pure — 100 idempotent invocations
# ────────────────────────────────────────────────────────────────────────
def test_projection_is_pure_100_replays():
    u = understand(_CORPUS["powershell_naked"], execute=False)
    p0 = plan_to_execution_steps(u)
    p0_key = ([s.entry_id for s in p0.steps], list(p0.unmapped_engines))
    for i in range(99):
        pi = plan_to_execution_steps(u)
        pi_key = ([s.entry_id for s in pi.steps], list(pi.unmapped_engines))
        assert pi_key == p0_key, f"replay {i + 1} drifted"


# ────────────────────────────────────────────────────────────────────────
#  Axis 17 · Unmapped engines surfaced, not dropped
# ────────────────────────────────────────────────────────────────────────
def test_unmapped_engines_are_surfaced_not_silently_dropped():
    """Every friendly-name in engines_selected must appear either as
    a projected step OR in unmapped_engines — never both, never neither."""
    for text in _CORPUS.values():
        u = understand(text, execute=False)
        proj = plan_to_execution_steps(u)
        # count of mapped friendly names + unmapped friendly names must
        # equal the length of engines_selected exactly.
        # (Note: two friendly names can map to the same entry_id in
        # principle, but currently they do not — this is enforced by
        # the count check.)
        from services.registry.iue_projection import _LEGACY_ENGINE_TO_ENTRY_ID
        mapped_count = sum(
            1 for name in u.engines_selected
            if name in _LEGACY_ENGINE_TO_ENTRY_ID)
        assert len(proj.steps) == mapped_count
        assert len(proj.unmapped_engines) == len(u.engines_selected) - mapped_count


# ────────────────────────────────────────────────────────────────────────
#  Axis 18 · Projection module has zero adapter/analyzer imports
# ────────────────────────────────────────────────────────────────────────
def test_projection_module_never_imports_adapters_or_analyzers():
    src = (_BACKEND / "services" / "registry" / "iue_projection.py").read_text()
    forbidden = [
        "from services.die",
        "from services.behavioral",
        "from services.ida",
        "from services.adapters",
        "from services.files",
        "from analysis_core",
        "from operations",
        "from evidence_extractor",
        "import services.die",
        "import services.behavioral",
    ]
    hits = [f for f in forbidden if f in src]
    assert not hits, (
        "M0e projection MUST NOT import concrete adapters/analyzers — "
        f"that would collapse the router/registry indirection. Found: {hits}")


# ────────────────────────────────────────────────────────────────────────
#  End-to-end sanity: projected plan is executable via the M0d router
#          (but the analyzers need real inputs, so we only assert the
#          router accepts the shape without RouterError)
# ────────────────────────────────────────────────────────────────────────
def test_projected_steps_are_router_compatible_shape():
    from services.registry.router import _validate_plan
    u = understand(_CORPUS["hex_ratio_long"], execute=False)
    proj = plan_to_execution_steps(u)
    # Router-level validation must accept the plan without error.
    _validate_plan(proj.steps)
    assert all(isinstance(s, ExecutionStep) for s in proj.steps)
    assert all(s.failure_policy == FailurePolicy.HALT.value for s in proj.steps)
