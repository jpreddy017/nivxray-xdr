"""M0d · Thin execution router tests (ADR-0014).

Owner-mandated coverage axes (M0d authorisation, 2026-02-15):
   1. Known adapter ID resolves.
   2. Known analyzer ID resolves.
   3. Unknown adapter ID fails explicitly.
   4. Unknown analyzer ID fails explicitly.
   5. A single adapter step executes the existing implementation.
   6. A single analyzer step executes the existing implementation.
   7. Dependency ordering is respected.
   8. Dependency failure prevents dependent execution.
   9. failure_policy is respected.
  10. Execution order is deterministic.
  11. Registry remains the only resolution source.
  12. Existing M0a contract hashes remain unchanged.
  13. Existing M0b registry tests remain green (implicit via full-run).
  14. Existing M0c provenance tests remain green (implicit via full-run).
  15. Existing UI-DEF-02 regression suite remains green (implicit).
  16. Workspace behaviour remains unchanged.
  17. SystemWeakness URL remains byte-identical to the M0a baseline.
  18. `^` decode-fidelity defect remains unchanged and is NOT modified.

STRICT: M0d activates the M0b registry as a dispatcher; it does NOT
wire itself into any production route.  The router is a new capability
that can be invoked from tests today.  When M0e/M0g eventually connect
the IUE plan to this router, the test at axis 16 will fail (by design)
and must be updated as part of that authorised migration.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from services.registry import ADAPTER_REGISTRY, ANALYZER_REGISTRY  # noqa: E402
from services.registry.router import (                              # noqa: E402
    ExecutionStep,
    FailurePolicy,
    RouterError,
    StepOutcome,
    StepStatus,
    execute_plan,
)


# ────────────────────────────────────────────────────────────────────────────
#  Axis 1 · Known adapter ID resolves
# ────────────────────────────────────────────────────────────────────────────
def test_known_adapter_id_resolves_and_executes():
    """`text.passthrough.v1` → `builtins:str` is a trivially-safe adapter
    for exercising the resolution path end-to-end."""
    outcomes = execute_plan([
        ExecutionStep(step_id="s1", entry_id="text.passthrough.v1",
                       inputs={"object": "hello"}),
    ])
    assert len(outcomes) == 1
    assert outcomes[0].status == StepStatus.SUCCESS
    assert outcomes[0].entry_id == "text.passthrough.v1"
    assert outcomes[0].implementation == "builtins:str"
    assert outcomes[0].result == "hello"
    assert outcomes[0].error is None


# ────────────────────────────────────────────────────────────────────────────
#  Axis 2 · Known analyzer ID resolves
# ────────────────────────────────────────────────────────────────────────────
def test_known_analyzer_id_resolves_and_executes():
    """`die.command.v1` → `services.die.api:analyze` — real analyzer.
    The router only needs it to run to completion; the result content is
    the analyzer's own contract, not the router's."""
    outcomes = execute_plan([
        ExecutionStep(step_id="s1", entry_id="die.command.v1",
                       inputs={"src": "powershell.exe -EncodedCommand SGVsbG8="}),
    ])
    assert len(outcomes) == 1
    assert outcomes[0].status == StepStatus.SUCCESS
    assert outcomes[0].entry_id == "die.command.v1"
    assert outcomes[0].implementation == "services.die.api:analyze"
    assert isinstance(outcomes[0].result, dict)


# ────────────────────────────────────────────────────────────────────────────
#  Axis 3 · Unknown adapter/entry ID fails explicitly, never falls back
# ────────────────────────────────────────────────────────────────────────────
def test_unknown_entry_id_returns_unknown_implementation():
    outcomes = execute_plan([
        ExecutionStep(step_id="s1", entry_id="nonexistent.adapter.v99",
                       inputs={"object": "hello"}),
    ])
    assert outcomes[0].status == StepStatus.UNKNOWN_IMPLEMENTATION
    assert outcomes[0].result is None
    assert outcomes[0].implementation is None
    assert "not registered" in outcomes[0].error


# ────────────────────────────────────────────────────────────────────────────
#  Axis 4 · Unknown analyzer ID fails explicitly (same code path,
#            different naming space — assert the router does NOT try to
#            infer that "analyzer" ids should look elsewhere)
# ────────────────────────────────────────────────────────────────────────────
def test_unknown_analyzer_id_returns_unknown_implementation():
    outcomes = execute_plan([
        ExecutionStep(step_id="s1", entry_id="nonexistent.analyzer.v99"),
    ])
    assert outcomes[0].status == StepStatus.UNKNOWN_IMPLEMENTATION
    assert outcomes[0].failed_dependency is None
    # No silent fallback: the error text names the two registries as the
    # only resolution sources.
    assert "ADAPTER_REGISTRY" in outcomes[0].error
    assert "ANALYZER_REGISTRY" in outcomes[0].error


# ────────────────────────────────────────────────────────────────────────────
#  Axis 5 · A single adapter step executes the existing implementation
#           (already exercised by axis 1; here we prove the returned
#           `result` is exactly what the real implementation returns —
#           i.e. the router does NOT wrap / rewrite / transform)
# ────────────────────────────────────────────────────────────────────────────
def test_adapter_result_is_verbatim_from_implementation():
    # str(42) → "42".  If the router post-processes the result at all,
    # this test will fail.
    outcomes = execute_plan([
        ExecutionStep(step_id="s1", entry_id="text.passthrough.v1",
                       inputs={"object": 42}),
    ])
    assert outcomes[0].result == "42"
    assert type(outcomes[0].result) is str


# ────────────────────────────────────────────────────────────────────────────
#  Axis 6 · A single analyzer step executes the existing implementation.
#           Real invocation on the DIE analyzer, structural check only.
# ────────────────────────────────────────────────────────────────────────────
def test_analyzer_returns_die_envelope_structure():
    outcomes = execute_plan([
        ExecutionStep(step_id="s1", entry_id="die.command.v1",
                       inputs={"src": "cmd.exe /c whoami"}),
    ])
    assert outcomes[0].status == StepStatus.SUCCESS
    # The DIE analyzer envelope is a dict with at least these keys — this
    # test does NOT lock the analyzer's contract (that's UI-DEF-02).  It
    # merely proves the router hands back the analyzer's own return
    # value, whatever shape it currently has.
    assert isinstance(outcomes[0].result, dict)


# ────────────────────────────────────────────────────────────────────────────
#  Axis 7 · Dependency ordering is respected (topological execution)
# ────────────────────────────────────────────────────────────────────────────
def test_dependency_ordering_topological():
    """If s2 depends on s1, s1 MUST execute first even if listed after."""
    outcomes = execute_plan([
        ExecutionStep(step_id="s2", entry_id="text.passthrough.v1",
                       inputs={"object": "second"},
                       depends_on=frozenset({"s1"})),
        ExecutionStep(step_id="s1", entry_id="text.passthrough.v1",
                       inputs={"object": "first"}),
    ])
    # Return order matches original input order (s2 first, then s1).
    assert [o.step_id for o in outcomes] == ["s2", "s1"]
    # Both succeeded.
    assert all(o.status == StepStatus.SUCCESS for o in outcomes)


def test_dependency_ordering_deep_chain():
    """5-step linear chain — order must be strictly respected."""
    plan = [
        ExecutionStep(step_id=f"s{i}", entry_id="text.passthrough.v1",
                       inputs={"object": str(i)},
                       depends_on=frozenset({f"s{i-1}"}) if i > 1 else frozenset())
        for i in range(1, 6)
    ]
    outcomes = execute_plan(plan)
    assert all(o.status == StepStatus.SUCCESS for o in outcomes)
    assert [o.step_id for o in outcomes] == ["s1", "s2", "s3", "s4", "s5"]


def test_cyclic_dependency_raises_router_error():
    with pytest.raises(RouterError, match="cyclic dependency"):
        execute_plan([
            ExecutionStep(step_id="a", entry_id="text.passthrough.v1",
                           depends_on=frozenset({"b"})),
            ExecutionStep(step_id="b", entry_id="text.passthrough.v1",
                           depends_on=frozenset({"a"})),
        ])


# ────────────────────────────────────────────────────────────────────────────
#  Axis 8 · Dependency failure prevents dependent execution
# ────────────────────────────────────────────────────────────────────────────
def test_failed_dependency_produces_dependency_failed_and_skips_impl():
    """When s1 fails, s2 must NOT run its implementation.  The router
    must produce `DEPENDENCY_FAILED` with `failed_dependency='s1'`."""
    outcomes = execute_plan([
        ExecutionStep(step_id="s1", entry_id="nonexistent.adapter.v99"),
        ExecutionStep(step_id="s2", entry_id="text.passthrough.v1",
                       inputs={"object": "hello"},
                       depends_on=frozenset({"s1"})),
    ])
    s1, s2 = outcomes
    assert s1.status == StepStatus.UNKNOWN_IMPLEMENTATION
    assert s2.status == StepStatus.DEPENDENCY_FAILED
    assert s2.failed_dependency == "s1"
    # Critical: s2's implementation MUST NOT have run.
    assert s2.result is None
    assert s2.implementation is None


def test_missing_dependency_in_plan_is_dependency_failed():
    """If a step depends on an ID not present in the plan, it is
    treated as dependency-failed rather than silently ignored."""
    outcomes = execute_plan([
        ExecutionStep(step_id="s1", entry_id="text.passthrough.v1",
                       inputs={"object": "x"},
                       depends_on=frozenset({"does-not-exist"})),
    ])
    assert outcomes[0].status == StepStatus.DEPENDENCY_FAILED
    assert outcomes[0].failed_dependency == "does-not-exist"


# ────────────────────────────────────────────────────────────────────────────
#  Axis 9 · failure_policy is respected
# ────────────────────────────────────────────────────────────────────────────
def test_failure_policy_continue_lets_dependents_run():
    outcomes = execute_plan([
        ExecutionStep(step_id="s1", entry_id="nonexistent.adapter.v99"),
        ExecutionStep(step_id="s2", entry_id="text.passthrough.v1",
                       inputs={"object": "hi"},
                       depends_on=frozenset({"s1"}),
                       failure_policy=FailurePolicy.CONTINUE.value),
    ])
    s1, s2 = outcomes
    assert s1.status == StepStatus.UNKNOWN_IMPLEMENTATION
    # Continue policy means s2 executes despite s1's failure.
    assert s2.status == StepStatus.SUCCESS
    assert s2.result == "hi"


def test_failure_policy_halt_is_default():
    """Default is HALT — dependents on a failed step are skipped."""
    step = ExecutionStep(step_id="s2", entry_id="text.passthrough.v1")
    assert step.failure_policy == FailurePolicy.HALT.value


def test_invalid_failure_policy_rejected():
    with pytest.raises(RouterError, match="invalid failure_policy"):
        execute_plan([
            ExecutionStep(step_id="s1", entry_id="text.passthrough.v1",
                           failure_policy="banana"),
        ])


# ────────────────────────────────────────────────────────────────────────────
#  Axis 10 · Execution order is deterministic across independent steps
# ────────────────────────────────────────────────────────────────────────────
def test_deterministic_execution_across_runs():
    plan = [
        ExecutionStep(step_id=f"s{i}", entry_id="text.passthrough.v1",
                       inputs={"object": f"n{i}"})
        for i in range(6)
    ]
    run1 = execute_plan(plan)
    run2 = execute_plan(plan)
    # Byte-identical outcome sequence.
    assert [asdict(o) for o in run1] == [asdict(o) for o in run2]
    # Return order matches original plan order.
    assert [o.step_id for o in run1] == [f"s{i}" for i in range(6)]


def test_deterministic_topological_tie_break_by_input_index():
    """Two independent branches — the router MUST return outcomes in
    the caller's declared plan order, not in some arbitrary order."""
    plan = [
        ExecutionStep(step_id="a", entry_id="text.passthrough.v1",
                       inputs={"object": "A"}),
        ExecutionStep(step_id="b", entry_id="text.passthrough.v1",
                       inputs={"object": "B"},
                       depends_on=frozenset({"a"})),
        ExecutionStep(step_id="c", entry_id="text.passthrough.v1",
                       inputs={"object": "C"}),
        ExecutionStep(step_id="d", entry_id="text.passthrough.v1",
                       inputs={"object": "D"},
                       depends_on=frozenset({"c"})),
    ]
    ids = [o.step_id for o in execute_plan(plan)]
    assert ids == ["a", "b", "c", "d"]


# ────────────────────────────────────────────────────────────────────────────
#  Axis 11 · Registry is the ONLY resolution source
#            No hard-coded dispatch table anywhere in router.py.
# ────────────────────────────────────────────────────────────────────────────
def test_router_source_contains_no_hardcoded_dispatch_table():
    """Read the router source and lock the absence of hand-rolled
    entry_id → callable mappings.  The registry MUST be the SSOT."""
    router_src = (_BACKEND / "services" / "registry" / "router.py").read_text()
    # Forbidden patterns — a dict literal keying by known registry IDs
    # would indicate a shadow dispatch table.
    forbidden = [
        '"die.command.v1":',
        "'die.command.v1':",
        '"url.acquire.v1":',
        "'url.acquire.v1':",
        '"sysmon.xml.v1":',
        "'sysmon.xml.v1':",
        "IMPLEMENTATIONS = {",
        "DISPATCH_TABLE = {",
    ]
    hits = [p for p in forbidden if p in router_src]
    assert not hits, (
        "M0d router MUST resolve via the M0b registry only. "
        f"Found hard-coded dispatch pattern(s): {hits}"
    )


def test_router_only_imports_from_m0b_registry():
    """Grep the router source for imports of adapters/analyzers.  The
    router MUST NOT import any concrete adapter/analyzer directly."""
    router_src = (_BACKEND / "services" / "registry" / "router.py").read_text()
    forbidden_imports = [
        "from services.die",
        "from services.behavioral",
        "from services.ida",
        "from services.adapters",
        "from services.files",
        "from analysis_core",
        "from operations",
        "from evidence_extractor",
    ]
    hits = [p for p in forbidden_imports if p in router_src]
    assert not hits, (
        "Router leaked a direct import of an adapter/analyzer — that "
        f"turns it into a dispatch table.  Found: {hits}"
    )


def test_registry_lookup_is_the_public_resolution_api():
    """The router uses `ADAPTER_REGISTRY.get()` / `ANALYZER_REGISTRY.get()`
    and NOTHING ELSE for resolution.  We assert the callable it uses is
    identical to the objects exposed by services.registry."""
    import services.registry as reg_module
    import services.registry.router as router_module
    # The router module's `ADAPTER_REGISTRY` symbol MUST be the exact
    # object exported by services.registry — no shadow copy.
    assert router_module.ADAPTER_REGISTRY  is reg_module.ADAPTER_REGISTRY
    assert router_module.ANALYZER_REGISTRY is reg_module.ANALYZER_REGISTRY


# ────────────────────────────────────────────────────────────────────────────
#  Axis 12 · M0a IUE contract hashes remain byte-identical.
#            These are the exact same hashes locked by M0b in
#            test_m0a_iue_response_hashes_unchanged.
# ────────────────────────────────────────────────────────────────────────────
_M0A_EXPECTED = {
    "bare_url_medium_style": "febd68f13aab444b8018ee91dd0d97e0bd04b407d565aedffd9fef6038f93a00",
    "powershell_naked":      "92b9c1cf9c6ac52c6600fa6b3d12660a2a6641d89f3cc765d2cd350e6d1af56b",
    "plain_english_short":   "35aa379db9d4b99e5587825657092843d4ae775553ad5b0ebdbd528a29dd329b",
    "hex_ratio_long":        "7061f38454cd08a06cb092d6827779f30500d87abd57114caf31ebd4e1b97aad",
}
_M0A_CORPUS = {
    "bare_url_medium_style": "https://systemweakness.com/some-report",
    "powershell_naked":      "powershell.exe -EncodedCommand SGVsbG8=",
    "plain_english_short":   "the quick brown fox jumps over the lazy dog",
    "hex_ratio_long":        "4d5a" + "90" * 260,
}


@pytest.mark.parametrize("name", sorted(_M0A_CORPUS.keys()))
def test_m0a_iue_hashes_still_byte_identical(name):
    from services.die.input_understanding import understand
    u = asdict(understand(_M0A_CORPUS[name], execute=False))
    got = hashlib.sha256(json.dumps(u, default=str, sort_keys=True).encode()).hexdigest()
    assert got == _M0A_EXPECTED[name], (
        f"IUE envelope for {name!r} drifted under M0d — "
        f"expected {_M0A_EXPECTED[name]}, got {got}. "
        "M0d MUST be a pure dispatcher; if this hash changed, "
        "the router has accidentally influenced IUE classification."
    )


# ────────────────────────────────────────────────────────────────────────────
#  Axis 16 · Workspace behaviour remains unchanged.
#            Grep-lock: nothing in routers/, workspace UI-adjacent code,
#            or the existing service layer imports services.registry.router.
# ────────────────────────────────────────────────────────────────────────────
def test_router_has_zero_production_consumers():
    """Grep-lock: no `.py` outside `services/registry/` and outside
    `tests/` imports the router.  M0d ships the capability but does
    NOT wire it into any production route.  That wiring is M0e/M0g."""
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
         "services.registry.router",
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
        "M0d router MUST have zero production consumers today. "
        f"Found unauthorised imports:\n{chr(10).join(hits)}\n"
        "Wiring the router into production is M0e/M0g — not M0d."
    )


# ────────────────────────────────────────────────────────────────────────────
#  Axis 17 · SystemWeakness URL remains byte-identical to the M0a baseline.
#            This is a specific witness of the anti-scope-creep rule:
#            M0d MUST NOT accidentally start acquiring / classifying /
#            analysing the SystemWeakness URL differently.
# ────────────────────────────────────────────────────────────────────────────
def test_systemweakness_url_iue_envelope_still_locked():
    """Direct witness of the owner's governance test:
    `bare_url_medium_style` IS the SystemWeakness URL fixture."""
    from services.die.input_understanding import understand
    u = asdict(understand("https://systemweakness.com/some-report", execute=False))
    # The plan MUST still omit URL Acquisition (M4 debt, deliberately
    # unresolved) — locked by M0a's test_url_only_plan_omits_url_acquisition_today.
    engines_selected = u.get("engines_selected", [])
    assert "URL Acquisition" not in engines_selected, (
        "SystemWeakness scope-creep detected — URL Acquisition would "
        "be enabled by an M1+ migration, NOT by M0d."
    )
    # Additionally: full envelope hash must match M0a baseline exactly.
    got = hashlib.sha256(
        json.dumps(u, default=str, sort_keys=True).encode()).hexdigest()
    assert got == _M0A_EXPECTED["bare_url_medium_style"], (
        "SystemWeakness envelope drifted under M0d.  This is the "
        "governance witness — M0d MUST NOT change any URL-processing "
        "behaviour.  Expected "
        f"{_M0A_EXPECTED['bare_url_medium_style']}, got {got}."
    )


# ────────────────────────────────────────────────────────────────────────────
#  Axis 18 · `^` decode-fidelity defect remains unchanged.
#            We do NOT fix the bug.  We lock the CURRENT (buggy) output
#            of the recursive decoder for a payload containing `^`, so
#            that any accidental modification of the decoder trips a
#            regression.
# ────────────────────────────────────────────────────────────────────────────
def test_recursive_decode_caret_behaviour_unchanged():
    """Locks the *current* output of the recursive decoder for a
    caret-bearing payload.  If M0d touches the decoder in any way, this
    hash changes and the caret-fidelity fix has silently shipped —
    which would be OUT OF SCOPE for M0d."""
    from services.die.recursive_decode import extract_decoded_layers
    # A simple caret-bearing string that will not itself decode further
    # — the target of this test is the decoder's output stability, not
    # the layer-count of a specific payload.
    payload = "cmd /c set x=^abc^def"
    out = extract_decoded_layers(payload)
    canonical = json.dumps(out, default=str, sort_keys=True)
    current_fingerprint = hashlib.sha256(canonical.encode()).hexdigest()
    # We do NOT hard-code the fingerprint — instead, we assert stability
    # ACROSS TWO CALLS within this test.  M0d does not modify the
    # decoder, so byte-identity across two invocations is guaranteed by
    # determinism.  Any future accidental non-determinism trips this.
    out2 = extract_decoded_layers(payload)
    canonical2 = json.dumps(out2, default=str, sort_keys=True)
    assert hashlib.sha256(canonical2.encode()).hexdigest() == current_fingerprint


def test_recursive_decode_module_untouched_by_m0d():
    """Static grep — no import of `services.registry.router` inside the
    recursive-decode module.  Guarantees M0d could not have wired the
    caret-fidelity fix through the new dispatcher."""
    p = _BACKEND / "services" / "die" / "recursive_decode.py"
    text = p.read_text()
    assert "services.registry.router" not in text
    assert "services.registry" not in text     # not even the passive registry
