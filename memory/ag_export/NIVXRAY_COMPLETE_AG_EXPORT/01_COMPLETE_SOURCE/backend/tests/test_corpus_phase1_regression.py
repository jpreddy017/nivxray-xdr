"""Phase 1 · Naked-Script Encoding Corpus Regression.

Locked with SOC user 2026-07-27. Every Phase-1 sample must:

    1. Produce the EXPECTED decode chain (ordered, subset match).
    2. Reduce to the EXPECTED final payload.
    3. Halt at the EXPECTED execution boundary (or None).
    4. Emit the EXPECTED verdict, MITRE, and behavior tags.
    5. Produce IDENTICAL semantic output when normalised through the
       `/decode/smart` path (naked input) vs the `/auto-investigate`
       path (naked-PS fallback that wraps the script in
       `powershell.exe -NoP -Command "..."`).

Missing any one of these = regression = red build.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from v2.semantic.ps_semantic import analyze                                # noqa: E402
from tests.corpus.phase1_samples import all_phase1_samples, Phase1Sample   # noqa: E402


def _chain_contains_all(actual_techniques: list[str], expected: list[str]) -> tuple[bool, list[str]]:
    """Ordered subset match — every expected technique must appear in
    `actual_techniques` and in the same order (allowing extra stages
    in between)."""
    i, missing = 0, []
    for want in expected:
        while i < len(actual_techniques) and actual_techniques[i] != want:
            i += 1
        if i >= len(actual_techniques):
            missing.append(want)
        else:
            i += 1
    return (not missing), missing


@pytest.mark.parametrize("s", all_phase1_samples(),
                          ids=lambda s: f"{s.category}:{s.id}")
def test_phase1_naked_encoding_sample(s: Phase1Sample) -> None:
    # Skip brotli sample gracefully if the runtime doesn't have the lib.
    if s.id == "naked_brotli_b64":
        try:
            import brotli    # noqa: F401
        except Exception:
            pytest.skip("brotli library not installed at test-run time")

    result = analyze(s.cmdline)
    d = result.to_dict()

    # ── 1. detected
    assert d.get("detected"), \
        f"[{s.id}] semantic engine failed to detect PowerShell in the naked sample"

    # ── 2. decode chain — subset match, order-preserving
    stages = (d.get("deobfuscation") or {}).get("stages") or []
    actual_techniques = [st["technique"] for st in stages]
    ok, missing = _chain_contains_all(actual_techniques, s.expected_decode_chain)
    assert ok, (
        f"[{s.id}] expected decode chain {s.expected_decode_chain!r} not "
        f"present (in order) in actual {actual_techniques!r}. "
        f"Missing steps: {missing!r}")

    # ── 3. final payload substring
    final = (d.get("deobfuscation") or {}).get("final") \
             or d.get("recovered_script") or ""
    assert s.expected_final_payload.lower() in final.lower(), (
        f"[{s.id}] final payload does NOT contain expected substring "
        f"{s.expected_final_payload!r}; got {final[:200]!r}")

    # ── 4. execution boundary
    boundary = (d.get("deobfuscation") or {}).get("boundary_op") or None
    if s.expected_boundary is None:
        assert not boundary, (
            f"[{s.id}] expected no boundary, got {boundary!r}")
    else:
        assert boundary and s.expected_boundary.lower() in boundary.lower(), (
            f"[{s.id}] expected boundary containing {s.expected_boundary!r}, "
            f"got {boundary!r}")

    # ── 5. verdict banding
    v = (d.get("verdict_breakdown") or {}).get("verdict")
    assert v in s.expected_verdict, (
        f"[{s.id}] verdict={v!r} not in expected {s.expected_verdict!r}")

    # ── 6. MITRE — any-of match
    got_mitre = set(d.get("mitre_ids") or [])
    got_mitre |= {m for m_group in (d.get("storyline", {}).get("mitre_techniques") or [])
                    for m in (m_group.get("id"),) if m}
    matched_mitre = [m for m in s.expected_mitre if m in got_mitre]
    assert matched_mitre, (
        f"[{s.id}] no expected MITRE ID from {s.expected_mitre!r} in "
        f"{sorted(got_mitre)!r}")

    # ── 7. behaviors — subset match
    got_behaviors = {b["id"] for b in (d.get("behaviors_v2") or [])}
    missing_bh = set(s.expected_behaviors) - got_behaviors
    assert not missing_bh, (
        f"[{s.id}] missing behavior IDs {missing_bh!r}; "
        f"extracted={sorted(got_behaviors)}")

    # ── 8. storyline sections — observed / not_observed contract
    story = d.get("storyline") or {}
    sec_by_key = {s2["key"]: s2 for s2 in (story.get("sections") or [])}
    for key, want in s.expected_storyline_flags.items():
        sec = sec_by_key.get(key)
        assert sec, f"[{s.id}] storyline missing section {key!r}"
        got = "observed" if sec.get("observed") else "not_observed"
        assert got == want, (
            f"[{s.id}] storyline section {key!r} expected {want!r}, "
            f"got {got!r} (narrative: {sec.get('narrative','')[:120]!r})")


# ─────────────────────────────────────────────────────────────────
#  PARITY TEST · /workspace  ↔  /auto-investigate
# ─────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("s", all_phase1_samples(),
                          ids=lambda s: f"parity:{s.id}")
def test_phase1_workspace_autoinvestigate_parity(s: Phase1Sample) -> None:
    """The SAME sample MUST produce identical decode chain + final +
    boundary regardless of whether it enters via naked (Workspace) or
    the auto-investigate `powershell.exe -NoP -Command "..."` wrapper."""
    if s.id == "naked_brotli_b64":
        try:
            import brotli    # noqa: F401
        except Exception:
            pytest.skip("brotli library not installed at test-run time")

    naked = s.cmdline
    # Reuse the same helper the auto-investigate route uses.
    from routers.auto_investigate import _fallback_naked_powershell as _nps
    wrapped_candidates = _nps(naked)
    assert wrapped_candidates, (
        f"[{s.id}] naked-PS fallback failed to synthesise a wrapped command "
        f"— cannot check parity")
    wrapped = wrapped_candidates[0]["command_line"]

    d1 = analyze(naked).to_dict()
    d2 = analyze(wrapped).to_dict()

    tech1 = [st["technique"] for st in (d1.get("deobfuscation") or {}).get("stages") or []]
    tech2 = [st["technique"] for st in (d2.get("deobfuscation") or {}).get("stages") or []]
    assert tech1 == tech2, (
        f"[{s.id}] decode-chain drift between /workspace ({tech1}) and "
        f"/auto-investigate ({tech2}) — the two entry points MUST produce "
        f"identical technique chains.")

    # Boundary should match (both should end at Invoke-Expression here).
    b1 = (d1.get("deobfuscation") or {}).get("boundary_op") or ""
    b2 = (d2.get("deobfuscation") or {}).get("boundary_op") or ""
    assert b1.lower() == b2.lower(), \
        f"[{s.id}] boundary drift: workspace={b1!r} vs auto-investigate={b2!r}"

    # Final payload contains the expected plaintext on both sides.
    f1 = (d1.get("deobfuscation") or {}).get("final") \
          or d1.get("recovered_script") or ""
    f2 = (d2.get("deobfuscation") or {}).get("final") \
          or d2.get("recovered_script") or ""
    assert s.expected_final_payload.lower() in f1.lower(), \
        f"[{s.id}] Workspace decoded final missing expected payload"
    assert s.expected_final_payload.lower() in f2.lower(), \
        f"[{s.id}] Auto-Investigate decoded final missing expected payload"


# ─────────────────────────────────────────────────────────────────
#  Coverage assertions — Phase 1 encoding families must be complete.
# ─────────────────────────────────────────────────────────────────
def test_phase1_covers_all_encoding_families() -> None:
    """Phase 1 defines a mandatory set of encoding categories. Every
    category MUST have at least one sample so this suite meaningfully
    gates the deobfuscator's coverage claims."""
    required = {"base64", "utf16le", "gzip", "deflate", "brotli",
                 "hex", "octal", "binary", "decimal", "string_format"}
    got: set[str] = set()
    for s in all_phase1_samples():
        got.update(s.expected_coverage)
    missing = required - got
    assert not missing, (
        f"Phase 1 corpus missing encoding categories: {missing}. "
        f"Every family must have at least one sample.")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
