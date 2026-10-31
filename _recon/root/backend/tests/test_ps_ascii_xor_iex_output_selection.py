"""Regression — PS_ASCII_XOR_IEX archetype output must reach the analyst.

v1.6.0 Phase 1a · narrowly-scoped correctness fix (Feb-2026)
============================================================

Real SOC case (logged Feb-2026 in `/app/memory/REAL_WORLD_LOG.md`)
uncovered a two-part defect:

  1. `wrapper_archetypes.py` archetype handlers (e.g. `PS_ASCII_XOR_IEX`)
     recover per-sample state (XOR key `0x36`) INSIDE the handler and
     produce the correct plaintext in `result.output`. The recipe steps
     they return (`ascii-decimal-decode`, `xor`) are emitted with
     `args: {}` — the recovered key is NOT persisted.

  2. Frontend `selectCanonicalOutput.js` used to always replay the
     returned recipe via `/api/recipe/run` and prefer that replay over
     `result.output` when the two differed. Because the replayed `xor`
     op ran with its default key (`0x2A`), the analyst saw garbage
     (`.)+Knuhy1Tsoh...`) instead of the correct `Write-Host 'Hello World!'`.

The frontend fix (skip recipe replay when `engine.startsWith("archetype:")`)
lives in `/app/frontend/src/lib/selectCanonicalOutput.js`. This backend
test locks THREE invariants that together prevent the defect returning.

Root cause (one-line):
    The canonical output shown to the analyst comes from replaying a
    non-self-contained recipe instead of using the already-correct
    deterministic decoder output.
"""

from __future__ import annotations

from analysis_core import deterministic_best_decode
from operations import OPERATIONS


ACCEPTANCE_SAMPLE = (
    "powershell -NoProfile -NonInteractive \""
    "((97,68,95,66,83,27,126,89,69,66,22,17,126,83,90,90,89,22,97,89,68,"
    "90,82,23,17,22,27,112,89,68,83,81,68,89,67,88,82,117,89,90,89,68,22,"
    "113,68,83,83,88,13,22,97,68,95,66,83,27,126,89,69,66,22,17,121,84,80,"
    "67,69,85,87,66,95,89,88,22,100,89,85,93,69,23,17,22,27,112,89,68,83,"
    "81,68,89,67,88,82,117,89,90,89,68,22,113,68,83,83,88) | "
    "ForEach-Object {[Char]($_ -bxor '0x36')} ) -join '' | Invoke-Expression\""
)


# ── Invariant A · handler produces correct plaintext ──────────────────
def test_ps_ascii_xor_iex_handler_produces_correct_plaintext():
    r = deterministic_best_decode(ACCEPTANCE_SAMPLE)
    out = r.get("output") or ""
    assert "Write-Host" in out, (
        "PS_ASCII_XOR_IEX handler regressed — no 'Write-Host' in decoded "
        f"output. Head: {out[:200]!r}"
    )
    assert "Hello World" in out, (
        "PS_ASCII_XOR_IEX handler decoded but not the acceptance sample's "
        f"payload. Head: {out[:200]!r}"
    )
    # The garbled replay bytes must NOT leak into result.output.
    assert "Knuhy1Tsoh" not in out, (
        "Garbled replay bytes leaked into result.output — the handler "
        "itself ran with the wrong key, not a selection bug."
    )


# ── Invariant B · engine name advertises the archetype ────────────────
def test_ps_ascii_xor_iex_engine_name_stable():
    r = deterministic_best_decode(ACCEPTANCE_SAMPLE)
    engine = r.get("engine") or ""
    assert engine.startswith("archetype:"), (
        f"engine field should start with 'archetype:' — got {engine!r}. "
        "The frontend selectCanonicalOutput.js guard depends on this "
        "prefix to skip non-reproducible recipe replay."
    )
    assert "PS_ASCII_XOR_IEX" in engine, (
        f"Expected PS_ASCII_XOR_IEX in engine name — got {engine!r}. If "
        "the archetype was renamed, update the frontend guard's audit "
        "and this test in one atomic change."
    )


# ── Invariant C · recipe is documentary, not self-reproducible ────────
# This test documents the invariant the frontend guard protects. If a
# future change makes the recipe self-reproducible (handler persists
# recovered args onto the steps), delete this test AND the frontend
# guard in `selectCanonicalOutput.js` in the same commit.
def test_ps_ascii_xor_iex_recipe_replay_is_not_self_reproducible():
    r = deterministic_best_decode(ACCEPTANCE_SAMPLE)
    correct_out = r.get("output") or ""
    steps = r.get("steps") or []
    assert steps, "archetype did not emit steps — separate regression"

    # Every returned step should currently carry empty args — proof
    # the recipe is documentary, not self-reproducible.
    for step in steps:
        assert (step.get("args") or {}) == {}, (
            "A recipe step now carries args — the archetype has become "
            "self-reproducible. Delete this test AND the frontend guard "
            "in selectCanonicalOutput.js in the same commit."
        )

    # Replay the same steps linearly against `OPERATIONS`. Expected to
    # produce garbage today, because `xor` runs with its default key.
    cur = ACCEPTANCE_SAMPLE
    for step in steps:
        op_id = step["op"]
        op_entry = OPERATIONS.get(op_id)
        assert op_entry is not None, f"op {op_id!r} missing from OPERATIONS"
        cur = op_entry["fn"](cur)

    assert cur != correct_out, (
        "Linear replay now matches the archetype's correct output — the "
        "recipe has become self-reproducible. Remove the frontend "
        "guard in selectCanonicalOutput.js and delete this test."
    )
