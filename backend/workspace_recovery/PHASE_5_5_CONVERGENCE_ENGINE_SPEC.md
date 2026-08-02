# Phase 5.5 · Multi-Pass Convergence Engine — Path C Specification

**Author**: Workspace owner
**Status**: **LOCKED · Implementation-Only From Here**. No further design
refinement until runtime evidence from the implementation requires it.
**Predecessor evidence**: `workspace_recovery/phase5_status.md` (5-hunk restore → 10/11)
**Predecessor RCA**:      `workspace_recovery/phase4_5_final_rca.md`

This document is the authoritative architectural specification for the
Phase 5.5 replacement of the current winner-selection logic in
`analysis_core.smart_pipeline`. It is the direct outcome of the runtime
evidence gathered in Phases 3, 3.5, 4, 4.5, and 5.

---

## Confirmed Findings (from runtime evidence)

- ✅ The original Workspace decoder has not been lost.
- ✅ The regression is not caused by missing decoder implementations.
- ✅ The Shared / RC22 preflight changed which engine owns the decode
      path, causing Workspace behavior to change.
- ✅ Decoder ordering (`insert(0)` vs `append`) directly affects
      pipeline behavior.
- ✅ Interpreter ownership became broader than intended, resulting in
      routing errors.
- ✅ The remaining S001 failure is not a decoding failure. Both decode
      engines independently recover `Write-Host "tweet, tweet!"`, but
      the pipeline selects a less-converged candidate during final
      selection.

**The problem is no longer decoder recovery. The problem is pipeline
convergence and canonical result selection.**

---

## Why Path A (promote 10/11 and defer) is REJECTED

Deploying with S001 unresolved would permanently accept a known
architectural defect in the decode pipeline. S001 is the certification
anchor. Path A is technically safe but architecturally wrong.

## Why Path B (chain-level truncation) is INCOMPLETE

Path B addresses S001's symptom but does not establish a generalized
decoding model. It is likely to solve S001; it is not guaranteed to
solve future multi-stage obfuscation families that expose similar
pipeline-selection behavior.

## Path C — Multi-Pass Convergence Engine

Replace the terminal portion of the decode pipeline with a
deterministic convergence engine. The objective is no longer to
determine which decoder "wins"; the objective is to repeatedly simplify
the artifact until every deterministic transformation has been
exhausted and a canonical representation has been reached. Only after
convergence should any candidate selection occur.

---

## High-Level Architecture

```
                    ┌──────────────────────────────┐
                    │        Raw Input             │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                 ┌─────────────────────────────────┐
                 │  Structural Transformation Pass │
                 │  • AST Reduction                │
                 │  • Operator Folding             │
                 │  • Parentheses Collapse         │
                 └─────────────────────────────────┘
                                   │
                                   ▼
                 ┌─────────────────────────────────┐
                 │  Content Normalization Pass     │
                 │  • Environment Variables        │
                 │  • Quote/Backtick Cleanup       │
                 │  • Constant Folding             │
                 └─────────────────────────────────┘
                                   │
                                   ▼
                 ┌─────────────────────────────────┐
                 │  Decoder Pass                   │
                 │  • Base64                       │
                 │  • UTF-16LE                     │
                 │  • Gzip                         │
                 │  • Hex                          │
                 │  • RC4/XOR                      │
                 └─────────────────────────────────┘
                                   │
                                   ▼
                 ┌─────────────────────────────────┐
                 │  Semantic Reconstruction Pass   │
                 │  • String Reassembly            │
                 │  • Runtime Simplification       │
                 │  • Canonical Folding            │
                 └─────────────────────────────────┘
                                   │
                                   ▼
                     ┌─────────────────────────┐
                     │ Did State Change?       │
                     └──────────┬──────────────┘
                                │
                       YES ─────┘
                                │
                                ▼
                        Execute Next Iteration

                       NO
                       ▼
             Canonical Candidate Selection
                       ▼
            Final Canonical Plaintext
```

---

## Canonical State Contract

Convergence terminates only when **all six** of the following are true:

1. The artifact hash remains identical across two consecutive iterations.
2. No transformation pass reports a deterministic state change.
3. No new decoder candidates are generated.
4. Interpreter ownership remains unchanged.
5. No additional semantic evidence is produced.
6. No remaining deterministic transformations can be applied.

Only after all six conditions hold is the artifact considered to have
reached **Canonical State** and eligible for downstream Behavioral
Analysis, MITRE Mapping, Threat Intelligence, or Reporting.

## Transformation Provenance

Every iteration emits a structured provenance record:

```
Iteration 1
------------
Structural
✓ Parentheses collapsed
Content
✓ Environment variables substituted
Decoder
✓ Base64 decoded
Semantic
✓ Constant folded

Iteration 2
------------
Structural
No Change
Content
✓ Backticks removed
Decoder
✓ UTF-16LE decoded
Semantic
✓ Runtime string reconstructed

Iteration 3
------------
No deterministic changes
Canonical State Achieved
```

## Canonical Candidate Selection

Selection occurs **only after every candidate has independently
converged**. Ranking criteria (all deterministic):

- Greatest structural simplification
- Greatest semantic recovery
- Highest decoder confidence
- Lowest remaining obfuscation
- Longest valid convergence chain
- Zero unresolved deterministic transformations

The selector compares **fully converged artifacts, never intermediate
states**.

## Pass Independence Rule

Every transformation pass must satisfy:

- Operate solely on the current artifact state
- Produce deterministic output
- Have no hidden mutable state
- Have no decoder-specific side effects
- Have no dependency on previous execution order
- Be independently replayable from any intermediate artifact

## Convergence Certificate

At completion, emit a machine-readable certificate:

```
Convergence Certificate
-----------------------
Iterations Executed          : 4
Structural Changes           : 3
Content Changes              : 2
Decoder Changes              : 4
Semantic Changes             : 2

Canonical State              : YES
Remaining Deterministic Ops  : 0
Residual Obfuscation         : NONE

Final Artifact Hash SHA-256  : <hash>

Ready for Behavioral Analysis: YES
```

---

## Phase 5.5 Recommendation

Replace the current Path B implementation with:

> **Phase 5.5 — Multi-Pass Convergence Engine.** Do not introduce
> additional winner-selection heuristics. Instead, implement a
> deterministic convergence loop that repeatedly executes the
> Structural, Content, Decoder, and Semantic transformation passes
> until the Canonical State Contract is satisfied (or a configurable
> maximum iteration depth is reached). During every iteration, emit
> Transformation Provenance. After convergence, perform Canonical
> Candidate Selection, emit a Convergence Certificate, and execute the
> complete deterministic regression corpus. Promotion to production
> occurs only after all certification samples pass without introducing
> new regressions.

---

## Concrete implementation footholds (for the next session)

The 5 hunks from Phase 5 remain the prerequisite runtime environment
for Phase 5.5 (they eliminate rc22 hijack, fix decoder ordering,
positional PS routing, and abbreviation coverage). Recommended
sequence for the implementing session:

1. **Promote hunks 1-5 to `/app/backend`** behind
   `DECODER-RECOVERY-LOCK · phase5_hunk_<n>` markers.
2. Run `python -m workspace_recovery.runner` against `/app/backend` to
   confirm production parity at 10/11.
3. **Skeleton the four transformation passes** as pure functions in
   `backend/workspace/convergence/{structural,content,decoder,semantic}.py`.
   Each pass has signature
   `(artifact: Artifact) -> tuple[Artifact, list[Provenance]]`.
4. **Build `backend/workspace/convergence/engine.py`** with the loop,
   the Canonical State Contract check, and the `max_depth` guard
   (recommend 16 iterations).
5. **Wire the engine into `analysis_core.smart_pipeline`** so it runs
   **after** `smart_decode()` and `magic_decode()` complete and
   BEFORE the current winner-selection block. The engine takes both
   candidates as inputs and returns the canonical one.
6. **Emit Convergence Certificate** into the response envelope at
   `resp["convergence_certificate"]`.
7. **Add a test file** `backend/tests/test_convergence_engine.py` that
   asserts:
   - S06 XOR terminates at iteration 2 (no change) with canonical hash
     matching the v1.5.6 fingerprint.
   - S001 reaches `Write-Host "tweet, tweet!"` in ≤4 iterations.
   - Every corpus sample produces a Convergence Certificate with
     `Canonical State: YES`.
8. **Re-run** `python -m workspace_recovery.phase5_hunk_validator` with
   the convergence engine wired in. Target: 11/11.
9. **Only after 11/11 is proven on `/tmp/wsp-bisect`**, promote the
   convergence engine to `/app/backend/workspace/convergence/`.

## Files this touches

- **New** — `backend/workspace/convergence/__init__.py`
- **New** — `backend/workspace/convergence/engine.py`
- **New** — `backend/workspace/convergence/structural.py`
- **New** — `backend/workspace/convergence/content.py`
- **New** — `backend/workspace/convergence/decoder.py`
- **New** — `backend/workspace/convergence/semantic.py`
- **New** — `backend/workspace/convergence/certificate.py`
- **New** — `backend/tests/test_convergence_engine.py`
- **Modified** — `backend/analysis_core.py` (wire engine into
  `smart_pipeline` between candidate generation and winner selection)
- **Modified** — `backend/workspace_recovery/corpus.json` (bump to v1.2.0
  with per-sample Canonical Hash expectations)

Nothing in `nivxforge/`, `engine/`, `v2/`, `timeline/`, or Intelligence
Layer paths is touched by the initial implementation. The convergence
engine is placed inside Workspace **by the current design**.

## Architectural principles (location-independent)

The following contracts govern the convergence architecture. They are
**principles, not placement decisions**. The initial implementation
places the engine under `backend/workspace/convergence/` because that
aligns with the current Workspace isolation objective (Phase 6). If a
future iteration generalizes the same deterministic convergence
architecture into Shared, the following contracts remain unchanged:

- **Determinism** — every pass is a pure function of the current
  artifact state; identical inputs produce identical Convergence
  Certificates (hash-verifiable).
- **Certification** — every convergence run emits a machine-readable
  Convergence Certificate suitable for CI verification.
- **Convergence Model** — Structural → Content → Decoder → Semantic
  passes iterated until the 6-condition Canonical State Contract holds.
- **Behavioral Consistency** — Canonical Candidate Selection happens
  only after every candidate has independently converged; no
  intermediate-state selection is allowed.
- **Pass Independence** — no hidden mutable state, no decoder-specific
  side effects, independent replayability from any intermediate
  artifact.

Rephrased for the record:

> The current design places the convergence engine in the Workspace,
> which aligns with the current Workspace isolation objective. If the
> same deterministic convergence architecture is later generalized for
> Shared, it should preserve the same behavioral contracts and
> certification standards.

> The current proposal keeps decode orchestration within the Workspace
> while treating Shared as a provider of reusable deterministic
> transformation capabilities. If this architecture is later
> generalized into Shared, the same deterministic contracts,
> convergence model, and certification process should remain unchanged.

## Engineering Assessment (owner-provided)

| Path | Score | Verdict |
|------|:-----:|---------|
| A (ship 10/11) | 7.0 / 10 | Safe but leaves the anchor unresolved |
| B (chain truncation) | 8.8 / 10 | Symptom fix, narrowly focused |
| **C (Convergence Engine)** | **9.9 / 10** | **APPROVED** — addresses root architectural problem, preserves determinism, scales to future obfuscation techniques, aligns with long-term isolation goal |

Investigation quality assessment: 9.8 / 10.

## Alignment with the standing Recovery Program invariants

1. Decoder Ordering Contract — enforced structurally by the pass-order
   requirement (Structural → Content → Decoder → Semantic).
2. Interpreter Ownership Contract — enforced by Canonical State
   condition #4 (interpreter ownership must not change across
   iterations).
3. Orchestrator Preflight Lock — stays enforced; rc22 preflight remains
   gated OFF as established in Phase 5 Hunk 1.
4. Exception-Swallow Ban on decode path — every pass must return a
   Provenance record; silent exception-swallowing is banned by the
   Pass Independence Rule.
5. Certification Corpus CI Gate — the Convergence Certificate is the
   machine-readable artifact that CI verifies on every PR.
