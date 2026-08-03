# PR-2.1.2 · Canonical Investigation Pipeline (ARB Directive · 2026-08-04)

**Status**: 🟡 IN PROGRESS · scope expanded beyond initial hotfix
**Blocking**: PR-3 resume until this is complete
**Owner**: next fresh session (context budget on current session exhausted)

---

## 1 · Immediate Bug Fixes (must land first)

- Locate and remove every reference to `content-ps-operator-case-normalize`
  — it's an unregistered op that must not appear in any deterministic
  recipe, pipeline, or transformation registry.
- Rule: **No decode recipe may reference an unregistered operation.**

## 2 · Canonical Evidence Recovery Service

Both `Decode` and `Auto Investigate` must invoke **the same shared
backend service** — not "Auto Investigate calls Decode". Draft name:
`services/canonical_evidence_recovery.py`.

Signature (sketch)::

    def recover_canonical_evidence(input_text: str) -> CanonicalArtifact:
        # deterministic recovery: parse, base64, encoded-command, hex,
        # xor, split-reverse-join, etc. Terminates at Decoder Stability Gate.
        ...

Both `/api/decode/smart` and `/api/analyze/async` route through this
function for evidence recovery. No parallel decode paths.

## 3 · Architectural Invariants

- **Investigation First**: engine owns the workflow (Parse → Normalize
  → Aggregate → Correlate → Investigate → Narrative → Final Assessment).
- **Interpreter Ownership**: normalization only when the active
  interpreter is positively identified — never inferred from a backtick,
  diagnostic note, or literal token match.
- **Canonical Artifact**: once produced, every consumer reads from it
  (Summary, Runtime Sim, Threat Analysis, Verdict, Workspace Bundle,
  Reports, Detection Rules, Auto Investigate, Decode).
- **Terminal Output**: Investigation Engine output is terminal — never
  fed back to parser/decoder/interpreter detector/normalizer.

## 4 · Stability Gates

- **Recursive Safety**: `input_hash != output_hash` for every
  deterministic transformation. Never analyze rendered output, reports,
  or investigation summaries.
- **Decoder Stability Gate**: terminate when no new evidence recovered
  AND no new interpreter identified AND no deterministic transformation
  remains. Return: *"Decoder Stability Gate reached. No further
  deterministic progress possible."*
- **Deterministic Fallback**: when a stage cannot be statically
  recovered (AES/OpenSSL/runtime decryptor), explain why and continue
  down every statically-recoverable fallback branch.

## 5 · Output Contract

Investigation Engine returns only:
- Interpreter & execution flow
- Evidence recovered
- Runtime-dependent stages
- Deterministic fallback results
- Final analyst assessment

Never expose: internal normalization traces · debug logs · recursive
diagnostics · internal pipeline state.

## 6 · Acceptance Criteria

- [ ] `content-ps-operator-case-normalize` no longer exists anywhere.
- [ ] Decode and Auto Investigate invoke the same Canonical Evidence
      Recovery Service.
- [ ] Both produce the same canonical decoded artifact for identical
      input.
- [ ] Auto Investigate no longer re-processes its own output.
- [ ] No recursive decode loops occur.
- [ ] Decoder Stability Gate terminates correctly.
- [ ] Investigation output is identical regardless of Decode vs Auto
      Investigate entry point.
- [ ] Regression gates unchanged: DCS 17/17 · R1 107/107 · pytest all-green.

---

## Progress Already Made (do not redo)

- PR-2.1 · Verdict Engine capability-driven downgrade + ps_normalizer
  `-EncodedCommand` support · **DONE**
- PR-2.1.1 · `verdict_projection.py` helper (`derive_risk_projection`,
  `ensure_canonical_response`, `promote_semantic_review_signal`) ·
  **DONE**
- PR-2.1.2 (initial cut) · Auto Investigate worker now internally calls
  `/decode/smart` for verdict_card unification · **PARTIAL — see notes**
- ps_normalizer now promotes decoded payload as canonical Reconstructed
  Command; wrapper demoted to Wrapper Evidence · **DONE**
- Governance Rules 12 (strengthened), 13, 14, 15 · **RATIFIED**

## Remaining Work Under This Directive

- **Full replacement of the initial "call /decode/smart" shim with a
  proper shared `Canonical Evidence Recovery Service`** — the ARB
  explicitly wants a shared service, not a cross-endpoint call.
- Purge every `content-ps-operator-case-normalize` reference in
  registries and recipes (grep across `backend/` — likely a few hits
  in legacy recipe fixtures).
- Formalize the Decoder Stability Gate as a returnable terminal state
  in the recovery service.
- Add Recursive-Safety hash check to every transformation entry.
- Interpreter Ownership check gates PowerShell normalization on a
  positive interpreter identification (not on token heuristics).

## Testing Contract

Independent tests must prove:
1. `Decode` and `Auto Investigate` return the same canonical artifact
   byte-for-byte for the same input.
2. Zero `content-ps-operator-case-normalize` references in any
   response, recipe, or transformation registry.
3. L0 damage-prevention: DCS 17/17 · R1 107/107 byte-identical.
4. Existing PR-2.1 / PR-2.1.1 tests remain green.
