# NivXRay Investigation Engine — Architectural Contract v1.0

_Status: **Frozen**. Owner-authored 2026-02-XX. Version `1.0`. Any change
requires a new version and a migration ADR._

This document is the source-of-truth architectural contract for the
NivXRay Investigation Engine. It governs how the engine consumes,
transforms, and emits evidence. Every stage — Timeline, Attack Chain,
Correlation, Narrative — must comply.

Where possible, an invariant is enforced by executable code in
`backend/nivxforge/investigation/pipeline/recursion_safety.py` and by
tests under `backend/tests/investigation/`. Where enforcement is
architectural (naming, module boundaries), the invariant is stated
here and reviewed at PR time.

---

## Invariant 1 — Investigation-first

The primary output is a **security investigation**, never a transcript
of internal decoder stages.

The mandated pipeline is exactly:

```
Parse → Normalize → Aggregate → Correlate → Investigate → Narrative
```

Decoder output is **evidence**, never the final narrative. A stage that
emits diagnostic text as its top-level product is in violation.

**Enforced by**:
- Timeline / Attack Chain / Correlation modules take validated
  `CEM + InvestigationGraph` — never raw decoder text.
- Narrative engine consumes `IncidentCluster + AttackEdge + TimelineEvent`,
  never the decoder pipeline log.

---

## Invariant 2 — Interpreter Ownership

Language-specific normalization runs only when the active interpreter
matches. Ownership is a **first-class contract**, not a heuristic.

| Interpreter | Normalization allowed |
|-------------|----------------------|
| Bash        | Bash stages only      |
| PowerShell  | PowerShell stages only |
| CMD         | CMD stages only       |
| Python      | Python stages only    |

The engine must **never** infer an interpreter merely because
distinctive syntax (backticks, aliases, `$()`, shebangs, …) appears in:

- diagnostic messages
- rendered reports
- comments
- quoted strings
- previous engine output

**Enforced by**:
- `routers/ops.py::_looks_like_non_powershell()` Interpreter Gate.
- Planned: `interpreter_ownership_coverage.json` regeneration on
  every pytest run (see ROADMAP P1).

---

## Invariant 3 — Rendered Output is Terminal

Anything the Investigation Engine renders is **terminal**.  It must
**never** be submitted back into:

- parser
- decoder
- normalizer
- alias expander
- interpreter detector
- vendor detection
- artifact discovery

Diagnostic text is **not** executable input.

**Enforced by**:
- `PayloadKind` classification — non-executable kinds (REPORT,
  NARRATIVE, DIAGNOSTIC, ERROR) are refused by `assert_parseable()`
  regardless of content.
- `PayloadState.FINAL_RENDERED` — payloads at the terminal state are
  refused by `assert_parseable()`.
- Central `OutputGate.emit()` — the single chokepoint every renderer
  passes through; seals content as `FINAL_RENDERED` and stamps
  provenance. Workspace, Reports, REST APIs, JSON export, and PDF
  all inherit the guarantee.
- Legacy string-based `tag_rendered() / assert_terminal()` remain as
  backward-compatible shims for pre-Payload call sites.
- Tests: `test_recursion_safety.py::test_assert_parseable_rejects_*`,
  `test_output_gate_output_refused_by_parser_end_to_end`.

---

## Invariant 4 — Recursive Safety

Every transformation `f(input) → output` must satisfy at least one of:

- `input_hash != output_hash`  (structural change), or
- `semantic_progress == True`  (new evidence produced)

If neither holds:

- stop processing
- emit a **No Further Progress** state
- return the current investigation

The engine never analyses its own rendered output. Maximum recursion
depth is configurable (recommended **8**).

**Enforced by**:
- `recursion_safety.RecursionGuard` — call-once-per-stage helper that
  raises `NoFurtherProgress` when the guard's condition is not met.
- Test: `test_recursion_safety.py::test_guard_stops_on_hash_equality`.

---

## Invariant 5 — Deterministic Fallback

If a stage cannot be statically recovered (AES / OpenSSL / DPAPI /
password-protected archive / runtime-dependent value):

- report **why**
- do **not** invent plaintext
- evaluate any deterministic fallback path already present in the
  command (`||`, `&&`, alternate branches, conditional execution)
- decode that branch as far as deterministically possible
- clearly distinguish:
    - **recovered evidence**
    - **unresolved runtime-dependent stages**

**Enforced by**:
- Decoder plugins emit an explicit `unresolved_reason` when a stage
  cannot be statically recovered (existing behaviour under
  `pipeline/recursive_decoder.py`).
- Narrative renderer separates "recovered evidence" from
  "runtime-dependent" in its output schema (see Invariant 6).

---

## Invariant 6 — Investigation Output

The engine returns **only**:

```
Investigation Summary
├── Interpreter
├── Execution flow
├── Evidence recovered
│   ├── Successfully decoded stages
│   └── Runtime-dependent stages
├── Deterministic fallback result (if present)
├── Final analyst assessment
├── Confidence
└── Remaining unknowns
```

Anything outside this schema is out of scope for the final output.

---

## Invariant 7 — Never Output Diagnostic Text

The final narrative must never expose:

- `ps-backtick-normalize`
- `ps-alias-expand`
- decoder pipeline logs
- repeated normalization steps
- internal diagnostic text of any kind

Those are implementation details, not investigation results.

**Enforced by**:
- Narrative renderer keeps the pipeline diagnostic buffer out of the
  final payload.
- Test: `test_recursion_safety.py::test_narrative_scrubs_diagnostic_markers`.

---

## Invariant 8 — Decoder Stability Gate

If a stage produces:

- no new evidence
- no command changes
- no new interpreter identified

the engine must terminate immediately with:

```
Decoder Stability Gate reached.
No further deterministic progress possible.
```

Recursion is **forbidden** past this gate.

**Enforced by**:
- `recursion_safety.stability_gate()` — helper that inspects a
  before/after evidence snapshot and returns a terminal marker when
  the gate is reached.
- Test: `test_recursion_safety.py::test_stability_gate_terminates_cleanly`.

---

## Schema Versioning

All downstream contract objects carry `schema_version = "1.0"`:

- `TimelineEvent` / `Timeline`
- `AttackEdge` / `AttackChain`
- `IncidentCluster` / `Correlation`

Any breaking change is a versioned migration, never a silent rename.

---

## Relationship to Workspace / X-Lab boundary

This contract governs both surfaces. Workspace (production) has
additional deployment constraints (see `NIVXRAY_ARCHITECTURE_VISION.md`).
X-Lab (observational) is the incubator; new invariants land here
first, then graduate.

---

_End of contract v1.0._
