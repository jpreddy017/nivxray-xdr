# ADR 0001 — Command-Line Obfuscation Deobfuscation Coverage

- **Status:** Accepted  (2026-02-28 · with amendment: framework must be artifact-agnostic)
- **Date:** 2026-02-28
- **Author(s):** e1 (evidence review)
- **Supersedes:** —
- **Superseded by:** —

---

## 1 · Problem Statement

Command-line obfuscation is the single most recurring investigation
pattern in the historical NivXRay corpus. Analysts routinely
encounter obfuscated one-liners (PowerShell, cmd) where the engine's
current deobfuscation coverage varies significantly by sub-family.
When the archetype library covers the shape, output is clean
(e.g. Case 0001 · `PS_ASCII_XOR_IEX`). When it does not, analysts
must fall back to manual decoding — the tool degrades from an answer
to a hint. The problem is not "decoders are missing" but "coverage
is uneven across a very common technique family."

## 2 · Supporting Evidence

Source: `/app/memory/EVIDENCE_INVENTORY_2026-02-28.md` §2
and `/app/memory/DIAGNOSTIC_RC4_SHELLCODE_2026-02-28.md` §4.

- **MITRE T1027.010 (Command Obfuscation)** — 414 rows raw
- **+187 rows re-attributed from T1027.013** (per RC4 diagnostic)
- **= ~601 recurring cases** — the largest single obfuscation-family
  bucket in the corpus.
- Case 0001 (`REAL_WORLD_LOG.md`) is the exemplar of this family. Its
  archetype handler (`PS_ASCII_XOR_IEX`) shows the shape a good
  handler takes. 601 rows implies dozens of similar-but-not-identical
  shapes below the handler's threshold.
- IOC signal on this bucket is dense (712 domains · 709 URLs across
  the merged corpus), meaning downstream enrichment depends on the
  deobfuscation succeeding.

Missing-Evidence tally row this ADR would decrement: not yet in the
tally (Charter §4.5 · scorecard reads "Real SOC cases reviewed = 1").
This ADR draws primarily on **historical evidence** from the
Evidence Inventory Report, which the Charter's Validation Mode
permits as a source once quality-gated.

## 3 · Proposed Change

**Lift** from `NORTH_STAR.md §2 · Processing Layer` and
`NORTH_STAR.md §6 · Foundation / Decode` a single, evidence-scoped
capability:

> A deterministic, coverage-audited **Command-Line Obfuscation
> Deobfuscation** service that catalogues obfuscation sub-families
> observed in real cases, exposes a handler per family, and reports
> both handler-fired coverage and unhandled-shape counts back to the
> analyst.

Concrete first-cut implementation shape (subject to full ADR
technical section on approval):

- New subpackage under `nivxforge/` (which is dormant and isolated
  today per Phase 0). No Workspace code modified.
- A **Shape Registry** — declarative table of obfuscation sub-family
  signatures, each pointing to a handler and to its expected input
  invariants.
- A **Handler Protocol** implementing the existing `engines/base.Engine`
  Protocol. Handlers append into the CIO's `decode_layers` and
  `evidence` buckets with provenance.
- A **Coverage Reporter** — surfaces per-case which shape was
  detected, which handler ran, and whether the residual output still
  looks obfuscated (heuristic: entropy + non-printable ratio).
- **No new decoders shipped in this ADR.** Only the registry,
  protocol, and coverage reporter. Individual handlers each require
  their own ADR (or a batched ADR-0001-b that lists the first N
  handlers with per-family evidence).

**This ADR scopes only the framework**, not the family handlers. The
handlers earn their own smaller ADRs as evidence accumulates for
each sub-family.

## 4 · Alternatives Considered

**(a) Do nothing.**
Rejected. The corpus shows a recurring pattern the tool is only
partially serving. Not building infrastructure means every future
handler is bolted onto the existing archetype system with no coverage
visibility.

**(b) Do it in Workspace.**
Rejected. The Workspace Protection Policy explicitly forbids this
class of change without a Workspace ADR. NivXForge is the intended
home for platform capabilities per `NORTH_STAR.md §1`. Doing this in
Workspace would also violate the Charter's isolation principle.

**(c) Extend the existing archetype system in-place.**
Rejected in scope, but acknowledged as prior art. The existing
`wrapper_archetypes.py` mechanism already implements per-shape
handlers; however, it lives in Workspace, has no coverage reporter,
and no shape registry that the analyst can inspect. NivXForge's
Shape Registry + Coverage Reporter learns from this prior art
without modifying it.

**(d) Ship one handler at a time and skip the framework.**
Rejected. Handlers accumulate quickly and without a registry the
architecture becomes another `wrapper_archetypes.py`. The framework
is cheap; the accumulated debt of not having it is expensive.

## 5 · Workspace Impact

- **Is any Workspace file affected?** **No.**
- Files that will be modified: none in `/app/backend/routers/`,
  `/app/backend/engine/`, `/app/backend/decoders/`,
  `/app/backend/heuristics/`, `/app/backend/knowledge_base/`,
  `/app/backend/extractors/`, `/app/backend/enrichment/`,
  `/app/backend/wrapper_archetypes.py`, `/app/backend/operations.py`,
  `/app/backend/analysis_core.py`, `/app/backend/server.py`, or
  `/app/backend/v2/**`. Nor any file under `/app/frontend/src/pages/`
  or `/app/frontend/src/components/`.
- All code lives under `/app/backend/nivxforge/` (new subtree).
- Decision A1 (router remains dormant) remains in force unless a
  follow-up ADR explicitly reverses it with justification.
- The Workspace Compatibility Contract is satisfied by the existing
  `test_workspace_isolation.py` and `test_workspace_compatibility.py`.

**Structural test that will prove non-mutation for this ADR:**
`nivxforge/tests/test_workspace_compatibility.py::test_nivxforge_router_not_registered_in_workspace_server`
and `test_no_nivxforge_module_imports_from_workspace` — both already
green in Phase 0 and remain the contract for this ADR.

## 6 · Success Criteria

- **Regression proof:** ≥15 tests under `nivxforge/tests/` covering:
  the Shape Registry contract, the Handler Protocol, the Coverage
  Reporter output shape, and one exemplar shape entry (matching the
  Case 0001 archetype) as a smoke test — without shipping a real
  handler.
- **Benchmark proof:** framework construction and Coverage Reporter
  output for a synthetic 100-shape registry must complete in <100 ms
  on the reference container. (Threshold set to detect early bloat,
  not to gate feature performance.)
- **Compatibility proof:** all Phase 0 tests (26) remain green, and
  the Workspace regression suite (Phase 1a · PS_ASCII_XOR_IEX)
  remains green.
- **Missing-Evidence tally row this ADR aims to decrement (once the
  first family handler is added under a follow-up ADR):**
  "Command-Line Obfuscation coverage — coverage-unaudited handlers"
  (row to be added to `PRODUCT_CHARTER.md §4.5` scorecard on ADR
  acceptance, not before).

## 7 · Consequences

- **Unlocks:** every future PowerShell / cmd obfuscation sub-family
  becomes an independently-evidenced ADR under a stable framework.
- **Forbids (until further ADR):** no analytical decoder is shipped
  as part of THIS ADR. Any handler must earn its own ADR referencing
  real case evidence.
- **Long-lived contract:** the Shape Registry and Handler Protocol
  become part of the NivXForge API surface. Backward compatibility
  applies from the day of acceptance.

---

## Acceptance checklist (to complete before status → Accepted)

- [ ] Human review of §2 evidence citations against
  `EVIDENCE_INVENTORY_2026-02-28.md` and
  `DIAGNOSTIC_RC4_SHELLCODE_2026-02-28.md`.
- [ ] Confirmation that no §3 element requires Workspace change.
- [ ] Explicit sign-off from the analyst that "framework only, no
  handler in this ADR" is understood.
- [ ] `IMPLEMENTATION_ROADMAP.md §3` entry drafted (do not commit
  until ADR is Accepted).
- [ ] `DECISION_LOG.md` row prepared (do not commit until ADR is
  Accepted).
