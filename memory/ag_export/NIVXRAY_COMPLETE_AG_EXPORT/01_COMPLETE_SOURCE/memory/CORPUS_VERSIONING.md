# Corpus Versioning · Evidence Benchmark Discipline

**Status:** Governance baseline (adopted 2026-02-28)
**Owner:** Operator
**Applies to:** Every case in `REAL_WORLD_LOG.md` and every ADR that claims to
improve analytical behaviour.

---

## 1 · Principle

The 20-case evidence corpus is now the **empirical reference baseline** for
NivXForge. From this point onward:

- **Improvements** are measured against corpus results.
- **Regressions** are detected against corpus results.
- **New heuristics** must demonstrate measurable benefit on the corpus before
  they are accepted.
- **Subjective judgments or intuition** are not sufficient to justify
  behavioural changes.

This aligns NivXForge governance with mature software-engineering and ML
evaluation practices: deterministic implementations evolve only when they
demonstrate measurable improvement against a stable, versioned benchmark while
remaining regression-free on prior validated behaviour.

---

## 2 · Corpus versions

Each corpus version is **frozen** at declaration. Historical expected outputs
are never edited. New cases are always **appended** — never retro-fitted.

| Version   | Size          | Purpose                                                    | Status                                       |
| --------- | ------------- | ---------------------------------------------------------- | -------------------------------------------- |
| Corpus v1 | 20 cases      | Canonical baseline · anchors ADR-0007/0008 regression pins | **Frozen 2026-02-28**                        |
| Corpus v2 | ~50 cases     | Adds validated `analyst_corrections` sample · introduces Analyst Scorecard | Planned — activates after ADR-0007/0008 land |
| Corpus v3 | 100+ cases    | Production-derived cases from real analyst workflow        | Future                                       |

Corpus versions increment monotonically. `v2` supersedes `v1` only after `v1`'s
regression suite is confirmed green under `v2`'s new implementation.

---

## 3 · Freezing rules

Once a corpus version is frozen:

1. **No case is ever removed.** Cases judged uninteresting stay in the corpus
   as low-signal ballast — their existence is itself an observation.
2. **No expected output is ever edited.** If NivXRay's output changes for a
   case, the case entry records *both* the historical output (baseline) and
   the current output (post-change). Divergence is the audit signal.
3. **No case is re-scored under a different template.** The 9-category
   template used at freeze time is bound to the case. If the template evolves
   in a future corpus version, older cases keep their v1 scoring.
4. **New cases only append.** They are numbered continuously (0023, 0024, …)
   and tagged with the corpus version they entered under.

---

## 4 · When a corpus version increments

A corpus version increments when **all** of the following are true:

1. The prior version's pinned regressions still pass under the current
   implementation.
2. The new sample of cases has been reviewed under the same (or extended)
   9-category template.
3. Any new pattern candidates have been logged and, where ≥3-recurrence, have
   an Accepted ADR.
4. An operator directive explicitly declares the new version frozen.

Version bumps are recorded here (§5) and in `REAL_WORLD_LOG.md`.

---

## 5 · Version log

### Corpus v1 · Frozen 2026-02-28

- Contents: Cases 0001, 0003–0022 (20 cases; Case 0002 reserved for live
  Meterpreter run, not yet included).
- Sample-class coverage: ps-encoded, cmd-caret, PE-b64-wrapped, RTF,
  certutil-LOLBIN, schtasks-persistence, DLL-sideload, ClickFix,
  base32-nested, AMSI-bypass, LSASS-dump, trivial-invalid.
- Reference-quality cases: 0003, 0009, 0018, 0019, 0020.
- Anchors: ADR-0007 (§6 pins) and ADR-0008 (§6 pins).
- Frozen expected outputs: as of the reviews in `REAL_WORLD_LOG.md`
  §Batches 1–4.

### Corpus v2 · Planned

- Trigger: ADR-0007 + ADR-0008 both land green under the Mandatory
  Verification Pipeline (`OPERATIONAL_LOOP.md` §Implementation-phase rules).
- Additions: 50–100 sampled `analyst_corrections` cases + any new live SOC
  investigations (Case 0002 forward).
- New capabilities: Analyst Scorecard on `/nivxforge/governance` (read-only,
  derived from `REAL_WORLD_LOG.md`).

---

## 6 · How this document interacts with other memory files

- `REAL_WORLD_LOG.md` is the append-only case log. Cases live there; this
  document declares how cases *versions* work.
- `OPERATIONAL_LOOP.md` describes the daily "Run → Review → Record → …" loop.
  This document adds the versioning layer beneath it.
- `PRODUCT_CHARTER.md` establishes evidence-driven governance. This document
  is the mechanism that makes "evidence" a stable, comparable object across
  releases.
- Every future ADR that changes analytical behaviour MUST reference the
  corpus version its expected outcomes are pinned to.
