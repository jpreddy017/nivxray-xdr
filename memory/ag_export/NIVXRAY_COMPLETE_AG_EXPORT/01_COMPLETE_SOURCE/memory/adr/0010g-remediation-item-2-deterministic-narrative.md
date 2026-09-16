# ADR-0010g · Remediation Item 2 — Deterministic Narrative

**Status:** ✅ IMPLEMENTED · 2026-08-12 · owner acknowledgement
**Scope:** ADR-0010e §10 item 2 · ADR-0023 §4 precondition 2
**Guiding principle:** ADR-0023 §3a Cruise-Missile — verdict / narrative is a function of the *correlated evidence set*, never a single indicator; every narrative sentence must be traceable to an evidence element that already exists.

---

## 1 · Problem (from ADR-0010e §7 Q5.3)

`/api/die/narrate` returned empty `executive_summary` / `analyst_summary` / `recommended_actions` for direct command-line inputs — the exact class the Workspace UI targets. The narrative endpoint only consumed *narrative-prose rule matches* (`_canonical_techniques_from_text`), which return `[]` for command lines like `powershell.exe -Enc …`. The DIE analyzer had already extracted 3+ techniques for the same input, but that evidence was never fed to the enricher.

## 2 · Change (pure projection · zero LLM · zero new inference)

`backend/routers/die.py::die_narrate()` now, additively, invokes `services.die.api.analyze()` (the same call that powers `/api/die/analyze`) and lifts its `techniques[]` + `lolbins[].mitre[]` + `iocs[]` into the `mitre_full` set that seeds `enrich_narrative()`. Priority order — narrative-prose rules → DIE analyzer → LOLBIN-linked → existing matrix. Each block only adds ids not yet seen; no source over-writes another. Evidence provenance preserved: every technique row carries an `evidence` snippet either from the DIE catalogue or a `"LOLBIN abuse: <binary>"` marker.

Companion change in `backend/canonical/projections/attck.py`: `_TECHNIQUE_META` extended with previously-missing rows so the enricher stops silently dropping T1218.005 / T1562.004 / T1197 / T1140 / T1047 / T1059.005 / T1059.007 / T1112 / T1053.005 / T1543.003 / T1134.004 / T1036.005 / T1490 / T1070.001 / T1218.004/007/008/009. The file's own header explicitly permits data-catalog completion without projection-logic change — the assertion applied.

**No new endpoints, no new flags, no data-source additions, no LLM calls.**

## 3 · Regression matrix (frozen 12-case corpus)

| # | Case | Verdict (unchanged from Item 1) | Narrative populated? | Actions surfaced |
|---|------|---------------------------------|:---------------------:|:----------------:|
| 01 | ps-enc-launcher | Malicious (80) | ✅ | 7 |
| 02 | mshta-remote-hta | Malicious (100) | ✅ | 2 |
| 03 | certutil-urlcache | Malicious (70) | ✅ | 4 |
| 04 | squiblydoo | Malicious (100) | ✅ | 3 |
| 05 | wmic-process | Malicious (100) | ✅ | 8 |
| 06 | benign-recon-ps | Benign (10) | — (correct: no evidence) | 0 |
| 07 | netsh-fw-off | Low Risk (20) | — (T1562.004 not in DIE catalogue → Item 4) | 0 |
| 08 | nested-b64-ps | Malicious (80) | ✅ | 5 |
| 09 | too-short (`dir`) | Benign (0) | — (correct: no evidence) | 0 |
| 10 | empty-input | *no verdict* | — (correct: rejected input) | 0 |
| 11 | bitsadmin | Malicious (80) | ✅ | 4 |
| 12 | rundll32-poweliks | Malicious (80) | ✅ | 6 |

**Narrative populated: 8 / 12** (up from 0 / 12 in Phase A). Every case with DIE-observable evidence now narrates; the 4 empty are exactly `rip-06 benign-recon-ps` · `rip-07 netsh-fw-off` · `rip-09 too-short` · `rip-10 empty-input`. Of those four: 3 have no DIE-observable evidence at all (correct silence — no manufactured narrative on benign / too-short / empty input); 1 (`rip-07`) has T1562.004 evidence in `/api/analyze`'s mapper but not yet in the DIE catalogue → deferred to Item 4. **Zero manufactured narratives.**

**Determinism gate: 12 / 12 stable** (narrate response byte-identical across two runs). Verdict / risk / MITRE snapshots unchanged from Item 1.

## 4 · Safety and non-manipulation

- Cruise-Missile principle honoured — no single-indicator narrative branch introduced.
- Case 06 (benign admin recon) → no narrative fired. Correct.
- Case 09 (`dir`) → no narrative fired. Correct.
- Case 10 (empty input) → no narrative fired. Correct.
- Case 07 (netsh) still empty on the DIE side — this is the T1562.004 DIE-catalogue gap, deferred to Item 4.

## 5 · Wider regression

* `canonical/api/` suite — same **174 pass · 5 skip · 0 fail** as after Item 1.
* `git status --short` diff limited to `backend/routers/die.py`, `backend/canonical/projections/attck.py`, `backend/tests/canonical/ssot/test_ssot_isolation.py` (allow-list), plus memory-only files.

## 6 · Protected surfaces verified untouched

RC5 / DIE canonical pipeline (analyzer output shape) · Workspace UI · IKG (shadow) · Verdict v3 (shadow) · Case Engine (shadow) · Retention sweeper · FileStore · P0 archive-guard · risk-score calibration (Item 1). No new `NIVX_FLAG_*`. No Mongo schema redesign. No shadow → live promotion.

## 7 · Owner-recorded observations (2026-08-12)

* **Prod vs Preview screenshots** — deploy gap, not a regression. Preview holds Item-1 + Item-2 changes; Prod runs the pre-Item-1 build. Not fixed in this session (no user request to redeploy).
* **Deploy-Application PowerShell case** registered as **Phase-B (post-P2) canonical test case** at `/app/memory/experiments/rip/future-cases.md::pb-01`. This case is the "suspicious behaviour ≠ malicious verdict" falsification target that requires behavioural evidence ingestion (ADR-0023) to resolve correctly. Not added to the frozen 12-case corpus; the corpus stays frozen.
* **Scoring-guardrail note** (owner): technique-count alone must not dominate; the long-term philosophy is combination-of-evidence. Captured for Item 4 / P2 design review — not actioned in Item 2.

## 8 · Item-2 gate: PASS

- ✅ Every case with DIE-observable evidence now narrates deterministically
- ✅ Zero manufactured narratives on benign / empty / short / ambiguous-without-evidence cases
- ✅ Zero LLM, zero new inference, zero new data source
- ✅ Evidence provenance preserved (every narrative sentence traces to a technique+evidence row)
- ✅ Determinism 100 %
- ✅ Verdict / risk unchanged from Item 1
- ✅ Canonical suite still 174 pass / 5 skip / 0 fail
- ✅ Zero protected-surface disturbance

**Item 2 closed.** Ready for owner authorisation of Item 3 (recursive decode).
