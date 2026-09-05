# Workspace Decode Pipeline Recovery — Evidence Summary (Phases 3 + 3.5 + 4-bisect)

Corpus: **v1.1.0 · 11 samples** (S001 owner anchor + S01–S10 certification corpus)
Trees compared: `/tmp/workspace-v1.5.6/backend/` (v1.5.6 · `fff5897`, Jul 28 16:10 UTC) and `/app/backend/` (HEAD · `1a07de3`, Aug 2)
Additional bisect: 15 sampled revisions from Jul 9 through HEAD.

**Zero files restored, forked, or wired.** All findings below are runtime-observed by executing `/api/decode/smart` on each tree.

---

## Two clean regression windows — both proven by runtime evidence

### Window A · S001 broke here — `-EncodedCommand` UTF-16LE decode step lost

| Anchor | Date (UTC) | S001 |
|---|---|:-:|
| `02715be1cd` | 2026-07-15 08:58:42 | ✅ Write-Host "tweet, tweet!" produced |
| `43d4400410` | 2026-07-17 01:47:58 | ✅ |
| `53f6076eae` | 2026-07-18 09:54:11 | ✅ |
| `20d0cb88bb` | 2026-07-19 07:00:46 | ✅ |
| **`5cab99e2b8`** | **2026-07-20 03:06:27** | **✅ LAST KNOWN GOOD for S001** |
| **`51666219ed`** | **2026-07-21 09:07:02** | **❌ FIRST BAD for S001** |
| `009d149768` through `1a07de3775` | Jul 22 → Aug 2 (HEAD) | ❌ persists |

Commits inside Window A (Jul 20 03:06 → Jul 21 09:07): **80**. This is the surgical target for the S001-specific root-cause bisect.

Per-stage detail across Window A (from `phase4_bisect_report.md`):
- Before Jul 21: interpreter tag not emitted, but `-EncodedCommand` recognition indirectly succeeds via extract → base64 → **utf16le-decode = ✅** → Write-Host produced.
- Jul 21 onwards: interpreter tagged `powershell`, extract ✅, base64 ✅, but **utf16le-decode = ❌**. The step that produces the plaintext was removed for the generic `powershell.exe -encod …` chain.

### Window B · Mass regression — 9/10 baseline samples broke here

| Anchor | Date (UTC) | S01..S10 PASS count (vs v1.5.6 fingerprint) |
|---|---|:-:|
| `7f147f8fc1` | 2026-07-27 16:41:06 | 8 / 10 (S05, S09 not yet supported) |
| **`fff5897b17`** | **2026-07-28 16:10:16** | **10 / 10 — v1.5.6 Certified Baseline** |
| **`09a556701a`** | **2026-07-29 02:20:21** | **10 / 10 — LAST KNOWN GLOBAL GOOD** |
| **`42d7dffd1d`** | **2026-07-30 13:30:41** | **1 / 10 — FIRST BAD (only S06 survives)** |
| `9d680addc1` | 2026-08-01 09:06:52 | 1 / 10 (persists) |
| `1a07de3775` (HEAD) | 2026-08-02 14:59:01 | 1 / 10 (persists) |

Commits inside Window B (Jul 29 02:20 → Jul 30 13:30): **80**. This is the surgical target for the mass-regression root-cause bisect.

---

## What this proves — and what the owner asked us to answer

**Owner's question:** "Was there ever a Workspace revision that correctly decoded S001, and if so which commit introduced or removed that behavior?"

**Runtime evidence answer:**
1. **YES** — five reachable revisions (Jul 15 → Jul 20) correctly produce `Write-Host "tweet, tweet!"`. S001 is NOT a build-not-restore case; it is a genuine regression.
2. The S001-breaking commit lies in the 80-commit window `5cab99e2b8..51666219ed` (Jul 20 03:06 → Jul 21 09:07).
3. Separately, a MASS regression landed on Jul 30 13:30 that broke 9/10 of the certified baseline. `09a556701a` (Jul 29 02:20) is the last SHA where the full corpus + v1.5.6 fingerprint = 10 / 10.

Per the owner's decision rule (option b, Case 1 — a historical revision passes → restore):
> "treat that revision as the behavioral reference, identify the minimal Workspace-owned change that introduced the regression, restore only that behavior."

---

## Recommended Phase 4 execution (no builds, no restores yet — this is a plan only)

### Phase 4a — Narrow Window A to a single commit (S001-specific)
- Binary-search the 80 commits between `5cab99e2b8` and `51666219ed`.
- Effort: ≤ 7 more bisect iterations (≈ 3 min). Deterministic, non-destructive.
- Deliverable: exact SHA that dropped the UTF-16LE step + list of files it changed.

### Phase 4b — Narrow Window B to a single commit (S01..S10 mass regression)
- Binary-search the 80 commits between `09a556701a` and `42d7dffd1d`.
- Effort: ≤ 7 more bisect iterations (≈ 3 min).
- Deliverable: exact SHA that broke the certified baseline + list of files it changed.

### Phase 4c — For each identified SHA, per-file disable/swap/restore
- Take the diff `git show <SHA> -- backend/`.
- For each file changed, disable that file only (rename to `.py.disabled`) and re-run the corpus.
- Only files whose *runtime* removal restores PASS become **restoration candidates**.
- Files that don't change behavior are noise and remain untouched.

### Phase 4d — Consolidated restoration candidate list
- Union the Window A and Window B candidates.
- Cross-reference against the Phase 3.5 blast-radius rollup (`operations`, `magic_decoder`, `analysis_core`, `engine.orchestrator`, `rc22_adapter`, `decoders/ps_alias_normalizer.py`) — expect strong overlap.

### Phase 5 — Minimal Restore (gated on Phase 4d)
Restore only the specific files in the candidate list, at the state they had at the last-known-good SHA. Nothing else moves.

### Phase 6 — Minimal Isolation into `backend/workspace/`
Walk the transitive imports from `routers/ops.py` on the restored tree; copy ONLY the used files into `backend/workspace/`. Everything in `engine/`, `v2/`, `timeline/`, `nivxforge/` stays put for X-Lab.

### Phase 7 — Isolation Certificate
- Rerun full corpus (11 samples) against the isolated Workspace → require 11/11 PASS.
- Confirm zero behavioral imports from Shared / X-Lab / Lab 2.0.
- Emit `WORKSPACE_ISOLATION_CERTIFICATE.md` signed with runtime evidence.
- Only then is the app deployable.

### Phase 7.5 — Permanent regression corpus
Grow `workspace_recovery/corpus.json` (v1.1.0, 11 samples) into `backend/workspace_regression_corpus/` (60 samples). This runs as CI on every subsequent change to any file that touches the Decode Pipeline.

---

## Architectural constraints (owner-stated, held throughout)

- Decode Pipeline Contract: `Interpreter → Payload Extraction → EncodedCommand Detection → Base64 Decode → UTF-16LE Decode → Normalization → Remaining Chain → Final Payload`.
- Intelligence Layer (MITRE / Timeline / Graphs / Reports / AI / OSINT) is a downstream consumer only — must not influence decoding.
- No unrelated infra changes (the `/health` root alias added earlier was per an explicit owner request to run `deployment_agent`; if the owner prefers strict scope, it can be reverted with one search-replace).

---

## Reproducibility

```
cd /app/backend
python -m workspace_recovery.runner          # Phase 3 (baseline v1.5.6 vs HEAD)
python -m workspace_recovery.dep_graph       # Phase 3.5 (behavior-linked dep graph)
python -m workspace_recovery.phase4_bisect   # Phase 4 bisect (15 anchors)
```

All three are deterministic; repeat runs produce byte-identical artifacts.

## Artifact inventory (all under `/app/backend/workspace_recovery/`)

```
corpus.json                                 · v1.1.0 · 11 samples (S001 + S01..S10)
tree_worker.py                              · isolated subprocess worker
runner.py                                   · Phase 3 orchestrator
dep_graph.py                                · Phase 3.5 orchestrator
phase4_bisect.py                            · Phase 4 historical bisect
phase3_ab_report.md                         · A/B report incl. Candidate column
phase3_5_dep_graph.md                       · behavior-linked chains + blast radius
phase4_S001_stage_analysis.md               · S001-specific per-stage table
phase4_bisect_report.md                     · 15-anchor bisect + Window A/B verdict
EVIDENCE_SUMMARY.md                         · earlier (Phase 3 only) summary
EVIDENCE_SUMMARY_v2.md                      · THIS document (current)
artifacts/baseline_raw.json                 · v1.5.6 raw responses (11 samples)
artifacts/current_raw.json                  · HEAD raw responses (11 samples)
artifacts/phase3_ab_matrix.json             · normalized per-sample diff
artifacts/phase3_5_dep_graph.json           · full dep-graph JSON
artifacts/phase4_bisect_matrix.json         · full bisect JSON (15 × 11 samples)
```

## Decision required from owner

**Which do you want next?**

- **(1) Fine-grained bisect first.** Run Phase 4a + 4b (≈ 6 min, no code changes) to reduce each 80-commit window to one exact SHA before we touch any file. Highest evidence, lowest risk.
- **(2) Restore directly to `09a556701a` (Jul 29 02:20 · Last Known Global Good) for S01..S10.** Skip window B narrowing. Then still bisect Window A for S001. This is faster but wider surface.
- **(3) Something else.**
