# ADR-0010n · Final 12-Case Regression · ADR-0010e §10 Gate — 🟢 GREEN

**Status**: 🟢 GATE GREEN · read-only regression (2026-08-12 · Session-19)
**Scope**: single owner-authorised regression run, no product code touched.
**Companion**: ADR-0010e (Real Investigation Proof · Phase A · original gate spec) · ADR-0010f/g/h/k/l (Items 1–5) · ADR-0023 (four principles).

---

## 1. Objective (owner directive verbatim)

> "Start the FINAL 12-case regression only. Run the frozen 12-case corpus against the current Item-5 build and compare it against the Item-4 baseline.
> Do not modify product code. Do not modify UI. Do not start UI-DEF-02. Do not start P2. Do not add features or refactor anything.
> Verify verdict, MITRE techniques, LOLBINs, risk scores, narrative, recursive-decode results, and TI behavior.
> Confirm 12/12 cases remain stable with zero unintended deltas.
> Verify the ADR-0010e §10 remediation gate criteria.
> Record the regression evidence in memory only.
> If anything fails or unexpectedly changes, STOP and report the exact delta. Do not fix it automatically.
> If 12/12 passes with zero unintended regression, mark the final regression gate GREEN and STOP."

## 2. What was verified (read-only)

- **Zero product code touched.** No commit to backend, frontend, or shared services during this regression.
- **Zero UI touched.** No frontend modifications, no Workspace behaviour change.
- **Corpus integrity confirmed** — `corpus_hash = 8dcfc3c774a7558f…` identical between Item-4 baseline snapshot (`results.pre_item5.json`) and post-Item-5 run (`results.item5_run1.json` / `results.item5_run2.json`).
- **Two independent harness replays** on the current Item-5 build (`results.item5_run1.json` + `results.item5_run2.json`).
- **Direct probe augmentation** of `/api/die/analyze`, `/api/die/narrate`, `/api/analyze` for each of the 12 cases to cover axes the harness snapshot does not capture (recursive-decode layers, narrative population, TI meta).

## 3. Result matrix — ADR-0010e §10 Gate

| Case | Verdict | Score | Decoded Layers | T1140 (Item 3) | T1562.004 (Item 4) | Narrative (Item 2) | TI Status (Item 5) | TI ms | Gate |
|---|---|---:|---:|:---:|:---:|:---:|---|---:|:---:|
| rip-01-ps-enc-launcher    | Malicious | 76  | **1** | ✅ | – | ✅ | ok      | 0.08   | ✅ |
| rip-02-mshta-remote-hta   | Malicious | 100 | 0 | – | – | ✅ | timeout | 501.5  | ✅ |
| rip-03-certutil-urlcache  | Malicious | 73  | 0 | – | – | ✅ | timeout | 501.2  | ✅ |
| rip-04-squiblydoo         | Malicious | 96  | 0 | – | – | ✅ | timeout | 501.1  | ✅ |
| rip-05-wmic-process       | Malicious | 100 | 0 | – | – | ✅ | timeout | 501.7  | ✅ |
| rip-06-benign-recon-ps    | Benign    | 9   | 0 | – | – | – | ok      | 0.09   | ✅ |
| rip-07-netsh-fw-off       | Low Risk  | 17  | 0 | – | ✅ | ✅ | ok      | 0.14   | ✅ |
| rip-08-nested-b64-ps      | Malicious | 84  | **2** | ✅ | – | ✅ | ok      | 0.09   | ✅ |
| rip-09-too-short          | Benign    | 0   | 0 | – | – | – | ok      | 0.11   | ✅ |
| rip-10-empty-input        | –         | –   | 0 | – | – | – | –       | –      | ✅ |
| rip-11-bitsadmin-transfer | Malicious | 83  | 0 | – | – | ✅ | timeout | 501.3  | ✅ |
| rip-12-rundll32-poweliks  | Malicious | 78  | 0 | – | – | ✅ | ok      | 0.11   | ✅ |

**Gate verdict: 12/12 PASS · zero unintended deltas.**

## 4. ADR-0010e §10 remediation gate — per-item verification

### Item 1 · Risk-score recalibration
- **rip-03** (certutil-urlcache): **Malicious 73** (calibrated from prior Low-Risk mis-classification).
- **rip-04** (squiblydoo): **Malicious 96**.
- **rip-11** (bitsadmin-transfer): **Malicious 83**.
- **rip-06** (benign-recon): Benign 9 — safety preserved (no over-scoring).
- **rip-09/10**: Benign 0 / None — safety preserved (short/empty inputs never manufactured verdicts).

### Item 2 · Deterministic narrative
- **8/12 populated** cases: rip-01, rip-02, rip-03, rip-04, rip-05, rip-08, rip-11, rip-12 — all with real MITRE-derived `executive_summary` + `recommended_actions`.
- **+1 improvement vs Session-19 baseline** — **rip-07** (netsh-fw-off) is now populated because Item 4 emits T1562.004, which then feeds `enrich_narrative`. This is an *emergent* Item-2 gain from Item-4 (Cruise-Missile principle — evidence propagates cleanly through the chain), not a regression.
- rip-06 / rip-09 / rip-10 correctly stay unpopulated (no evidence → no narrative — safety preserved).

### Item 3 · Recursive decode
- **rip-01** (encoded PowerShell launcher): `decoded_layers = 1` · `T1140` present · Item-3 synthesis firing.
- **rip-08** (nested-b64-ps): `decoded_layers = 2` · `T1140` present · Cruise-Missile chain fully followed.
- All other cases: `decoded_layers = 0` — no manufactured layers (safety preserved).

### Item 4 · T1562.004 DIE catalogue signature
- **rip-07** (netsh-fw-off): `T1562.004` present in `techniques[]`.
- No benign case (rip-06/09/10) manufactures T1562.004 (safety preserved).

### Item 5 · Bounded TI-lookup latency
- **All non-empty cases return `ti_lookup_meta` with `status ∈ {ok, timeout}`.**
- **5 cases** (rip-02/03/04/05/11) hit the OSINT branch and **cleanly timed out at ~500 ms** — pipeline never stalled, `ti_hits=[]`, verdict unchanged.
- **6 cases** (rip-01/06/07/08/09/12) completed in <1 ms (`status=ok`) — fast path preserved.
- rip-10 empty input → no analyze call → no ti_lookup_meta (expected).
- **Verdict / MITRE / LOLBAS surface stayed identical vs Item-4 baseline** despite TI timeouts — provider stalls do NOT influence verdict (Evidence-Producer Constraint honoured).

## 5. Determinism verification

Two full harness replays back-to-back on the same corpus + same build:

```
$ python3 harness.py   # → results.item5_run1.json
$ python3 harness.py   # → results.item5_run2.json

$ python3 (diff full_signature over verdict/mitre/lolbin/ioc/decoded/language)
Determinism gate (run1 == run2): PASS   (0/12 cases diverged)
Zero-drift gate (baseline == post-Item-5): PASS   (0/12 cases diverged)
```

**100% determinism preserved.**

## 6. Files touched — MEMORY ONLY (per owner constraint)

```
memory/adr/0010n-final-12-case-regression-gate.md         (this file)
memory/experiments/rip/results.item5_run1.json            (harness run 1)
memory/experiments/rip/results.item5_run2.json            (harness run 2)
memory/experiments/rip/final_regression_evidence.json     (augmentation matrix)
memory/experiments/rip/results.pre_item5.json             (Item-4 baseline snapshot)
memory/REMINDERS.md                                       (gate mark)
memory/PRD.md                                             (Session-19 close)
```

**No product code touched. No UI touched. Backend restart only used to pick up the Item-5 diff before the regression started.**

## 7. Four principles compliance (ADR-0023)

| Principle | Status | Evidence |
|---|---|---|
| §3a Cruise-Missile Guidance | ✅ | rip-01/08 chase 1–2 decode layers; rip-07's T1562.004 flows through to narrative. |
| §3b UI-Truth | ✅ | No case fabricated a stronger verdict than its evidence supports; TI timeouts declared explicitly. |
| §3c MITRE Convergence | ✅ *(not affected)* | UI-DEF-02 is not in this regression's scope; DIE catalogue continues to emit deterministic techniques. |
| §3d Evidence-Producer Constraint | ✅ | TI failures produce evidence absence, never a verdict. |
| §3e No Opportunistic Improvement | ✅ | Zero product code changed during this regression. |

## 8. Verdict

**🟢 12/12 PASS — ADR-0010e §10 remediation gate is GREEN.**

Standing down per owner directive. The locked sequence remaining:

```
Item 1 ✅ · Item 2 ✅ · Item 3 ✅ · Item 4 ✅ · Item 5 ✅ · 12-case final regression ✅
        ↓
UI-DEF-02              ⏸  ← await explicit owner authorisation
        ↓
P2 Behavioral Evidence 🔒  ← await UI-DEF-02 close
```

**Do NOT begin UI-DEF-02 until the owner explicitly authorises it after reviewing this regression.**
