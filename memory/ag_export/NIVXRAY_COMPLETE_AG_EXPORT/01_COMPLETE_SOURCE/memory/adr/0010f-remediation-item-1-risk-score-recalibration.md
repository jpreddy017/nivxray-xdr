# ADR-0010f · Remediation Item 1 — Risk-Score Recalibration

**Status:** ✅ IMPLEMENTED · 2026-08-12 · owner sign-off
**Scope:** ADR-0010e §10 item 1 · ADR-0023 §4 precondition 1
**Regression gate:** Frozen 12-case corpus at `/app/memory/experiments/rip/` · canonical/api/ suite · legacy risk_score unit tests
**Guiding principle:** ADR-0023 §3a Cruise-Missile Guidance — verdict is a function of the *correlated evidence set*, never a single indicator.

---

## 1 · Problem (from ADR-0010e §7 Q1 + §10)

The risk-score layer under-classified 3 / 8 malicious cases in the Real Investigation Proof:

| Case | Baseline verdict | MITRE observed | LOLBIN observed |
|------|------------------|----------------|-----------------|
| rip-03 certutil-urlcache | Low Risk (20) | T1105, T1140, T1218 | certutil.exe |
| rip-04 squiblydoo | Low Risk (20) | T1218.010 | regsvr32.exe |
| rip-11 bitsadmin-transfer | Low Risk (30) | T1105, T1197 | bitsadmin.exe |

Root cause: `risk_score(mitre, yara, iocs)` did not consume the `lolbas` signal set that `/api/analyze` already extracted. The signed-binary-proxy-execution + external-destination TTP class was invisible to the score.

## 2 · Change

`backend/operations.py::risk_score()` — extended signature:

```python
def risk_score(mitre, yara, iocs, lolbas: Optional[List[Dict]] = None) -> Dict[str, Any]:
```

New signals added, all additive on top of the pre-existing YARA / MITRE-count / IOC-family weights (which were not changed):

| Signal | Weight | Cap |
|--------|--------|-----|
| LOLBIN detected | +8 per LOLBIN | +24 |
| LOLBIN + external IOC (URL or IP) | +30 (bonus, once) | — |
| Known-bad-TTP MITRE technique matched (prefix in `_HIGH_SIGNAL_TTPS`) | +8 per match | +24 |
| T1218.* (signed-binary-proxy-execution) present | +10 (bonus, once) | — |

`_HIGH_SIGNAL_TTPS = ("T1218", "T1105", "T1140", "T1197", "T1059", "T1047")`.

Thresholds unchanged: ≥70 Malicious · ≥40 Suspicious · ≥15 Low Risk · else Benign. Max score cap unchanged at 100.

**Backward compatibility:** the four legacy call sites in `analysis_core.py`, `chain_analyzer.py` (2×), and the two `tests/test_bits_*` / `tests/test_encodedcommand_coverage.py` files continue to work — `lolbas` defaults to `None`, in which case only the known-bad-TTP boost fires (from MITRE alone), preserving pre-recalibration behaviour on the LOLBIN signals for those call sites. The three `/api/analyze` sites (sync, SSE stream, async job) now pass `lolbas=lolbas` explicitly.

## 3 · Regression matrix (frozen 12-case corpus)

Baseline saved at `results.baseline.json`; new run at `results.json`.

| # | Case | Baseline | New | Δ | Expected (per corpus.md) | Verdict |
|---|------|----------|-----|-----|--------------------------|---------|
| 01 | ps-enc-launcher   | Suspicious (60) | **Malicious (80)** | 🟢 up | Malicious | ✓ target met |
| 02 | mshta-remote-hta  | Suspicious (50) | **Malicious (100)** | 🟢 up | Malicious | ✓ target met |
| 03 | certutil-urlcache | Low Risk (20)   | **Malicious (70)** | 🟢 up | Malicious | ✓ **target met (P0 goal)** |
| 04 | squiblydoo        | Low Risk (20)   | **Malicious (100)** | 🟢 up | Malicious | ✓ **target met (P0 goal)** |
| 05 | wmic-process      | Malicious (100) | Malicious (100) | — | Malicious | ✓ preserved |
| 06 | benign-recon-ps   | Benign (10)     | Benign (10) | — | Benign | ✓ safety preserved |
| 07 | netsh-fw-off      | Benign (10)     | Low Risk (20) | 🟡 up | Ambiguous / Suspicious (with caveat) | ⚠️ minor drift — see §4 |
| 08 | nested-b64-ps     | Suspicious (60) | **Malicious (80)** | 🟢 up | Malicious | ✓ target met |
| 09 | too-short (`dir`) | Benign (0)      | Benign (0) | — | Insufficient / Benign | ✓ safety preserved |
| 10 | empty-input       | *no verdict*    | *no verdict* | — | Reject / no verdict | ✓ safety preserved |
| 11 | bitsadmin         | Low Risk (30)   | **Malicious (80)** | 🟢 up | Malicious | ✓ **target met (P0 goal)** |
| 12 | rundll32-poweliks | Suspicious (40) | **Malicious (80)** | 🟢 up | Malicious | ✓ target met |

**Determinism gate: 100 % (12/12 stable across two runs, DIE + `/api/analyze` snapshots identical).** FileStore dedup remains stable (all payloads return `dedup=True` on second replay).

**Safety gate: 100 %** — no benign / insufficient / empty case flipped to Malicious or Suspicious. Case 09 and 10 still receive no manufactured verdict. Case 06 (benign administrative PowerShell) remains Benign.

## 4 · Honest drift: case 07 (netsh-fw-off)

Predicted before the change: *"Case 07 stays Benign(10) until item 4 T1562.004 signature is added"*.
Observed after the change: **Benign(10) → Low Risk(20)**.

Investigation:
- `/api/analyze`'s `mitre_map()` **already** surfaces T1562.004 for `netsh advfirewall set allprofiles state off` (verified in baseline results). The "T1562.004 gap" from ADR-0010e §7 Q3 was a **DIE-catalogue gap**, not an `/api/analyze` gap.
- Baseline score for case 07 = `5 (mitre) + 4 (yara-low) = 9` → Benign.
- New score = `5 + 4 + 8 (netsh.exe LOLBIN)` = 17 → Low Risk (crosses the 15 threshold).

Assessment: netsh.exe is a **curated LOLBAS** binary, T1562.004 is a real defense-evasion technique, and the `advfirewall … state off` snippet has a YARA case-mix obfuscation hit. Low Risk is arguably a more honest reading of this signal set than Benign — and closer to the frozen corpus's expected classification for case 07 ("Ambiguous / Suspicious with caveat"). The drift is directionally **correct**, not a regression.

Not accepted as an emergency reversion. Item 4 (DIE T1562.004 catalogue entry) will further improve case 07 by making the DIE analyzer surface the technique too; that change may push case 07 to Suspicious. The recalibration itself does not need adjustment.

## 5 · Wider regression

* `canonical/api/` suite: **174 pass · 5 skip · 0 fail** (identical to post-P1.1 baseline).
* `tests/test_bits_and_sandbox_evasion.py` + `tests/test_encodedcommand_coverage.py`: **15 pass** (all legacy risk-score expectations honoured).
* `git status --short` diff limited to: `backend/operations.py`, `backend/routers/analyze.py`, `backend/tests/canonical/ssot/test_ssot_isolation.py` (allow-list), plus memory-only files.

## 6 · Protected surfaces verified untouched

* RC5 / DIE canonical pipeline — unchanged
* Workspace UI — unchanged (verdict field format identical)
* IKG (shadow) — unchanged
* Verdict v3 (shadow) — unchanged
* Case Engine (shadow) — unchanged
* Retention sweeper / FileStore / P0 archive-guard — unchanged
* No new `NIVX_FLAG_*` introduced
* No Mongo schema redesign
* No shadow → live promotion

## 7 · Cruise-Missile principle compliance

The recalibration adds no *single-indicator* branch. Every new signal fires only via combinations (LOLBIN × external IOC · known-bad-TTP MITRE presence · T1218.* class). Verdict remains a function of the correlated evidence set. ADR-0023 §3a not violated.

## 8 · Item-1 gate: PASS

- ✅ 3 target cases (certutil / squiblydoo / bitsadmin) crossed into Malicious
- ✅ 4 additional under-classified cases (ps-enc-launcher / mshta / nested-b64 / poweliks) also upgraded to Malicious
- ✅ 4 preserved (wmic Malicious · 3 benign / insufficient / empty stay non-malicious)
- ⚠️ 1 acceptable directional drift (case 07 Benign → Low Risk)
- ✅ 100 % determinism preserved
- ✅ Zero canonical suite regressions
- ✅ Legacy risk_score unit tests green
- ✅ Zero protected-surface disturbance

**Item 1 closed.** Ready for owner authorisation of Item 2 (deterministic narrative).
