# ADR-0010k · Remediation Item 4 — T1562.004 DIE Catalogue Signature

**Status:** ✅ IMPLEMENTED · 2026-08-12 · owner explicit "Start Item 4"
**Scope:** ADR-0010e §10 item 4 · ADR-0023 §4 precondition 4
**Guiding principles honoured:** ADR-0023 §3a Cruise-Missile · §3b UI-Truth · §3e No Opportunistic Improvement.

---

## 1 · Problem

`services.die.api.analyze` did not surface **T1562.004 · Impair Defenses: Disable or Modify System Firewall** on the canonical MITRE-attested command `netsh advfirewall set allprofiles state off`. The frontend Attack Chain and `/api/die/narrate` therefore received no defense-evasion evidence for this case — despite `/api/analyze::mitre_map` correctly identifying it. This was the ADR-0010e §7 Q3 DIE-catalogue gap.

## 2 · Change (additive-only, deterministic)

`backend/services/die/cmd_ast.py`:

1. New precompiled regex `_NETSH_FW_DISABLE_RE` matches:
   * `netsh advfirewall set (allprofiles|currentprofile|domainprofile|privateprofile|publicprofile) state off`
   * Legacy syntax `netsh firewall set opmode disable`
   * Case-insensitive
2. New boolean flag `netsh_fw_disable` in the `flags` dictionary emitted by `parse_cmd()`.
3. New emit rule in `_techniques()`:
   ```
   T1562.004 · Impair Defenses: Disable or Modify System Firewall
   evidence: "netsh advfirewall … state off — Windows Firewall disabled."
   ```

No other rules touched. No language other than CMD/Batch touched.

## 3 · Frozen 12-case regression

| # | Case | Verdict Δ | DIE MITRE Δ | Narrative Δ |
|---|------|-----------|-------------|-------------|
| **07** | **netsh-fw-off** | Low Risk (20) — **unchanged** | `[]` → **`[T1562.004]`** | **empty → populated** |
| 06 | benign-recon-ps | Benign (10) unchanged | `[]` unchanged | empty unchanged |
| 09 | too-short | Benign (0) unchanged | `[]` unchanged | empty unchanged |
| 10 | empty-input | no verdict unchanged | `[]` unchanged | empty unchanged |
| 01-05 · 08 · 11 · 12 (all malicious) | Malicious unchanged | unchanged | unchanged |

**Target achieved on rip-07:** the DIE-catalogue gap is closed. T1562.004 now flows through DIE → `_apply_recursive_decode` merge → `/api/die/narrate` enrichment → analyst-facing summary.

**Score-threshold observation** (not part of Item 4): rip-07 remains at Low Risk (20) because the score signals for this input are `1 mitre + 4 yara-low + 8 lolbin = 17` post-recalibration — below the Suspicious 40 threshold. This is consistent with the UI-Truth Principle (§3b): weak signals get a weak verdict, no manufactured elevation.

**Determinism gate:** 12 / 12 stable (die + analyze snapshots byte-identical across two runs).

**Safety gate:** rip-06 · rip-09 · rip-10 all unchanged. No benign case flipped. No manufactured verdicts.

## 4 · Wider regression

* `canonical/api/` suite: **174 pass · 5 skip · 0 fail** — identical to post-UI-DEF-01 baseline.
* SSOT isolation guard: PASS (allow-list rationale updated for `backend/services/die/cmd_ast.py`).
* `git status --short` diff limited to: `backend/services/die/cmd_ast.py` + `backend/tests/canonical/ssot/test_ssot_isolation.py` + memory-only files.

## 5 · Protected surfaces verified untouched

RC5 · Workspace UI · IKG · Verdict v3 · Case Engine · P0/P1 · Retention sweeper · FileStore · Items 1/2/3 · UI-DEF-01. No new `NIVX_FLAG_*`. No Mongo schema change. No shadow → live promotion. No opportunistic changes.

## 6 · Item-4 gate: PASS

- ✅ T1562.004 now surfaces in DIE for the canonical `netsh advfirewall … state off` input
- ✅ Legacy `netsh firewall set opmode disable` also covered
- ✅ Case rip-07 narrative populated (was empty)
- ✅ Verdict semantics preserved — Low Risk is the honest reading given weak overall signal set
- ✅ Zero benign / empty / short case perturbed
- ✅ Zero canonical regression
- ✅ Determinism 100 %
- ✅ Cruise-Missile · UI-Truth · No-Opportunistic-Improvement principles honoured

**Item 4 closed. Standing down. Ready for owner authorisation of Item 5 (bounded TI latency).**
