# RC5 · Phase 9.5d Compliance Report

**Date:** 2026-07-21
**Scope:** Golden Corpus expansion (round 2) · Taxonomy · Per-category coverage · xfail hygiene
**Status:** ✅ COMPLETE · 698/698 backend tests pass · Golden Corpus 82/82 (100% within corpus scope)

---

## Framing note — what these numbers mean and don't mean

Following user feedback (2026-02-23), this report deliberately narrows
its claims to the corpus's actual scope:

* **"100% pass rate"** = *"every currently curated sample matches its documented expected outcome"*. It does NOT imply zero false-positives across all enterprise environments — only across the 82 curated samples.
* **"Zero regressions"** = *"no previously-passing sample now fails"*. It is bounded by whatever the corpus covers.
* **"Corpus quality"** takes priority over sample count. Every sample must be traceable to (a) a credible real-world source or (b) a realistic enterprise workflow, and every sample must add unique coverage rather than duplicate an existing scenario.

The gap-tracking `xfail` mechanism (below) documents where the engine
still has known limitations. Those gaps are not fixed by this phase.

---

## 1. Objectives (per user directive)

1. Expand Golden Corpus GC-260 → GC-290 with high-value enterprise workloads AND diverse malware families.
2. Introduce a **canonical taxonomy** so coverage is measurable per category (not just aggregate sample count).
3. Emit **per-category coverage** in the corpus runner + PR-delta report.
4. Add **`xfail` hygiene** so gap-tracking tests don't rot into permanent ignored failures.
5. Tone down overclaiming language in docs.
6. Keep Phase 10 blocked.

## 2. Corpus expansion (round 2)

Added 30 new samples (`backend/engine/golden_corpus_expansion_r2.py`):

**Benign enterprise (GC-260 → GC-274, 15 samples):**
Exchange EMS search-mailbox, ADFS install, WSUS approve-updates, DNS add-record, PKI cert request, Print Management add-printer, DHCP add-scope, GPO update, VSS **create** shadow (vs delete), FSRM quota, Windows Update Agent, LAPS retrieve, RDS deploy, SCOM agent config, Defender MpCmdRun scan.

**Real-world malware families (GC-275 → GC-286, 12 samples):**
TrickBot loader, Ryuk precursor (net view + net user + wmic shadowcopy delete), LockBit shadow purge, BlackCat/ALPHV config fetch, Conti esentutl NTDS.dit, Bumblebee IEX + WebClient, DarkGate AutoIT curl drop, IcedID rundll32 export, Astaroth bitsadmin, Snake KeyLogger reflective load, SocGholish mshta JS, Latrodectus aliased-IEX loader.

**Obfuscation / red-team edge cases (GC-287 → GC-290, 4 samples):**
Invoke-Obfuscation backtick chain, format-op class-name concat, DOSfuscation `^` escape, WMIC XSL Transform LOLBAS.

## 3. Taxonomy

`engine/golden_corpus_taxonomy.py` defines a closed set of 15 canonical
categories. New samples MUST declare a `category` from this list; the
CI corpus-shape test catches drift.

Existing 82 samples retrofitted via `engine/golden_corpus_categories.py`
(ID-prefix map so sample dicts stay untouched, preserving git-blame
provenance).

## 4. Per-category coverage (current baseline)

| Category                    | Samples | Pass rate | Notes                                                                 |
| --------------------------- | ------- | --------- | --------------------------------------------------------------------- |
| baseline_smoke              | 8/8     | 100%      | Original GC-001..GC-090 baseline set                                  |
| enterprise_administration   | 25/25   | 100%      | FP-floor bucket — largest single category by design                   |
| powershell_administration   | 3/3     | 100%      | Exchange EMS, AD, MS Graph                                            |
| cloud_administration        | 1/1     | 100%      | MS Graph (Azure/AWS/GCP still under-represented — see Backlog)        |
| devops_iac                  | 2/2     | 100%      | GH Actions, Azure DevOps agents                                       |
| developer_tooling           | 2/2     | 100%      | choco, winget                                                         |
| downloaders                 | 9/9     | 100%      | WebClient, iwr, curl, bitsadmin, TrickBot, BlackCat, Bumblebee variants |
| packers_obfuscation         | 12/12   | 100%      | -enc, gzip+IEX, backticks, format-op, DOSfuscation, char-array        |
| lolbas                      | 9/9     | 100%      | regsvr32, mshta, msbuild, installutil, rundll32, WMIC-XSL             |
| persistence                 | 3/3     | 100%      | HKCU Run, schtasks SYSTEM, Winlogon Userinit                          |
| credential_access           | 2/2     | 100%      | reg.exe SAM/SECURITY dump, Conti esentutl NTDS                        |
| lateral_movement            | 2/2     | 100%      | WMIC /node:, Ryuk net-view discovery chain                            |
| ransomware                  | 2/2     | 100%      | vssadmin delete, LockBit vssadmin+wmic+wbadmin combo                  |
| defense_evasion             | 1/1     | 100%      | certutil decode+run                                                   |
| edge_case_regression        | 1/1     | 100%      | catch-all for uncategorized IDs                                       |

**Honest gaps** (per-category count = 1 or 0):
* `cloud_administration` — need Azure AZ CLI, aws-cli, gcloud, Storage-account SAS, Key Vault, IAM-role samples.
* `defense_evasion` — need AMSI-bypass PS variants, Script-Block-Logging disable, ClearEventLog patterns.
* `credential_access` — need Kerberoasting (Rubeus-style), LSASS Comsvcs.dll dump, Cred-Manager access.
* `lateral_movement` — need PsExec, WinRM/Enter-PSSession, SMB admin$ push.

## 5. xfail hygiene (`tests/rc5/unit/hygiene/test_xfail_hygiene.py`)

Every gap-tracking `@pytest.mark.xfail` MUST:
1. Carry a `reason=...` string.
2. Use `strict=True` (accidental fix → build fails, forcing review).
3. Be reviewed at least every 60 days — `LAST_REVIEW_DATE` in the hygiene test enforces this.

Current gap-tracking tests (`tests/rc5/unit/coverage_gaps/`):
* `test_env_var_expression_concat_parses_within_2s` — `$env:VAR + '...'` parser hang.
* `test_reflection_assembly_load_emits_suspicious_verdict` — reflective PE load missing T1620 mapping.

Both are `xfail(strict=True)` with reasons and tracked for post-cutover.

## 6. Test suite result

| Metric                             | Before  | After   |
| ---------------------------------- | ------- | ------- |
| Full RC5 backend regression        | 695/695 | 698/698 |
| Golden Corpus                      | 51/51   | 82/82   |
| Regressions on original 15         | 0       | 0       |
| xfailed coverage-gap tests         | 0       | 2       |
| Per-category coverage tracking     | none    | 15 categories |
| Latency p95 (per sample)           | 0.628ms | 0.701ms |
| Latency total (whole corpus)       | 13.48ms | 82.80ms |

## 7. Invariant compliance

| Invariant                                                       | Status |
| --------------------------------------------------------------- | ------ |
| No AI in deterministic pipeline (`--no-ai` graph identical)     | ✅     |
| No new MITRE rules / LOLBIN table entries / verdict math        | ✅     |
| Every recursion path bounded (`MAX_DECODE_DEPTH=10` + cycles)   | ✅     |
| Charter — corpus quality > count                                | ✅     |
| Each new sample maps to a real-world source or workflow         | ✅     |
| Every gap has an `xfail(strict=True)` with a reason             | ✅     |

## 8. Deferred to post-cutover (tracked, not implemented)

* Verdict-math uplift for `regsvr32 /i:http`, `wmic /node:`, msbuild inline tasks, installutil /U.
* MITRE mappings: mshta→T1105, msbuild→T1127, installutil→T1218, vssadmin-delete→T1490, `[Reflection.Assembly]::Load`→T1620.
* LOLBIN semantic differentiation (wbadmin start-vs-delete, esentutl legit-vs-abuse).
* Obfuscation behavior emission for FromBase64+decompress chains → T1027.
* Parser fix: `$env:VAR + '...'` expression concatenation.
* Cloud administration category expansion (Azure CLI, aws-cli, gcloud).
* Credential-access category expansion (Kerberoasting, LSASS-comsvcs).
* Lateral-movement category expansion (PsExec, WinRM, SMB push).

## 9. Phase 10 — still BLOCKED

* 30-day shadow-run window in progress.
* All 9 cutover-gate criteria untouched.
* No cutover-gate signals modified in this phase.

---

**Signed off:** deterministic RC5 semantic engine, Phase 9.5d.
