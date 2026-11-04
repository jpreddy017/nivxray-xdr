# NivXRay XDR · P0-1 + P0-2 · IMPLEMENTATION DELIVERY & VALIDATION EVIDENCE

> **Owner-authorised implementation** (2026-09-05). Scope strictly limited to the two approved items. P0-3 delivered as a **design decision only**; P0-4 (real Suricata) **not started**.
> **Branch:** `feature/rc2-alignment`. **Rule:** NO EVIDENCE → NO CLAIM.

---

# PART A · P0-1 · CASE STORE RATIFICATION + `doc_type` DISCRIMINATOR

## A.1 · What was ratified

`workspace_cases` is the authoritative case/incident store. This ratifies what three source files already declared (`detection_content/xdr_incident.py:5-7`, `routers/incidents.py:1-7`, `v2/case_engine/schema.py:8`). **No store was migrated, merged, deleted or re-keyed.**

## A.2 · Deterministic classification — defined BEFORE any write

`backend/case_doc_type.py` — pure function, no I/O, no clock, no randomness. Rules mutually exclusive, evaluated in order:

| Rule | Predicate | Result | Justification |
|---|---|---|---|
`R1` | `xdr_pipeline` present | `xdr_incident` | only `materialise_incident` writes this envelope |
`R2` | `ssot` present | `analysis_case` | SSOT bundle is written only by the analysis save path |
`R3` | `input` present | `analysis_case` | pre-SSOT analysis case; carries the analysed artifact |
`R4` | none of the above | `unclassified` | **classification withheld, not guessed** |

## A.3 · The 77 "neither" documents — resolved, not assumed

The reconciliation left the 77 as `MEDIUM` confidence (U-1). Key-signature analysis of all 77 resolves them **deterministically**:

| Docs | Key signature | Resolution |
|---|---|---|
| 31 | `chain_ids, confidence, created_at, engine, id, input, input_len, investigation_summary, iocs, name, output, output_len, updated_at, user_email, verdict` | `analysis_case` (R3) |
| 28 | same + `confidence_backfilled_at, lolbas, mitre, reached_shellcode, reinvestigated_at, verdict_card` | `analysis_case` (R3) |
| 11 | same family | `analysis_case` (R3) |
| 3 | same + `closed_loop_last_run, evidence_state_hash` | `analysis_case` (R3) |
| 1 | same + `investigation_summary` | `analysis_case` (R3) |
| 1 | same + `incident_state, incident_state_history` | `analysis_case` (R3) — an analysis case triaged through the incident API. **Recorded as a real finding: analysis cases can acquire incident lifecycle state** |
| 1 | `id, mitre, tenant_id, title, user_email` — **no `input`, no `ssot`, no `xdr_pipeline`** | **`unclassified` (R4)** — `id = inc_r381_empty`, a test fixture |
| **77** | | **76 deterministic, 1 ambiguous** |

`inc_r381_empty` also **resolves the reconciliation's U-3**: it is the reason 199 documents match `^inc_` while only 198 carry `xdr_pipeline`.

## A.4 · Writers changed (2 lines of behaviour, additive only)

| Writer | Change |
|---|---|
`detection_content/xdr_incident.py:74-77` | new incidents carry `"doc_type": "xdr_incident"` |
`routers/cases.py:209-216` | new analysis cases carry `"doc_type": "analysis_case"` |

Nothing else in either writer changed. Incident ID namespace, gate logic and provenance envelope untouched.

### Writer proof (in-memory DB double — no DB pollution)

```
created: True | collection: workspace_cases
doc_type in written doc: 'xdr_incident'
id namespace preserved: True | inc_be9950d67736472581d9
keys: ['created_at','doc_type','id','incident_priority','incident_state',
       'incident_state_history','priority_label','tenant_id','title',
       'updated_at','verdict_card','xdr_pipeline']

GATE unchanged:
  {'created': False, 'reason': 'verdict.label=INCONCLUSIVE score=10 below gate
    (min_score=55, required_labels=MALICIOUS|SUSPICIOUS)',
   'honesty_note': 'No fabricated incident: gate honestly refused this verdict.'}
```

## A.5 · Backfill — deterministic, opt-in for ambiguity, idempotent

`backend/scripts/backfill_case_doc_type.py`. Dry-run by default. Ambiguous documents are **left completely untouched** unless `--mark-unclassified` is explicitly passed — which was **not** used.

### BEFORE → AFTER

| Metric | Before | After |
|---|---|---|
`workspace_cases` total | **484** | **484** |
docs with `doc_type` | **0** | **483** |
`doc_type = xdr_incident` | 0 | **198** |
`doc_type = analysis_case` | 0 | **285** |
`doc_type = unclassified` | 0 | **0** (deliberately not stamped) |
docs **without** `doc_type` | 484 | **1** → `inc_r381_empty` |
conflicts (existing ≠ computed) | — | **0** |
documents deleted | — | **0** |
`id` values changed | — | **0** |

Dry-run classification matched the applied run exactly: `R1:198 · R2:209 · R3:76 · R4:1` → 198 + 285 + 1 = **484** ✓ (`sum_matches_total: true`).

### Idempotency proof (second `--apply` run)

```
written(2nd run): 0 | skipped_already_correct: 483 | skipped_ambiguous: 1 | conflicts: 0
```

## A.6 · No-regression evidence

`GET /api/xdr/mss/kpis` — **byte-identical tile counts before and after**:

| Tile | Before | After |
|---|---|---|
critical | 0 | **0** |
high_priority | 7 | **7** |
high_fidelity | 0 | 0 |
unassigned | — | 121 |
recently_created / recently_updated | — | 13 / 13 |

All tiles still `count_source: "live"`. `GET /api/incidents` still returns the same incident records. **No reader was changed**, so no reader behaviour could change — the discriminator is available to readers but not yet consumed by any of them.

## A.7 · Findings surfaced by this work (recorded, NOT fixed — no authorisation)

| # | Finding | Severity |
|---|---|---|
| F-1 | **Analysis cases appear in the incident queue.** `GET /api/incidents` returns `analysis_case` documents (e.g. `660dcaf2-…`, `47dd8b61-…`) with `priority P5 / severity unknown`, because the list query does not filter by type. The new `doc_type` field makes this filterable **for the first time** — but I did not change the query | **P1** |
| F-2 | One `analysis_case` carries `incident_state: in_progress` (`69bcf510-…`), so analysis cases can enter the incident lifecycle | P2 |
| F-3 | `inc_r381_empty` is a test fixture occupying the `inc_` namespace | P3 |

---

# PART B · P0-2 · DSM REGISTRY UNIFICATION

## B.1 · Requirements → evidence

| Owner requirement | Status | Evidence |
|---|---|---|
One authoritative production DSM registry | ✅ | `TELEMETRY_DSM_REGISTRY` is now the single instance; `xdr_pipeline.DSM_REGISTRY` **is the same object** (parity snapshot: `"same_object": true`, was `false`) |
Fail loudly on DSM load/import failure | ✅ | `registry.py::register_failure` logs `log.error("DSM LOAD FAILED · dsm_id=%s phase=%s …")` |
Per-DSM failure visibility | ✅ | `load_failures()` + `health()`; exposed additively at `GET /api/admin/content-supply-chain/dsm/registry` |
Preserve all working DSMs incl. `SysmonDSM` | ✅ | 5 loaded, order unchanged (§B.3) |
No silent `except/pass` swallowing | ✅ | both `pass` blocks removed (§B.2) |
Preserve resolution semantics unless proven safe | ✅ | parity snapshot: every fixture resolves to the identical DSM (§B.3) |
Parity-test DSM selection before changing priority/order | ✅ | **priority/order was NOT changed.** Harness committed at `backend/tools/dsm_parity_snapshot.py` for the future ordering decision |
No unrelated pipeline changes | ✅ | `process_event_through_pipeline` untouched; 4 files changed, all registry-related |

## B.2 · What changed

| File | Change |
|---|---|
`detection_content/telemetry/registry.py` | Rewritten as the authoritative registry: `register(first=)`, `try_register()` (per-DSM guarded), `register_failure()`, `load_failures()`, `resolve_failures()`, `health()`. `resolve()` now **fails closed and records** `SUPPORTS_ERROR`. `register_dsm()` retained as an alias — **it is now actually reachable** (was dead code, C-3) |
`detection_content/telemetry/__init__.py` | DSM classes re-exported **lazily** (PEP-562 `__getattr__`). Eager top-level imports would have defeated per-DSM visibility: one broken DSM module made importing the whole telemetry package fail. Public import surface unchanged. `SysmonDSM/Parser/Normalizer` added to `__all__` |
`detection_content/xdr_pipeline.py` | `DSM_REGISTRY = TELEMETRY_DSM_REGISTRY`; `snort-eve` registered with `first=True` to hold position 0. Both `except Exception: pass` blocks **deleted**. `DSMRegistry` retained as a shim returning the shared instance so the name stays importable |
`routers/content_supply_chain.py:905-910` | `GET /dsm/registry` response is **additive**: `dsms` shape unchanged, plus `load_failures` / `resolve_failures` / `loaded_count` |
`tools/dsm_parity_snapshot.py` | **new** — 14-fixture parity harness (Suricata alert/flow, Windows 4688, Windows 4624-unsupported, Sysmon 1/3/unsupported-EID, Sysmon-provider-with-4688 overlap probe, Linux auditd, CloudTrail, garbage, non-dict, exception-raising probe) |

## B.3 · Parity proof — BEFORE vs AFTER

Production registry (`DSM_REGISTRY`):

| Fixture | Before | After | Δ |
|---|---|---|---|
inventory (ordered) | `snort-eve, windows-security-evd, linux-auditd, aws-cloudtrail, microsoft-sysmon` | **identical** | — |
`suricata_eve_alert` | `snort-eve` | `snort-eve` | — |
`suricata_eve_flow` | `snort-eve` | `snort-eve` | — |
`windows_security_4688` | `windows-security-evd` | `windows-security-evd` | — |
`windows_security_4624_unsupported` | `null` | `null` | — |
`sysmon_1_process_create` | `microsoft-sysmon` | `microsoft-sysmon` | — |
`sysmon_3_network` | `microsoft-sysmon` | `microsoft-sysmon` | — |
`sysmon_unsupported_eid` | `null` | `null` | — |
`overlap_sysmon_provider_eid_4688` | `windows-security-evd` | `windows-security-evd` | — |
`linux_auditd_execve` | `linux-auditd` | `linux-auditd` | — |
`aws_cloudtrail_event` | `aws-cloudtrail` | `aws-cloudtrail` | — |
`unsupported_garbage` / `not_a_dict` | `null` | `null` | — |
**`raising_probe`** | **`RAISED:RuntimeError`** | **`null`** | ✅ **the authorised fix** |

**Zero DSM selection changed. The only behavioural delta is the crash becoming a logged, fail-closed skip** — which is exactly requirement *"supports() failures must fail closed and be observable"*.

Test-path registry (`TELEMETRY_DSM_REGISTRY`): previously `[windows-security-evd, linux-auditd, aws-cloudtrail]`; now identical to production. **Additive only** — every previously-resolving fixture resolves to the same DSM. This closes **C-2** (Sysmon was invisible to the telemetry test suite).

## B.4 · The asymmetry (C-4) was empirically proven, then removed

The `raising_probe` row above is the proof: **before**, the production registry propagated `RuntimeError` while the test registry silently skipped — *tests were strictly more forgiving than production*. Both now fail closed and log:

```
DSM supports() FAILED · dsm_id=microsoft-sysmon RuntimeError: exploding event fixture — failing closed
```

## B.5 · Load-failure visibility — negative test

A simulated broken DSM was injected at runtime (no repo change):

```
DSM LOAD FAILED · dsm_id=simulated-broken-dsm phase=import SyntaxError: simulated broken DSM module
loaded: ['snort-eve','windows-security-evd','linux-auditd','aws-cloudtrail','microsoft-sysmon']
load_failures: [('simulated-broken-dsm','SyntaxError')]
siblings still resolve:
  suricata -> snort-eve
  sysmon   -> microsoft-sysmon
```

Two properties proven: (1) the failure is **loud and recorded**; (2) a broken DSM **no longer takes its siblings down** — the shared `try` that let one broken file disable three DSMs (S-1) is gone.

## B.6 · Live operator surface

`GET /api/admin/content-supply-chain/dsm/registry`:

```json
{"loaded_count": 5,
 "dsms": ["snort-eve","windows-security-evd","linux-auditd","aws-cloudtrail","microsoft-sysmon"],
 "load_failure_count": 0, "load_failures": [],
 "resolve_failure_count": 0,
 "honesty_note": "load_failures lists DSMs that exist in the codebase but could not be
   imported or constructed. A source whose DSM appears here will report 'no DSM supports
   this event' for every event — that is a CODE failure, not a data mismatch."}
```

**The owner's stated concern is closed:** "DSM never loaded" is now distinguishable from "no DSM supports this event".

## B.7 · End-to-end pipeline regression

`POST /api/v2/ingestion/golden/clean_workstation` (live, authenticated) — 9 traces, first trace:

```
dsm -> EXECUTED · parser -> EXECUTED · normalizer -> EXECUTED
canonical_evidence -> EXECUTED · ssot -> EXECUTED · detection -> EXECUTED
iue -> EXECUTED · correlation -> EXECUTED · verdict -> EXECUTED
incident -> NOT_CREATED   (blocker: incident_gate)
investigation / response / closed_loop / framework_mapping -> NOT_CREATED
pipeline_error: (none)
```

Correct and honest: `clean_workstation` is a benign dataset, so the VEEE gate refuses to materialise an incident. Stages 1-9 all execute post-change.

## B.8 · Test regression

```
tests/test_phase2_telemetry_normalization.py
tests/test_phase2_1_field_normalization_adversarial.py
tests/test_phase2_1_scale_microbenchmark.py
tests/test_phase2_1_tenant_isolation.py
tests/canonical/incidents/  tests/canonical/edr/
→ 52 passed, 2 failed
```

**Both failures are PRE-EXISTING and unrelated to this work.** Proven by `git stash`-ing all four changed files and re-running: the identical two tests fail on the untouched baseline.

| Pre-existing failure | Assertion |
|---|---|
`test_phase2_telemetry_normalization::test_windows_security_4688_process_creation` | expects `process.name == "powershell.exe"`, gets `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
`test_phase2_1_field_normalization_adversarial::test_windows_4688_alternate_casing_and_null_fields` | expects `process.name == "cmd.exe"`, gets `C:\Windows\System32\cmd.exe` |

**Root cause (not fixed, no authorisation):** `WindowsSecurityNormalizer` writes the full image path into `process.name` instead of the basename. **Recorded as F-4, P2.**

## B.9 · Additional finding (recorded, NOT fixed)

| # | Finding | Severity |
|---|---|---|
| F-4 | `WindowsSecurityDSM` normalizer puts the full path in `process.name` (2 pre-existing red tests) | P2 |
| F-5 | **`WindowsSecurityDSM.supports()` accepts ONLY EventID 4688, 4768, 4769** (`windows_security_dsm.py:299`). Logon events **4624/4625 are NOT supported**. This materially qualifies the identity-telemetry assumption in the audit's CAT-15 — Windows-Security does **not** currently give NivXRay logon visibility | **P1** |
| F-6 | DSM priority order remains a positional accident. `SnortEveDSM.supports()` matches any dict with `event_type` + `src_ip` and sits at index 0. The parity harness now exists to make an explicit-ordering change safe — **but that change was deliberately NOT made** | P1 |

---

# PART C · SCOPE INTEGRITY

## C.1 · Files changed (complete)

```
M backend/detection_content/telemetry/__init__.py     P0-2
M backend/detection_content/telemetry/registry.py     P0-2
M backend/detection_content/xdr_pipeline.py           P0-2 (registry wiring only)
M backend/routers/content_supply_chain.py             P0-2 (additive response)
M backend/detection_content/xdr_incident.py           P0-1 (doc_type on write)
M backend/routers/cases.py                            P0-1 (doc_type on write)
+ backend/case_doc_type.py                            P0-1 (new · classifier)
+ backend/scripts/backfill_case_doc_type.py            P0-1 (new · backfill)
+ backend/tools/dsm_parity_snapshot.py                 P0-2 (new · parity harness)
+ docs/truth-contract/edr-review/*.md                  artifacts
```

## C.2 · Explicitly NOT done

`verdict_stage2`/`verdict_card` fix (design decision only, per directive) · real Suricata telemetry · Security State UI · Counterfactual Defense Projection · telemetry-trust dashboard tile · UBAE · Sandbox · Stage 4 · Gap B · Stage 11 · `mal-20` · DSM priority/order change · incident-queue filtering by `doc_type` (F-1) · any store migration, merge or deletion.

## END · P0-1 + P0-2 delivered with before/after evidence · P0-3 decision awaiting ratification · P0-4 not started
