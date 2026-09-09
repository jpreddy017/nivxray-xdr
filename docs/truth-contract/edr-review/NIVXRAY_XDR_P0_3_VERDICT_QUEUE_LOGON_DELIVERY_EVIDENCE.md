# NivXRay XDR · P0-3 · VERDICT REPRESENTATION + QUEUE PURITY + WINDOWS LOGON · DELIVERY EVIDENCE

> **Owner-authorised implementation** 2026-09-05 (items 1, 2, 3). **NOT approved and NOT done:** historical verdict backfill of the 198 existing incidents · real Suricata telemetry · Security State UI · Counterfactual Defense Projection · UBAE · Sandbox · Stage 4 · Gap B · Stage 11 · `mal-20`.
> **Rule:** NO EVIDENCE → NO CLAIM.

---

# 1 · VERDICT REPRESENTATION — `verdict_stage2` ratified canonical

## 1.1 · A field-name mismatch found during implementation (new finding)

Before writing anything I read both contracts, and they **do not agree**:

| | Stage-2 engine actually persists | 8 readers actually read |
|---|---|---|
evidence list | **`evidence_rows`** (`services/verdict_stage2/model.py:89`) | **`evidence`** (`incidents.py:128`, `edr.py:66`, `xdr_mss.py:355`, `xdr_scenarios.py:189`, …) |
confidence bucket | **`confidence`** (`model.py:86`) | **`confidence_bucket`** (`incidents.py:736`) |

**Consequence:** even if `routers/verdict_stage2.py` had been running all along, the readers would still have seen nothing. The empty columns were **never only** a "Stage-2 has not run" problem — there is a writer/reader contract divergence underneath.

**Resolution chosen (within the authorised scope, and honouring "preserve `evidence[]`"):** the pipeline publishes **both names with identical content**. The owner-locked Stage-2 engine contract (`model.py:18` *"Never mutate the v3.x verdict/verdict_card contract"*) is untouched, and no reader needs to change.

## 1.2 · What was implemented

`detection_content/xdr_incident.py` — new `_stage2_from_veee(verdict, canonical)`, and the incident document now carries `verdict_stage2` alongside the retained `verdict_card`.

**No second engine, no independent scoring.** Every evidence row is a re-shape of VEEE's own `contributors[]` (`xdr_veee.compute_verdict` → `_score`, `xdr_veee.py:49-69`). The confidence bucket is taken from the **existing** Stage-2 banding function (`services/verdict_stage2/engine.py::_label_and_confidence`) — reused, never re-derived — and **only its confidence component** is used so VEEE remains the sole authority on the label.

| Field | Source |
|---|---|
`label` | VEEE label, mapped to the Stage-2 vocabulary: `MALICIOUS→malicious`, `SUSPICIOUS→suspicious`, `LIKELY_BENIGN→benign`, `INCONCLUSIVE→unknown` |
`risk_score` | `veee.score` verbatim |
`confidence` / `confidence_bucket` | `_label_and_confidence(score, len(contributors), bool(contributors))[1]` |
`engine` | `veee.engine_id` (`nivxray::xdr::veee`) |
`evidence` / `evidence_rows` | one row per VEEE contributor — `row_id` (sha256 of event+source+detail+weight), `rule_id`, `canonical_field_matched`, `matched_value`, `weight_contribution`, `event_ids`, `provenance_chain`, `display_summary` |
`contributing_signals` | one signal per contributor |
`weight_sum` / `score_cap_applied` | published because VEEE caps at 100 (`_MAX_SCORE`), so row weights can legitimately sum higher than `risk_score`. Stated explicitly so the numbers are never misread as inconsistent |

## 1.3 · Verification (in-memory DB double — no DB pollution)

Populated case — VEEE returns 3 contributors totalling 120, capped to 100:

```
label: malicious | confidence: high | confidence_bucket: high
risk_score: 100  | engine: nivxray::xdr::veee
evidence rows: 3 | evidence_rows alias identical: True
   detection.rule_id | rule_id=rule-abc-123      | +45 | event_ids=['cev-1']
   iue.severity_hint | rule_id=iue.severity_hint | +35 | event_ids=['cev-1']
   ice.matches       | rule_id=ice.matches       | +40 | event_ids=['cev-1']
weight_sum: 120 · risk_score: 100 · score_cap_applied: True
provenance_chain: ['nivxray::xdr::veee', 'nivxray::xdr::incident']
```

Zero-contributor case — **honest-empty, nothing fabricated**:

```
label: suspicious | confidence: insufficient | evidence: []
```

The incident gate is unchanged (`label ∈ {MALICIOUS,SUSPICIOUS}` **and** `score ≥ 55`).

## 1.4 · Not done (not approved)

The 198 existing incidents still have no `verdict_stage2`. Deterministic backfill remains possible from `xdr_pipeline.veee.contributors[]` already stored on each document — **design retained, awaiting the separate authorisation** as instructed.

---

# 2 · QUEUE PURITY — `doc_type == "xdr_incident"`

## 2.1 · A blocker found before implementing (new finding)

Filtering the queue to `doc_type == "xdr_incident"` **alone** would have reduced it from 292 rows to **7**. Measured cause:

| Fact | Count |
|---|---|
`doc_type = xdr_incident` documents | **198** |
…of those carrying a non-empty **`name`** | **7** |
…of those carrying a **`title`** | **198** |

The queue gate is `{"name": {"$exists": True, "$ne": ""}}` (`dashboard_lenses.py::_scope`, docstring: *"Only saved cases (with a persisted name) are surfaced"*), but `xdr_incident.py` persists the incident's display string as **`title`**, not `name`.

**So the pre-change incident queue was 285 analysis cases + 7 incidents = 292, and 191 of 198 real incidents were invisible.**

**Minimal fix applied** — strictly in service of the authorised goal, not a refactor: the display-name gate now accepts `name` **or** `title`, and `_project_row` falls back to `title`. Without this, "queue purity" would have hidden almost every real incident.

## 2.2 · What was implemented

| File | Change |
|---|---|
`services/dashboard_lenses.py::_scope` | `doc_type = "xdr_incident"` + `_DISPLAY_NAME_CLAUSE` (`name` OR `title`) merged via `$and` so it composes with lens predicates that already use `$or`. **One choke point → tiles and queue share the same predicate, preserving the tile-count == queue-count invariant** |
`routers/incidents.py` non-lens branch | same `doc_type` + display-name clause |
`routers/incidents.py::_project_row` | `name` falls back to `title` before `"(unnamed)"` |
`routers/incidents.py` list projection | `title` and `doc_type` added |

## 2.3 · BEFORE → AFTER (live, authenticated)

| Tile / lens | Before | After | Why |
|---|---|---|---|
`critical` | 0 | **2** | real P1 incidents were hidden by the `name` gate |
`high_priority` | 7 | **16** | 9 more real P1/P2 incidents surfaced |
`high_fidelity` | 0 | 0 | — |
`unassigned` | 121 | **18** | 103 **analysis cases** removed from the incident queue |
`recently_created` | 13 | **17** | — |
`recently_updated` | 13 | **17** | — |
`in_progress_mine` / `customer_response` / `on_hold` / `aging` | 0 | 0 | — |

**Invariant preserved exactly** — tile count == queue count for every lens: `critical 2/2`, `high_priority 16/16`, `unassigned 18/18`. All tiles still `count_source: "live"`.

**Purity proven** — non-lens queue now returns 18 rows, and **every id starts with `inc_`**:

```
rows: 18
sample names: ['R40 empty-summary polish', 'R38.2 SSOT',
               'R42 evidence deep-link fixture', 'R41 Timeline Replay fixture']
any UUID-style ids (analysis cases): NONE
```

Nothing was deleted, migrated or altered. The 285 analysis cases are untouched and still reachable through their own surfaces.

## 2.4 · Finding NOT fixed (out of authorised scope)

| # | Finding | Sev |
|---|---|---|
| **F-7** | **Only 18 of 198 incidents reach the queue** because `_scope` also applies `q["user_email"] = email`, and **180 pipeline incidents have no `user_email` field at all** (`distinct user_email on xdr_incident` → `['admin@nivxray.com']`, present on **18** docs). The pipeline writes `tenant_id`, not `user_email`. Ownership scoping was **NOT** touched — it is a separate decision (per-analyst scoping vs tenant scoping) and was not authorised | **P1** |

---

# 3 · WINDOWS LOGON VISIBILITY — 4624 / 4625

## 3.1 · What was implemented

`detection_content/telemetry/windows_security_dsm.py`:

| Change | Detail |
|---|---|
`SUPPORTED_EVENT_IDS = (4688, 4768, 4769, 4624, 4625)` | single constant; `supports()` and the parser's `UNSUPPORTED_EID` guard both read it (previously two hard-coded tuples) |
`_LOGON_TYPE_LABELS` | 2 interactive · 3 network · 4 batch · 5 service · 7 unlock · 8 network_cleartext · 9 new_credentials · 10 remote_interactive · 11 cached_interactive |
new normalizer branch `elif eid in (4624, 4625)` | `event_type` = `logon_success` / `logon_failure`; populates the **existing** `AuthEntity` (`auth_type` from `AuthenticationPackageName`, `logon_type`, `status`, `failure_reason` from `SubStatus`/`Status`), `IdentityEntity` (principal/username/domain/SID/logon-id), `NetworkEntity` (source IP+port, `::ffff:` stripped as in the 4768 branch), `ProcessEntity` when `ProcessName` is present |
`additional_fields` | `logon_type`, `logon_type_label`, `workstation_name`, `logon_process`, `authentication_package`, and (failures only) `status`, `sub_status` — **each written only when the event actually carried it (rule #13)** |
module docstring | records 4624/4625 and states explicitly: telemetry coverage correction, **no identity engine, no UBAE, no baselining** |

**No new engine, no new DSM, no new registry entry.** Canonical evidence shape and provenance envelope unchanged.

## 3.2 · Regression fixtures — `tests/test_p0_3_windows_logon_coverage.py` · **20 passed**

**Positive:** `4624`/`4625` in `SUPPORTED_EVENT_IDS` · `supports()` true for both · **unified registry resolves both to `windows-security-evd`** · 4624 → `SUCCESS`, `logon_type 10`, `remote_interactive`, `CORP\alice`, SID, logon-id, `10.20.30.40:51544`, **no failure metadata** · 4625 → `FAILURE`, `logon_type 3`, `failure_reason 0xC000006A`, `auth_type ntlm`, `status`+`sub_status` present · provenance (`parser_id`, `normalizer_id`, `event_id`) populated.

**Negative:** 4688/4768/4769 **still supported** · 1, 4634, 4672, 5140, 255, 0 **still refused** · parser still raises `UNSUPPORTED_EID` for 4634 · `None` and `"4624"` refused · **missing `LogonType` yields `None` and is omitted from `additional_fields` — not fabricated**.

## 3.3 · DSM selection parity

`tools/dsm_parity_snapshot.py` re-run before/after. **Exactly one intentional change; everything else byte-identical:**

```
CHANGED -> windows_security_4624 : None -> windows-security-evd
   same   suricata_eve_alert / suricata_eve_flow      : snort-eve
   same   windows_security_4688                       : windows-security-evd
   same   sysmon_1 / sysmon_3                         : microsoft-sysmon
   same   overlap_sysmon_provider_eid_4688            : windows-security-evd
   same   linux_auditd_execve                         : linux-auditd
   same   aws_cloudtrail_event                        : aws-cloudtrail
   same   sysmon_unsupported_eid / garbage / not_a_dict / raising_probe : null
   same   inventory + order : snort-eve, windows-security-evd, linux-auditd,
                              aws-cloudtrail, microsoft-sysmon
```

**DSM priority/order was NOT changed** (F-6 remains open).

---

# 4 · REGRESSION SUMMARY

```
tests/test_p0_3_windows_logon_coverage.py            20 passed  (new)
tests/test_phase2_telemetry_normalization.py
tests/test_phase2_1_field_normalization_adversarial.py
tests/canonical/incidents  tests/canonical/edr
→ 65 passed, 2 failed
```

**Both failures are the same PRE-EXISTING F-4 defect** (`WindowsSecurityNormalizer` writes the full image path into `process.name` for **4688**), previously proven pre-existing via a `git stash` baseline run. **Not touched — no authorisation.** The new 4624/4625 branch does not use `process.name` for its assertions and is unaffected.

Backend log clean of errors after restart. End-to-end golden ingestion unaffected.

---

# 5 · FILES CHANGED

```
M backend/detection_content/xdr_incident.py                     verdict_stage2 projection (+ doc_type from P0-1)
M backend/routers/incidents.py                                  queue purity + title fallback
M backend/services/dashboard_lenses.py                          queue purity (shared predicate)
M backend/detection_content/telemetry/windows_security_dsm.py    4624/4625 coverage
M backend/tools/dsm_parity_snapshot.py                           fixture rename (4624 now supported)
+ backend/tests/test_p0_3_windows_logon_coverage.py              20 regression fixtures
```

# 6 · OPEN FINDINGS CARRIED FORWARD

| # | Finding | Sev |
|---|---|---|
| **F-7** | Only 18 of 198 incidents reach the queue — `_scope` applies `user_email`, and 180 pipeline incidents have no `user_email` (pipeline writes `tenant_id`). **Ownership-scoping model needs an owner decision** | **P1** |
| F-4 | `WindowsSecurityNormalizer` puts the full path in `process.name` for 4688 (2 pre-existing red tests) | P2 |
| F-6 | DSM priority remains positional; `SnortEveDSM.supports()` matches any dict with `event_type`+`src_ip` at index 0. Parity harness now exists to change it safely | P1 |
| F-2 | An `analysis_case` carries `incident_state: in_progress` | P2 |
| F-3 | `inc_r381_empty` test fixture occupies the `inc_` namespace | P3 |
| — | **Historical verdict backfill of the 198 incidents — designed, NOT executed** (explicitly not approved) | — |

## END · P0-3 items 1-3 delivered with before/after evidence · backfill and Suricata awaiting authorisation
