# STEP 1 — READ-ONLY REAL-LOOP PROOF

Generated: 2026-09-14T14:50:08.704600+00:00
Events walked: 13 · source: live NivXForge Linux sensor on this real host
**Read-only. No writes. No pipeline change. No fabricated timestamp.**

## 1 · Per-event chain

| Event (raw_id) | Cohort | Activity | ActOccur | SensorObs | CollRecv | NivXRecv | Parsed | Normalized | RuleEval | VerdictAt | Rule ID | Detection | SrcVerdict | NivXVerdict |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| raw_90bbb7c2c63ee96… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 14:50:05.375 | n/a | 14:50:07.526 | 14:50:07.632 | 14:50:07.632 | 14:50:07.633 | 14:50:07.635 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_0ec4d8b1c42f429… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 14:50:05.375 | n/a | 14:50:07.280 | 14:50:07.386 | 14:50:07.386 | 14:50:07.387 | 14:50:07.388 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_1a0f62eb51ffe03… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 14:50:05.375 | n/a | 14:50:07.033 | 14:50:07.139 | 14:50:07.139 | 14:50:07.140 | 14:50:07.141 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_5eec14c36fe529a… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 14:50:05.374 | n/a | 14:50:06.786 | 14:50:06.891 | 14:50:06.891 | 14:50:06.893 | 14:50:06.894 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_ffa994750f6b702… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 14:50:05.374 | n/a | 14:50:06.540 | 14:50:06.646 | 14:50:06.646 | 14:50:06.648 | 14:50:06.649 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_acc62f2a9f0b4e9… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 14:50:05.374 | n/a | 14:50:06.296 | 14:50:06.399 | 14:50:06.399 | 14:50:06.401 | 14:50:06.402 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_7dc6609bea8087a… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 14:50:05.374 | n/a | 14:50:06.051 | 14:50:06.157 | 14:50:06.157 | 14:50:06.158 | 14:50:06.160 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_040d51adc247cf9… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 14:50:05.374 | n/a | 14:50:05.807 | 14:50:05.912 | 14:50:05.912 | 14:50:05.914 | 14:50:05.915 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_363575b15f6816c… | PRE-PATCH | PROCESS/PROCESS_OBSER… | 14:47:06.030 | 14:47:12.740 | — | 14:47:15.599 | 14:47:15.602* | 14:47:15.602* | 14:47:15.713* | 14:47:15.713* | EDR-LNX-002 | DETECTION_MATCHED | — | SUSPICIOUS |
| raw_5a252f24a200961… | PRE-PATCH | PROCESS/PROCESS_OBSER… | 14:45:07.290 | 14:45:19.667 | — | 14:45:19.718 | 14:45:19.723* | 14:45:19.723* | 14:45:19.928* | 14:45:19.928* | EDR-LNX-002 | DETECTION_MATCHED | — | SUSPICIOUS |
| raw_350b60ffd8f69fa… | PRE-PATCH | NETWORK/CONNECTION_OB… | — | 14:49:07.382 | — | 14:49:07.847 | 14:49:07.850* | 14:49:07.850* | 14:49:07.954* | 14:49:07.954* | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_400f46064d6301d… | PRE-PATCH | NETWORK/CONNECTION_OB… | — | 14:49:07.382 | — | 14:49:07.635 | 14:49:07.638* | 14:49:07.638* | 14:49:07.742* | 14:49:07.742* | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_7666407671d2847… | PRE-PATCH | NETWORK/CONNECTION_OB… | — | 14:49:07.382 | — | 14:49:07.421 | 14:49:07.425* | 14:49:07.425* | 14:49:07.529* | 14:49:07.529* | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |

`*` = **PROXY, not a real stamp** (pre-patch events only): the derivation's single `derived_at`, which covered parse AND normalize as one write. · `n/a` = NOT_APPLICABLE · `n/obs` = NOT_OBSERVED.

`SrcVerdict` is `—` for every row **honestly**: a first-party sensor emits observations, not verdicts. There is no vendor verdict to preserve or overwrite on this path.

## 2 · Evidence references, tenant attribution, trust

| Event | Raw evidence ref | Canonical evidence ref | Bridge canonical ID | Tenant (raw) | Tenant (canonical) | Trust | Quality | Credential | Session | Dedup key | Dupes | Incident |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| raw_90bbb7c2c63… | edr_raw_events/raw_90bbb7c2c63ee9… | xdr_canonical_evidence/cev_raw_90bbb7c2c63e… | cev_90bbb7c2c63ee96b89dfc92… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_633821a7f163444d | 90bbb7c2c63ee… | 0 | — |
| raw_0ec4d8b1c42… | edr_raw_events/raw_0ec4d8b1c42f42… | xdr_canonical_evidence/cev_raw_0ec4d8b1c42f… | cev_0ec4d8b1c42f4290cdb4d55… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_633821a7f163444d | 0ec4d8b1c42f4… | 0 | — |
| raw_1a0f62eb51f… | edr_raw_events/raw_1a0f62eb51ffe0… | xdr_canonical_evidence/cev_raw_1a0f62eb51ff… | cev_1a0f62eb51ffe03c5597f06… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_633821a7f163444d | 1a0f62eb51ffe… | 0 | — |
| raw_5eec14c36fe… | edr_raw_events/raw_5eec14c36fe529… | xdr_canonical_evidence/cev_raw_5eec14c36fe5… | cev_5eec14c36fe529ab7a50e86… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_633821a7f163444d | 5eec14c36fe52… | 0 | — |
| raw_ffa994750f6… | edr_raw_events/raw_ffa994750f6b70… | xdr_canonical_evidence/cev_raw_ffa994750f6b… | cev_ffa994750f6b7023e54f847… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_633821a7f163444d | ffa994750f6b7… | 0 | — |
| raw_acc62f2a9f0… | edr_raw_events/raw_acc62f2a9f0b4e… | xdr_canonical_evidence/cev_raw_acc62f2a9f0b… | cev_acc62f2a9f0b4e912a2e180… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_633821a7f163444d | acc62f2a9f0b4… | 0 | — |
| raw_7dc6609bea8… | edr_raw_events/raw_7dc6609bea8087… | xdr_canonical_evidence/cev_raw_7dc6609bea80… | cev_7dc6609bea8087a418307bb… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_633821a7f163444d | 7dc6609bea808… | 0 | — |
| raw_040d51adc24… | edr_raw_events/raw_040d51adc247cf… | xdr_canonical_evidence/cev_raw_040d51adc247… | cev_040d51adc247cf95e95ed98… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_633821a7f163444d | 040d51adc247c… | 0 | — |
| raw_363575b15f6… | edr_raw_events/raw_363575b15f6816… | xdr_canonical_evidence/cev_raw_363575b15f68… | cev_363575b15f6816c3c41c0ab… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_7f8ad83fc5144088 | 363575b15f681… | 0 | inc_1a9f4bdd241442d2b… |
| raw_5a252f24a20… | edr_raw_events/raw_5a252f24a20096… | xdr_canonical_evidence/cev_raw_5a252f24a200… | cev_5a252f24a200961dbe22f2a… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_7f8ad83fc5144088 | 5a252f24a2009… | 0 | inc_1a9f4bdd241442d2b… |
| raw_350b60ffd8f… | edr_raw_events/raw_350b60ffd8f69f… | xdr_canonical_evidence/cev_raw_350b60ffd8f6… | cev_350b60ffd8f69fa49129a9a… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_633821a7f163444d | 350b60ffd8f69… | 0 | — |
| raw_400f46064d6… | edr_raw_events/raw_400f46064d6301… | xdr_canonical_evidence/cev_raw_400f46064d63… | cev_400f46064d6301db08c10df… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_633821a7f163444d | 400f46064d630… | 0 | — |
| raw_7666407671d… | edr_raw_events/raw_7666407671d284… | xdr_canonical_evidence/cev_raw_7666407671d2… | cev_7666407671d2847aca2d0f4… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_633821a7f163444d | 7666407671d28… | 0 | — |

## 3 · Provenance status per stamp (D1 evidence)

| Event | Cohort | activity_occurred | sensor_observed | collector_received | nivx_received | parsed | normalized | rule_evaluated | verdict |
|---|---|---|---|---|---|---|---|---|---|
| raw_90bbb7c2c63… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_0ec4d8b1c42… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_1a0f62eb51f… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_5eec14c36fe… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_ffa994750f6… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_acc62f2a9f0… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_7dc6609bea8… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_040d51adc24… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_363575b15f6… | PRE-PATCH | OK | OK | **MISS** | OK | **MISS** | **MISS** | **MISS** | **MISS** |
| raw_5a252f24a20… | PRE-PATCH | OK | OK | **MISS** | OK | **MISS** | **MISS** | **MISS** | **MISS** |
| raw_350b60ffd8f… | PRE-PATCH | **MISS** | OK | **MISS** | OK | **MISS** | **MISS** | **MISS** | **MISS** |
| raw_400f46064d6… | PRE-PATCH | **MISS** | OK | **MISS** | OK | **MISS** | **MISS** | **MISS** | **MISS** |
| raw_7666407671d… | PRE-PATCH | **MISS** | OK | **MISS** | OK | **MISS** | **MISS** | **MISS** | **MISS** |

`OK` = AVAILABLE (a real value) · `N/A` = NOT_APPLICABLE (no such boundary on this path) · `N-OBS` = NOT_OBSERVED (boundary exists, source could not see it) · `MISS` = MISSING (should exist, was not captured).

- **PRE-PATCH** — 5 events · 0/5 with **no MISSING stamp**
    - `activity_occurred_at`: 2×AVAILABLE, 3×MISSING
    - `sensor_observed_at`: 5×AVAILABLE
    - `collector_received_at`: 5×MISSING
    - `nivx_received_at`: 5×AVAILABLE
    - `parsed_at`: 5×MISSING
    - `normalized_at`: 5×MISSING
    - `rule_evaluated_at`: 5×MISSING
    - `verdict_at`: 5×MISSING
- **POST-PATCH** — 8 events · 8/8 with **no MISSING stamp**
    - `activity_occurred_at`: 8×NOT_OBSERVED
    - `sensor_observed_at`: 8×AVAILABLE
    - `collector_received_at`: 8×NOT_APPLICABLE
    - `nivx_received_at`: 8×AVAILABLE
    - `parsed_at`: 8×AVAILABLE
    - `normalized_at`: 8×AVAILABLE
    - `rule_evaluated_at`: 8×AVAILABLE
    - `verdict_at`: 8×AVAILABLE

### Sources recorded for the real stamps (post-patch)

| Stamp | Status | Source / reason |
|---|---|---|
| `activity_occurred_at` | NOT_OBSERVED | this collection method observes a state, not the instant it began |
| `sensor_observed_at` | AVAILABLE | sensor:observed_at |
| `collector_received_at` | NOT_APPLICABLE | no collector boundary exists on the sensor path: the sensor delivers straight to NivX ingress |
| `nivx_received_at` | AVAILABLE | ingest:raw row ingest_time |
| `parsed_at` | AVAILABLE | pipeline:parser:nivxforge-linux-sensor-parser |
| `normalized_at` | AVAILABLE | pipeline:normalizer:nivxforge-linux-sensor-normalizer |
| `rule_evaluated_at` | AVAILABLE | pipeline:detection:nivxray::detection_content::nivxray_native_sigma |
| `verdict_at` | AVAILABLE | pipeline:verdict:nivxray::xdr::veee |

- `activity_occurred_at` has a real value on **2/13** events — every PROCESS row, no NETWORK row. Source: the sensor's `start_time` read from `/proc`.

| Event | Activity | activity_occurred_at | canonical.event_time | event_time_basis (D9) |
|---|---|---|---|---|
| raw_90bbb7c2c63… | NETWORK/CONNECTION_OBSE… | — | 14:50:05.375 | OBSERVATION_TIME |
| raw_0ec4d8b1c42… | NETWORK/CONNECTION_OBSE… | — | 14:50:05.375 | OBSERVATION_TIME |
| raw_1a0f62eb51f… | NETWORK/CONNECTION_OBSE… | — | 14:50:05.375 | OBSERVATION_TIME |
| raw_5eec14c36fe… | NETWORK/CONNECTION_OBSE… | — | 14:50:05.374 | OBSERVATION_TIME |
| raw_ffa994750f6… | NETWORK/CONNECTION_OBSE… | — | 14:50:05.374 | OBSERVATION_TIME |
| raw_acc62f2a9f0… | NETWORK/CONNECTION_OBSE… | — | 14:50:05.374 | OBSERVATION_TIME |
| raw_7dc6609bea8… | NETWORK/CONNECTION_OBSE… | — | 14:50:05.374 | OBSERVATION_TIME |
| raw_040d51adc24… | NETWORK/CONNECTION_OBSE… | — | 14:50:05.374 | OBSERVATION_TIME |
| raw_363575b15f6… | PROCESS/PROCESS_OBSERVED | 14:47:06.030 | 14:47:06.030 | **absent** |
| raw_5a252f24a20… | PROCESS/PROCESS_OBSERVED | 14:45:07.290 | 14:45:07.290 | **absent** |
| raw_350b60ffd8f… | NETWORK/CONNECTION_OBSE… | — | 14:49:07.382 | **absent** |
| raw_400f46064d6… | NETWORK/CONNECTION_OBSE… | — | 14:49:07.382 | **absent** |
| raw_7666407671d… | NETWORK/CONNECTION_OBSE… | — | 14:49:07.382 | **absent** |

**D9 · `event_time` carries two different meanings.** On 11/13 events (all NETWORK) `canonical.event_time` equals `sensor_observed_at`, not an activity time.

- **8/11** of those now declare `event_time_basis` explicitly, so a consumer can tell *when it happened* from *when we noticed*. Where it is `**absent**` the conflation is still silent (pre-patch events).

## 4 · Latencies — computed ONLY from stamps that genuinely exist

| Event | Cohort | sensor_obs → nivx_recv | nivx_recv → parsed | parsed → normalized | normalized → rule_eval | rule_eval → verdict |
|---|---|---|---|---|---|---|
| raw_90bbb7c2c63… | POST-PATCH | 2150.9 ms | 106.5 ms | 0.1 ms | 1.4 ms | 1.2 ms |
| raw_0ec4d8b1c42… | POST-PATCH | 1905.5 ms | 105.9 ms | 0.1 ms | 1.3 ms | 1.2 ms |
| raw_1a0f62eb51f… | POST-PATCH | 1658.4 ms | 105.8 ms | 0.1 ms | 1.3 ms | 1.3 ms |
| raw_5eec14c36fe… | POST-PATCH | 1411.4 ms | 105.2 ms | 0.1 ms | 1.4 ms | 1.2 ms |
| raw_ffa994750f6… | POST-PATCH | 1165.6 ms | 106.2 ms | 0.1 ms | 1.3 ms | 1.1 ms |
| raw_acc62f2a9f0… | POST-PATCH | 921.8 ms | 103.1 ms | 0.1 ms | 1.3 ms | 1.2 ms |
| raw_7dc6609bea8… | POST-PATCH | 676.9 ms | 105.6 ms | 0.1 ms | 1.4 ms | 1.3 ms |
| raw_040d51adc24… | POST-PATCH | 432.5 ms | 105.4 ms | 0.1 ms | 1.9 ms | 1.3 ms |
| raw_363575b15f6… | PRE-PATCH | 2859.2 ms | 3.0 ms* | 0.0 ms* | 110.6 ms* | 0.0 ms* |
| raw_5a252f24a20… | PRE-PATCH | 51.2 ms | 4.5 ms* | 0.0 ms* | 205.7 ms* | 0.0 ms* |
| raw_350b60ffd8f… | PRE-PATCH | 464.9 ms | 2.9 ms* | 0.0 ms* | 103.8 ms* | 0.0 ms* |
| raw_400f46064d6… | PRE-PATCH | 252.7 ms | 3.0 ms* | 0.0 ms* | 103.9 ms* | 0.0 ms* |
| raw_7666407671d… | PRE-PATCH | 39.6 ms | 3.5 ms* | 0.0 ms* | 104.2 ms* | 0.0 ms* |

**Genuinely measured stages** (both endpoints are real stamps, no proxy):

- `sensor_observed_at` → `nivx_received_at` — n=13 · min 39.6 ms · median 921.8 ms · max 2859.2 ms
- `nivx_received_at` → `parsed_at` — n=8 · min 103.1 ms · median 105.8 ms · max 106.5 ms
- `parsed_at` → `normalized_at` — n=8 · min 0.1 ms · median 0.1 ms · max 0.1 ms
- `normalized_at` → `rule_evaluated_at` — n=8 · min 1.3 ms · median 1.4 ms · max 1.9 ms
- `rule_evaluated_at` → `verdict_at` — n=8 · min 1.1 ms · median 1.2 ms · max 1.3 ms

`*` = at least one endpoint is a PROXY stamp, so the figure bounds the stage rather than measuring it. Sample size is too small for p95/p99 and none is claimed.

## 5 · Acceptance gates

| Gate | Verdict | Count | Evidence |
|---|---|---|---|
| Real telemetry | **PASS** | 13/13 | every row `trust_state=AUTHENTICATED`, credential + session bound; produced by the running sensor on this host |
| Raw persistence | **PASS** | 13/13 | `edr_raw_events` row with `payload_sha256` + `dedup_key` |
| Parsing | **PASS** | 13/13 | derivation `parser_state=OK` recorded on the raw row |
| Normalization | **PASS** | 13/13 | same derivation carries `normalizer_version` |
| Canonical evidence | **PASS** | 13/13 | `xdr_canonical_evidence` row resolved via `provenance.trace_id` |
| Provenance | **PARTIAL** | 8/13 | requires all 8 owner-specified stamps — see §3 |
| Provenance · literal value on all 8 (strict, informational) | **FAIL** | 0/13 | expected to stay below total: `collector_received_at` is legitimately NOT_APPLICABLE on the sensor path and must never be given a value |
| Detection | **PASS** | 13/13 | deterministic evaluation recorded with engine id; no-match is a real answer |
| Verdict traceability | **PASS** | 13/13 | `verdict_version` on the derivation, traceable to the raw row |
| Tenant attribution | **PASS** | 13/13 | raw tenant == canonical tenant on every row |
| End-to-end traceability | **PASS** | 13/13 | raw_id → derivation → canonical id, both directions resolvable |

### Provenance gate, split by cohort — the before/after

| Cohort | Events | No MISSING stamp | Verdict |
|---|---|---|---|
| PRE-PATCH | 5 | 0/5 | **FAIL** |
| POST-PATCH | 8 | 8/8 | **PASS** |

### Disclosure — the one definition that changed, and why

The 8-stamp list and the gate arithmetic are unchanged. **One definition did change and it must not pass unnoticed:** a stamp now counts as satisfied when its status is anything other than `MISSING`, where previously it had to carry a literal value.

This follows directly from owner decision #4 — `NOT_APPLICABLE` is a legitimate terminal answer for a boundary that does not exist, and `NOT_OBSERVED` for one the source genuinely could not see. Under the old definition the sensor path could **never** pass, because giving `collector_received_at` a value would require inventing one.

So the strict literal-value count is reported above as well, unhidden. Anyone who disagrees with the looser reading can use the strict row instead.

## 6 · Matched detections — fields and observed values

| Event | Rule | Engine | NivX verdict | Incident | process.executable_path | process.command_line | parent |
|---|---|---|---|---|---|---|---|
| raw_363575b15f6… | EDR-LNX-002 | nivxray::detection_co… | SUSPICIOUS | inc_1a9f4bdd241442d2b… | /usr/bin/bash | /bin/bash /tmp/tmpcrijfpif.sh | python3.11 |
| raw_5a252f24a20… | EDR-LNX-002 | nivxray::detection_co… | SUSPICIOUS | inc_1a9f4bdd241442d2b… | /usr/bin/bash | /bin/bash /tmp/tmp9yqbk2oc.sh | python3.11 |

**The observed values above were read back from canonical evidence at report time — they are NOT persisted as part of the match record.** The derivation stores only `rule_id` + engine id + verdict label. Which field matched, and on what value, is not recoverable from storage. Recorded as **D8**.

## 7 · What the sensor said it could NOT see

| Event | Activity | not_observed |
|---|---|---|
| raw_90bbb7c2c63… | NETWORK/CONNECTION_OBSERV… | — |
| raw_0ec4d8b1c42… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_1a0f62eb51f… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_5eec14c36fe… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_ffa994750f6… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_acc62f2a9f0… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_7dc6609bea8… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_040d51adc24… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_363575b15f6… | PROCESS/PROCESS_OBSERVED | exit_time, signer, integrity |
| raw_5a252f24a20… | PROCESS/PROCESS_OBSERVED | exit_time, signer, integrity |
| raw_350b60ffd8f… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_400f46064d6… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_7666407671d… | NETWORK/CONNECTION_OBSERV… | owning_process |

This is why `activity_occurred_at` is absent on NETWORK rows and present on PROCESS rows: the sensor reports the limits of its own observation instead of inventing a time.

## 8 · Observation: two canonical identities per activity

Each event carries **two** canonical ids for one real activity:

| Event | Bridge id (`v2_shadow_observations`) | Core id (`xdr_canonical_evidence`) |
|---|---|---|
| raw_90bbb7c2c63… | cev_90bbb7c2c63ee96b89dfc927_0 | cev_raw_90bbb7c2c63ee96b89dfc… |
| raw_0ec4d8b1c42… | cev_0ec4d8b1c42f4290cdb4d55e_0 | cev_raw_0ec4d8b1c42f4290cdb4d… |
| raw_1a0f62eb51f… | cev_1a0f62eb51ffe03c5597f06b_0 | cev_raw_1a0f62eb51ffe03c5597f… |
| raw_5eec14c36fe… | cev_5eec14c36fe529ab7a50e860_0 | cev_raw_5eec14c36fe529ab7a50e… |
| raw_ffa994750f6… | cev_ffa994750f6b7023e54f847f_0 | cev_raw_ffa994750f6b7023e54f8… |
| raw_acc62f2a9f0… | cev_acc62f2a9f0b4e912a2e1807_0 | cev_raw_acc62f2a9f0b4e912a2e1… |
| raw_7dc6609bea8… | cev_7dc6609bea8087a418307bbb_0 | cev_raw_7dc6609bea8087a418307… |
| raw_040d51adc24… | cev_040d51adc247cf95e95ed985_0 | cev_raw_040d51adc247cf95e95ed… |
| raw_363575b15f6… | cev_363575b15f6816c3c41c0abd_0 | cev_raw_363575b15f6816c3c41c0… |
| raw_5a252f24a20… | cev_5a252f24a200961dbe22f2a8_0 | cev_raw_5a252f24a200961dbe22f… |
| raw_350b60ffd8f… | cev_350b60ffd8f69fa49129a9aa_0 | cev_raw_350b60ffd8f69fa49129a… |
| raw_400f46064d6… | cev_400f46064d6301db08c10df3_0 | cev_raw_400f46064d6301db08c10… |
| raw_7666407671d… | cev_7666407671d2847aca2d0f42_0 | cev_raw_7666407671d2847aca2d0… |

Both derive deterministically from the same immutable `raw_id`, so this is a **naming/indexing** concern, not evidence duplication — but "the" canonical id for an activity is currently ambiguous.

