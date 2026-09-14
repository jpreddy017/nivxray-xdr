# STEP 1 — READ-ONLY REAL-LOOP PROOF

Generated: 2026-09-14T16:15:12.928511+00:00
Events walked: 13 · source: live NivXForge Linux sensor on this real host
**Read-only. No writes. No pipeline change. No fabricated timestamp.**

## 1 · Per-event chain

| Event (raw_id) | Cohort | Activity | ActOccur | SensorObs | CollRecv | NivXRecv | Parsed | Normalized | RuleEval | VerdictAt | Rule ID | Detection | SrcVerdict | NivXVerdict |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| raw_b658259809fa4f9… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 16:11:31.368 | n/a | 16:15:11.859 | 16:15:11.981 | 16:15:11.981 | 16:15:11.984 | 16:15:11.986 | — | — | — | — |
| raw_652a5f6cdbb364c… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 16:11:31.368 | n/a | 16:15:11.571 | 16:15:11.692 | 16:15:11.692 | 16:15:11.694 | 16:15:11.695 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_f2716d0386a11b8… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 16:11:31.368 | n/a | 16:15:11.286 | 16:15:11.410 | 16:15:11.410 | 16:15:11.412 | 16:15:11.413 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_0539a310fad6f74… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 16:11:31.368 | n/a | 16:15:11.004 | 16:15:11.125 | 16:15:11.125 | 16:15:11.126 | 16:15:11.128 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_4f6deea2da61371… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 16:11:31.368 | n/a | 16:15:10.715 | 16:15:10.839 | 16:15:10.839 | 16:15:10.841 | 16:15:10.843 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_5c92c2048f85328… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 16:11:31.368 | n/a | 16:15:10.367 | 16:15:10.549 | 16:15:10.549 | 16:15:10.554 | 16:15:10.556 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_7aba6b53207499c… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 16:11:31.368 | n/a | 16:15:09.923 | 16:15:10.043 | 16:15:10.043 | 16:15:10.046 | 16:15:10.047 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_0bb8a96941e1d89… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 16:11:31.368 | n/a | 16:15:09.630 | 16:15:09.757 | 16:15:09.757 | 16:15:09.758 | 16:15:09.760 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_0434bd7e2915823… | POST-PATCH | PROCESS/PROCESS_OBSER… | 16:07:47.560 | 16:09:08.991 | n/a | 16:12:22.693 | 16:12:22.810 | 16:12:22.810 | 16:12:22.811 | 16:12:22.817 | EDR-LNX-002 | DETECTION_MATCHED | — | SUSPICIOUS |
| raw_726dc6dcac5aecc… | POST-PATCH | PROCESS/PROCESS_OBSER… | 16:03:50.760 | 16:03:53.202 | n/a | 16:09:49.284 | 16:09:49.398 | 16:09:49.398 | 16:09:49.400 | 16:09:49.406 | EDR-LNX-002 | DETECTION_MATCHED | — | SUSPICIOUS |
| raw_350b60ffd8f69fa… | PRE-PATCH | NETWORK/CONNECTION_OB… | — | 14:49:07.382 | — | 14:49:07.847 | 14:49:07.850* | 14:49:07.850* | 14:49:07.954* | 14:49:07.954* | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_400f46064d6301d… | PRE-PATCH | NETWORK/CONNECTION_OB… | — | 14:49:07.382 | — | 14:49:07.635 | 14:49:07.638* | 14:49:07.638* | 14:49:07.742* | 14:49:07.742* | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_7666407671d2847… | PRE-PATCH | NETWORK/CONNECTION_OB… | — | 14:49:07.382 | — | 14:49:07.421 | 14:49:07.425* | 14:49:07.425* | 14:49:07.529* | 14:49:07.529* | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |

`*` = **PROXY, not a real stamp** (pre-patch events only): the derivation's single `derived_at`, which covered parse AND normalize as one write. · `n/a` = NOT_APPLICABLE · `n/obs` = NOT_OBSERVED.

`SrcVerdict` is `—` for every row **honestly**: a first-party sensor emits observations, not verdicts. There is no vendor verdict to preserve or overwrite on this path.

## 2 · Evidence references, tenant attribution, trust

| Event | Raw evidence ref | Canonical evidence ref | Bridge canonical ID | Tenant (raw) | Tenant (canonical) | Trust | Quality | Credential | Session | Dedup key | Dupes | Incident |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| raw_b658259809f… | edr_raw_events/raw_b658259809fa4f… | xdr_canonical_evidence/cev_raw_b658259809fa… | cev_b658259809fa4f9fe3c1389… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_4d6dedc12f5c4d58 | b658259809fa4… | 0 | — |
| raw_652a5f6cdbb… | edr_raw_events/raw_652a5f6cdbb364… | xdr_canonical_evidence/cev_raw_652a5f6cdbb3… | cev_652a5f6cdbb364cebaf3320… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_4d6dedc12f5c4d58 | 652a5f6cdbb36… | 0 | — |
| raw_f2716d0386a… | edr_raw_events/raw_f2716d0386a11b… | xdr_canonical_evidence/cev_raw_f2716d0386a1… | cev_f2716d0386a11b8dc2a4448… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_4d6dedc12f5c4d58 | f2716d0386a11… | 0 | — |
| raw_0539a310fad… | edr_raw_events/raw_0539a310fad6f7… | xdr_canonical_evidence/cev_raw_0539a310fad6… | cev_0539a310fad6f74e24c2e1f… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_4d6dedc12f5c4d58 | 0539a310fad6f… | 0 | — |
| raw_4f6deea2da6… | edr_raw_events/raw_4f6deea2da6137… | xdr_canonical_evidence/cev_raw_4f6deea2da61… | cev_4f6deea2da6137147d9f018… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_4d6dedc12f5c4d58 | 4f6deea2da613… | 0 | — |
| raw_5c92c2048f8… | edr_raw_events/raw_5c92c2048f8532… | xdr_canonical_evidence/cev_raw_5c92c2048f85… | cev_5c92c2048f85328c950df1a… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_4d6dedc12f5c4d58 | 5c92c2048f853… | 0 | — |
| raw_7aba6b53207… | edr_raw_events/raw_7aba6b53207499… | xdr_canonical_evidence/cev_raw_7aba6b532074… | cev_7aba6b53207499c5f44109d… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_4d6dedc12f5c4d58 | 7aba6b5320749… | 0 | — |
| raw_0bb8a96941e… | edr_raw_events/raw_0bb8a96941e1d8… | xdr_canonical_evidence/cev_raw_0bb8a96941e1… | cev_0bb8a96941e1d89f34702c1… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_4d6dedc12f5c4d58 | 0bb8a96941e1d… | 0 | — |
| raw_0434bd7e291… | edr_raw_events/raw_0434bd7e291582… | xdr_canonical_evidence/cev_raw_0434bd7e2915… | cev_0434bd7e2915823e9ba91f2… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_66e148db942b461c | 0434bd7e29158… | 0 | inc_1a9f4bdd241442d2b… |
| raw_726dc6dcac5… | edr_raw_events/raw_726dc6dcac5aec… | xdr_canonical_evidence/cev_raw_726dc6dcac5a… | cev_726dc6dcac5aeccf4bec366… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_66e148db942b461c | 726dc6dcac5ae… | 0 | inc_1a9f4bdd241442d2b… |
| raw_350b60ffd8f… | edr_raw_events/raw_350b60ffd8f69f… | xdr_canonical_evidence/cev_raw_350b60ffd8f6… | cev_350b60ffd8f69fa49129a9a… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_633821a7f163444d | 350b60ffd8f69… | 0 | — |
| raw_400f46064d6… | edr_raw_events/raw_400f46064d6301… | xdr_canonical_evidence/cev_raw_400f46064d63… | cev_400f46064d6301db08c10df… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_633821a7f163444d | 400f46064d630… | 0 | — |
| raw_7666407671d… | edr_raw_events/raw_7666407671d284… | xdr_canonical_evidence/cev_raw_7666407671d2… | cev_7666407671d2847aca2d0f4… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_633821a7f163444d | 7666407671d28… | 0 | — |

## 3 · Provenance status per stamp (D1 evidence)

| Event | Cohort | activity_occurred | sensor_observed | collector_received | nivx_received | parsed | normalized | rule_evaluated | verdict |
|---|---|---|---|---|---|---|---|---|---|
| raw_b658259809f… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_652a5f6cdbb… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_f2716d0386a… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_0539a310fad… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_4f6deea2da6… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_5c92c2048f8… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_7aba6b53207… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_0bb8a96941e… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_0434bd7e291… | POST-PATCH | OK | OK | N/A | OK | OK | OK | OK | OK |
| raw_726dc6dcac5… | POST-PATCH | OK | OK | N/A | OK | OK | OK | OK | OK |
| raw_350b60ffd8f… | PRE-PATCH | **MISS** | OK | **MISS** | OK | **MISS** | **MISS** | **MISS** | **MISS** |
| raw_400f46064d6… | PRE-PATCH | **MISS** | OK | **MISS** | OK | **MISS** | **MISS** | **MISS** | **MISS** |
| raw_7666407671d… | PRE-PATCH | **MISS** | OK | **MISS** | OK | **MISS** | **MISS** | **MISS** | **MISS** |

`OK` = AVAILABLE (a real value) · `N/A` = NOT_APPLICABLE (no such boundary on this path) · `N-OBS` = NOT_OBSERVED (boundary exists, source could not see it) · `MISS` = MISSING (should exist, was not captured).

- **PRE-PATCH** — 3 events · 0/3 with **no MISSING stamp**
    - `activity_occurred_at`: 3×MISSING
    - `sensor_observed_at`: 3×AVAILABLE
    - `collector_received_at`: 3×MISSING
    - `nivx_received_at`: 3×AVAILABLE
    - `parsed_at`: 3×MISSING
    - `normalized_at`: 3×MISSING
    - `rule_evaluated_at`: 3×MISSING
    - `verdict_at`: 3×MISSING
- **POST-PATCH** — 10 events · 10/10 with **no MISSING stamp**
    - `activity_occurred_at`: 2×AVAILABLE, 8×NOT_OBSERVED
    - `sensor_observed_at`: 10×AVAILABLE
    - `collector_received_at`: 10×NOT_APPLICABLE
    - `nivx_received_at`: 10×AVAILABLE
    - `parsed_at`: 10×AVAILABLE
    - `normalized_at`: 10×AVAILABLE
    - `rule_evaluated_at`: 10×AVAILABLE
    - `verdict_at`: 10×AVAILABLE

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
| raw_b658259809f… | NETWORK/CONNECTION_OBSE… | — | 16:11:31.368 | OBSERVATION_TIME |
| raw_652a5f6cdbb… | NETWORK/CONNECTION_OBSE… | — | 16:11:31.368 | OBSERVATION_TIME |
| raw_f2716d0386a… | NETWORK/CONNECTION_OBSE… | — | 16:11:31.368 | OBSERVATION_TIME |
| raw_0539a310fad… | NETWORK/CONNECTION_OBSE… | — | 16:11:31.368 | OBSERVATION_TIME |
| raw_4f6deea2da6… | NETWORK/CONNECTION_OBSE… | — | 16:11:31.368 | OBSERVATION_TIME |
| raw_5c92c2048f8… | NETWORK/CONNECTION_OBSE… | — | 16:11:31.368 | OBSERVATION_TIME |
| raw_7aba6b53207… | NETWORK/CONNECTION_OBSE… | — | 16:11:31.368 | OBSERVATION_TIME |
| raw_0bb8a96941e… | NETWORK/CONNECTION_OBSE… | — | 16:11:31.368 | OBSERVATION_TIME |
| raw_0434bd7e291… | PROCESS/PROCESS_OBSERVED | 16:07:47.560 | 16:07:47.560 | ACTIVITY_TIME |
| raw_726dc6dcac5… | PROCESS/PROCESS_OBSERVED | 16:03:50.760 | 16:03:50.760 | ACTIVITY_TIME |
| raw_350b60ffd8f… | NETWORK/CONNECTION_OBSE… | — | 14:49:07.382 | **absent** |
| raw_400f46064d6… | NETWORK/CONNECTION_OBSE… | — | 14:49:07.382 | **absent** |
| raw_7666407671d… | NETWORK/CONNECTION_OBSE… | — | 14:49:07.382 | **absent** |

**D9 · `event_time` carries two different meanings.** On 11/13 events (all NETWORK) `canonical.event_time` equals `sensor_observed_at`, not an activity time.

- **8/11** of those now declare `event_time_basis` explicitly, so a consumer can tell *when it happened* from *when we noticed*. Where it is `**absent**` the conflation is still silent (pre-patch events).

## 4 · Latencies — computed ONLY from stamps that genuinely exist

| Event | Cohort | sensor_obs → nivx_recv | nivx_recv → parsed | parsed → normalized | normalized → rule_eval | rule_eval → verdict |
|---|---|---|---|---|---|---|
| raw_b658259809f… | POST-PATCH | 220490.9 ms | 121.9 ms | 0.1 ms | 2.9 ms | 2.6 ms |
| raw_652a5f6cdbb… | POST-PATCH | 220202.5 ms | 121.6 ms | 0.1 ms | 1.4 ms | 1.4 ms |
| raw_f2716d0386a… | POST-PATCH | 219917.9 ms | 124.3 ms | 0.1 ms | 1.4 ms | 1.4 ms |
| raw_0539a310fad… | POST-PATCH | 219635.9 ms | 121.0 ms | 0.1 ms | 1.4 ms | 1.3 ms |
| raw_4f6deea2da6… | POST-PATCH | 219347.2 ms | 124.0 ms | 0.1 ms | 1.6 ms | 1.6 ms |
| raw_5c92c2048f8… | POST-PATCH | 218998.7 ms | 182.2 ms | 0.1 ms | 4.7 ms | 1.9 ms |
| raw_7aba6b53207… | POST-PATCH | 218555.2 ms | 120.1 ms | 0.1 ms | 2.1 ms | 1.6 ms |
| raw_0bb8a96941e… | POST-PATCH | 218261.6 ms | 127.1 ms | 0.1 ms | 1.4 ms | 1.5 ms |
| raw_0434bd7e291… | POST-PATCH | 193702.5 ms | 116.8 ms | 0.1 ms | 1.5 ms | 5.9 ms |
| raw_726dc6dcac5… | POST-PATCH | 356082.5 ms | 114.0 ms | 0.1 ms | 1.4 ms | 5.9 ms |
| raw_350b60ffd8f… | PRE-PATCH | 464.9 ms | 2.9 ms* | 0.0 ms* | 103.8 ms* | 0.0 ms* |
| raw_400f46064d6… | PRE-PATCH | 252.7 ms | 3.0 ms* | 0.0 ms* | 103.9 ms* | 0.0 ms* |
| raw_7666407671d… | PRE-PATCH | 39.6 ms | 3.5 ms* | 0.0 ms* | 104.2 ms* | 0.0 ms* |

**Genuinely measured stages** (both endpoints are real stamps, no proxy):

- `sensor_observed_at` → `nivx_received_at` — n=13 · min 39.6 ms · median 218998.7 ms · max 356082.5 ms
- `nivx_received_at` → `parsed_at` — n=10 · min 114.0 ms · median 121.9 ms · max 182.2 ms
- `parsed_at` → `normalized_at` — n=10 · min 0.1 ms · median 0.1 ms · max 0.1 ms
- `normalized_at` → `rule_evaluated_at` — n=10 · min 1.4 ms · median 1.5 ms · max 4.7 ms
- `rule_evaluated_at` → `verdict_at` — n=10 · min 1.3 ms · median 1.6 ms · max 5.9 ms

`*` = at least one endpoint is a PROXY stamp, so the figure bounds the stage rather than measuring it. Sample size is too small for p95/p99 and none is claimed.

## 5 · Acceptance gates

| Gate | Verdict | Count | Evidence |
|---|---|---|---|
| Real telemetry | **PASS** | 13/13 | every row `trust_state=AUTHENTICATED`, credential + session bound; produced by the running sensor on this host |
| Raw persistence | **PASS** | 13/13 | `edr_raw_events` row with `payload_sha256` + `dedup_key` |
| Parsing | **PASS** | 13/13 | derivation `parser_state=OK` recorded on the raw row |
| Normalization | **PASS** | 13/13 | same derivation carries `normalizer_version` |
| Canonical evidence | **PASS** | 13/13 | `xdr_canonical_evidence` row resolved via `provenance.trace_id` |
| Provenance | **PARTIAL** | 10/13 | requires all 8 owner-specified stamps — see §3 |
| Provenance · literal value on all 8 (strict, informational) | **FAIL** | 0/13 | expected to stay below total: `collector_received_at` is legitimately NOT_APPLICABLE on the sensor path and must never be given a value |
| Detection | **PARTIAL** | 12/13 | deterministic evaluation recorded with engine id; no-match is a real answer |
| Verdict traceability | **PARTIAL** | 12/13 | `verdict_version` on the derivation, traceable to the raw row |
| Tenant attribution | **PASS** | 13/13 | raw tenant == canonical tenant on every row |
| End-to-end traceability | **PASS** | 13/13 | raw_id → derivation → canonical id, both directions resolvable |

### Provenance gate, split by cohort — the before/after

| Cohort | Events | No MISSING stamp | Verdict |
|---|---|---|---|
| PRE-PATCH | 3 | 0/3 | **FAIL** |
| POST-PATCH | 10 | 10/10 | **PASS** |

### Disclosure — the one definition that changed, and why

The 8-stamp list and the gate arithmetic are unchanged. **One definition did change and it must not pass unnoticed:** a stamp now counts as satisfied when its status is anything other than `MISSING`, where previously it had to carry a literal value.

This follows directly from owner decision #4 — `NOT_APPLICABLE` is a legitimate terminal answer for a boundary that does not exist, and `NOT_OBSERVED` for one the source genuinely could not see. Under the old definition the sensor path could **never** pass, because giving `collector_received_at` a value would require inventing one.

So the strict literal-value count is reported above as well, unhidden. Anyone who disagrees with the looser reading can use the strict row instead.

## 6 · Matched detections — fields and observed values

| Event | Rule | Engine | NivX verdict | Incident | process.executable_path | process.command_line | parent |
|---|---|---|---|---|---|---|---|
| raw_0434bd7e291… | EDR-LNX-002 | nivxray::detection_co… | SUSPICIOUS | inc_1a9f4bdd241442d2b… | /usr/bin/bash | /bin/bash /tmp/tmp1rt6zm5h.sh | bash |
| raw_726dc6dcac5… | EDR-LNX-002 | nivxray::detection_co… | SUSPICIOUS | inc_1a9f4bdd241442d2b… | /usr/bin/bash | /bin/bash /tmp/tmpmvonbx9n.sh | python3.11 |

**The observed values above were read back from canonical evidence at report time — they are NOT persisted as part of the match record.** The derivation stores only `rule_id` + engine id + verdict label. Which field matched, and on what value, is not recoverable from storage. Recorded as **D8**.

## 7 · What the sensor said it could NOT see

| Event | Activity | not_observed |
|---|---|---|
| raw_b658259809f… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_652a5f6cdbb… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_f2716d0386a… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_0539a310fad… | NETWORK/CONNECTION_OBSERV… | — |
| raw_4f6deea2da6… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_5c92c2048f8… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_7aba6b53207… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_0bb8a96941e… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_0434bd7e291… | PROCESS/PROCESS_OBSERVED | exit_time, signer, integrity |
| raw_726dc6dcac5… | PROCESS/PROCESS_OBSERVED | exit_time, signer, integrity |
| raw_350b60ffd8f… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_400f46064d6… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_7666407671d… | NETWORK/CONNECTION_OBSERV… | owning_process |

This is why `activity_occurred_at` is absent on NETWORK rows and present on PROCESS rows: the sensor reports the limits of its own observation instead of inventing a time.

## 8 · Observation: two canonical identities per activity

Each event carries **two** canonical ids for one real activity:

| Event | Bridge id (`v2_shadow_observations`) | Core id (`xdr_canonical_evidence`) |
|---|---|---|
| raw_b658259809f… | cev_b658259809fa4f9fe3c13892_0 | cev_raw_b658259809fa4f9fe3c13… |
| raw_652a5f6cdbb… | cev_652a5f6cdbb364cebaf3320f_0 | cev_raw_652a5f6cdbb364cebaf33… |
| raw_f2716d0386a… | cev_f2716d0386a11b8dc2a4448a_0 | cev_raw_f2716d0386a11b8dc2a44… |
| raw_0539a310fad… | cev_0539a310fad6f74e24c2e1f5_0 | cev_raw_0539a310fad6f74e24c2e… |
| raw_4f6deea2da6… | cev_4f6deea2da6137147d9f0181_0 | cev_raw_4f6deea2da6137147d9f0… |
| raw_5c92c2048f8… | cev_5c92c2048f85328c950df1a1_0 | cev_raw_5c92c2048f85328c950df… |
| raw_7aba6b53207… | cev_7aba6b53207499c5f44109de_0 | cev_raw_7aba6b53207499c5f4410… |
| raw_0bb8a96941e… | cev_0bb8a96941e1d89f34702c15_0 | cev_raw_0bb8a96941e1d89f34702… |
| raw_0434bd7e291… | cev_0434bd7e2915823e9ba91f2e_0 | cev_raw_0434bd7e2915823e9ba91… |
| raw_726dc6dcac5… | cev_726dc6dcac5aeccf4bec3667_0 | cev_raw_726dc6dcac5aeccf4bec3… |
| raw_350b60ffd8f… | cev_350b60ffd8f69fa49129a9aa_0 | cev_raw_350b60ffd8f69fa49129a… |
| raw_400f46064d6… | cev_400f46064d6301db08c10df3_0 | cev_raw_400f46064d6301db08c10… |
| raw_7666407671d… | cev_7666407671d2847aca2d0f42_0 | cev_raw_7666407671d2847aca2d0… |

Both derive deterministically from the same immutable `raw_id`, so this is a **naming/indexing** concern, not evidence duplication — but "the" canonical id for an activity is currently ambiguous.

