# STEP 1 — READ-ONLY REAL-LOOP PROOF

Generated: 2026-09-14T15:10:38.661855+00:00
Events walked: 11 · source: live NivXForge Linux sensor on this real host
**Read-only. No writes. No pipeline change. No fabricated timestamp.**

## 1 · Per-event chain

| Event (raw_id) | Cohort | Activity | ActOccur | SensorObs | CollRecv | NivXRecv | Parsed | Normalized | RuleEval | VerdictAt | Rule ID | Detection | SrcVerdict | NivXVerdict |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| raw_311509b0bd3ea64… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 15:10:04.276 | n/a | 15:10:32.382 | 15:10:32.489 | 15:10:32.489 | 15:10:32.491 | 15:10:32.492 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_2c6a4a973e16415… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 15:10:04.276 | n/a | 15:10:32.129 | 15:10:32.237 | 15:10:32.237 | 15:10:32.239 | 15:10:32.240 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_2b36917d5c491bd… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 15:10:04.276 | n/a | 15:10:31.875 | 15:10:31.983 | 15:10:31.983 | 15:10:31.985 | 15:10:31.986 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_fbde42d934b2688… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 15:10:04.276 | n/a | 15:10:31.624 | 15:10:31.732 | 15:10:31.732 | 15:10:31.733 | 15:10:31.734 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_1b9111f9921761b… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 15:10:04.276 | n/a | 15:10:31.371 | 15:10:31.480 | 15:10:31.480 | 15:10:31.481 | 15:10:31.482 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_144d8328f468871… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 15:10:04.276 | n/a | 15:10:31.119 | 15:10:31.227 | 15:10:31.227 | 15:10:31.229 | 15:10:31.230 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_aa3f7f8134e73c3… | POST-PATCH | PROCESS/PROCESS_OBSER… | 15:10:01.460 | 15:10:04.267 | n/a | 15:10:08.192 | 15:10:08.466 | 15:10:08.466 | 15:10:08.497 | 15:10:08.515 | EDR-LNX-002 | DETECTION_MATCHED | — | SUSPICIOUS |
| raw_e864d8a66dd50c9… | POST-PATCH | PROCESS/PROCESS_OBSER… | 15:07:56.250 | 15:08:16.575 | n/a | 15:08:16.624 | 15:08:16.733 | 15:08:16.733 | 15:08:16.735 | 15:08:16.740 | EDR-LNX-002 | DETECTION_MATCHED | — | SUSPICIOUS |
| raw_350b60ffd8f69fa… | PRE-PATCH | NETWORK/CONNECTION_OB… | — | 14:49:07.382 | — | 14:49:07.847 | 14:49:07.850* | 14:49:07.850* | 14:49:07.954* | 14:49:07.954* | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_400f46064d6301d… | PRE-PATCH | NETWORK/CONNECTION_OB… | — | 14:49:07.382 | — | 14:49:07.635 | 14:49:07.638* | 14:49:07.638* | 14:49:07.742* | 14:49:07.742* | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_7666407671d2847… | PRE-PATCH | NETWORK/CONNECTION_OB… | — | 14:49:07.382 | — | 14:49:07.421 | 14:49:07.425* | 14:49:07.425* | 14:49:07.529* | 14:49:07.529* | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |

`*` = **PROXY, not a real stamp** (pre-patch events only): the derivation's single `derived_at`, which covered parse AND normalize as one write. · `n/a` = NOT_APPLICABLE · `n/obs` = NOT_OBSERVED.

`SrcVerdict` is `—` for every row **honestly**: a first-party sensor emits observations, not verdicts. There is no vendor verdict to preserve or overwrite on this path.

## 2 · Evidence references, tenant attribution, trust

| Event | Raw evidence ref | Canonical evidence ref | Bridge canonical ID | Tenant (raw) | Tenant (canonical) | Trust | Quality | Credential | Session | Dedup key | Dupes | Incident |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| raw_311509b0bd3… | edr_raw_events/raw_311509b0bd3ea6… | xdr_canonical_evidence/cev_raw_311509b0bd3e… | cev_311509b0bd3ea642ffedaa4… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_1e75217822764c61 | 311509b0bd3ea… | 0 | — |
| raw_2c6a4a973e1… | edr_raw_events/raw_2c6a4a973e1641… | xdr_canonical_evidence/cev_raw_2c6a4a973e16… | cev_2c6a4a973e1641537f895c6… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_1e75217822764c61 | 2c6a4a973e164… | 0 | — |
| raw_2b36917d5c4… | edr_raw_events/raw_2b36917d5c491b… | xdr_canonical_evidence/cev_raw_2b36917d5c49… | cev_2b36917d5c491bd009c3db8… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_1e75217822764c61 | 2b36917d5c491… | 0 | — |
| raw_fbde42d934b… | edr_raw_events/raw_fbde42d934b268… | xdr_canonical_evidence/cev_raw_fbde42d934b2… | cev_fbde42d934b2688fd27788c… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_1e75217822764c61 | fbde42d934b26… | 0 | — |
| raw_1b9111f9921… | edr_raw_events/raw_1b9111f9921761… | xdr_canonical_evidence/cev_raw_1b9111f99217… | cev_1b9111f9921761be23fddd2… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_1e75217822764c61 | 1b9111f992176… | 0 | — |
| raw_144d8328f46… | edr_raw_events/raw_144d8328f46887… | xdr_canonical_evidence/cev_raw_144d8328f468… | cev_144d8328f468871629a7734… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_1e75217822764c61 | 144d8328f4688… | 0 | — |
| raw_aa3f7f8134e… | edr_raw_events/raw_aa3f7f8134e73c… | xdr_canonical_evidence/cev_raw_aa3f7f8134e7… | cev_aa3f7f8134e73c32450e1c1… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_1e75217822764c61 | aa3f7f8134e73… | 0 | inc_1a9f4bdd241442d2b… |
| raw_e864d8a66dd… | edr_raw_events/raw_e864d8a66dd50c… | xdr_canonical_evidence/cev_raw_e864d8a66dd5… | cev_e864d8a66dd50c9f145da25… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_1e75217822764c61 | e864d8a66dd50… | 0 | inc_1a9f4bdd241442d2b… |
| raw_350b60ffd8f… | edr_raw_events/raw_350b60ffd8f69f… | xdr_canonical_evidence/cev_raw_350b60ffd8f6… | cev_350b60ffd8f69fa49129a9a… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_633821a7f163444d | 350b60ffd8f69… | 0 | — |
| raw_400f46064d6… | edr_raw_events/raw_400f46064d6301… | xdr_canonical_evidence/cev_raw_400f46064d63… | cev_400f46064d6301db08c10df… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_633821a7f163444d | 400f46064d630… | 0 | — |
| raw_7666407671d… | edr_raw_events/raw_7666407671d284… | xdr_canonical_evidence/cev_raw_7666407671d2… | cev_7666407671d2847aca2d0f4… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_633821a7f163444d | 7666407671d28… | 0 | — |

## 3 · Provenance status per stamp (D1 evidence)

| Event | Cohort | activity_occurred | sensor_observed | collector_received | nivx_received | parsed | normalized | rule_evaluated | verdict |
|---|---|---|---|---|---|---|---|---|---|
| raw_311509b0bd3… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_2c6a4a973e1… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_2b36917d5c4… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_fbde42d934b… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_1b9111f9921… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_144d8328f46… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_aa3f7f8134e… | POST-PATCH | OK | OK | N/A | OK | OK | OK | OK | OK |
| raw_e864d8a66dd… | POST-PATCH | OK | OK | N/A | OK | OK | OK | OK | OK |
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
- **POST-PATCH** — 8 events · 8/8 with **no MISSING stamp**
    - `activity_occurred_at`: 2×AVAILABLE, 6×NOT_OBSERVED
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

- `activity_occurred_at` has a real value on **2/11** events — every PROCESS row, no NETWORK row. Source: the sensor's `start_time` read from `/proc`.

| Event | Activity | activity_occurred_at | canonical.event_time | event_time_basis (D9) |
|---|---|---|---|---|
| raw_311509b0bd3… | NETWORK/CONNECTION_OBSE… | — | 15:10:04.276 | OBSERVATION_TIME |
| raw_2c6a4a973e1… | NETWORK/CONNECTION_OBSE… | — | 15:10:04.276 | OBSERVATION_TIME |
| raw_2b36917d5c4… | NETWORK/CONNECTION_OBSE… | — | 15:10:04.276 | OBSERVATION_TIME |
| raw_fbde42d934b… | NETWORK/CONNECTION_OBSE… | — | 15:10:04.276 | OBSERVATION_TIME |
| raw_1b9111f9921… | NETWORK/CONNECTION_OBSE… | — | 15:10:04.276 | OBSERVATION_TIME |
| raw_144d8328f46… | NETWORK/CONNECTION_OBSE… | — | 15:10:04.276 | OBSERVATION_TIME |
| raw_aa3f7f8134e… | PROCESS/PROCESS_OBSERVED | 15:10:01.460 | 15:10:01.460 | ACTIVITY_TIME |
| raw_e864d8a66dd… | PROCESS/PROCESS_OBSERVED | 15:07:56.250 | 15:07:56.250 | ACTIVITY_TIME |
| raw_350b60ffd8f… | NETWORK/CONNECTION_OBSE… | — | 14:49:07.382 | **absent** |
| raw_400f46064d6… | NETWORK/CONNECTION_OBSE… | — | 14:49:07.382 | **absent** |
| raw_7666407671d… | NETWORK/CONNECTION_OBSE… | — | 14:49:07.382 | **absent** |

**D9 · `event_time` carries two different meanings.** On 9/11 events (all NETWORK) `canonical.event_time` equals `sensor_observed_at`, not an activity time.

- **6/9** of those now declare `event_time_basis` explicitly, so a consumer can tell *when it happened* from *when we noticed*. Where it is `**absent**` the conflation is still silent (pre-patch events).

## 4 · Latencies — computed ONLY from stamps that genuinely exist

| Event | Cohort | sensor_obs → nivx_recv | nivx_recv → parsed | parsed → normalized | normalized → rule_eval | rule_eval → verdict |
|---|---|---|---|---|---|---|
| raw_311509b0bd3… | POST-PATCH | 28106.3 ms | 107.3 ms | 0.1 ms | 1.3 ms | 1.3 ms |
| raw_2c6a4a973e1… | POST-PATCH | 27853.8 ms | 108.0 ms | 0.1 ms | 1.4 ms | 1.4 ms |
| raw_2b36917d5c4… | POST-PATCH | 27599.3 ms | 108.3 ms | 0.1 ms | 1.5 ms | 1.4 ms |
| raw_fbde42d934b… | POST-PATCH | 27348.2 ms | 107.7 ms | 0.1 ms | 1.4 ms | 1.4 ms |
| raw_1b9111f9921… | POST-PATCH | 27095.7 ms | 108.3 ms | 0.1 ms | 1.4 ms | 1.4 ms |
| raw_144d8328f46… | POST-PATCH | 26843.4 ms | 108.2 ms | 0.1 ms | 1.3 ms | 1.3 ms |
| raw_aa3f7f8134e… | POST-PATCH | 3924.6 ms | 273.9 ms | 0.1 ms | 30.8 ms | 18.4 ms |
| raw_e864d8a66dd… | POST-PATCH | 48.9 ms | 109.3 ms | 0.1 ms | 1.4 ms | 5.5 ms |
| raw_350b60ffd8f… | PRE-PATCH | 464.9 ms | 2.9 ms* | 0.0 ms* | 103.8 ms* | 0.0 ms* |
| raw_400f46064d6… | PRE-PATCH | 252.7 ms | 3.0 ms* | 0.0 ms* | 103.9 ms* | 0.0 ms* |
| raw_7666407671d… | PRE-PATCH | 39.6 ms | 3.5 ms* | 0.0 ms* | 104.2 ms* | 0.0 ms* |

**Genuinely measured stages** (both endpoints are real stamps, no proxy):

- `sensor_observed_at` → `nivx_received_at` — n=11 · min 39.6 ms · median 26843.4 ms · max 28106.3 ms
- `nivx_received_at` → `parsed_at` — n=8 · min 107.3 ms · median 108.3 ms · max 273.9 ms
- `parsed_at` → `normalized_at` — n=8 · min 0.1 ms · median 0.1 ms · max 0.1 ms
- `normalized_at` → `rule_evaluated_at` — n=8 · min 1.3 ms · median 1.4 ms · max 30.8 ms
- `rule_evaluated_at` → `verdict_at` — n=8 · min 1.3 ms · median 1.4 ms · max 18.4 ms

`*` = at least one endpoint is a PROXY stamp, so the figure bounds the stage rather than measuring it. Sample size is too small for p95/p99 and none is claimed.

## 5 · Acceptance gates

| Gate | Verdict | Count | Evidence |
|---|---|---|---|
| Real telemetry | **PASS** | 11/11 | every row `trust_state=AUTHENTICATED`, credential + session bound; produced by the running sensor on this host |
| Raw persistence | **PASS** | 11/11 | `edr_raw_events` row with `payload_sha256` + `dedup_key` |
| Parsing | **PASS** | 11/11 | derivation `parser_state=OK` recorded on the raw row |
| Normalization | **PASS** | 11/11 | same derivation carries `normalizer_version` |
| Canonical evidence | **PASS** | 11/11 | `xdr_canonical_evidence` row resolved via `provenance.trace_id` |
| Provenance | **PARTIAL** | 8/11 | requires all 8 owner-specified stamps — see §3 |
| Provenance · literal value on all 8 (strict, informational) | **FAIL** | 0/11 | expected to stay below total: `collector_received_at` is legitimately NOT_APPLICABLE on the sensor path and must never be given a value |
| Detection | **PASS** | 11/11 | deterministic evaluation recorded with engine id; no-match is a real answer |
| Verdict traceability | **PASS** | 11/11 | `verdict_version` on the derivation, traceable to the raw row |
| Tenant attribution | **PASS** | 11/11 | raw tenant == canonical tenant on every row |
| End-to-end traceability | **PASS** | 11/11 | raw_id → derivation → canonical id, both directions resolvable |

### Provenance gate, split by cohort — the before/after

| Cohort | Events | No MISSING stamp | Verdict |
|---|---|---|---|
| PRE-PATCH | 3 | 0/3 | **FAIL** |
| POST-PATCH | 8 | 8/8 | **PASS** |

### Disclosure — the one definition that changed, and why

The 8-stamp list and the gate arithmetic are unchanged. **One definition did change and it must not pass unnoticed:** a stamp now counts as satisfied when its status is anything other than `MISSING`, where previously it had to carry a literal value.

This follows directly from owner decision #4 — `NOT_APPLICABLE` is a legitimate terminal answer for a boundary that does not exist, and `NOT_OBSERVED` for one the source genuinely could not see. Under the old definition the sensor path could **never** pass, because giving `collector_received_at` a value would require inventing one.

So the strict literal-value count is reported above as well, unhidden. Anyone who disagrees with the looser reading can use the strict row instead.

## 6 · Matched detections — fields and observed values

| Event | Rule | Engine | NivX verdict | Incident | process.executable_path | process.command_line | parent |
|---|---|---|---|---|---|---|---|
| raw_aa3f7f8134e… | EDR-LNX-002 | nivxray::detection_co… | SUSPICIOUS | inc_1a9f4bdd241442d2b… | /usr/bin/bash | /bin/bash /tmp/tmpnlpt4646.sh | python3.11 |
| raw_e864d8a66dd… | EDR-LNX-002 | nivxray::detection_co… | SUSPICIOUS | inc_1a9f4bdd241442d2b… | /usr/bin/bash | /bin/bash /tmp/tmpfas3i_h6.sh | python3.11 |

**The observed values above were read back from canonical evidence at report time — they are NOT persisted as part of the match record.** The derivation stores only `rule_id` + engine id + verdict label. Which field matched, and on what value, is not recoverable from storage. Recorded as **D8**.

## 7 · What the sensor said it could NOT see

| Event | Activity | not_observed |
|---|---|---|
| raw_311509b0bd3… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_2c6a4a973e1… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_2b36917d5c4… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_fbde42d934b… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_1b9111f9921… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_144d8328f46… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_aa3f7f8134e… | PROCESS/PROCESS_OBSERVED | exit_time, signer, integrity |
| raw_e864d8a66dd… | PROCESS/PROCESS_OBSERVED | exit_time, signer, integrity |
| raw_350b60ffd8f… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_400f46064d6… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_7666407671d… | NETWORK/CONNECTION_OBSERV… | owning_process |

This is why `activity_occurred_at` is absent on NETWORK rows and present on PROCESS rows: the sensor reports the limits of its own observation instead of inventing a time.

## 8 · Observation: two canonical identities per activity

Each event carries **two** canonical ids for one real activity:

| Event | Bridge id (`v2_shadow_observations`) | Core id (`xdr_canonical_evidence`) |
|---|---|---|
| raw_311509b0bd3… | cev_311509b0bd3ea642ffedaa4c_0 | cev_raw_311509b0bd3ea642ffeda… |
| raw_2c6a4a973e1… | cev_2c6a4a973e1641537f895c6b_0 | cev_raw_2c6a4a973e1641537f895… |
| raw_2b36917d5c4… | cev_2b36917d5c491bd009c3db80_0 | cev_raw_2b36917d5c491bd009c3d… |
| raw_fbde42d934b… | cev_fbde42d934b2688fd27788ce_0 | cev_raw_fbde42d934b2688fd2778… |
| raw_1b9111f9921… | cev_1b9111f9921761be23fddd2c_0 | cev_raw_1b9111f9921761be23fdd… |
| raw_144d8328f46… | cev_144d8328f468871629a7734d_0 | cev_raw_144d8328f468871629a77… |
| raw_aa3f7f8134e… | cev_aa3f7f8134e73c32450e1c1d_0 | cev_raw_aa3f7f8134e73c32450e1… |
| raw_e864d8a66dd… | cev_e864d8a66dd50c9f145da259_0 | cev_raw_e864d8a66dd50c9f145da… |
| raw_350b60ffd8f… | cev_350b60ffd8f69fa49129a9aa_0 | cev_raw_350b60ffd8f69fa49129a… |
| raw_400f46064d6… | cev_400f46064d6301db08c10df3_0 | cev_raw_400f46064d6301db08c10… |
| raw_7666407671d… | cev_7666407671d2847aca2d0f42_0 | cev_raw_7666407671d2847aca2d0… |

Both derive deterministically from the same immutable `raw_id`, so this is a **naming/indexing** concern, not evidence duplication — but "the" canonical id for an activity is currently ambiguous.

