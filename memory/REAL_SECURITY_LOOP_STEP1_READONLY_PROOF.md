# STEP 1 — READ-ONLY REAL-LOOP PROOF

Generated: 2026-09-14T17:22:18.758793+00:00
Events walked: 13 · source: live NivXForge Linux sensor on this real host
**Read-only. No writes. No pipeline change. No fabricated timestamp.**

## 1 · Per-event chain

| Event (raw_id) | Cohort | Activity | ActOccur | SensorObs | CollRecv | NivXRecv | Parsed | Normalized | RuleEval | VerdictAt | Rule ID | Detection | SrcVerdict | NivXVerdict |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| raw_baf79c24b33f102… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 17:22:01.942 | n/a | 17:22:03.485 | 17:22:03.618 | 17:22:03.618 | 17:22:03.620 | 17:22:03.626 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_e6924584fc42e75… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 17:22:01.942 | n/a | 17:22:03.176 | 17:22:03.302 | 17:22:03.302 | 17:22:03.304 | 17:22:03.305 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_3fcdb8372c11821… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 17:22:01.942 | n/a | 17:22:02.882 | 17:22:03.011 | 17:22:03.011 | 17:22:03.013 | 17:22:03.014 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_f15ef845d8426af… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 17:22:01.942 | n/a | 17:22:02.589 | 17:22:02.716 | 17:22:02.716 | 17:22:02.717 | 17:22:02.718 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_e86196ae6908702… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 17:22:01.941 | n/a | 17:22:02.293 | 17:22:02.422 | 17:22:02.422 | 17:22:02.423 | 17:22:02.425 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_558ffa95b8f51bc… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 17:22:01.941 | n/a | 17:22:01.996 | 17:22:02.126 | 17:22:02.126 | 17:22:02.128 | 17:22:02.129 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_a8bba4048e87b6a… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 17:21:27.439 | n/a | 17:21:31.593 | 17:21:31.718 | 17:21:31.718 | 17:21:31.720 | 17:21:31.721 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_6b802a42ffb4869… | POST-PATCH | NETWORK/CONNECTION_OB… | n/obs | 17:21:27.439 | n/a | 17:21:31.304 | 17:21:31.430 | 17:21:31.430 | 17:21:31.431 | 17:21:31.432 | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_2a90520d7122e97… | POST-PATCH | PROCESS/PROCESS_OBSER… | 17:19:54.550 | 17:20:10.424 | n/a | 17:20:10.486 | 17:20:10.613 | 17:20:10.613 | 17:20:10.615 | 17:20:10.621 | EDR-LNX-002 | DETECTION_MATCHED | — | SUSPICIOUS |
| raw_2a38bf701d64ee2… | POST-PATCH | PROCESS/PROCESS_OBSER… | 17:17:54.030 | 17:18:09.447 | n/a | 17:18:09.837 | 17:18:10.230 | 17:18:10.230 | 17:18:10.259 | 17:18:10.475 | EDR-LNX-002 | DETECTION_MATCHED | — | SUSPICIOUS |
| raw_350b60ffd8f69fa… | PRE-PATCH | NETWORK/CONNECTION_OB… | — | 14:49:07.382 | — | 14:49:07.847 | 14:49:07.850* | 14:49:07.850* | 14:49:07.954* | 14:49:07.954* | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_400f46064d6301d… | PRE-PATCH | NETWORK/CONNECTION_OB… | — | 14:49:07.382 | — | 14:49:07.635 | 14:49:07.638* | 14:49:07.638* | 14:49:07.742* | 14:49:07.742* | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |
| raw_7666407671d2847… | PRE-PATCH | NETWORK/CONNECTION_OB… | — | 14:49:07.382 | — | 14:49:07.421 | 14:49:07.425* | 14:49:07.425* | 14:49:07.529* | 14:49:07.529* | — | DETECTION_EVALUATED_NO_… | — | INCONCLUSIVE |

`*` = **PROXY, not a real stamp** (pre-patch events only): the derivation's single `derived_at`, which covered parse AND normalize as one write. · `n/a` = NOT_APPLICABLE · `n/obs` = NOT_OBSERVED.

`SrcVerdict` is `—` for every row **honestly**: a first-party sensor emits observations, not verdicts. There is no vendor verdict to preserve or overwrite on this path.

## 2 · Evidence references, tenant attribution, trust

| Event | Raw evidence ref | Canonical evidence ref | Bridge canonical ID | Tenant (raw) | Tenant (canonical) | Trust | Quality | Credential | Session | Dedup key | Dupes | Incident |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| raw_baf79c24b33… | edr_raw_events/raw_baf79c24b33f10… | xdr_canonical_evidence/cev_raw_baf79c24b33f… | cev_baf79c24b33f102679eb66c… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_06d1a425af984053 | baf79c24b33f1… | 0 | — |
| raw_e6924584fc4… | edr_raw_events/raw_e6924584fc42e7… | xdr_canonical_evidence/cev_raw_e6924584fc42… | cev_e6924584fc42e75e9dec774… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_06d1a425af984053 | e6924584fc42e… | 0 | — |
| raw_3fcdb8372c1… | edr_raw_events/raw_3fcdb8372c1182… | xdr_canonical_evidence/cev_raw_3fcdb8372c11… | cev_3fcdb8372c11821413ae4bb… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_06d1a425af984053 | 3fcdb8372c118… | 0 | — |
| raw_f15ef845d84… | edr_raw_events/raw_f15ef845d8426a… | xdr_canonical_evidence/cev_raw_f15ef845d842… | cev_f15ef845d8426afb0aa316e… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_06d1a425af984053 | f15ef845d8426… | 0 | — |
| raw_e86196ae690… | edr_raw_events/raw_e86196ae690870… | xdr_canonical_evidence/cev_raw_e86196ae6908… | cev_e86196ae6908702c830f5f3… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_06d1a425af984053 | e86196ae69087… | 0 | — |
| raw_558ffa95b8f… | edr_raw_events/raw_558ffa95b8f51b… | xdr_canonical_evidence/cev_raw_558ffa95b8f5… | cev_558ffa95b8f51bcc2c02a6d… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_06d1a425af984053 | 558ffa95b8f51… | 0 | — |
| raw_a8bba4048e8… | edr_raw_events/raw_a8bba4048e87b6… | xdr_canonical_evidence/cev_raw_a8bba4048e87… | cev_a8bba4048e87b6a5c1c86a1… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_06d1a425af984053 | a8bba4048e87b… | 0 | — |
| raw_6b802a42ffb… | edr_raw_events/raw_6b802a42ffb486… | xdr_canonical_evidence/cev_raw_6b802a42ffb4… | cev_6b802a42ffb48690190fa14… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_06d1a425af984053 | 6b802a42ffb48… | 0 | — |
| raw_2a90520d712… | edr_raw_events/raw_2a90520d7122e9… | xdr_canonical_evidence/cev_raw_2a90520d7122… | cev_2a90520d7122e97cd5a78fd… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_06d1a425af984053 | 2a90520d7122e… | 0 | inc_0f9b99c50f5b45a78… |
| raw_2a38bf701d6… | edr_raw_events/raw_2a38bf701d64ee… | xdr_canonical_evidence/cev_raw_2a38bf701d64… | cev_2a38bf701d64ee277111978… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_6355c87ad50f4ec6 | 2a38bf701d64e… | 0 | inc_0f9b99c50f5b45a78… |
| raw_350b60ffd8f… | edr_raw_events/raw_350b60ffd8f69f… | xdr_canonical_evidence/cev_raw_350b60ffd8f6… | cev_350b60ffd8f69fa49129a9a… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_633821a7f163444d | 350b60ffd8f69… | 0 | — |
| raw_400f46064d6… | edr_raw_events/raw_400f46064d6301… | xdr_canonical_evidence/cev_raw_400f46064d63… | cev_400f46064d6301db08c10df… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_633821a7f163444d | 400f46064d630… | 0 | — |
| raw_7666407671d… | edr_raw_events/raw_7666407671d284… | xdr_canonical_evidence/cev_raw_7666407671d2… | cev_7666407671d2847aca2d0f4… | default | default | AUTHENTICATED | HEALTHY | cred_00b4f731548443fd | sess_633821a7f163444d | 7666407671d28… | 0 | — |

## 3 · Provenance status per stamp (D1 evidence)

| Event | Cohort | activity_occurred | sensor_observed | collector_received | nivx_received | parsed | normalized | rule_evaluated | verdict |
|---|---|---|---|---|---|---|---|---|---|
| raw_baf79c24b33… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_e6924584fc4… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_3fcdb8372c1… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_f15ef845d84… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_e86196ae690… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_558ffa95b8f… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_a8bba4048e8… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_6b802a42ffb… | POST-PATCH | N-OBS | OK | N/A | OK | OK | OK | OK | OK |
| raw_2a90520d712… | POST-PATCH | OK | OK | N/A | OK | OK | OK | OK | OK |
| raw_2a38bf701d6… | POST-PATCH | OK | OK | N/A | OK | OK | OK | OK | OK |
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
| raw_baf79c24b33… | NETWORK/CONNECTION_OBSE… | — | 17:22:01.942 | OBSERVATION_TIME |
| raw_e6924584fc4… | NETWORK/CONNECTION_OBSE… | — | 17:22:01.942 | OBSERVATION_TIME |
| raw_3fcdb8372c1… | NETWORK/CONNECTION_OBSE… | — | 17:22:01.942 | OBSERVATION_TIME |
| raw_f15ef845d84… | NETWORK/CONNECTION_OBSE… | — | 17:22:01.942 | OBSERVATION_TIME |
| raw_e86196ae690… | NETWORK/CONNECTION_OBSE… | — | 17:22:01.941 | OBSERVATION_TIME |
| raw_558ffa95b8f… | NETWORK/CONNECTION_OBSE… | — | 17:22:01.941 | OBSERVATION_TIME |
| raw_a8bba4048e8… | NETWORK/CONNECTION_OBSE… | — | 17:21:27.439 | OBSERVATION_TIME |
| raw_6b802a42ffb… | NETWORK/CONNECTION_OBSE… | — | 17:21:27.439 | OBSERVATION_TIME |
| raw_2a90520d712… | PROCESS/PROCESS_OBSERVED | 17:19:54.550 | 17:19:54.550 | ACTIVITY_TIME |
| raw_2a38bf701d6… | PROCESS/PROCESS_OBSERVED | 17:17:54.030 | 17:17:54.030 | ACTIVITY_TIME |
| raw_350b60ffd8f… | NETWORK/CONNECTION_OBSE… | — | 14:49:07.382 | **absent** |
| raw_400f46064d6… | NETWORK/CONNECTION_OBSE… | — | 14:49:07.382 | **absent** |
| raw_7666407671d… | NETWORK/CONNECTION_OBSE… | — | 14:49:07.382 | **absent** |

**D9 · `event_time` carries two different meanings.** On 11/13 events (all NETWORK) `canonical.event_time` equals `sensor_observed_at`, not an activity time.

- **8/11** of those now declare `event_time_basis` explicitly, so a consumer can tell *when it happened* from *when we noticed*. Where it is `**absent**` the conflation is still silent (pre-patch events).

## 4 · Latencies — computed ONLY from stamps that genuinely exist

| Event | Cohort | sensor_obs → nivx_recv | nivx_recv → parsed | parsed → normalized | normalized → rule_eval | rule_eval → verdict |
|---|---|---|---|---|---|---|
| raw_baf79c24b33… | POST-PATCH | 1543.3 ms | 132.9 ms | 0.1 ms | 2.5 ms | 6.0 ms |
| raw_e6924584fc4… | POST-PATCH | 1234.8 ms | 125.9 ms | 0.1 ms | 1.4 ms | 1.4 ms |
| raw_3fcdb8372c1… | POST-PATCH | 940.4 ms | 129.2 ms | 0.1 ms | 1.4 ms | 1.2 ms |
| raw_f15ef845d84… | POST-PATCH | 647.1 ms | 127.1 ms | 0.1 ms | 1.3 ms | 1.3 ms |
| raw_e86196ae690… | POST-PATCH | 351.6 ms | 128.5 ms | 0.1 ms | 1.7 ms | 1.4 ms |
| raw_558ffa95b8f… | POST-PATCH | 54.3 ms | 130.7 ms | 0.1 ms | 1.4 ms | 1.3 ms |
| raw_a8bba4048e8… | POST-PATCH | 4154.2 ms | 125.2 ms | 0.1 ms | 1.3 ms | 1.2 ms |
| raw_6b802a42ffb… | POST-PATCH | 3865.2 ms | 125.5 ms | 0.1 ms | 1.4 ms | 1.3 ms |
| raw_2a90520d712… | POST-PATCH | 61.7 ms | 127.6 ms | 0.1 ms | 1.4 ms | 5.8 ms |
| raw_2a38bf701d6… | POST-PATCH | 389.6 ms | 392.9 ms | 0.1 ms | 29.6 ms | 215.6 ms |
| raw_350b60ffd8f… | PRE-PATCH | 464.9 ms | 2.9 ms* | 0.0 ms* | 103.8 ms* | 0.0 ms* |
| raw_400f46064d6… | PRE-PATCH | 252.7 ms | 3.0 ms* | 0.0 ms* | 103.9 ms* | 0.0 ms* |
| raw_7666407671d… | PRE-PATCH | 39.6 ms | 3.5 ms* | 0.0 ms* | 104.2 ms* | 0.0 ms* |

**Genuinely measured stages** (both endpoints are real stamps, no proxy):

- `sensor_observed_at` → `nivx_received_at` — n=13 · min 39.6 ms · median 464.9 ms · max 4154.2 ms
- `nivx_received_at` → `parsed_at` — n=10 · min 125.2 ms · median 128.5 ms · max 392.9 ms
- `parsed_at` → `normalized_at` — n=10 · min 0.1 ms · median 0.1 ms · max 0.1 ms
- `normalized_at` → `rule_evaluated_at` — n=10 · min 1.3 ms · median 1.4 ms · max 29.6 ms
- `rule_evaluated_at` → `verdict_at` — n=10 · min 1.2 ms · median 1.4 ms · max 215.6 ms

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
| Detection | **PASS** | 13/13 | deterministic evaluation recorded with engine id; no-match is a real answer |
| Verdict traceability | **PASS** | 13/13 | `verdict_version` on the derivation, traceable to the raw row |
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
| raw_2a90520d712… | EDR-LNX-002 | nivxray::detection_co… | SUSPICIOUS | inc_0f9b99c50f5b45a78… | /usr/bin/bash | /bin/bash /tmp/tmpaohfuocb.sh | python3.11 |
| raw_2a38bf701d6… | EDR-LNX-002 | nivxray::detection_co… | SUSPICIOUS | inc_0f9b99c50f5b45a78… | /usr/bin/bash | /bin/bash /tmp/tmp2saqit75.sh | python3.11 |

**The observed values above were read back from canonical evidence at report time — they are NOT persisted as part of the match record.** The derivation stores only `rule_id` + engine id + verdict label. Which field matched, and on what value, is not recoverable from storage. Recorded as **D8**.

## 7 · What the sensor said it could NOT see

| Event | Activity | not_observed |
|---|---|---|
| raw_baf79c24b33… | NETWORK/CONNECTION_OBSERV… | — |
| raw_e6924584fc4… | NETWORK/CONNECTION_OBSERV… | — |
| raw_3fcdb8372c1… | NETWORK/CONNECTION_OBSERV… | — |
| raw_f15ef845d84… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_e86196ae690… | NETWORK/CONNECTION_OBSERV… | — |
| raw_558ffa95b8f… | NETWORK/CONNECTION_OBSERV… | — |
| raw_a8bba4048e8… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_6b802a42ffb… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_2a90520d712… | PROCESS/PROCESS_OBSERVED | exit_time, signer, integrity |
| raw_2a38bf701d6… | PROCESS/PROCESS_OBSERVED | exit_time, signer, integrity |
| raw_350b60ffd8f… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_400f46064d6… | NETWORK/CONNECTION_OBSERV… | owning_process |
| raw_7666407671d… | NETWORK/CONNECTION_OBSERV… | owning_process |

This is why `activity_occurred_at` is absent on NETWORK rows and present on PROCESS rows: the sensor reports the limits of its own observation instead of inventing a time.

## 8 · Observation: two canonical identities per activity

Each event carries **two** canonical ids for one real activity:

| Event | Bridge id (`v2_shadow_observations`) | Core id (`xdr_canonical_evidence`) |
|---|---|---|
| raw_baf79c24b33… | cev_baf79c24b33f102679eb66c9_0 | cev_raw_baf79c24b33f102679eb6… |
| raw_e6924584fc4… | cev_e6924584fc42e75e9dec7748_0 | cev_raw_e6924584fc42e75e9dec7… |
| raw_3fcdb8372c1… | cev_3fcdb8372c11821413ae4bb7_0 | cev_raw_3fcdb8372c11821413ae4… |
| raw_f15ef845d84… | cev_f15ef845d8426afb0aa316e7_0 | cev_raw_f15ef845d8426afb0aa31… |
| raw_e86196ae690… | cev_e86196ae6908702c830f5f35_0 | cev_raw_e86196ae6908702c830f5… |
| raw_558ffa95b8f… | cev_558ffa95b8f51bcc2c02a6d4_0 | cev_raw_558ffa95b8f51bcc2c02a… |
| raw_a8bba4048e8… | cev_a8bba4048e87b6a5c1c86a13_0 | cev_raw_a8bba4048e87b6a5c1c86… |
| raw_6b802a42ffb… | cev_6b802a42ffb48690190fa14d_0 | cev_raw_6b802a42ffb48690190fa… |
| raw_2a90520d712… | cev_2a90520d7122e97cd5a78fd9_0 | cev_raw_2a90520d7122e97cd5a78… |
| raw_2a38bf701d6… | cev_2a38bf701d64ee277111978c_0 | cev_raw_2a38bf701d64ee2771119… |
| raw_350b60ffd8f… | cev_350b60ffd8f69fa49129a9aa_0 | cev_raw_350b60ffd8f69fa49129a… |
| raw_400f46064d6… | cev_400f46064d6301db08c10df3_0 | cev_raw_400f46064d6301db08c10… |
| raw_7666407671d… | cev_7666407671d2847aca2d0f42_0 | cev_raw_7666407671d2847aca2d0… |

Both derive deterministically from the same immutable `raw_id`, so this is a **naming/indexing** concern, not evidence duplication — but "the" canonical id for an activity is currently ambiguous.

