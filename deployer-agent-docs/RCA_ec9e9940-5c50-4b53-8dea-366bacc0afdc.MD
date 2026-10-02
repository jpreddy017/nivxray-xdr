# Device Trajectory Evidence Baseline — READ-ONLY measurement

**Target:** deployment `greeting-app-5782` (Publish 100), run `ec9e9940`, DB `greeting-app-5782-test_database`.
**Endpoint of interest:** hostname **KUSHU**, `endpoint_id = ep_a67be48d5b4e01d4d9e8`, `tenant_id = ten_e759b7288598bd882e3dcac49d`.
**Excluded entirely:** DESKTOP-A9HGFJJ (`ep_1989031c8c1d0085812f`). It appears in the same tenant; wherever a collection is tenant-scoped with no endpoint field, I say so rather than attributing its rows to KUSHU.
All operations were find/count/distinct with projections. No writes, no host access, no credential material displayed, backlog only measured.

---

## A. Endpoint record — collection `edr_endpoints`, key `endpoint_id`
(credential material projected OUT; no agent_credential/token/secret/hash/digest/salt read)

| field | value |
|---|---|
| endpoint_id | ep_a67be48d5b4e01d4d9e8 |
| hostname | KUSHU |
| tenant_id | ten_e759b7288598bd882e3dcac49d |
| sensor_version | 0.3.0-windows |
| enrollment_state | ENROLLED |
| credential_state | ACTIVE |
| sensor_state | REPORTING |
| last_telemetry_at | 2026-10-02T13:47:55.118424+00:00 |
| last_heartbeat_at | 2026-10-02T13:47:55.741275+00:00 |
| report_interval_seconds | 30 |
| event_count | **2683** |
| outbox_queue_depth | **249455** |

Note: the earlier `event_count=61` snapshot is stale — current value is 2683, and the sensor is REPORTING. The on-host outbox is still very deep (249,455), i.e. the host has a large un-shipped backlog on top of what has been ingested.

---

## B. Raw evidence volume — collection `edr_raw_events`
Filter field: both `endpoint_ref` and `source` are populated and identical for this endpoint (each returns 131,750). I used **`endpoint_ref`** + `tenant_id`.

- Total documents: **131,750**
- With `processing_contract == "durable_queue_v1"`: **130,500** (the remaining 1,250 — the oldest rows — carry no `processing_contract` field, i.e. predate that contract)
- ingest_time — oldest: **2026-10-01T09:54:59.592921+00:00**, newest: **2026-10-02T13:47:55.071240+00:00**
- **Observation time — NOT directly queryable on this collection.** Top-level `event_time` is **null for 100%** of this endpoint's raw rows (count of `event_time != null` = 0). The observation timestamp exists only INSIDE the `payload` JSON string (`observed_at`, and the Sysmon `UtcTime`/`TimeCreated` in the embedded XML). With find/count/distinct only (no aggregate, string payload) a true min/max across 131,750 payloads cannot be computed. The queryable observation time lives on the canonical collection (see below).
- Observation window from `xdr_canonical_evidence.event_time` (the processed subset, 17,721 rows): oldest **2026-09-29T04:16:54Z**, newest **2026-10-01T09:59:36Z**.
- **Backlog replay still visible: YES.** Newest ingest_time (2026-10-02 13:47) is ~28h newer than the newest observation time (2026-10-01 09:59). ingest_time ≫ observation time → replay ongoing.

---

## C. Processing queue — collection `edr_processing_queue`
**Important limitation:** this collection carries only `raw_id` + `tenant_id` + `state`/timestamps — **no endpoint field.** A per-endpoint breakdown is NOT derivable from it directly (would require resolving each `raw_id` back to `edr_raw_events.endpoint_ref`). Counts below are **tenant-level** and therefore include the excluded host DESKTOP-A9HGFJJ; they cannot be attributed purely to KUSHU.

Counts by state (tenant `ten_e759b7288598bd882e3dcac49d`):
| state | count |
|---|---|
| PENDING | 76,358 |
| PROCESSING | 1 |
| DONE | 54,191 |
| RETRY | 0 |
| **total** | **130,550** |

- Oldest PENDING `created_at`: **2026-10-02T07:40:30.428Z**
- Draining assessment: **not draining meaningfully.** 76,358 PENDING vs 54,191 DONE, only 1 PROCESSING (worker_count=1). The queue is still ~58% pending.

---

## D. Evidence TYPE availability — collection `xdr_canonical_evidence`
Filter: `host.host_id = ep_a67be48d5b4e01d4d9e8` + `tenant_id`. Category derived from `additional_fields.winlog.event_id` (the Sysmon EventID). Total canonical evidence for KUSHU = **17,721**.

| category | Sysmon EventID | count |
|---|---|---|
| process create | 1 | **69** |
| file create | 11 | **239** |
| registry (create/setvalue/rename) | 12 / 13 / 14 | **15,983 / 591 / 0** → **16,574 total** |
| network connect | 3 | **360** |
| DNS query | 22 | **4** |
| process terminate | 5 | **66** |
| image load | 7 | **0** |
| driver load | 6 | **0** |

(Typed EventIDs above sum to 17,312; the remaining ~409 are other event types e.g. `logon_success`, winsec 5379, etc.)

Process-lineage viability (EventID 1, n=69):
- with non-empty `process.command_line`: **69 / 69 (100%)**
- with `process.parent_process_guid`: **69 / 69 (100%)**

→ Evidence-backed process lineage IS possible, but only across **69** process-create events. Registry (EventID 12) dominates the dataset. Image/driver load (6/7) are absent.

---

## E. Detection / ATT&CK availability
- `edr_findings`: **0** (entire collection empty; also 0 filtered to this endpoint) → **no detection/finding records.**
- `edr_finding_evaluations` (endpoint-scoped via `endpoint_ref`): **55,432** evaluations for KUSHU, but states are only `EVALUATED_NO_FINDING` and `NOT_EVALUATED`; rows with a non-empty `finding_ids` = **0**. So evaluations ran, none produced a finding.
- `xdr_correlation_matches`: 0 · `xdr_multi_evidence_incidents`: 0 · `correlations`: 0 (all tenant-scoped).
- **MITRE/ATT&CK attribution records: 0.** No findings exist, so no `findings.attck` / `event.mitre` / `mitre_basis` attribution is attached to any of this tenant's evidence. No example can be given — there is no end-to-end attribution trace to produce.

---

## F. Retired ATT&CK v19.2 techniques in stored evidence
Because this tenant has **zero** findings and **zero** ATT&CK-attributed evidence/correlation records, **none** of the 16 retired technique ids (T1070.001, T1070.002, T1562[.001–.012], T1574.002, T1656) appear in any stored ATT&CK attribution for this tenant. Record count for each = **0**. An ATT&CK catalogue upgrade would therefore have **no effect on historical evidence display** for this tenant — there is no stored technique attribution to re-map.

---

## Bottom line for the Device Trajectory UI validation
- The sensor is live and ingesting (131,750 raw rows), but the pipeline is mid-replay: ingest is ~28h ahead of observation time, and the processing queue is ~58% PENDING with a single worker — canonical evidence (17,721) is a partial, lagging view that will keep growing.
- Trajectory content is overwhelmingly **registry** (16,574) and **network** (360); **process-create is only 69 events** (all with CommandLine + ParentProcessGuid, so lineage is sound but sparse). DNS=4, terminate=66, image/driver load=0.
- There is **no detection or ATT&CK layer at all** for this endpoint/tenant — any trajectory UI element that expects findings or MITRE technique badges will have nothing to render from real data here.
- Observation time is NOT stored queryably on `edr_raw_events` (event_time null; only inside payload) — any UI/analytics relying on a top-level raw observation timestamp must read it from `xdr_canonical_evidence.event_time` instead.
