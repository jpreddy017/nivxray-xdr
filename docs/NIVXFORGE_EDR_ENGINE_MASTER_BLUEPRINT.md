# NIVXFORGE EDR · ENGINE MASTER BLUEPRINT

WAVE 0 — read-only repository inventory + architecture.
Device Trajectory is FROZEN as a consumer/projection from this point.

Owner directive: engine-first. The UI must never be where missing
intelligence is fabricated.

---

## 0 · THE HEADLINE FINDING

The reason the real endpoint looks less intelligent than the fixture is
**not** missing engines in the repository and **not** a
misunderstanding of Cisco's UI. It is a BROKEN PIPELINE ENTRY:

```
ten_3f7f772b353a6bbbb0ac8bc564  v2_shadow_observations 3299   edr_raw_events 0
ten_f1a5479243e901cf159e230fa0  v2_shadow_observations 3298   edr_raw_events 0
platform-wide                   edr_raw_events with DETECTION_MATCHED = 1456
```

Both acceptance corpora were written DIRECTLY into
`v2_shadow_observations` by re-projection scripts
(`scripts/g1_clean_reprojection.py`), bypassing `edr_raw_events` and
therefore bypassing the detection fabric entirely.

Consequence chain:

```
no raw evidence row
  -> no derivations[]
    -> no DETECTION_MATCHED
      -> trajectory_window attribution = None
        -> assessment_state = NO_DETECTION_CLAIMED_THIS_OBSERVATION
          -> disposition = UNKNOWN_NOT_ASSESSED
            -> no ATT&CK, no IOC, no compromise, no contributors
              -> "No detection engine claimed this observation"
```

`detection_content/library/registry.py` already carries **37 runtime
rules, 23 of them WINDOWS, every one ATT&CK-mapped**, including:

| rule | technique | what it is |
|---|---|---|
| DET-EX-001 | T1059.001 | PowerShell execution |
| DET-EX-002/003 | T1105 | ingress tool transfer / download-execute |
| DET-PS-001 | T1547.001 | **Run-key persistence — exactly what the fixture hand-authored** |
| DET-PS-002 | T1053.005 | scheduled-task persistence |
| DET-PS-003 | T1543.003 | service persistence |
| DET-CR-001/002 | T1003.001/003 | LSASS / SAM credential access |
| DET-DE-001/002/003 | T1562.001, T1070.001 | defence evasion |
| DET-EX-005 | T1218.010 | LOLBin (regsvr32) |
| DET-EX-004 | T1047 | WMI execution |
| DET-CC-001/002 | T1219, T1071.004 | C2 / DNS tunnelling |
| DET-LM-001/002 | T1021.002/006 | lateral movement |
| DET-IM-001/004 | T1490, T1486 | impact / ransomware |

So E3 CONTENT is substantially present. E3 **EXECUTION on the
acceptance corpora is absent.** That single defect accounts for most of
the perceived immaturity gap versus Cisco.

---

## 1 · ENGINE MATRIX

| ENGINE | CURRENT | REUSE | GAP | RISK | PRIORITY | FIRST CHANGE |
|---|---|---|---|---|---|---|
| **E1** Evidence/Identity Authority | PARTIAL → now PASS | `services/edr/device_identity.py`, `services/edr/endpoint_query.py`, `edr_plane/instant.py`, `routers/edr_tenancy.py` | was UNSAFE: hostname aliasing unioned two customers (6,597-row merged read) | **CRITICAL** | P0 | DONE this session — tenant-partitioned evidence predicate, fail-closed |
| **E2** Process/Entity Graph | PARTIAL | `edr_plane/trajectory/relationships.py` (`identity_of`, `process_edges`, activity edges), `projection.py` | projection DROPPED `parent_guid`/`parent_image`/`process_guid`; no PID-reuse model; no process termination family; no SERVICE/TASK/MODULE entities | HIGH | P1 | parent identity now propagated (10 PROCESS_PROCESS edges appeared on real corpus) |
| **E3** Detection | CONTENT PRESENT / **NOT EXECUTED** | `detection_content/library/registry.py` (37 rules, 23 Windows), `edr_plane/fabric/*`, `detection_content/nivxray_native_sigma.py`, `engine_registry.py` | acceptance corpora never entered `edr_raw_events`; no re-evaluation path for already-canonicalised observations | **CRITICAL** | P1 | build an evaluation path that can run the fabric over EXISTING canonical observations |
| **E4** IOC / Reputation | STUB | `detection_content/ioc_watchlist.py` (contract written, 3 namespaces), `services/ice/correlate.py` | no reputation source; corpus carries **0 file SHA-256** (sensor does not hash) — hard telemetry gap | HIGH | P1 | sensor-side hashing + observable extraction, then watchlist binding |
| **E5** Behaviour Correlation | PRIMITIVES ONLY | `edr_plane/trajectory/sequence.py`, `behavior.py`, `detection_content/correlation_library.py` | primitives are never invoked on real telemetry; no stateful window evaluator | HIGH | P1 | drive `sequence.py`/`behavior.py` from E3 output |
| **E6** ATT&CK Attribution | PARTIAL | rule-level `technique_id`/`mitre_attack` on all 37 rules; `attack_posture_normalizer.py` | attribution only exists where a detection fired ⇒ absent because E3 does not run | MEDIUM | P1 | falls out of E3 automatically |
| **E7** Compromise / Contributor | **CONTRACT COMPLETE** | `edr_plane/compromise_contract.py`, `compromise_store.py`, `dt2/compromise.js` | nothing PRODUCES a compromise from real evidence; producer only exists in `scripts/dt2_3c_ioc_fixture.py` | MEDIUM | P1 | wire E3/E4/E5 output into `from_detection_derivation()` |
| **E8** Retrospective | ABSENT | `edr_plane/exclusions/contracts.py`, `capability/inventory.py` mention it only | no retained-evidence re-evaluation, no EVENT_TIME vs RETROSPECTIVE_TIME model | MEDIUM | P1 | after E3/E4 |
| **E9** Response | COMPLETE + HARDENED | `edr_plane/response.py`, `isolation_policy.py`, `routers/edr_response.py` | findings do not feed it | LOW | P1/P2 | integrate only; DO NOT build a second approval authority |
| **E10** Prevention/Policy | STUB | `edr_plane/policy/*`, `edr_plane/exclusions/*` | no endpoint-local enforcement | LOW | P2 | deferred |

DUPLICATE COMPONENTS (do not add an eleventh): `services/mitigation/evidence_driven/rule_library.py` and
`detection_content/library/registry.py` are two rule stores;
`services/behavioral/sysmon_adapter.py` overlaps `edr_plane/windows_eventlog.py`.
Reconcile, do not fork.

---

## 2 · CURRENT CAPABILITIES (evidence-backed, not claimed)

**Sensor / telemetry** — `edr_plane/windows_eventlog.py::SUPPORTED`, 8 families:
Sysmon 1 PROCESS, 3 NETWORK, 11 FILE, 12/13 REGISTRY, 22 DNS; Security
4688 PROCESS, 4624 AUTH. Real corpus: 3,299 observations, 15:43–16:46 UTC.
ABSENT: kernel/driver telemetry, ETW breadth, process TERMINATION
(Sysmon 5), file hashing, signer/integrity, module loads, WMI, memory.

**Evidence** — canonical observations with `observation_id`
(UNIQUE_BY_SOURCE_RECORD_IDENTITY), RFC 3339 on new writes, parsed-instant
comparison (`edr_plane/instant.py`), provenance chain, idempotent replay.

**Graph** — 42 process nodes, 82 activity nodes, 92 edges on the real
corpus over its full hour: 74 PROCESS_FILE, 10 PROCESS_PROCESS, 7
PROCESS_NETWORK, 1 PROCESS_DNS. Bases: `CANONICAL_ACTOR_PROCESS_BINDING`,
`CANONICAL_PARENT_PROCESS_IDENTITY`, `SYSMON_PARENT_PROCESS_GUID`.

**Detection on real corpus** — 0. **IOC** — 0. **ATT&CK** — 0.
**Compromise** — `NO_AUTHORITATIVE_COMPROMISE_OBSERVED`. All honest.

---

## 3 · E1 ACCEPTANCE GATE — RESULT

| gate | result | proof |
|---|---|---|
| TENANT_AUTHORITY | **PASS** | Tenant Authority closed earlier; `edr_tenant()` authorises before registry lookup |
| ENDPOINT_AUTHORITY | **PASS** | `TENANT_PARTITIONED_STORES` + `$and[tenant, identity]` predicate |
| SAME_HOSTNAME_CROSS_TENANT | **PASS** | `DESKTOP-A9HGFJJ` → tenant A 3,298 / tenant B 3,299; never 6,597 |
| CROSS_TENANT_ENDPOINT_REFUSAL | **PASS** | `dev_2adbb41a04a4` under tenant B → `ENDPOINT_NOT_RESOLVED` (opaque) |
| DESKTOP_A9HGFJJ_ALIAS | **PASS** | unscoped predicate 6,597 → scoped 3,298/3,299; tenantless → 0 |
| OBSERVATION_IDENTITY | **PASS** | 3,299 unique `observation_id` over 1,049 distinct content iids |
| REPLAY_IDEMPOTENCY | **PASS** | pass-2 re-projection wrote 0 |
| TIMESTAMP_CORRECTNESS | **PASS** | X = 8.333 px/s pure linear; `?from/?to` = exactly 120,000 ms |
| SOURCE_PROVENANCE | **PASS** | `provenance.source = v2_shadow_observations`, authoritative chain declared |
| TRAJECTORY_ENDPOINT_ISOLATION | **PASS** | projection cache key now includes tenant |
| NO_DEFAULT_TENANT | **PASS** | missing tenant ⇒ `_nivx_unresolved_tenant`, never a read |
| NO_HOSTNAME_AUTHORITY | **PASS** | hostname is an ALIAS inside the tenant clause, never the authority |
| NO_EVIDENCE_FABRICATION | **PASS** | 2 fabrications REMOVED this session (see §4) |

**E1 = PASS.**

---

## 4 · FABRICATIONS REMOVED THIS SESSION

1. **Navigator false compromises.** `_activity()` counted a marker from
   the per-observation `compromise_authority` classification
   (`MITRE_ATTRIBUTED_EVIDENCE`). The clean corpus reported **70
   navigator compromise events** for an endpoint whose contract state is
   `NO_AUTHORITATIVE_COMPROMISE_OBSERVED`, while the fixture that really
   holds one reported 0. Replaced by `_mark_compromises()`, which reads
   the contract-validated compromise store and nothing else. Marker and
   contract can no longer disagree.
2. **False malicious rows.** `isRed()` painted red off a bare
   `is_detection` flag; on the historical corpus 480/500 observations
   carry `kind=detection` + `UNKNOWN_NOT_ASSESSED`, so ordinary Sysmon
   telemetry rendered malicious. Now requires
   `ASSESSED_BY_DETECTION_FABRIC` or a MALICIOUS disposition.
3. **Red ATT&CK box on unattributed events** — now neutral when nothing
   is attributed.

---

## 5 · ORDERED IMPLEMENTATION PLAN

**WAVE 1 · E1 — DONE, PASS.** (this session)

**WAVE 2 · E2 Process/Entity Graph — NEXT**
1. PID-reuse-safe process identity (boot/session context), retire the PID surrogate.
2. Ingest Sysmon 5 so process termination becomes real; keep
   `OBSERVED_EVIDENCE_SPAN` distinct from `PROCESS_LIFETIME`.
3. Entities: SERVICE, TASK, MODULE, SCRIPT, USER/AUTH where telemetry allows.
4. Store `process_guid`/`parent_process_guid` on the observation at
   ingest instead of re-deriving per read.

**WAVE 3 · E3 Detection — the biggest single win**
1. **P0: an evaluation path over EXISTING canonical observations.** The
   fabric today only runs at ingest via `edr_raw_events`. Without this,
   every re-projected corpus is permanently undetectable.
2. Bind the 23 Windows rules to the Windows canonical dialect and prove
   each fires on real `DESKTOP-A9HGFJJ` evidence or state why not.
3. Rule registry/versioning/enable-disable/tenant applicability,
   evidence + entity binding, engine_version on every detection.
4. Reconcile the two rule stores.

**WAVE 4 · E4 IOC/Reputation** — sensor-side SHA-256 first (0 hashes
today), then observable extraction, then `ioc_watchlist` binding.
UNKNOWN ≠ BENIGN.

**WAVE 5–8** · E5 correlation (drive the existing `sequence.py`/
`behavior.py`), E6 ATT&CK (falls out of E3), E7 compromise producer
(wire into `from_detection_derivation`), E8 retrospection.

**WAVE 9–10** · E9 integrate only. E10 deferred.

---

## 6 · DEVICE TRAJECTORY FREEZE

FROZEN at DT2-3c REV 2. Fix only security, evidence-integrity, engine
integration and critical usability. No visual redesign.

Preserved contracts the engines must feed: X = authoritative time;
Y = trajectory row; `OBSERVED_EVIDENCE_SPAN`; zero-span = point;
no invented termination; evidence-only edges;
`frontend_may_infer_contributors = false`; contributor identity =
`observation_id`; absence ≠ clean.

## 7 · NEGATIVE EXPLAINABILITY (product invariant)

`NO DETECTION OBSERVED` ≠ benign · `NO TERMINATION EVIDENCE` ≠ running ·
`NO IOC MATCH` ≠ safe · `NO COMPROMISE RECORD` ≠ clean ·
`NO PARENT EDGE` ⇒ never infer a parent.

## 8 · CISCO REFERENCE CLASSIFICATION

DOCUMENTED: trajectory semantics, navigator (C12 p.171), IOC/compromise
+ blue halo (C13 p.405), file types (TAC 118711), repeat-event cache.
PUBLICLY OBSERVED: dark operational console, Activity/Activity Details
master-detail, search reduction (owner captures, 2026-09-06).
NIVXFORGE DESIGN DECISION: the removed full-height yellow IOC column;
the dedicated Compromise band; the zoom ladder.
NOT VERIFIED: cloud-query line graph (no NivXForge data source).
No proprietary Cisco internals claimed, no Cisco code or assets used.
