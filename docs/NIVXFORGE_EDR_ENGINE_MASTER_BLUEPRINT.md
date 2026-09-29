# NIVXFORGE EDR · ENGINE MASTER BLUEPRINT

WAVE 0 — read-only repository inventory + architecture.
Device Trajectory is FROZEN as a consumer/projection from this point.

Owner directive: engine-first. The UI must never be where missing
intelligence is fabricated.

---

## 0 · THE HEADLINE FINDING (CORRECTED BY MEASUREMENT)

The first reading of this was "the corpus bypassed detection". Measuring
it properly gave a sharper and different answer.

**What is actually true**

| measurement | result |
|---|---|
| `xdr_canonical_evidence` for `ten_f1a5…` (DESKTOP-A9HGFJJ) | **3,299 rows**, fully normalised, with Sysmon `process_guid` + field provenance |
| `edr_raw_events` for that tenant | 0 — it arrived via `POST /api/xdr/ingest/telemetry` (XDR plane), not the EDR endpoint plane |
| `xdr_detection_matches` / `edr_findings` / `edr_finding_evaluations` | **0 / 0 / 0** |
| `evaluate_detection()` run over all 3,299 rows | **3,299 × `RULE_NO_MATCH`, zero errors** |
| rows carrying ANY command line | **16 of 3,299** |
| interpreter / LOLBin process rows | **0** |
| top processes | svchost.exe 2,615 · hpsvcsscan 137 · msedgewebview2 95 · audiodg 91 · chrome 80 |

**Positive control — do the rules bind to the canonical dialect?**

| authored canonical evidence that SHOULD fire | result |
|---|---|
| encoded PowerShell | **FIRED** DET-EX-001 / T1059.001 |
| regsvr32 LOLBin | **FIRED** DET-EX-005 / T1218.010 |
| Run-key persistence | **FIRED** DET-PS-001 / T1547.001 |
| WMI exec | **FIRED** DET-EX-004 / T1047 |
| IEX download-execute | did not fire — **E3 content gap** |
| LSASS credential access | did not fire — **E3 content gap** |

**Conclusion.** The detection authority executes correctly and the rules
bind correctly.

**CORRECTED CLAIM (owner ruling, 2026-09-29).** An earlier version of
this document said "Cisco on the same machine would also show no
detections". That is NOT establishable from this corpus and is
withdrawn. The defensible statement is:

> NivXForge's CURRENTLY AVAILABLE TELEMETRY and CURRENTLY IMPLEMENTED
> RULES produced no detections for this corpus.

Cisco Secure Endpoint has file intelligence, cloud reputation,
behavioural engines, retrospection and endpoint capabilities this sensor
does not have, so no conclusion may be drawn about what Cisco would
report. `RULE_NO_MATCH × 3,299` is correct FOR THE EVIDENCE AND CONTENT
WE HAVE — it is not a verdict that the endpoint was clean.

The real defect was the platform's own negative-explainability
invariant being violated: nothing recorded that the evidence HAD been
evaluated, so no surface could tell

    EVALUATED AND NOTHING MATCHED   from   NOBODY HAS LOOKED YET

and silence reads as benign. Three genuine gaps remain, in this order:

1. **the evaluation record** (fixed — E3 Detection Replay, §1a);
2. **sensor starvation** — 16/3,299 rows carry a command line, so the
   content-based rules have almost nothing to read. This is a SENSOR
   gap, and it is the single biggest limiter on real-world detection;
3. **two proven rule-content gaps** (T1105 download-execute, T1003
   credential access).

`detection_content/library/registry.py` holds **37 rules, 23 Windows,
all ATT&CK-mapped**: DET-EX-001 T1059.001, DET-EX-002/003 T1105,
DET-PS-001 T1547.001, DET-PS-002 T1053.005, DET-PS-003 T1543.003,
DET-CR-001/002 T1003.001/003, DET-DE-001/002/003, DET-EX-004 T1047,
DET-EX-005 T1218.010, DET-CC-001/002, DET-LM-001/002, DET-IM-001/004.

---

## 1a · WAVE 3 / E3 · DETECTION REPLAY — IMPLEMENTED

`edr_plane/detection_replay.py`, route
`POST /api/edr/endpoints/{endpoint_id}/detection-replay?apply=false`.

**It is not a second detection engine.** The verdict comes from
`detection_content.xdr_pipeline.evaluate_detection` — the identical
function `process_event_through_pipeline` calls at its detection stage —
and durability from `record_endpoint_detection`, the identical function
live ingest calls. Replay defines no rule, no predicate, no threshold
and no match shape, so live and replayed verdicts cannot diverge. A
structural test asserts this.

* enters at the DETECTION stage over already-canonical evidence, so it
  cannot re-run DSM/parser/normalizer and cannot mint a duplicate
  canonical row or a second evidence identity;
* writes no `edr_raw_events` — fabricating a raw row would claim sensor
  bytes arrived at an instant they did not;
* `apply=false` is the DEFAULT: evaluates, reports, writes nothing;
* `xdr_canonical_evidence` is now a DECLARED tenant-partitioned
  endpoint-keyed store, so E1 governs the read and an unresolved
  customer reads nothing;
* time model: `observed_at` = the endpoint instant, NEVER touched;
  `derived_at`/`evaluated_at` = when the verdict was produced. This is
  the retrospective two-instant contract, established here for E8.

**Results**

| corpus | evaluated | matched | rules fired |
|---|---|---|---|
| real Windows `DESKTOP-A9HGFJJ` | 3,299 | 0 | — (genuinely benign) |
| deterministic IOC fixture | 6 | **4** | DET-EX-001 ×4, DET-PS-001 ×2 |
| same hostname, other tenant | **0** | — | tenant-isolated |
| no tenant resolved | **0** | — | `TENANT_NOT_RESOLVED_FOR_REPLAY` |

**Read-path unification.** `assessment_state` now carries three
distinct facts instead of two — `ASSESSED_BY_DETECTION_FABRIC`,
`EVALUATED_NO_DETECTION`, `NOT_EVALUATED` (plus
`EVALUATION_SUPPRESSED_BY_EXCLUSION`, `EVALUATION_FAILED`) — each with a
stated `evaluation_meaning`. `NO_DETECTION_CLAIMED_THIS_OBSERVATION` was
RETIRED: it read as "evaluated and nothing claimed it", which is the
exact ambiguity being fixed.

**E6 boundary enforced.** `mitre_basis` distinguishes
`RULE_DECLARED_BY_MATCHED_DETECTION` from
`SOURCE_NORMALIZER_TAG_NOT_VALIDATED_DETECTION` and `NOT_ATTRIBUTED`. A
technique is presented as a claim ONLY when the matched rule declared
it; the normalizer's `event.mitre` tag is never promoted.

**Fixture dependency REVERSED.** `scripts/dt2_3c_ioc_fixture.py` now
authors TELEMETRY only (canonical evidence + command lines + parentage).
It no longer writes a detection derivation or a technique list. The
engine produces the detection at replay time, and the compromise is
built from THAT real finding: techniques are the ones the matched rules
declared, contributors are the exact observations those rules cited.

---

## 1 · ENGINE MATRIX

| ENGINE | CURRENT | REUSE | GAP | RISK | PRIORITY | FIRST CHANGE |
|---|---|---|---|---|---|---|
| **E1** Evidence/Identity Authority | PARTIAL → now PASS | `services/edr/device_identity.py`, `services/edr/endpoint_query.py`, `edr_plane/instant.py`, `routers/edr_tenancy.py` | was UNSAFE: hostname aliasing unioned two customers (6,597-row merged read) | **CRITICAL** | P0 | DONE this session — tenant-partitioned evidence predicate, fail-closed |
| **E2** Process/Entity Graph | PARTIAL | `edr_plane/trajectory/relationships.py` (`identity_of`, `process_edges`, activity edges), `projection.py` | projection DROPPED `parent_guid`/`parent_image`/`process_guid`; no PID-reuse model; no process termination family; no SERVICE/TASK/MODULE entities | HIGH | P1 | parent identity now propagated (10 PROCESS_PROCESS edges appeared on real corpus) |
| **E3** Detection | **REPLAY DONE** · content PARTIAL | `detection_content/library/registry.py` (37 rules, 23 Windows), `edr_plane/detection_replay.py`, `edr_plane/fabric/*` | 2 proven content gaps (T1105 download-execute, T1003 credential access); rules are content-based but only 16/3,299 real rows carry a command line | HIGH | P1 | close the 2 rule gaps; then E4 |
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

**WAVE 1 · E1 — DONE, PASS.**
**WAVE 3 · E3 Detection Replay — DONE (§1a).**

**WAVE 2 · E2 Process/Entity Graph — NEXT**
1. PID-reuse-safe process identity (boot/session context), retire the PID surrogate.
2. Ingest Sysmon 5 so process termination becomes real; keep
   `OBSERVED_EVIDENCE_SPAN` distinct from `PROCESS_LIFETIME`.
3. Entities: SERVICE, TASK, MODULE, SCRIPT, USER/AUTH where telemetry allows.
4. Store `process_guid`/`parent_process_guid` on the observation at
   ingest instead of re-deriving per read.

**WAVE 3 · E3 Detection — replay DONE; content work remaining**
1. ~~an evaluation path over existing canonical observations~~ DONE.
2. Close the 2 rule gaps proven by positive control: T1105
   download-execute (DET-EX-002/003 did not fire on IEX/DownloadString)
   and T1003 credential access (DET-CR-001 did not fire on the
   `comsvcs.dll MiniDump` pattern).
3. **SENSOR: collect command lines for every process event.** 16 of
   3,299 real rows carry one, which starves every content rule. This is
   the single biggest limiter on real-world detection and it belongs to
   the sensor, not to the rules.
4. Rule enable/disable + tenant applicability; reconcile the two rule
   stores (`services/mitigation/evidence_driven/rule_library.py` vs
   `detection_content/library/registry.py`).
5. Re-projection gap: `scripts/g1_clean_reprojection.py` wrote only the
   CEM shadow store, so the clean corpus `dev_f4b3fb82d7f3` has NO
   canonical evidence and replay honestly evaluates 0 there.

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

---

## 9 · CURRENT ENGINE ASSESSMENT (owner-required form, 2026-09-29)

| engine | assessment |
|---|---|
| **E1** Evidence / Identity Authority | **PASS**, subject to continued regression protection (32 isolation tests + a structural guard that no query site may read a partitioned store without a tenant). |
| **E2** Process Graph | **PARTIAL.** ProcessGuid, ParentProcessGuid, PID, PPID, Image, ParentImage all reach canonical evidence with field provenance, and 10 PROCESS_PROCESS / 74 PROCESS_FILE / 7 PROCESS_NETWORK / 1 PROCESS_DNS edges are derived on the real corpus. Missing: PID-reuse handling, Sysmon 5 termination, `PROCESS_START_OBSERVED` / `PROCESS_TERMINATION_OBSERVED` / `PROCESS_LIFETIME_UNKNOWN` as explicit states, SERVICE/TASK/MODULE entities. |
| **E3** Detection | **FRAMEWORK OPERATIONAL. CONTENT COVERAGE INCOMPLETE. REAL CORPUS EVALUATED WITH NO MATCHES.** Replay runs the live evaluator over stored canonical evidence; 3,299/3,299 evaluated, 0 matched; measured coverage 22 SUPPORTED / 14 NOT_APPLICABLE / 1 PARTIAL / 0 dead rules. |
| **E4** IOC / Reputation | **PARTIAL FOUNDATION. PROCESS-IMAGE SHA-256 EXISTS** (16/16 process_create rows, MD5 + SHA-256, with `sysmon:EventData.Hashes` provenance). **FILE-CREATE HASH COVERAGE + REPUTATION MISSING** — 107 `file_create` rows carry no hash, and there is no reputation source or provider/adapter interface. |
| **E5** Behaviour Correlation | **PARTIAL / NOT OPERATIONALLY WIRED** — verified from code: `edr_plane/trajectory/sequence.py`, `behavior.py` and `detection_content/correlation_library.py` exist and are unit-tested, but nothing invokes them over real canonical evidence and no stateful window evaluator exists. |
| **E6** ATT&CK Attribution | **PARTIAL.** Technique mappings exist on all 37 rules and now reach the surface only via a matched finding (`mitre_basis = RULE_DECLARED_BY_MATCHED_DETECTION`). **Tactic attribution incomplete**: rules declare a tactic NAME, not a TA id, so Activity Details correctly reads "Tactics: not attributed". No mapping was invented. |
| **E7** Compromise / Contributor | **Contract exists; real compromise production still incomplete.** Proven end-to-end on authored telemetry (engine detection → techniques from the matched rules → 4 rule-cited contributors → compromise), but there is no producer that runs over real evidence. |
| **E8** Retrospective | **ABSENT / NOT COMPLETE.** Its time model is now in place (`observed_at` never touched, `derived_at` = evaluation instant) but no intelligence-change-triggered re-evaluation exists. |
| **E9** Response | COMPLETE + HARDENED; findings do not feed it yet. |
| **E10** Prevention | STUB. Server-side detection is NOT prevention. |

### Standing correction
Do **not** state that Cisco would have produced no detection on this
endpoint. We have no equivalent Cisco endpoint/cloud telemetry or
engines with which to prove it. The correct statement is:

> NivXForge's currently collected evidence and currently implemented
> detection content produced no detections for this corpus.

### Companion documents
* `docs/E3_DETECTION_COVERAGE_MATRIX.md` / `.json` — regenerate with
  `python3 backend/scripts/e3_coverage_matrix.py`
* `docs/WAVE_A_WINDOWS_TELEMETRY_TRACE_AND_RUNBOOK.md` — the measured
  telemetry trace, the owner runbook, and every retraction
