# DT2-0 IMPLEMENTATION REPORT — Device Trajectory V2 contract

**1 · Executive result — PASS.** The DT2-0 first-class contract is implemented,
validated and wired additively into the existing trajectory route. 45 new
focused tests plus a 148-test focused regression are green, a live read-only
check against a 232 k-observation device returns a populated V2 contract with
the V1 surface byte-intact, and cross-tenant access is refused. No deployment,
no DB write, no migration, no sensor change, no detection-semantics change, no
response-authority change. DT2-1 not started.

**2 · Repository / branch / HEAD** — `feature/rc2-alignment`, pre-change HEAD
`f1dcb454f81060cf51e737c4d56305abff0df19a`, authoritative writable workspace
(platform-managed remote; push is owner-initiated).

**3 · Pre-change workspace state** — clean under `backend/`, `apps/`,
`.github/`; only untracked `memory/availability_probe.log`. Phase A and Phase B
documents present and read in full; source inspected directly and treated as
authoritative over documentation.

**4-5 · Public research + classification** — see
`DEVICE_TRAJECTORY_V2_PUBLIC_REFERENCE_ADDENDUM.md`: 5 public Cisco source
categories (User Guide, TAC articles, security blog, Cisco Live public deck,
DevNet API material), 22 capabilities classified
[DOCUMENTED] / [INFERRED — NOT VERIFIED] / [NIVXFORGE]. **No third-party source
code obtained or incorporated → REFERENCE ONLY.** Nothing decompiled, no access
control bypassed.

**6 · Phase-B reconciliation** — architecture stands; one refinement adopted
(Activity-vs-Behavioral telemetry ⇒ explicit Observation-vs-DetectionMarker
authority separation). Four reference behaviours remain NOT VERIFIED and are
implemented as labelled NivXForge decisions. **REPLACE: none.**

**7 · Owner decisions recorded and implemented**

| Decision | Implementation |
|---|---|
| Retention truth wins | `requested_range` / `effective_range` / `available_range` / `retention_boundary{state: UNKNOWN}` are four separate fields; no NOT_COLLECTED is synthesised for a short retention (test: `test_retention_is_never_manufactured_as_not_collected`) |
| Show unattributed artifacts | `ArtifactInstance.attribution_state = UNATTRIBUTED`, artifact still emitted, observation still emitted (test: `..._kept_as_unattributed`) |
| 4624 without process binding | AUTH observation on its own lane, `relationships == []` (test: `test_auth_without_a_process_binding_gets_no_process_edge`) |
| Inspector width per-session | no schema, no migration, no preference service in DT2-0 (nothing persisted) |
| DETECTION→PROCESS only when authoritative | edge emitted only when the detection row carries a process instance; `DetectionMarker` rejects a process binding without a stated authority (2 tests) |

**8 · Files changed**

```
NEW  backend/edr_plane/trajectory/__init__.py          19 L
NEW  backend/edr_plane/trajectory/models.py           ~430 L   13 contract objects + validation
NEW  backend/edr_plane/trajectory/contract.py         ~420 L   read-only adapters + augment()
NEW  backend/tests/edr/test_dt2_0_trajectory_contract.py  45 tests
EDIT backend/routers/edr.py                           +18/-1   import, `raw_event_id` query param, additive `dt2` key
```

**9 · APIs / contracts changed** — `GET /api/edr/endpoints/{id}/trajectory`
gains **one additive response key `dt2`** and **one optional query parameter
`raw_event_id`** (focus target). Classification: **ADDITIVE**. No key renamed,
removed or retyped. No other route touched.

**10-21 · Domain model** — `TrajectoryWindow`, `Observation`, `Relationship`,
`DetectionMarker`, `DensityBucket`, `CoverageInterval`, `FocusTarget`,
`FocusResolution`, `ProcessInstance`, `ArtifactInstance`,
`EvidenceReference`, `TrajectoryCursor`, `TrajectoryAxis` — all typed
dataclasses with constructor-time validation.

*Observation*: five time stamps preserved, `time_basis` =
`SOURCE_TIME_THEN_OBSERVED_TIME`, `activity_class ∈ {PROCESS, FILE, NETWORK,
REGISTRY, DNS, AUTHENTICATION}` or **None** for unsupported families,
`support_state`, `evaluation_state`, `parser_state`, `attribution_state`, raw +
canonical evidence refs.

*Process identity*: `AUTHORITATIVE` (Sysmon ProcessGuid) → `DERIVED`
(computer:pid:image, no guid — the 4688 case) → `UNSTABLE` (pid only, never
presented as identity). Claiming AUTHORITATIVE without a guid raises.
`end_time` without `exit_observed` raises — **no invented termination**.

*Artifact identity*: independent of process; FILE keyed on observed sha256
(AUTHORITATIVE) else path (DERIVED); REGISTRY key, DNS query, NETWORK
destination, AUTH user; missing properties are omitted, never fabricated.
Reusable for a future artifact-centric File Trajectory.

*Relationship*: 8 types; requires source, target, non-empty `evidence_ref`,
and a `derivation_basis` from `{SYSMON_PARENT_PROCESS_GUID,
CANONICAL_PARENT_PROCESS_IDENTITY, CANONICAL_ACTOR_PROCESS_BINDING,
DETECTION_EVIDENCE_REFERENCE}`. `FORBIDDEN_BASES` (temporal/timestamp
proximity, display/visual adjacency, same username, same filename, loose pid
match, guess) are **rejected at construction**. No binding ⇒ no edge.

*DetectionMarker*: separate object, never mutates an Observation;
`evaluation_state`, engine + version, rule id, severity, `mitre` with
`mitre_authority = DERIVED`, contributing `observation_ids`, optional
`process_iid` with a mandatory binding authority.

*Density*: `{start, end, stream, count, semantics:
NAVIGATION_ONLY_NOT_SEVERITY}` — **no severity/risk/score field exists**;
per-stream (`events` + activity class + `detection` separately).

*Coverage*: 7 states; `NOT_COLLECTED / NOT_CANONICALIZED / PARSE_FAILURE /
EVALUATION_FAILED` cannot be constructed without `proof_ref`;
`absence_inferable` may be true only for `NOT_OBSERVED`; unprovable spans emit
`UNKNOWN` with `boundary_certainty: UNKNOWN`.

*Focus*: 6 target kinds, 4 states; `FOCUS_RESOLVED` must name what it resolved
(else raises) — **no silent generic fallback**; timestamp-only focus is
explicitly flagged `timestamp_only: true`.

*Cursor/window/axis*: V1 opaque `(timestamp, event_iid)` cursor retained and
validated; axis declares `ENDPOINT_INVARIANT` vs `FILTER_SCOPED` with
`order: LINEAGE_DEPTH_FIRST_PREORDER` and a `collapsed_lane_ids` slot for
DT2-3.

*Availability vocabulary*: `AVAILABLE / EMPTY / UNAVAILABLE / NOT_EVALUATED /
UNKNOWN` — so **unavailable is never reported as empty**;
`process_end_evidence`, `signer_evidence`, `module_load_evidence` are reported
`UNAVAILABLE` today.

**22 · Unsupported events** — `parser_state ∈ {UNSUPPORTED,
WINDOWS_EVENT_ID_NOT_SUPPORTED}` ⇒ `activity_class: None`,
`support_state: NOT_CANONICALIZED`, raw ref preserved, zero relationships, and
a `NOT_CANONICALIZED` coverage interval with the raw event as proof. Verified
for the Security 5379/4798 shape.

**23-26 · Semantics** — retention, unattributed, AUTH-without-process and
detection-relationship semantics are exactly the owner decisions in §7, each
with a test.

**27 · Tenant / security** — the contract layer is pure: it receives the
already tenant-scoped V1 projection and performs no query. Route authority
unchanged (`get_current_user` + `edr_tenant`, server-side scope). Live check: a
foreign `X-Tenant-Id` returns **403** with no rows. `endpoint_id` is stamped on
every emitted object, so cross-endpoint binding is detectable by construction.

**28 · Backward compatibility — PASS.** Additive only. `test_v1_keys_are_
untouched_and_dt2_is_purely_additive` asserts the events list is the *same
object*, every V1 key is unchanged, and the only new key is `dt2`. Live check
confirms `events`, `lane_axis`, `projection`, `time_range`,
`epistemic_state`, `computer` all still present. The route also wraps the
contract in a guard: a V2 failure degrades to
`dt2.state = DT2_CONTRACT_UNAVAILABLE` and **never takes the V1 surface down**.

**29 · Performance implications** — one pass over the already-fetched window
rows (O(rows)); no extra query, no extra round trip, no fetch-all API
introduced; cursor/window/prefetch semantics untouched. Density is aggregated
server-side into ≤48 buckets per stream instead of shipping raw rows.
Contract adds payload proportional to the window, not to retention.

**30-31 · Tests added and results**

```
tests/edr/test_dt2_0_trajectory_contract.py            45 passed
focused regression (dt2 + windows projection + hermeticity +
detection handoff + process tree + fabric contracts +
response authority)                                   148 passed
ruff (F,I,E9) on new package                          clean
```
Coverage of the owner's A-AI list: A,B contract serialization/validation ·
C V1 compatibility · D guid authoritative · E pid downgrade · F 4688 downgrade ·
G open-ended process · H attributed artifact · I UNATTRIBUTED artifact ·
J-N process→process/file/registry/dns/network edges · O AUTH without edge ·
P detection→observation · Q detection→process only when proven · R edgeless
relationship rejected · S proximity basis rejected (6 variants) · T density ≠
severity · U retention truth · V UNKNOWN coverage · W NOT_COLLECTED needs
proof · X NOT_OBSERVED semantics · Y parse-failure semantics · Z focus
contract · AA ambiguity · AB evidence missing · AC out-of-window ·
AD provenance chain · AE cross-tenant (live) · AF endpoint stamping ·
AG no write side effect (source-level assertion) · AH unsupported event ·
AI route wiring stays additive.

**32 · Live read-only verification — PASS** (preview pod, `test_database`,
device `dev_42e8c6dc74b9`, 232,379 observations; the production Windows
endpoint was **not** touched, re-enrolled, rotated or reconfigured, and no
secret was read or printed):

```
http 200 | V1 keys present: True | dt2 version: dt2.0
observations 73 · relationships 42 · detections 1 · density 63 · coverage 1
process_instances 40 · artifacts 0 (this window is all PROCESS lanes)
rel types: PROCESS_PROCESS, DETECTION_OBSERVATION, DETECTION_PROCESS
every edge has evidence + basis: True
bases used: CANONICAL_PARENT_PROCESS_IDENTITY, DETECTION_EVIDENCE_REFERENCE
coverage states: OBSERVED          identity authorities: DERIVED
processes with invented end: 0     retention_boundary: UNKNOWN
availability: process_end/signer/module_load = UNAVAILABLE
focus(raw_event_id) → FOCUS_RESOLVED, basis EXACT_EVIDENCE_ID
cross-tenant request → 403
```
Note the honest detail: identity authority is `DERIVED` for this device because
its observations carry no ProcessGuid — exactly the downgrade the contract is
supposed to state rather than hide.

**33 · Known limitations** — (a) DT2-0 derives relationships from the projected
window, so an edge whose other end is outside the window is not emitted (DT2-3
adds off-window ancestors); (b) coverage currently proves only OBSERVED and
NOT_CANONICALIZED plus UNKNOWN spans — heartbeat/policy-derived NOT_COLLECTED
needs the enrolment/heartbeat join (DT2-6); (c) `applied_search` still declares
V1 substring mode; (d) no UI consumes `dt2` yet, by design.

**34 · Deferred telemetry** — Sysmon 5, module load, process access, WMI,
scheduled tasks, file reads, signer/signature/integrity, Security 5379/4798/
4648/4672. Sensor and canonicalization untouched.

**35 · Deferred UI** — DT2-1 navigation, DT2-2 handoffs, DT2-3 rendering,
DT2-4 inspector, DT2-5 search, DT2-6 detection nav, DT2-7 pivots.

**36 · Deferred analytics** — ML/UEBA, behaviour engine, retrospection,
threat-intel, XDR correlation. Contracts are versioned and evidence-referenced
so derived insight can be added as an attributable overlay that never
overwrites evidence.

**37 · Rollback** — revert the single commit. The package is new, the route
change is 18 lines, there is no migration, no persisted state and no write, so
rollback has **zero data consequence**; a V1 client is unaffected either way.

**38 · DT2-1 prerequisites** — consume `dt2.density` in the overview, adopt the
PUSH/REPLACE rules, add the explicit zoom/jump controls, add
generation-token + AbortController. All contract support already exists.

**39 · Diff summary** — 5 files, 4 new (1 package + 1 test module), 1 edited;
additive API only; no production code path outside the trajectory route.

**40 · Final owner gate** — DT2-0 PASS; stopped for owner approval; DT2-1 not
started; nothing deployed.

## Flowcharts

```
A  telemetry → contract
   Windows sensor → raw evidence (immutable) → canonical bridge
        ├─ unsupported ─► raw retained + reason ─► activity_class=None
        └─ supported ──► canonical observation ─► V1 window ─► DT2 contract

B  observation → identity → relationship → projection
   observation ─► process/artifact identity ─► evidence-backed edge ─► window

C  ProcessGuid identity          D  PID / 4688 downgrade
   guid? ─yes─► AUTHORITATIVE       no guid + pid+image ─► DERIVED
                                    pid only ──────────► UNSTABLE

E  attributed artifact           F  unattributed artifact
   actor process on the same        no actor binding ─► artifact kept,
   observation ─► edge + ATTRIBUTED  state=UNATTRIBUTED, NO edge

G  4624 AUTH, no process binding
   AUTH observation ─► own lane ─► no PROCESS_AUTH edge (never proximity)

H  detection → observation       I  detection → process
   detection ─► contributing obs    only when the detection row carries a
   (DETECTION_EVIDENCE_REFERENCE)   process instance + stated authority

J  coverage derivation           K  retention boundary
   rows? ─► OBSERVED                requested vs effective vs available;
   parser unsupported? ─► NOT_      retention_boundary = UNKNOWN unless
   CANONICALIZED (proof)            provable — never synthesised
   else ─► UNKNOWN (never
   NOT_COLLECTED without proof)

L  density aggregation           M  exact focus resolution
   rows ─► ≤48 buckets/stream       id ─► exact hit? ─► FOCUS_RESOLVED
   (+ detection stream)             many ─► AMBIGUOUS · none ─► EVIDENCE_
   severity: absent                 MISSING · timestamp ─► flagged

N  provenance (reverse traversable)
   detection ─► observation_ids ─► observation ─► canonical ref ─► raw ref

O  V1 compatibility              P  tenant authorization
   V1 keys untouched + `dt2`        principal ─► server-side tenant ─►
   contract failure ─► dt2.state    endpoint ownership ─► scoped rows
   = DT2_CONTRACT_UNAVAILABLE       foreign tenant ─► 403, no disclosure

Q  future window loading  R  Events→Trajectory  S  Detection→Trajectory
T  retrospection (new evaluation, same immutable evidence, new version)
U  behavioural analytics (DerivedInsight overlay, never overwriting)
V  File Trajectory pivot (ArtifactInstance is already reusable)
W  EDR→XDR correlation (pivot intent only, no evidence copy)
```
