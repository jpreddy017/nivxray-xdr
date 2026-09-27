# DEVICE TRAJECTORY V2 — PHASE B ARCHITECTURE

Status: **PHASE B (design only)**. No implementation, no deployment, no DB
write, no sensor change, no canonicalization change, no detection-semantics
change, no response-authority change. Phase A
(`DEVICE_TRAJECTORY_V2_GAP_ANALYSIS.md`) is the authoritative baseline.

---

## 1 · Executive architecture decision

NivXForge gets its **own** Trajectory Engine: a backend domain capability that
turns canonical endpoint evidence into a *navigable temporal relationship
graph*, plus a window service that serves bounded slices of that graph to a
three-surface investigation UI.

V1 is **not** replaced. V1 already contains the hard parts — windowed
projection, opaque cursor paging, an endpoint-wide invariant lane axis in
lineage pre-order, lifelines, parent→child connectors, a 30-day overview with a
draggable band, server-side filter/search with filter-scoped axis rebuild, a
pivot menu, an inspector and a focus resolver. V2 adds the four missing
**first-class domain objects** (relationship, detection marker, density bucket,
coverage interval) and the **interaction contract** that makes the workflow
analyst-grade.

One-line decision: *promote what V1 computes implicitly into explicit,
evidence-referenced contract objects, then specify every interaction against
that contract.*

## 2 · Owner requirements (restated as testable properties)

| # | Property |
|---|---|
| R1 | UI capability never exceeds evidence capability; UNKNOWN ≠ ABSENT; NOT COLLECTED ≠ CLEAN |
| R2 | An event reaches its **exact** trajectory position, never a generic 24 h window |
| R3 | A detection reaches its **contributing evidence**, not just a red dot |
| R4 | Every drawn edge answers "why is this edge drawn?" with an evidence reference |
| R5 | Time is navigable: overview → range → zoom → pan → jump, without losing selection |
| R6 | Scroll domains are isolated; page-level horizontal scrolling is never required |
| R7 | Coverage states are distinguishable; fabricated intervals are forbidden |
| R8 | 100 k+ observations are navigable without unbounded DOM or memory |
| R9 | Tenant/authority invariants unchanged; trajectory is read-only and never a response authority |
| R10 | NivXForge-native engines may extend, never overwrite, raw/canonical truth |

## 3 · Phase-A baseline (accepted)

Substrate verified present: `trajectory_window.py` (1155 L) windowed projection
with `(timestamp, event_iid)` opaque cursor, `build_lane_catalogue` lineage
pre-order, lifelines (`first_seen`/`last_seen`/`exit_observed`), `parent_state`
tri-state, `epistemic_state`, projection cache; `edr.py` routes
`/endpoints/{id}/trajectory`, `/trajectory/focus`, `/process-tree`,
`/file-trajectory`, `/device-trajectory`; UI `AmpCanvas` (wheel=rows,
shift=time, ctrl=zoom, drag=pan, elbow connectors, detection markers, pivot
menu), `AmpNavigator` (30-day band + 24 h band + handles), `AmpEventDetails`
(sections incl. provenance), deep-link params already accepted by the page.

## 4 · Reference-behaviour methodology

Every reference claim in this document is tagged:

- **[DOCUMENTED]** — Cisco public documentation / DevNet / public technical
  material: event → Device Trajectory opens with that event selected;
  relation-graph navigation; event detail inspection; review activity before
  and after an IOC; on-demand loading while scrolling historical trajectory;
  up to 30 days of history; activity spikes; timeline filtering; process/file
  relationship mapping; public computer-trajectory API with time-range
  filtering.
- **[OBSERVED]** — behaviour the owner has seen in the product.
- **[INFERRED]** — plausible but unverified → recorded as **REFERENCE
  BEHAVIOUR NOT VERIFIED**.
- **[NIVXFORGE]** — our own design decision, owing nothing to the reference.

Cisco's trajectory **engine itself is not public**; nothing here is derived
from Cisco source, assets, CSS, icons, branding or private protocols, and no
reverse engineering is performed. We reproduce *operational semantics*
independently. Where the reference is unknown we choose a NivXForge answer and
label it.

## 5 · Preserve / reuse matrix

| V1 primitive | Verdict | Note |
|---|---|---|
| Windowed projection `query_window` | **EXTEND** | add `relationships[]`, `detections[]`, `density[]`, `coverage[]` |
| Opaque cursor `(timestamp, event_iid)` | **KEEP** | already stable + order-total |
| Endpoint-wide invariant lane axis | **KEEP** | the identity anchor of the whole UI |
| Lineage depth-first pre-order | **EXTEND** | add collapse/expand state |
| Process lifelines | **KEEP** | `exit_observed:false` is correct truth |
| Parent→child connectors | **EXTEND** | become renderings of `relationships[]` |
| 30-day overview + 24 h band + handles | **EXTEND** | fed by `density[]`, gains `coverage[]` bands |
| Server-side filters (`kinds`, `dispositions`) | **EXTEND** | add evidence-status filters from `parser_state` |
| Server-side search `q` | **REFACTOR** | becomes field-scoped + match cursor |
| Filter-scoped axis rebuild | **KEEP** | with explicit axis-mode declaration |
| Pivot/context menu | **EXTEND** | evidence-gated action set |
| `AmpEventDetails` | **REFACTOR** | tabs, resizable, RAW tab |
| `trajectory_focus` | **EXTEND** | FocusTarget contract + explicit ambiguity failure |
| `ProcessGuid → process_iid` binding | **KEEP** | verified real for Sysmon 1 |
| Tenant authority + read-only projection | **KEEP** | non-negotiable |
| `EdrEventsPage` | **EXTEND** | gains the handoff action (DT2-2, not first) |

**REPLACE: none.** No V1 primitive is discarded; every change is additive or a
refactor that preserves behaviour. Justification requirement therefore unused.

## 6 · Current architecture (as-is)

```
raw event ──► canonical bridge ──► CES ──► CEM observation ──► v2_shadow_observations
                                                                      │
                                              trajectory_window.query_window
                                                                      │
             ┌────────────── events[] + lane_axis + activity + projection ──────────────┐
             ▼                                                                          ▼
      AmpNavigator (30d/24h)                                             AmpCanvas + AmpEventDetails
```
Implicit today: relationships (lane proximity + `parent_lane_index`),
detections (per-row attribution), density (day buckets in `activity`),
coverage (one header sentence).

## 7 · Proposed V2 architecture

```
                    ENDPOINT TELEMETRY
                            │
                    RAW EVENT STORE (immutable)
                            │
                    CANONICAL BRIDGE ── unsupported ─► raw retained + explicit reason
                            │
                    CANONICAL OBSERVATIONS
             ┌──────────────┼───────────────┐
             ▼              ▼               ▼
      ProcessIdentity  ArtifactIdentity  DetectionAssociation
             └──────────────┼───────────────┘
                            ▼
                    RELATIONSHIP ENGINE
                            ▼
                    TEMPORAL GRAPH ENGINE
             ┌──────────────┼───────────────┐
             ▼              ▼               ▼
        CoverageEngine  DensityEngine   FocusResolver
             └──────────────┼───────────────┘
                            ▼
                 TRAJECTORY PROJECTION (window)
                            ▼
                 WINDOW SERVICE (cursor/cache)
                            ▼
                 DEVICE TRAJECTORY V2 UI
```
All engines are **logical modules inside the existing backend** — no new
service, no new datastore. Proposed placement: `backend/edr_plane/trajectory/`
package (`engine.py`, `identity.py`, `relationships.py`, `graph.py`,
`window.py` (moved `trajectory_window.py` core), `focus.py`, `coverage.py`,
`density.py`, `evidence.py`, `detections.py`), re-exported so existing imports
keep working.

## 8-17 · Engine specifications

**8 TrajectoryEngine** — composition root. Input: endpoint identity + window +
filters + axis mode. Output: `TrajectoryWindow`. Owns nothing persistent;
`creates_no_store: True` stays true.

**9 ProcessIdentityEngine** — stable `process_iid`. Priority: (a) Sysmon
`ProcessGuid` → authoritative; (b) `computer:pid:image:first_seen` →
**derived, downgraded**; (c) pid only → **not stable**, never presented as
identity. Emits `identity_authority: AUTHORITATIVE | DERIVED | UNSTABLE` and
`identity_basis`. PID reuse is detected by disjoint lifelines on the same pid
with different guids → two instances, never merged.

**10 RelationshipEngine** — derives typed edges **server-side only**:
`PROCESS→PROCESS` (parent guid), `PROCESS→FILE` (Sysmon 11 actor),
`PROCESS→REGISTRY` (12/13), `PROCESS→DNS` (22), `PROCESS→NETWORK` (3),
`PROCESS→AUTH/USER` (4624 subject↔process where evidence binds),
`DETECTION→OBSERVATION`, `DETECTION→PROCESS`. Every edge carries
`evidence_ref` + `derivation_basis` + `authority`. **Temporal proximity is
never a basis.** Absent binding ⇒ no edge (and the UI may show the object on
its own lane, unattributed).

**11 TemporalGraphEngine** — orders nodes/edges by the authoritative time rule
(§23) and materialises the lane tree with collapse state.

**12 WindowEngine** — today's `query_window`, extended: bounded first paint,
background warm, cursor paging, per-lane bucketing, TTL cache. Adds
`generation` token for stale-response rejection (§33).

**13 FocusResolver** — `FocusTarget` in, deterministic position out. Resolves
`raw_event_id | canonical_event_id | observation_id | process_iid |
detection_id | timestamp`. Returns `state`: `FOCUS_RESOLVED` /
`FOCUS_AMBIGUOUS` / `FOCUS_NOT_IN_RETENTION` / `FOCUS_EVIDENCE_MISSING` —
**never a silent generic fallback**.

**14 CoverageEngine** — see §35. Derives intervals from sensor heartbeat/
enrolment history, parser outcomes and canonicalisation support; anything
unprovable is `UNKNOWN`, never `NOT_COLLECTED`.

**15 DensityEngine** — server-computed buckets over the requested span,
per-stream (`events`, `process`, `file`, `network`, `detection`). Density is
**navigation information, never a verdict**; the UI must not colour it by
severity.

**16 EvidenceResolver** — single authority for raw/canonical retrieval;
frontend never re-derives raw. Reuses `GET /api/edr/events/{raw_id}`.

**17 DetectionAssociationEngine** — detection ↔ contributing observations ↔
process, with `evaluation_state` (`MATCHED` / `EVALUATED_NO_MATCH` /
`NOT_EVALUATED` / `NOT_RECORDED`).

## 18-22 · Contract architecture

**Evolution rule**: additive only. V1 keys (`events`, `lane_axis`, `activity`,
`projection`, `time_range`, `provenance`, `epistemic_state`, `cursor`) are
**retained and unchanged**; V2 adds new top-level arrays. A V1 client keeps
working (backward compatibility documented per slice).

```
TrajectoryWindow {
  endpoint, from, to, axis_mode,
  observations[],            # V1 `events` retained; alias added
  relationships[],           # NEW
  detections[],              # NEW
  density[],                 # NEW  (promoted from `activity`)
  coverage[],                # NEW
  axis,                      # V1 lane_axis retained
  focus,                     # FocusTarget resolution echo
  cursor, next_cursor, generation,
  provenance, projection, epistemic_state
}

Observation { observation_id, canonical_event_id, raw_event_id, timestamp,
  time_basis, activity_class, operation, process_instance, object,
  detection_state, disposition, parser_state, provenance }

Relationship { relationship_id, source_id, target_id, relationship_type,
  observed_at, evidence_ref[], derivation_basis, authority, provenance }

DetectionMarker { detection_id, timestamp, severity, evaluation_state,
  contributing_observation_ids[], process_instance_id, engine, engine_version }

DensityBucket { from, to, stream, count }
CoverageInterval { from, to, state, authority, proof_ref, boundary_certainty }
FocusTarget { kind, value } → FocusResolution { state, window, object_id,
  process_instance_id, relationship_path[], detection_id, basis }
ProcessInstance { process_iid, identity_authority, identity_basis, pid, guid,
  image, command_line, user, integrity, hashes, parent_process_iid,
  parent_state, first_seen, last_seen, exit_observed, detection_state }
EvidenceReference { kind, id, collection, byte_preserved }
TrajectoryCursor { timestamp, event_iid }  # unchanged
TrajectoryAxis { mode: ENDPOINT_INVARIANT | FILTER_SCOPED, lanes[], order,
  collapsed_lane_ids[] }
```

**Artifact identity (22)** — file: `sha256` when present else normalised path;
registry: hive+key(+value); dns: query name; network: 5-tuple + first_seen;
user: SID when present else domain\\name. Each carries its own
`identity_authority`.

## 23-27 · Time, timeline, scroll, zoom/pan, focus

**23 Time model** — five distinct stamps: `source_time` (event log), 
`observed_time` (sensor), `ingest_time`, `canonicalization_time`,
`evaluation_time`. **Authoritative ordering = `source_time` when present,
else `observed_time`**, tie-broken by `event_iid`; the chosen basis is always
returned as `time_basis` so the analyst knows. Clock skew is surfaced, never
corrected silently.

**24 Timeline state machine** — states: `IDLE → LOADING_WINDOW → READY →
(SELECTING | NAVIGATING | SEARCHING) → READY`; `FAILED_SUBSYSTEM` is per-panel
(§34), never global.

**25 Scroll architecture (P0)** — four independent domains:

```
PAGE            never required for ordinary investigation (no horizontal page scroll)
CANVAS-Y        wheel / trackpad-vertical  → lane scroll (virtualised)
CANVAS-X(time)  shift+wheel, drag, handles → time pan   (NOT page scroll)
INSPECTOR-Y     own scroll container
SEARCH RESULTS  own list scroll
```
Rules: a domain consumes its gesture (`preventDefault` inside canvas bounds)
and never forwards it to a parent; sticky: endpoint header, toolbar, time
controls; the canvas keeps its `data-wheel-navigation` self-declaration.
Trackpad: two-finger vertical = lanes, two-finger horizontal = time,
pinch = zoom, ctrl+wheel = zoom (all specified, none inherited by accident).

**26 Zoom / pan** — zoom levels: 30 d → 7 d → 24 h → 4 h → 1 h → 15 m → 1 m →
event-resolution (floor = 1 s buckets, ceiling = retention span). Anchored on
cursor position; selection is preserved across zoom; controls: `+`, `−`,
`reset`, `fit selection`, `jump prev/next event`, `jump prev/next detection`.

**27 Focus / deep-link** — URL grammar
`/edr/device-trajectory?device&from&to&event&process_iid&detection&q&kinds&dispositions&zoom&focus_state`.
Refresh and deep-link reconstruct the investigation; ambiguity fails loudly.

## 28-29 · Handoffs

```
EVENT ROW ──► FocusTarget{raw_event_id|canonical_event_id}
        ──► FocusResolver ──► window(from,to centred on t) ──► select object
        ──► highlight relationship path ──► open inspector            [DOCUMENTED]

DETECTION ──► FocusTarget{detection_id} ──► contributing evidence
        ──► timestamp + process ──► relationship path ──► detection inspector
```
Both are **push** history entries (§39). Events integration is DT2-2, *after*
the contract (DT2-0) and navigation (DT2-1) — per owner decision.

## 30 · Inspector V2

Viewport-anchored, resizable (drag handle, persisted width), collapsible, own
scroll; narrow screens → overlay/full-detail mode instead of crushing the
canvas. Tabs: **SUMMARY · PROCESS · RELATIONSHIPS · EVIDENCE · DETECTION ·
RAW · PROVENANCE**, plus contextual **FILE / REGISTRY / DNS / NETWORK / AUTH**.
RAW fetches authoritative bytes from the backend (`/api/edr/events/{raw_id}`);
the frontend never becomes a second raw authority.

## 31-34 · Search, filters, detection navigation, density

**31/32 Search** — field-scoped (`process`, `path`, `cmdline`, `pid`, `guid`,
`process_iid`, `file`, `sha256`, `ip`, `port`, `domain`, `registry`, `user`,
`event_id`, `canonical_event_id`, `raw_event_id`, `detection`, `rule`), free
text still allowed. Server returns a **match cursor**: `total`, `index`,
`match_ids[]` page. UI shows `MATCH 4 OF 17` with prev/next; selecting a match
loads the window that contains it, jumps, selects, highlights, updates the
inspector, and preserves search+filter context.

**33 Filters** — activity, detection evaluation state, **evidence status**
(`CANONICALIZED | RAW_ONLY | UNSUPPORTED | PARSE_FAILURE` from `parser_state`),
disposition, operation, user, process, event family, time. Axis mode is
declared per request: default **ENDPOINT_INVARIANT**; when a filter would hide
ancestors the axis switches to **FILTER_SCOPED** and says so
(`FILTER_SCOPED_ROWS_WITH_MATCHING_ACTIVITY`, already in V1). Filtering never
merges or renames process identity.

**34 Detection navigation** — prev/next detection, jump-to-detection centring
the contributing evidence time, marker click → select + highlight path + open
detection tab.

## 35 · Coverage model (required in V2)

| State | Authority | Proof | Absence inferable? |
|---|---|---|---|
| `OBSERVED` | observations exist | observation ids | n/a |
| `NOT_OBSERVED` | sensor reporting, nothing matched filter | heartbeat + query | **only within the filter** |
| `NOT_COLLECTED` | collection policy excludes the family | policy id + family | **no** |
| `NOT_CANONICALIZED` | raw retained, family unsupported | raw ids + reason code | **no** |
| `PARSE_FAILURE` | parser error recorded | parser_state + raw id | **no** |
| `EVALUATION_FAILED` | detection evaluation errored | evaluation record | **no** |
| `UNKNOWN` | cannot be proven | — | **no** |

Boundary rule: an interval boundary is emitted only from a provable transition
(enrolment, heartbeat gap, policy change, parser outcome). Otherwise
`boundary_certainty: UNKNOWN` and the band renders as UNKNOWN. **Fabricating a
NOT_COLLECTED interval is forbidden**; UNKNOWN is always the safer answer.

## 36-37 · Telemetry truth

Present support (unchanged, do not widen in Phase B): Sysmon 1→PROCESS,
3→NETWORK, 11→FILE, 12/13→REGISTRY, 22→DNS, Security 4688→PROCESS,
4624→AUTH.

| Capability | Architecture | Current evidence |
|---|---|---|
| Process termination / lifeline end | SUPPORTED | **NOT COLLECTED** (no Sysmon 5) |
| Signer / signature / integrity | SUPPORTED | **NOT COLLECTED** |
| Module load, process access, WMI, scheduled task | SUPPORTED | **NOT COLLECTED** |
| File read | SUPPORTED | **NOT COLLECTED** |
| 4688 hashes / guid | SUPPORTED | **NOT AVAILABLE** (downgraded identity) |
| ATT&CK mapping | SUPPORTED | **DERIVED** (deterministic mapper — labelled, not an authored detection) |

Unsupported families (e.g. Security 5379, 4798) keep the proven chain: raw
retained → canonicalization unsupported → no canonical evidence → NOT STAMPED →
detection NOT RECORDED. They must never be promoted to make the canvas richer.

## 38-39 · Investigation state and history

Ownership: **URL** owns device/window/selection/detection/search/filters/zoom;
**server** owns evidence and match totals; **cache** owns fetched windows;
**ephemeral UI** owns hover, menu, panel width, scroll offsets — no duplicated
authority.

PUSH vs REPLACE: **PUSH** on selection change, focus handoff, detection jump,
search-match jump, expand/collapse of a lane branch, zoom-level change.
**REPLACE** on transient window nudges (pan inertia, handle drag in progress)
and on cursor-only pagination. This directly fixes V1's indiscriminate
`replace: true`, which is why Back does not step today.

## 40 · Keyboard / accessibility

`←/→` prev/next event · `shift+←/→` prev/next detection · `+/−` zoom ·
`0` reset zoom · `Enter` inspect · `Esc` close inspector / clear focus ·
`n/p` next/prev search match · `Tab` normal focus traversal (never hijacked).
Canvas is a focusable, labelled region with an accessible list alternative of
the current window; no browser shortcut is overridden.

## 41-44 · Virtualization, caching, prefetch, cancellation

Row virtualization (bounded DOM ≈ viewport + overscan), relationship
virtualization (edges only between visible lanes), density aggregation instead
of raw rendering, bounded window cache (keep V1's `CACHE_MAX 28`,
`LANE_PREFETCH 14`, `TIME_PREFETCH 0.3`), adjacent-window prefetch,
**request deduplication by request key**, and **AbortController per generation**
— a late R1 must never overwrite R4 (§33 of the mandate): responses carry
`generation`, and the client discards any response whose generation is not
current.

## 45-46 · Security and response boundary

Unchanged and re-asserted: authenticated principal, **server-side** tenant
derivation (frontend tenant ids are never authority), endpoint ownership
validation, cross-tenant non-disclosure, read-only projection
(`creates_no_store`), evidence immutability, raw payload integrity, provenance
preserved through every derived layer. Trajectory exposes **no** isolate/kill/
quarantine/block; any future action routes through the existing hardened
response authority with its approval flow. **No destructive action is
authorized in Phase B.**

## 47 · Extension layer (NivXForge-native)

```
TRAJECTORY CORE (evidence-navigation substrate)
        │
        ├── RelationshipEngine ──┐
        ├── EvidenceResolver ────┤──► DerivedInsight[] (separate store/namespace)
        └── DetectionAssociation ┘          │
                                            ▼
                     ML / analytics / retrospective / campaign / XDR correlation
```
Derived intelligence is **additive and separately attributable**: `source`,
`engine`, `engine_version`, `evidence_refs`, `derivation_basis`, `timestamp`,
`confidence`. It may never overwrite raw or canonical fields, and the renderer
never couples to an analytics engine — it renders `DerivedInsight` objects like
any other evidence-referenced overlay.

## 48 · EDR → XDR boundary

Device Trajectory stays **endpoint-centric**. Cross-endpoint/cross-source
correlation remains NivXRay XDR's incident graph; trajectory offers explicit
pivots (process/file/ip/domain/user → Hunt or XDR) and never becomes the
incident graph itself.

## 49 · Required flowcharts (A-R)

```
A telemetry→trajectory      sensor→raw→canonical→observation→graph→window→UI
B evidence chain            raw→canonical→observation→relationship→detection (and reverse)
C identity resolution       guid? ──yes──► AUTHORITATIVE
                                  └─no──► computer:pid:image ──► DERIVED ──► pid only ──► UNSTABLE
D lineage                   parent_iid known? ─no─► parent_state=NOT_REPORTED_BY_SENSOR (no invented root)
E window load               request(gen n) → cache hit? → serve : fetch → merge → evict → prefetch(n±1)
F pan/zoom                  gesture → new (from,to,zoom) → preserve selection → load → REPLACE|PUSH
G scroll domains            page / canvas-Y / canvas-X / inspector / results  (each consumes its gesture)
H events→focus              row → FocusTarget → resolver → window → select → highlight → inspector
I detection→focus           detection → contributing evidence → t,process → path → detection tab
J search→match              query → match cursor(total,index) → load window(match) → jump → select
K relationship expansion    node → expand(children|artifacts) → fetch edges for lane set → render
L inspector evidence        tab → resolver (canonical | RAW /api/edr/events/{raw_id}) → render
M coverage derivation       heartbeat+policy+parser → provable transition? ─no─► UNKNOWN
N url/history               interaction → PUSH (selection/focus/zoom) | REPLACE (transient/pagination)
O stale cancellation        gen n active; response gen<n → discard; abort in-flight on new gen
P cache/prefetch            [cached | ACTIVE | prefetch] sliding triple, LRU eviction
Q EDR→XDR pivot             object → pivot intent → XDR/Hunt query (no evidence copy)
R extension engines         core → DerivedInsight (attributable, additive, never overwriting)
```

## 50 · Component diagram (proposed)

```
EdrEventsPage / EdrDetectionsPage ──► FocusHandoff ──► DeviceTrajectoryPageV2
┌──────────────────────────────────────────────────────────────────────┐
│ AmpComputerHeader (sticky)                                           │
│ TrajectoryToolbar: search · filters · time controls · zoom (sticky)  │
│ OverviewStrip: density + detections + coverage + range handles       │
│ ┌───────────── InvestigationCanvas ─────────────┐ ┌ InspectorV2 ───┐ │
│ │ LaneTree (virtualised) │ TemporalGraph        │ │ tabs, resizable│ │
│ │ collapse/expand        │ lifelines + edges    │ │ own scroll     │ │
│ └───────────────────────────────────────────────┘ └────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
        │                        │                       │
   WindowEngine            FocusResolver          EvidenceResolver
        └────────────── TrajectoryEngine ──────────────┘
            Identity · Relationship · Coverage · Density · Detection
```

## 51 · Performance baseline

Harness written and saved: `memory/production-gates/dt2_perf_baseline.py` —
read-only, measures **separately**: cold projection, warm window, lane scroll,
time-window change, search, filter, disposition filter, focus by raw id, focus
by canonical id, with payload size and row/lane counts per call (never one
blended number).

**Measurement status: NOT YET CAPTURED.** Two honest blockers: (a) production
requires owner-side auth (token only, never a password — the harness accepts
`$NIVXJWT`); (b) the preview pod's supervisor services restarted repeatedly
during this session (backend/mongodb uptime resetting to ~25 s), so local
numbers would have been measurement noise, not a baseline. A suitable local
substrate **does** exist and is identified: `test_database` holds **236,444**
observations with a single device `dev_42e8c6dc74b9` carrying **232,379** — the
right order of magnitude for the §32 targets. DT2-8 targets will be set from
the first stable capture; no optimisation is performed in Phase B.

## 52 · Loading and failure semantics

Independent per subsystem: timeline, relationships, inspector, raw evidence,
search, density, coverage. A subrequest failure renders a scoped error that
**names the subsystem** and keeps the rest of the investigation usable; the
whole screen is never blanked. Empty ≠ error ≠ unknown: each has its own
presentation.

## 53 · Test architecture (defined before implementation)

Categories: unit · contract (schema + backward compatibility) · integration ·
tenant isolation · relationship provenance · focus resolution · time
navigation · scroll state · search · match navigation · filter · browser
history · raw evidence · coverage semantics · stale-request cancellation ·
virtualization · large dataset · accessibility · deep links · negative
controls.

Mandatory negative controls: unsupported Windows event stays unstamped ·
missing parent stays `PARENT_NOT_REPORTED_BY_SENSOR` · PID reuse yields two
instances · missing ProcessGuid downgrades identity (never silently stable) ·
**relationship without evidence is rejected at the contract boundary** ·
cross-tenant endpoint refused without disclosure · ambiguous focus fails
explicitly · missing raw evidence is reported, not synthesised · parse failure
surfaces as PARSE_FAILURE · unprovable coverage renders UNKNOWN · a late stale
response is discarded.

## 54 · Analyst acceptance stories (A-E)

**A Process** — find `powershell.exe` → select → command line → parent →
children → files → registry → DNS → network → raw evidence → prev/next
activity. **B Detection** — open detection → exact position → contributing
evidence → related process → before/after → raw → next detection. **C Event** —
Events row → *Open in Device Trajectory* → exact event centred → inspector open
→ related process → pivot → **Back restores the original event context**.
**D Historical** — 30-day overview → identify period → drag range → zoom → pan
→ load older data → search → jump matches → return to previous window.
**E Coverage truth** — traverse a period without coverage → UI distinguishes
UNKNOWN / NOT COLLECTED / NOT CANONICALIZED → the analyst cannot conclude
"no activity". Each story ships with the 23-step capture procedure from the
Phase-A mandate; real endpoint `ep_1989031c8c1d0085812f` is the final witness.

## 55 · Slice plan DT2-0 … DT2-9

| Slice | Files (planned) | API | Components | Back-compat | Tests | Security | Perf | Rollback | Acceptance gate |
|---|---|---|---|---|---|---|---|---|---|
| **DT2-0** contract/domain primitives | `edr_plane/trajectory/{models,relationships,detections,density,coverage}.py`, wrap `trajectory_window.py` | additive keys on `/trajectory` | — | V1 keys untouched | contract + provenance + negative | tenant-scope unchanged | payload bounded by window | drop new keys (client ignores) | every edge has `evidence_ref`; V1 client unaffected |
| **DT2-1** timeline/navigation/scroll/history | `trajectory/*` UI + `AmpNavigator`, `AmpCanvas` | `density[]` consumed | Overview, Toolbar, Canvas | no API break | time-nav, scroll, history, abort | none | abort + dedupe | feature-flag off | zoom/pan/jump/selection-preserving; Back steps |
| **DT2-2** Events+Detections focus handoff | `EdrEventsPage`, `EdrDetectionsPage`, `focus.py` | FocusTarget contract | row + inspector actions | additive | focus resolution + deep links | unchanged | 1 extra request | remove action | event → exact position, PUSH history |
| **DT2-3** first-class relationships | `relationships.py`, canvas edges | `relationships[]` | LaneTree, Graph | additive | provenance, expansion | unchanged | edge virtualization | render V1 connectors only | "what did this process touch" answered |
| **DT2-4** Inspector V2 | `AmpEventDetails` → tabs, `evidence.py` | `/events/{raw_id}` reuse | InspectorV2 | additive | raw/canonical/provenance | raw authority stays server-side | lazy tabs | keep V1 pane | 7 tabs incl. RAW, resizable |
| **DT2-5** structured search + match nav | `window.py` search, toolbar | match cursor | SearchBar, ResultNav | `q` still works | search/match/filter | unchanged | server-side matching | fall back to `q` | `MATCH n OF m` navigates |
| **DT2-6** detection navigation | `detections.py`, overview markers | `detections[]` | markers, DetectionTab | additive | detection nav | unchanged | bucketed markers | hide controls | prev/next detection + evidence |
| **DT2-7** pivots | pivot menu, intents | pivot intents | ContextMenu | additive | pivot gating | **no response action** | negligible | menu subset | only evidence-backed actions shown |
| **DT2-8** virtualization/perf/cache/cancel | canvas + cache layer | none | — | none | large dataset, stale | unchanged | **the point** | prior cache policy | targets from §51 met on the real endpoint |
| **DT2-9** analyst acceptance | tests/docs only | none | — | none | stories A-E | full invariant sweep | measured | n/a | owner sign-off |

## 56 · Rollback plan

Every slice is independently revertable: backend additions are additive keys
(a reverted client simply ignores them); UI slices land behind a per-slice
flag; DT2-0 introduces no migration and no write, so rollback is a code revert
with **zero data consequence**.

## 57 · Risks

1. Relationship attribution quality is bounded by Sysmon fields — mitigated by
   `authority` + `derivation_basis` on every edge.
2. Coverage provability — mitigated by the UNKNOWN-first rule.
3. Axis-mode confusion under filters — mitigated by declaring the mode in the
   response and the UI.
4. Perf baseline still uncaptured — mitigated by harness + DT2-8 gate.
5. Scope creep into coverage expansion — explicitly out of scope (§36).

## 58 · Open decisions (owner input welcome, none blocking)

1. Retention span offered in the overview: 30 days [DOCUMENTED reference] vs
   NivXForge's actual retention — which wins when they differ?
2. Do we show unattributed artifacts (no provable actor) on their own lane, or
   hide them behind a filter? (Recommendation: show, marked UNATTRIBUTED.)
3. Should `AUTH` events attach to a process lane when 4624 gives no process
   binding? (Recommendation: separate AUTH lane, no invented edge.)
4. Inspector width persistence: per-user or per-session?
5. Whether DT2-3 should also expose `DETECTION→PROCESS` edges before DT2-6.

## 59 · Cisco-class behavioural parity matrix

| Capability | Reference behaviour | Current NivXForge | V2 design | Data support | Slice | Acceptance test |
|---|---|---|---|---|---|---|
| Historical overview | 30 d history [DOCUMENTED] | 30-day band | OverviewStrip + density + coverage | yes | DT2-1 | Story D |
| Activity density / spikes | spikes shown [DOCUMENTED] | day buckets | `density[]` per stream | yes | DT2-0/1 | Story D |
| Range selection | range slider [DOCUMENTED] | draggable band + handles | same, + fit/reset | yes | DT2-1 | Story D |
| On-demand history load | loads while scrolling [DOCUMENTED] | cursor + prefetch | window triple + abort | yes | DT2-1/8 | Story D |
| Zoom | [DOCUMENTED] | ctrl+wheel only | 8 levels + controls | yes | DT2-1 | Story D |
| Pan | [DOCUMENTED] | drag + shift-wheel | specified gestures | yes | DT2-1 | Story D |
| Timeline double-click | double-click behaviour [DOCUMENTED] | none | double-click = zoom to interval | yes | DT2-1 | §60 Q2 |
| Event focus from event | opens with event selected [DOCUMENTED] | focus API exists, **no Events link** | FocusTarget + row action | yes | DT2-2 | Story C |
| Detection → relation jump | [DOCUMENTED] | detections page links | contributing-evidence resolution | yes | DT2-2/6 | Story B |
| Process lifelines | process execution over time [DOCUMENTED] | drawn | + identity authority | partial (no end event) | DT2-3 | Story A |
| Parent/child lineage | stems from parent [DOCUMENTED] | lineage axis + connectors | typed edges | yes (guid) | DT2-3 | Story A |
| Process→file | file activity from process [DOCUMENTED] | lane proximity only | typed edge + evidence | yes (Sysmon 11) | DT2-3 | Story A |
| Registry relations | [OBSERVED] | lane only | typed edge | yes (12/13) | DT2-3 | Story A |
| DNS relations | [OBSERVED] | lane only | typed edge | yes (22) | DT2-3 | Story A |
| Network relations | [OBSERVED] | lane only | typed edge | yes (3) | DT2-3 | Story A |
| Detection markers | [DOCUMENTED] | drawn per row | navigable markers | yes | DT2-6 | Story B |
| Before/after IOC review | recommended [DOCUMENTED] | manual scroll | jump prev/next + anchor | yes | DT2-1/6 | Story B |
| Search | filtering/search [DOCUMENTED] | substring `q` | field-scoped | yes | DT2-5 | Story A |
| Match navigation | [INFERRED — NOT VERIFIED] | none | `MATCH n OF m` | yes | DT2-5 | Story A |
| Filtering | [DOCUMENTED] | kinds/dispositions | + evidence status | yes | DT2-5 | Story E |
| Inspector / event details | event details [DOCUMENTED] | one column | 7 tabs, resizable | yes | DT2-4 | Story A |
| Raw evidence | [NIVXFORGE] | not in trajectory | RAW tab | yes | DT2-4 | Story A |
| Provenance chain | [NIVXFORGE] | ids shown | full chain both directions | yes | DT2-4 | Story B |
| Context menu / pivots | [OBSERVED] | exists | evidence-gated | yes | DT2-7 | Story A |
| Keyboard | [INFERRED — NOT VERIFIED] | none | §40 | yes | DT2-1/4 | Story A |
| Back / Forward | [INFERRED — NOT VERIFIED] | replace-only | PUSH/REPLACE rules | yes | DT2-1/2 | Story C |
| Coverage truth | **[NIVXFORGE — beyond reference]** | header sentence | 7-state bands | partial | DT2-0/6 | Story E |
| Large dataset behaviour | on-demand loading [DOCUMENTED] | bounded paint + cache | + abort/dedupe/virtualised edges | yes | DT2-8 | §51 targets |
| Public trajectory API w/ time range | [DOCUMENTED] | our own equivalent | `TrajectoryWindow` | yes | DT2-0 | contract tests |

No aggregate percentage is given, by owner rule.

## 60 · Phase-B exit gate — the 35 answers (condensed index)

1 click semantics per object type → §24, §30 (select + highlight + inspector,
no scroll jump) · 2 double-click → zoom to interval (canvas) / open full detail
(row) §26 · 3 right-click → evidence-gated pivot menu §46/DT2-7 · 4 vertical
scroll → lane domain only §25 · 5 horizontal/time → canvas-X only, never page
§25 · 6 trackpad → specified gestures §25 · 7 zoom → 8 anchored levels §26 ·
8 pan → drag/shift-wheel/handles §26 · 9 window loading → cached/active/
prefetch triple + cursor §41-44 · 10 selection preservation → §24/§26 ·
11 prev/next event → §26 · 12 prev/next detection → §34 · 13 prev/next match →
§31 · 14 parents → lineage edges + `parent_state` §10 · 15 children → same,
collapse/expand §12 · 16-19 file/registry/DNS/network proof → `evidence_ref` +
`derivation_basis`, proximity forbidden §10 · 20 Events row → exact event →
§28 · 21 detection → contributing evidence → §29 · 22 raw retrieval → §16/§30 ·
23-25 Back/Forward/refresh → §39 PUSH/REPLACE + URL grammar §27 · 26 rapid
pan/zoom → generation + AbortController §44 · 27 100 k+ → §41-44, substrate
232 k verified · 28 empty period → §35 (never "no data") · 29 NOT_COLLECTED vs
UNKNOWN → §35 table · 30 architecture-ready but telemetry-blocked → §36 table ·
31 evidence per relationship → §10/§18 contract rejects edgeless relationships ·
32 preserved V1 components → §5 (REPLACE: none) · 33 per-slice change → §55 ·
34 independent rollback → §56 · 35 safe extension → §47.

## 61 · Phase-C implementation plan

Order is fixed: **DT2-0 → DT2-1 → DT2-2 → DT2-3 → DT2-4 → DT2-5 → DT2-6 →
DT2-7 → DT2-8 → DT2-9**. Each slice: design-conformance check → tests first
where practical → implementation → local proof → owner review. No silent
deploy; no slice begins without owner approval of the previous gate.

**STOP — awaiting owner approval before DT2-0.**
