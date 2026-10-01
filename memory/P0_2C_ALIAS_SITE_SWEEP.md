# P0-2C · ALIAS SITE SWEEP — endpoint identity resolution made a structural invariant

**Date**: 2026-06 · **Owner decisions**: Q1 = B · Q2 = B · Q3 = A ·
`test_p0_f4` untouched
**Status**: `REAL_RUNTIME_VERIFIED` · proof `scripts/p0_2c_alias_site_sweep_proof.py`
→ **52 PASS · 0 FAIL**
**Structural guard**: `backend/tests/edr/test_p0_2c_alias_invariant.py` → **10 passed**

---

## 0 · Why this pass exists

`F-1` recurred **three** times (process tree → endpoint detections →
response commands). Each fix was correct and each fix was **local**, so
the class survived. This pass does not add a fourth local fix: it makes
the resolution a **contract on the query path**, and adds a guard that
fails when a *newly added* query site bypasses it — including one written
by a future developer who names the variable something else.

---

## 1 · Inventory reconciliation (the stop condition)

Counted by AST over the whole repository, not by grep of variable names.

| Measure | Count |
|---|---|
| Query calls against the **9 endpoint-keyed collections**, whole repo | **158** |
| — LIVE code (`routers/ services/ edr_plane/ detection_content/ v2/ security_state/ workspace/ nivxforge/`) | **88** |
| — test code | 68 |
| — proof/seed scripts | 2 |
| Of the 88 live calls: filter/projection names a **declared endpoint identity field** | **21** |
| — built **through the invariant** (`endpoint_predicate` / `EndpointResolution.predicate`) | **11** |
| — **raw identity predicate, allow-listed with a written reason** | **10** |
| — **raw identity predicate, NOT allow-listed (bypass)** | **0** |
| Of the 88 live calls: keyed on a **non-endpoint** identity (`id`, `raw_id`, `canonical_event_id`, `command_id`, `credential_id`, `tenant_id`) → `NOT_APPLICABLE` | **67** |
| **LIVE surfaces that accept a CALLER-SUPPLIED endpoint identifier** (the reconciled site list, pinned in `LIVE_ENDPOINT_ROUTES`) | **10** |
| — of those, proven by evidence-ID equivalence in the runtime proof | **6** (the 6 that expose evidence ids) |
| — proven by contract/negative gates instead (no evidence-id surface by contract) | **4** |
| Legacy / unwired lineages with endpoint-keyed query sites | **0** |
| `LOAD_BEARING_LEGACY` endpoint-keyed sites found | **0** |
| Frontend pivots emitting endpoint identity, audited | **14** |

The 10 live surfaces (module::handler → store):

| # | Live surface | Store(s) | Before | After |
|---|---|---|---|---|
| 1 | `GET /api/edr/process-tree?endpoint_id=` → `_project_endpoint_process_tree` | `v2_shadow_observations` | RESOLVED (F-1 fix #1) | RESOLVED · via invariant |
| 2 | `GET /api/edr/endpoint-detections?endpoint_id=` | `edr_raw_events` | RESOLVED (F-1 fix #2) | RESOLVED · via invariant |
| 3 | `GET /api/edr/response/actions?endpoint_id=` | `edr_response_commands` | RESOLVED (F-1 fix #3) | RESOLVED · via invariant |
| 4 | `GET /api/edr/endpoints/{id}/trajectory` → `trajectory_window._projected` | `v2_shadow_observations`, `edr_raw_events`, `edr_endpoints` | **UNRESOLVED** | **FIXED** |
| 5 | `GET /api/edr/endpoints/{id}/trajectory/focus` | inherits #4 | **UNRESOLVED** | **FIXED** |
| 6 | `GET /api/edr/endpoints/{id}/linked-incidents` | `workspace_cases.endpoint_campaign` | **UNRESOLVED** | **FIXED** |
| 7 | `GET /api/edr/device-trajectory?device=` → `device_identity.observations` | `v2_shadow_observations` | **UNRESOLVED** (partial) | **FIXED** |
| 8 | `GET /api/edr/observation-narrative?device=` → `find_observation` | `v2_shadow_observations` | **UNRESOLVED** (partial) | **FIXED** |
| 9 | `GET /api/edr/context?endpoint_id=` | resolution only | RESOLVED | RESOLVED · discloses `addressed_by` |
| 10 | `POST /api/edr/response/actions {endpoint_id}` | `edr_endpoints`, `edr_raw_events` | **UNRESOLVED** | **FIXED** |

---

## 2 · The invariant

`backend/services/edr/endpoint_query.py` — new, and the **only** place the
flow is expressed:

```
external identifier
  → resolve_endpoint(supplied, scope)      # delegates to device_identity.resolve
  → identity_refs(identity, supplied, tenant_ids=…)   # THE authoritative resolver
  → EndpointResolution{identity, refs}
  → .predicate(store)  → $or over the store's DECLARED identity fields
```

- **No second resolver was created.** `resolve_endpoint` calls
  `device_identity.resolve()` + `device_identity.identity_refs()`. Nothing
  else resolves identity anywhere in the product.
- **`ENDPOINT_KEYED_STORES` is a contract, not a comment.** A store must
  declare its identity fields before it can be queried through the helper;
  an undeclared store or field raises `KeyError`.
- **Alias-set querying, not forced canonicalisation** (per the owner's
  query-semantics instruction): a store is addressed by *every validated
  alias*, because `v2_shadow_observations` keys the same endpoint on
  `event.device_iid` **and** `collector_id`/`connector_id`, and
  `workspace_cases.endpoint_campaign` records whichever identifier the
  incident happened to see. No historical record is rewritten.
- **An empty alias set never degrades to an unfiltered read** — the
  predicate becomes deliberately unsatisfiable rather than "all rows".

---

## 3 · What was actually broken (with honest impact grading)

### 3.1 · `linked-incidents` built its own ref list — **REAL, structural**
`refs = [hostname, identity.endpoint_id, device_iid]`, where
`identity.endpoint_id` is populated **only when the caller arrived by
`ep_…`**. So a `dev_…` or hostname pivot could never match
`endpoint_campaign.endpoint_id`.
**Data proves the exposure is real, not theoretical**: of the 30
`workspace_cases` carrying an `endpoint_campaign`, **13 record an
`endpoint_id` and NO hostname** — those 13 were unreachable from a
`device_iid` pivot by construction.
**Observable delta on today's corpus: 0** — the only endpoint that
currently *resolves* (`dev_42e8c6dc74b9`) has campaigns that carry both
identifiers, so all three aliases returned the same 4 incidents before and
after. Stated plainly: the defect was real and is fixed; on this corpus it
was latent.

### 3.2 · `POST /edr/response/actions` rejected valid aliases — **REAL, observable**
The command plane looked the endpoint up by the literal string, so
requesting an action from a trajectory URL (`dev_…` / hostname) returned
**`404 ENDPOINT_NOT_ENROLLED`** — a **false statement about enrolment**
for an endpoint that is enrolled.
Fixed at the HTTP boundary (`_canonical_endpoint_id`): a string that is
already an enrolment key in the tenant is used **untouched** (the
enrolment registry stays the authority and is never re-resolved); only a
non-enrolment identifier is resolved, and only aliases that are themselves
enrolled **in that tenant** are accepted.
Proven **without creating a command** (gate G): with an unobserved pid,
`dev_…`, hostname and `ep_…` all now fail on `TARGET_NOT_OBSERVED`
(target identity), and a forged `dev_…` still fails on
`ENDPOINT_NOT_ENROLLED`. Reaching the target check at all proves the alias
resolved.

### 3.3 · The trajectory projection ignored two declared identity fields — **REAL, structural**
`trajectory_window._projected` queried `event.device_iid`, `device_iid`,
`event.raw.computer`, `event.computer`, `event.raw.hostname` — and **not**
`collector_id`/`connector_id`, which the process-tree projection *does*
honour. Two query sites, one store, two different answers about the same
endpoint: the exact shape of the F-1 class.
**Observable delta today: 0 rows** (measured: `0` observations in the
whole corpus are reachable only via `collector_id`; every observation
carries `event.device_iid`). Fixed anyway, because the divergence — not
the row count — is the defect.

### 3.4 · **NEW P0 SECURITY DEFECT found in the resolver itself — cross-customer alias bleed**
`identity_refs()`'s reverse lookup (`device_iid`/hostname → every enrolled
`endpoint_id`) queried `edr_endpoints` **with no tenant predicate**. The
enrolment registry *is* tenant-partitioned, so a hostname enrolled in two
customers would have handed one customer's surface the **other customer's
`endpoint_id`** — and every downstream query built from that alias set
(`edr_raw_events.endpoint_ref`, `edr_response_commands.endpoint_id`) would
then have addressed the other customer's records.
This is a genuine cross-tenant read path created by the F-1 fixes
themselves. Fixed: the reverse lookup is constrained to the resolved
identity's tenant, or — for an observation with no tenant at all — to the
caller's authorised tenants. The constraint can only **narrow**.
**Exposure today: none** — all 158 enrolments are in `default`, and the 3
duplicated hostnames (`LAB-ADV-01`, `LAB-REVKILL`, `LAB-ENV`, 52
enrolments each) are all within one customer. Proven by gate F: a foreign
tenant constraint strictly narrows the alias set (3 → 2).

### 3.5 · Frontend pivot defect — a **case id** used as an endpoint identifier
`XdrInvestigationWorkspacePage.jsx` fell back to
`/edr/device-trajectory?device=<CASE ID>`. A case id is never an endpoint
identifier, so that request could only ever return an empty canvas that
read as *"this case has no activity"*. **Removed** — there is no endpoint
identity in scope there, and inventing one would be worse, so the tab now
reports the absence instead of querying an unsupported identifier.

---

## 4 · Failure semantics (owner Q2 = B), as implemented

| Situation | Result |
|---|---|
| identifier supplied **and** resolvable | evidence, plus `identity.addressed_by` naming every alias queried |
| identifier supplied, **not** tenant-safely resolvable | `state = ENDPOINT_NOT_RESOLVED` · `reason = ENDPOINT_NOT_RESOLVED` · `identity.resolved = false` · note stating this is an authorisation/identity outcome, **not** a statement about the evidence |
| **no** identifier supplied, route contract is a collection | unchanged `200` + collection (proof gate D: `/edr/response/actions` → 31 rows; `/edr/endpoints` → 14 rows) |
| endpoint resolves but the *observation* identifier does not | `OBSERVATION_NOT_RESOLVED` — deliberately a different state from `ENDPOINT_NOT_RESOLVED` |

`/edr/device-trajectory` keeps its three granular reasons
(`identity_unresolved`, `…_endpoint_not_enrolled`,
`…_enrolment_revoked`, `…_never_reported`) **and** now also carries the
uniform `state: ENDPOINT_NOT_RESOLVED`, because the granular reason is
strictly more informative and was already honest.

---

## 5 · Proof — `scripts/p0_2c_alias_site_sweep_proof.py` · 52 PASS · 0 FAIL

**A · Evidence-ID equivalence (not counts).** For `dev_42e8c6dc74b9`,
`ep_2d57cbe6f80152062109` and hostname `agent-env-630704a1-…`, each
surface returns an **identical set of authoritative evidence ids**:

| Surface | Evidence ids compared | Identical | n |
|---|---|---|---|
| process-tree | `nodes[].event_iids` | ✔ | 427 |
| endpoint-detections | `raw_id` + `canonical_event_id` | ✔ | 64 |
| response/actions | `command_id` | ✔ | 31 |
| endpoints/{id}/trajectory | `events[].event_iid` | ✔ | 4000 (page 1) |
| endpoints/{id}/linked-incidents | `incident_id` | ✔ | 4 |
| device-trajectory | `events[].id` (`case::iid`) | ✔ | 6338 |

Each is additionally asserted **non-empty**, so equivalence can never pass
vacuously. No id was fabricated to satisfy a test.

**Aggregate-only / separately-covered surfaces.** `/edr/context` and
`/edr/observation-narrative` expose no evidence-id collection by
contract (one is a context envelope, the other a single-observation
projection). They are proven instead by: resolution state, the disclosed
`addressed_by` alias set, forged-identifier negatives and cross-tenant
negatives. `…/trajectory/focus` resolves exactly ONE observation by
contract, and its equivalence + negatives are already the subject of
`p0_f13_5_detection_handoff_proof` (**25/25**, re-run green on this
change) — it is not duplicated here.
`POST /edr/response/actions` is proven by failure-class
(gate G) because passing it would create a real command record — the
proof deliberately does not mutate the response plane.

**B · Forged identifiers** — 12 gates. Every surface, for both a forged
`dev_…` and a forged `ep_…`, declares `ENDPOINT_NOT_RESOLVED`. **No
surface returns `200 []`.**

**C · Cross-tenant** — 18 gates. `analyst@nivx-live.com` on a `default`
endpoint: 0 evidence ids everywhere, the **same externally observable
failure class as an unknown identifier**, and no hostname or
`endpoint_id` anywhere in the response body. Existence is never
disclosed.

**D · Collection semantics preserved** (Q2b) — 2 gates.

**E · Alias-set disclosure** — 3 gates: every fixed surface reports the
exact identifier set it queried
(`dev_42e8c6dc74b9, agent-env-630704a1-…, ep_2d57cbe6f80152062109`).

**F · Tenant-constrained reverse lookup** — 1 gate (3.4 above).

**G · Command plane alias acceptance** — 4 gates (3.2 above).

---

## 6 · Structural regression guard — design and its honest boundary

`backend/tests/edr/test_p0_2c_alias_invariant.py` (10 tests). Three
independent layers, because no single one is sufficient:

**Layer 1 · AST bypass guard** (`test_no_live_endpoint_keyed_query_bypasses_the_invariant`).
Deliberately **not** a grep for variable names — a future developer only
has to rename a variable to defeat that. It is anchored on the two things
a bypass cannot avoid:
1. the **store** it queries (must be in `ENDPOINT_KEYED_STORES`), and
2. the **identity field** it puts in the filter (must be one the store
   declared).
A call naming both must either be built by `endpoint_predicate` /
`EndpointResolution.predicate` (detected in the enclosing function's call
graph) or be listed in `ALLOWED_RAW_SITES` **with a written reason**
(11 entries, each reason asserted non-trivial and its file asserted to
still exist). Current offenders: **0**.

**Layer 2 · Route-contract test** (`test_every_live_route_resolves_identity`).
The reconciled live-site inventory `LIVE_ENDPOINT_ROUTES` (10 handlers) is
pinned; each must call `resolve_endpoint` itself. A new endpoint-addressed
surface that is not added here fails the test — this is what makes the
inventory reconcile to the proof rather than being a list in a document.

**Layer 3 · Enumeration pin** (`test_the_guard_actually_finds_the_known_query_sites`).
A guard that silently matches nothing is worse than no guard, so both
halves of the enumeration are pinned (≥8 raw sites, ≥8 invariant sites,
and the specific stores that must appear on each side).

Plus 6 unit contracts on the helper: undeclared store rejected,
undeclared field cannot be smuggled in, empty alias set never becomes an
unfiltered read, single- and multi-field predicate shapes, and
`unresolved_envelope` is a state rather than an empty collection.

**HONEST ENFORCEMENT BOUNDARY** (recorded in the test's own docstring):
static analysis cannot see a store or field name assembled at runtime, a
filter dict passed in opaquely from another module, or a dynamically
built aggregation pipeline. Those are covered by the runtime equivalence
proof and the route-contract test, not by Layer 1. The three layers
together are the enforcement; **static enforcement alone does not
guarantee it**, and nobody should read this guard as if it did.
Two known scanner artefacts, disclosed rather than tuned away:
`xdr_search.py:153` matches on a *projection* key (not a filter) and is
harmless; two unrelated `.predicate(` calls
(`detection_content/library/models.py`, `services/confidence_provenance.py`)
appear in the positive half and name no store.

---

## 7 · Legacy / unwired classification (owner Q1 = B)

Every lineage was enumerated; **none was modified**.

| Lineage | Endpoint-keyed query sites | Class |
|---|---|---|
| `backend/nivxforge/` (name collision, not the EDR backend) | 0 | `LEGACY_UNWIRED` |
| `backend/l1_evidence/`, `l2_investigation/`, `workspace/`, `reasoning/` | 0 | `LEGACY_UNWIRED` |
| `v2/trajectory/device.py` (+ `GET /api/v2/cases/{id}/trajectory/device`) | 1, in-memory | **`NOT_APPLICABLE`** — live and routed, but keyed on the **case**; the `device_iid` is derived from the case's own persisted events, never supplied by the caller |
| `edr_plane/enrollment/*` | 12 | **`NOT_APPLICABLE`** — sensor-side; identity comes from the AUTHENTICATED session. Resolving a caller alias here would *weaken* it |
| `edr_plane/campaign_story.py` | 3 | **`NOT_APPLICABLE`** — identity read from the already-authorised incident record |
| `detection_content/xdr_*`, `services/iue`, `services/report`, … (67 live calls) | incident/evidence-keyed | **`NOT_APPLICABLE`** |

No site was reclassified `LOAD_BEARING_LEGACY`, because no legacy lineage
queries an endpoint-keyed store at all.

---

## 8 · Frontend pivot contracts (14 audited)

**XDR → EDR (5)** — `OpenInEdr.buildEdrPivot` (the single builder:
carries `device|endpointId`, `incident_id`, `detection_id`,
`raw_event_id`, `canonical_event_id`, `event`, `process_iid`, `at`, and
`tenant` **declared for traceability only** — the EDR side reads the
customer from the server-resolved session/incident, never from the
parameter) · `xdr/components/Pivot.jsx` → `/edr/trajectory?device=` ·
`XdrIncidentDetailPage` → `endpoint_campaign.endpoint_id` ·
`XdrEndpointsPage` / `XdrEntity360Page` → `device_iid` ·
`XdrFleetFileTrajectoryPage` → `/xdr/endpoints/:device/trajectory`.

**EDR → XDR (4)** — `Investigate in NivXRay XDR` ·
`EdrDetectionsPage` → `/xdr/edr/device-trajectory?device=…` (permanent
redirect, whole query string preserved) · `EdrCampaignStoryPage` →
`/edr/trajectory?device=` and `/edr/detections?endpoint_id=` ·
`LinkedXdrIncidents` → `/xdr/incidents/:id`.

**Within EDR (5)** — `EdrResponsePage` (`{endpoint_id: ctx.device}`) ·
`EdrDeviceTrajectoryPage` endpoint picker · `pivots.js`
`buildProcessTreePivot` · `edrApi.listEndpointDetections` /
`getEndpointProcessTree` / `getDeviceTrajectory` /
`getObservationNarrative` · `EdrTrajectoryResolver`
(`?device_iid=` / `?device=` / `?incident_id=`).

Findings: the frontend correctly does **not** canonicalise identity
itself (the backend contract accepts aliases). `EdrDetectionsPage` and
`EdrProcessTreePage` accept **both** `?endpoint_id=` and `?device=`, so
every pivot spelling lands. **One defect found and fixed** (§3.5). No
pivot strips endpoint context, substitutes a hostname unnecessarily, or
loses tenant context.

---

## 9 · Regression — no baseline reset, no silent exclusion

| Gate | Result |
|---|---|
| `x1_x3_xdr_integration_proof` | **22/22** |
| `p0_f13_5_detection_handoff_proof` | **25/25** |
| `p0_detection_attribution_proof` | **12/12** |
| `p0_w_f1_f2_wiring_proof` | **27/27** |
| `p0_w_incident_tenant_authorization_proof` | **25/25** |
| `p01_response_service_deploy_proof` | **37 PASS · 0 FAIL · 2 BLOCKED** |
| response engine tests (`apps/nivxray-xdr-response`) | **27 passed** |
| `backend/tests/edr` | **340 passed · 3 failed** (330 + 10 new; the same 3 `test_p0_f4`) |
| `tests/test_xdr_incident_queue.py` + `tests/test_xdr_mss.py` | 27 passed · 2 failed (baselined) |
| `p0_f11_trajectory_window_proof` | **22/24** — see below |

**`test_p0_f4` (3 failures): UNTOUCHED, unchanged in identity and cause**
(they seed *unenrolled* endpoints, so the identity gate answers
`ENDPOINT_NOT_RESOLVED`). Not absorbed, not baseline-reset. One cosmetic
note: `test_an_unknown_endpoint_yields_no_fabricated_tree` now fails as an
`AssertionError` (`'ENDPOINT_NOT_RESOLVED' != 'no_matching_evidence'`)
because the unresolved envelope carries a `reason` key. Same test, same
cause. **The alias sweep did NOT prove any of the three is caused by
alias resolution**, so no F-4 classification changed and no collector
work was mixed in.

**`p0_f11_trajectory_window_proof` reads 22/24 — PRE-EXISTING PROOF DRIFT,
NOT A REGRESSION, and I am flagging it rather than quietly re-running it.**
The two `NOT PROVEN` gates are `process lanes are ordered by lineage
depth` and `an unobserved parent is declared, not invented`. Verified
against `git diff HEAD`: `build_lane_catalogue` — which produces `depth`
and `parent_state` — is **not touched by this pass**. The lane axis
became depth-**first** (lineage tree order) in P0-F.12/F.13, so `depth`
is legitimately non-monotonic (`0,1,1,1,1,2,3,4,4,4,2,3`), and
`parent_state` was refined from `NOT_OBSERVED` to the more specific
`PARENT_NOT_OBSERVED_VISIBILITY_GAP` / `PARENT_NOT_REPORTED_BY_SENSOR`.
The proof script still asserts the older contract. Same class as the
`test_p0_f4` trio: **script drift, separately classified, deliberately
not repaired here.**

---

## 10 · Adjacent finding — NOT fixed here, needs an owner decision

While smoke-checking the console, `/edr/process-tree?device=dev_42e8c6dc74b9`
rendered **"NO MATCHING EVIDENCE"**. This is **not** an alias failure —
alias resolution is correct and proven:

```
GET /api/edr/process-tree?endpoint_id=dev_42e8c6dc74b9
  hours=24  → 0   nodes · no_matching_evidence
  hours=48  → 439 nodes · ok
  hours=720 → 439 nodes · ok
```

There are **two distinct problems behind that one screen**, and both are
outside the alias invariant:

1. **`WINDOW_HONESTY_GAP` (P0-3 dependency).** The page's window is 24 h
   and the sensor's last delivery was `2026-09-06T15:46Z`, so the evidence
   sits just outside it. The statement is *true for the window* but it
   does not tell the analyst that **439 nodes exist 25 hours away**. The
   root cause is the sensor blindness P0-3 owns; the disclosure ("0 in the
   last 24 h · N observed outside this window") should be built with it.
2. **`EdrProcessTreePage` ignores `?hours=` entirely.**
   `getEndpointProcessTree(endpointId)` always sends the default
   `hours=24`, and the page exposes no window control — so
   `?hours=720` in the URL changes nothing and the analyst **cannot
   widen the window at all** from the console. Verified above: the same
   request at `hours=48` returns 439 nodes.

Neither was changed in this pass: (1) belongs to P0-3 and (2) is a UI
capability the owner has not asked for. **Both are disclosed here rather
than left for the owner to find on the same URL as last time.**
Recommended: fold (2) into P0-3 so the window control and the
out-of-window count land together, since the count has to come from the
backend anyway.

---

## 11 · The CONSUMER half — found by the frontend test agent (iteration_106), fixed

`iteration_106` returned 6/7 with one **MEDIUM** finding that was
correct and important: the backend said `ENDPOINT_NOT_RESOLVED`, and the
console **ignored it**. `/edr/response?device=dev_ffffffffffff` rendered
*"No endpoint command records in scope…"* and
`/edr/detections?endpoint_id=dev_ffffffffffff` rendered *"NO RULE
FIRED"* — visually indistinguishable from a real endpoint that
legitimately has none. **The invariant is worthless if its consumer
re-creates the ambiguity**, so this was fixed rather than deferred.
`/edr/process-tree` was worse: on an unresolved endpoint neither render
branch matched, so it drew **nothing at all**.

New `apps/nivxray-xdr/src/nivxforge/components/EndpointNotResolved.jsx`:
- `notResolved(payload)` reads the invariant's **own state field**
  (`state` / `reason` / `epistemic_state.state`). It **never infers
  unresolved from an empty collection**, because an empty collection is a
  legitimate answer for a resolved endpoint.
- One banner, `data-testid="edr-endpoint-not-resolved"`,
  `data-state="ENDPOINT_NOT_RESOLVED"`, carrying the literal token, the
  plain-English line *"No endpoint that this identifier resolves to."*,
  the reference that failed, and the backend's own note verbatim.
- Wired into **Response**, **Detections** and **Process Tree**. The
  response page's count now reads `ENDPOINT_NOT_RESOLVED` instead of
  `0 of 0`.

Re-verified live: forged `dev_ffffffffffff` → banner on all three
surfaces (`0 of 0` gone); real `dev_42e8c6dc74b9` → unchanged **33 of
33**; and `analyst@nivx-live.com` on the `default` endpoint gets the
**identical banner** — the same observable failure class as an unknown
identifier, with **no** hostname and **no** `endpoint_id` in the DOM.
The Device Trajectory page was already honest here (its P0-F.11
`epistemic_state` empty state) and was not changed.

## 12 · Files changed

| File | Change |
|---|---|
| `backend/services/edr/endpoint_query.py` | **NEW** — the invariant, the store contract, the unresolved envelope |
| `backend/services/edr/device_identity.py` | `identity_refs(..., tenant_ids=)` tenant-constrained reverse lookup (§3.4); `_addresses()` matches all four declared identity keys; `observations()` / `find_observation()` accept the validated alias set |
| `backend/edr_plane/trajectory_window.py` | `_projected(..., refs=)` + `query_window(..., refs=)`; both store queries built by the invariant; projection cache key includes the alias set |
| `backend/routers/edr.py` | 8 handlers moved onto `resolve_endpoint` / `.predicate()`; `linked-incidents` ref list replaced (§3.1); uniform `ENDPOINT_NOT_RESOLVED`; `addressed_by` disclosed |
| `backend/routers/edr_response.py` | `list_actions` via the invariant; **new** `_canonical_endpoint_id` for the command plane (§3.2) |
| `backend/edr_plane/response.py` | `_resolve_kill_target` + `list_commands` predicates built from the declared fields |
| `backend/routers/xdr_search.py` | detection search predicate built from the declared field |
| `backend/tests/edr/test_p0_2c_alias_invariant.py` | **NEW** — the 3-layer structural guard (10 tests) |
| `scripts/p0_2c_alias_site_sweep_proof.py` | **NEW** — 52-gate runtime proof |
| `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx` | pivot defect removed (§3.5) |
| `apps/nivxray-xdr/src/nivxforge/components/EndpointNotResolved.jsx` | **NEW** — the consumer half of the invariant (§11) |
| `apps/nivxray-xdr/src/nivxforge/pages/EdrResponsePage.jsx` · `EdrDetectionsPage.jsx` · `EdrProcessTreePage.jsx` | render the explicit unresolved state instead of a false-honest empty state |

## 13 · Intentionally NOT changed

- `edr_plane/enrollment/*` — sensor-side identity comes from the
  authenticated session. Alias resolution here would weaken authentication.
- `edr_plane/campaign_story.py` — identity read from the already-authorised
  incident record; there is no external alias.
- `v2/trajectory/device.py` + `/api/v2/cases/{id}/trajectory/device` —
  case-keyed; `device_iid` derived from the case's own events.
- All `LEGACY_UNWIRED` lineages — zero endpoint-keyed query sites, so
  nothing to change (Q1 = B).
- The 3 `test_p0_f4` failures and the 2 `p0_f11` script-drift gates.
- The 6 baselined queue/lens/MSS failures.
- **Nothing about isolation enforcement**: still `BLOCKED_ENVIRONMENT`
  (`CAP_NET_ADMIN`), never simulated.

## 14 · Stop condition — met

All **10** live endpoint-addressed surfaces either resolve through the
authoritative tenant-scoped resolver (10/10) or are proven
`NOT_APPLICABLE` with a recorded reason (the 67 non-endpoint-keyed live
calls, the sensor-side plane, the case-keyed plane). The enumerated
live-site inventory is **pinned in code** (`LIVE_ENDPOINT_ROUTES`) and
reconciles to the proof; the bypass count is **0**; and adding an
eleventh surface without resolution fails a test.

**Next per the owner's fixed order: `P0-3 SENSOR RECOVERY`.** Not Release
Isolation.
