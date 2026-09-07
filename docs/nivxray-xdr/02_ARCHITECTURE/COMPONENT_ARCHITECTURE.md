<!-- NIVX-DOC
layer: TARGET_SPEC
status: AUTHORED
-->

> **TARGET** component model. Maturity is stated per component.
> Generated inventories: `08_VALIDATION/GENERATED_*`.

# COMPONENT ARCHITECTURE

Adopts `memory/MASTER_OWNERSHIP_AUDIT.md` (1207 lines) and
`memory/NivXRay_360_Architecture.md`.

## 0 · What a component is

> **A route is not a component. An engine package is not automatically a
> product capability. A UI page is not proof of an operational
> component.** — owner rule, 2026-06

A first-class component has **all** of: purpose · authoritative owner ·
inputs · outputs · SSOT · API · runtime · upstream · downstream · UI
consumer · health · failure states · security boundary · proof · release
gate. Anything lacking these is classified `ORPHAN`,
`LEGACY_UNWIRED` or `LOAD_BEARING_LEGACY`.

The scale problem this document exists to solve, from the generated
inventories: **865 live API routes · 64 declared engine identities · 58
UI routes · 135 catalogued capabilities.** Those are four different
counts of four different things, and none of them is a count of
components.

> These four numbers are **generated**, not hand-written, and
> `scripts/docs_reconcile.py` fails if this document disagrees with the
> runtime. They are quoted here only because the whole point of the
> component model is to reconcile them.

## 1 · First-class components

### C1 · Endpoint Acquisition (NivXForge EDR)
| | |
|---|---|
| Purpose | acquire real endpoint evidence |
| Owner | NivXForge EDR |
| Inputs | OS primitives (`/proc`, file events, sockets) |
| Outputs | telemetry batches to `/api/edr/agent/telemetry` |
| SSOT | the authenticated enrolment session |
| API | `/api/edr/agent/{enroll,session,telemetry,commands,command-result,command-verification}` |
| Runtime | `agents/nivxforge-linux/nivxforge_sensor.py` (v0.1.0) |
| Upstream | none — it is the origin |
| Downstream | C2 |
| UI consumer | EDR inventory, trajectory, process tree |
| Health | last-delivery timestamp per endpoint |
| Failure states | queue backlog, transport failure, auth failure, silence |
| Security boundary | agent credential; identity is the session, never caller input |
| Proof | `scripts/p0_b_sensor_proof.py`; real events delivered from 2 endpoints |
| Maturity | `REAL_ENDPOINT_VALIDATED` — **Linux only**; Windows and macOS have no producer |
| Gap | **silence raises no alert** (see C13) |

### C2 · Ingest & Normalisation
| | |
|---|---|
| Purpose | accept, validate, attribute and normalise evidence |
| Owner | shared platform |
| SSOT | `edr_raw_events` (immutable, as-presented) → `xdr_canonical_events` |
| Downstream | C3, C4, C6 |
| Failure states | rejected telemetry (recorded, not discarded), unattributable tenant |
| Security boundary | tenant attribution at ingest; a sensor cannot claim another tenant |
| Maturity | `END_TO_END_VALIDATED` |

### C3 · Endpoint Identity & Assets
| | |
|---|---|
| Purpose | one endpoint identity from many aliases, per customer |
| Owner | shared platform |
| SSOT | `edr_endpoints` + `services/edr/device_identity.py` |
| API | resolution is internal; every endpoint-addressed route consumes it |
| Contract | `services/edr/endpoint_query.py` declares every endpoint-keyed store and its identity fields |
| Failure states | `ENDPOINT_NOT_RESOLVED` — explicit, never an empty result |
| Security boundary | tenant-constrained reverse lookup; a foreign identifier is indistinguishable from an unknown one |
| Proof | `scripts/p0_2c_alias_site_sweep_proof.py` (52 gates); AST + route-contract guard |
| Maturity | `OPERATIONAL` |
| Missing | **asset criticality / business context** — no source exists |

### C4 · Detection Fabric
| | |
|---|---|
| SSOT | `xdr_detection_rules` (98 rules, 5 sources) |
| Outputs | detections attributed to `raw_id` + `canonical_event_id` |
| Failure states | rule cannot evaluate (missing field) must be recorded as *not evaluated*, never as *no detection* |
| Proof | `scripts/p0_detection_attribution_proof.py` (12 gates) |
| Maturity | `REAL_ENDPOINT_VALIDATED` |
| Unknown | how many of the 98 rules assume Windows/Sysmon fields and therefore cannot fire on Linux telemetry |

### C5 · Correlation & Prioritisation
| | |
|---|---|
| SSOT | `xdr_correlation_rules` (10 rules) |
| Maturity | `BACKEND_IMPLEMENTED` |
| Honest limit | **one telemetry domain exists**, so cross-domain correlation is not demonstrable and any rule needing two domains silently never fires |
| Missing | asset-value input to prioritisation |

### C6 · Evidence & Investigation Plane
| | |
|---|---|
| Components | IUE · IKG / evidence graph · trajectory · process ancestry · verdict · security state · causal FSM |
| UI consumer | XDR Investigation Workspace; EDR trajectory/process tree |
| SSOT | **OPEN QUESTION** — IUE record vs `workspace_cases` (inherited, unresolved) |
| Maturity | `END_TO_END_VALIDATED` behaviourally; `GOLDEN_CORPUS_VALIDATED` for verdict |
| Highest risk | causal/counterfactual surfaces have **no evidentiary standard** — the largest over-claim exposure in the product |

### C7 · Incident Plane
| | |
|---|---|
| SSOT | `workspace_cases`; worklog is `incident_state_history[]`, append-only, **the only worklog** |
| Security boundary | strict tenant scope (a cross-tenant IDOR was found and closed here) |
| Proof | `scripts/p0_w_incident_tenant_authorization_proof.py` (25 gates) |
| Maturity | `OPERATIONAL` |
| Gap | **no provenance label** — real and seeded incidents are indistinguishable |

### C8 · Response Coordination (XDR) + C9 · Response Execution (EDR)
| | C8 XDR | C9 EDR / source product |
|---|---|---|
| Purpose | recommend, orchestrate, approve, record | execute and verify |
| Runtime | `apps/nivxray-xdr-response` `:8056`; boundary `routers/xdr_respond_boundary.py` | `edr_plane/response.py` + sensor |
| SSOT | execution store (SQLite) | the endpoint itself |
| Lifecycle | `REQUESTED → APPROVED → DISPATCHED → EXECUTING → EXECUTED → VERIFIED` | — |
| Invariant | **only `VERIFIED` is backed by post-action evidence**; a stub may never be marked executed | verification probe must carry the target's **process start identity**, so a recycled PID cannot be mistaken for the target |
| Failure states | `CAPABILITY_UNAVAILABLE`, `VERIFICATION_FAILED`, `FAILED` — all real, all recorded | — |
| Proof | `scripts/p01_response_service_deploy_proof.py` (37 pass, 2 blocked) | 5 `VERIFIED`, 1 `VERIFICATION_FAILED` on a real endpoint |
| Maturity | `OPERATIONAL` for `KILL_PROCESS` on Linux | isolation `BLOCKED_ENVIRONMENT` (no `CAP_NET_ADMIN`), never simulated |
| Debt | **18 actions catalogued, 2 operational, 16 `NON_OPERATIONAL` stubs** | — |

### C10 · Intelligence
7 live IOC providers. `OPERATIONAL`. Must never degrade to `clean`;
staleness and provider failure must be disclosed.

### C11 · Integration Plane
Collector `:8055`, vendor wizard, data sources.
`BACKEND_IMPLEMENTED`. **Known split-brain (P0-4): reported collector
status can differ from reality**, so integration health is not currently
trustworthy for administration decisions.

### C12 · Identity, Tenancy & Audit
Auth, RBAC, tenant scope, `xdr_audit_log`. `OPERATIONAL` where proven;
route coverage across 865 routes is not systematically proven. Tenant
scoping should become a **guarded** invariant like C3.

### C13 · Observability — MISSING
`NOT_IMPLEMENTED`. Structured logging exists; **nothing alerts on going
blind.** The platform lost telemetry for over 24 hours silently. This is
the component whose absence caused the most damage in this programme.

### C14 · Analyst Consoles
Two shells, 58 routes (42 XDR · 13 EDR · 3 shared). Consumers only —
they must own no truth. The `EndpointNotResolved` component is the
reference pattern: render the backend's declared state, never
reinterpret an absence.

## 2 · Component ↔ inventory reconciliation

| Inventory | Count | Reconciliation obligation |
|---|---|---|
| API routes | 865 | every route belongs to exactly one component, or is `ORPHAN` |
| Engine identities | 64 | every engine maps to a component with a UI consumer, or is `LEGACY_UNWIRED` |
| UI routes | 58 | every route maps to a screen spec and authoritative APIs |
| Capabilities | 135 | every capability names its owning component |

**This reconciliation is not yet done** — it is the first task after
owner approval, and it is the mechanism by which sprawl becomes a
decision list (`ADOPT` / `WIRE` / `CONSOLIDATE` / `EXTEND` /
`DEPRECATE` / `REMOVE_LATER` / `BUILD`) rather than a number.

## 3 · Classification of everything not first-class

| Class | Meaning | Action |
|---|---|---|
| `AUTHORITATIVE` | the SSOT for its stage | protect |
| `SHARED` | used by both products | keep shared, never fork |
| `ADOPT` | exists, works, use it | wire consumers |
| `WIRE` | exists, not connected | connect |
| `CONSOLIDATE` | duplicate lineage | merge |
| `EXTEND` | exists, insufficient | extend |
| `DUPLICATE` | second implementation of an SSOT | **architecture violation** |
| `ORPHAN` | no consumer, no owner | deprecate |
| `LEGACY_LOAD_BEARING` | old but still imported/routed | treat as live |
| `LEGACY_UNWIRED` | old and unreachable | leave; do not modify |
