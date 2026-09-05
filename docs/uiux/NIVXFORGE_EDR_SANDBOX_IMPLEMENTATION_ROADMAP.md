# NIVXFORGE EDR + SANDBOX — IMPLEMENTATION ROADMAP

**Document ID**: `NIVXFORGE-EDR-SANDBOX-ROADMAP-2026-09-05`
**Premise**: sequencing starts from the **honest current state** — 4 read-only EDR
APIs, **0 resolvable devices**, 639 IRG observations of which 223 carry a real
`device_iid`, operational static analysis + 59 decoders, zero sandbox runtime —
**not** from the aspirational 37-surface IA.

**Non-negotiables for every phase**
- No mock telemetry. No fabricated endpoint identity. No fabricated detonation.
- No second reasoning, correlation, verdict, evidence-store or trajectory engine.
- No weakening of tenant isolation.
- The frozen 615 content corpus and decoder truth are untouched.
- Any surface without a real backing engine renders `⊘ CAPABILITY UNAVAILABLE`.

---

## PHASE 1 · Make the endpoint plane true — *first*
**Why first**: every downstream EDR surface is worthless while zero devices
resolve. This phase adds **no new telemetry** — it binds the UI to a substrate
that already exists.

| # | Work item | Change | Acceptance test |
|---|---|---|---|
| 1.1 | Register `/edr/trajectory` as a **resolver route** | `App.jsx` — with `?device=`/`?device_iid=` redirect to `/xdr/endpoints/:device/trajectory`; with only `?incident_id=` resolve the incident's endpoint entity then redirect; with nothing resolvable render `⊘ CAPABILITY UNAVAILABLE — NO ENDPOINT ENTITY` (never a silent bounce to the queue) | all 7 existing call sites (`Pivot.jsx` ×2, `EdrProcessTreePage`, `EdrDetectionsPage`, `EdrOverviewPage`, `NivXForgeConsole`, `InvestigationTab`) land on the canvas or on an explicit unavailable state — never on `/xdr/incidents` |
| 1.2 | **Device Identity Resolution (DIR)** read service | new read-only projection over `v2_shadow_observations.event.device_iid` (223 populated) → `{device_iid, hostname?, identity_confidence: OBSERVED\|INFERRED, case_ids[], first_seen, last_seen, lane_counts}` | returns ≥1 device for the admin tenant; every row carries `device_iid` or is explicitly `INFERRED` |
| 1.3 | Re-bind `GET /api/edr/endpoints` | keep the SSOT-host path as a secondary source; make DIR the primary. Remove the assumption that `ssot.investigation_object.host` exists | live call returns `count > 0` with truthful provenance per row |
| 1.4 | Re-bind the trajectory canvas | `device_iid`-first addressing; hostname only as `INFERRED` with the pill; drop the `case_id == device_iid` assumption in `XdrIncidentDomainPage.jsx:103` | opening trajectory from an incident lands on that incident's real endpoint entity |
| 1.5 | Tenant scoping correction | `/api/edr/*` uses `resolve_tenant_scope()` (the helper the fixed incident queue uses) instead of raw `user_email`; normalise host matching | cross-tenant probe returns 0 leaked rows (`backend/tests/edr/test_cross_tenant.py` extended) |
| 1.6 | **Zero-device honest state** as a first-class screen | render the exact backend `reason` (`no_matching_evidence`), the ◆/◇/⊘ counters, and a bridge to the IRG observation plane. Never invent `workstation-01` | with DIR disabled the screen states the truth and offers a real next action |

**Phase 1 exit criterion**: an analyst can go
`Incident → Endpoint Entity → NivXForge EDR → Device Trajectory` and see **real**
`device_iid`-addressed activity, or an honest declaration of why not.

---

## PHASE 2 · Endpoint investigation lanes — *second*
**Why second**: the IRG kinds for these lanes are already persisted
(`file_create/write/delete`, `registry_value_set`, `network_connect/listen`,
`service_install`, `memory_alloc`, `kernel_event`). This is projection work, not
sensor work.

| # | Work item | Availability after |
|---|---|---|
| 2.1 | File lane surface + API (projection over IRG file kinds) | `LIVE` |
| 2.2 | Network lane surface + API (`network_connect/listen`) | `LIVE` |
| 2.3 | Registry lane surface + API (`registry_value_set`) | `LIVE` |
| 2.4 | Services / modules lane | `LIVE` (services) / `⊘` (modules — no substrate) |
| 2.5 | Process ancestry / causality canvas fed by `irg_enrich()` parent/root IIDs (Cortex CGO pattern, NivXRay grammar) | `LIVE` |
| 2.6 | Entity 360 aggregate for a device (lanes + detections + verdict + response history) | `LIVE` |
| 2.7 | Timeline scrubber + tri-pane sync on the trajectory canvas | `LIVE` |
| 2.8 | Upgrade the 6 reserved pages from "Reserved · later slice" to the `⊘ CAPABILITY UNAVAILABLE` grammar with the named missing engine | honest |

**Phase 2 exit criterion**: five investigation lanes render real observations with
provenance, and every non-backed surface names the engine it is waiting for.

---

## PHASE 3 · Search, response truth, and the static sandbox report — *third*

| # | Work item | Notes |
|---|---|---|
| 3.1 | Event search over `v2_shadow_observations` + `xdr_canonical_events` | start with a deterministic field/predicate filter, not a new query language. Saved hunts follow. |
| 3.2 | Response execution truth pass | audit `response/adapters.py` stubs; every action either has a real driver or renders `⊘ CAPABILITY UNAVAILABLE`. Never show a stub as executed. Approval → Execution → **Verification** → Audit must be provable end-to-end. |
| 3.3 | **Sandbox: Static Detonation Report** (`HYBRID` surface) | ship the *credible half* now — the 6 real analyzers + 59 decoders + static verdict + IOC/C2 extraction, presented in the sandbox IA. Every dynamic tab renders `⊘ DYNAMIC DETONATION ENGINE NOT IMPLEMENTED · DESIGN ONLY`. No synthetic PIDs, no fake PCAP, no fake screenshots. |
| 3.4 | Sandbox submission + artifact-router view | routes real artifacts to real static analysis; the "runtime required?" branch terminates in an honest unavailable state. |
| 3.5 | IKG write-path design document | design only, no code (already on the backlog). |

---

## PHASE 4 · Forensics, live query, memory *(P2 — requires an agent)*
Blocked on a sensor. Until an agent exists these remain `DESIGN-READY` and must
render `⊘`. Sequence when unblocked: forensic snapshot → MFT/prefetch/shimcache →
event logs → persistence → memory acquisition → live query with approval.

## PHASE 5 · Dynamic sandbox *(P2/P3 — largest single build)*
microVM orchestrator → kernel API tracing → network simulation (fake DNS / HTTP
sinkhole / TLS inspection) → dynamic telemetry → **canonical evidence ingestion
into the existing spine** → interactive VM → screenshots/replay → anti-evasion →
multi-OS. The convergence bridge is the differentiator; build it first inside
this phase, not last.

## PHASE 6 · Agent / sensor plane *(P2)*
Enrollment + TLS identity + heartbeat + health + update rings + policy manager.
This is what converts the whole EDR plane from projection to live telemetry.

---

## Sequencing rationale in one line each
1. **Phase 1** — nothing else matters while 0 devices resolve, and the fix needs no new data.
2. **Phase 2** — the lane substrate is already persisted; this is the cheapest parity gain available.
3. **Phase 3** — search and response truth are what SOC analysts actually use daily; the static sandbox report is real value with zero fabrication.
4. **Phases 4–6** — genuinely require new engines and hardware boundaries; they must not be faked earlier to look complete.

## Explicitly deferred (owner instruction)
Queue bulk row actions, saved searches, and number deep links remain deferred.
Counterfactual defence projection, UBAE, and the `mal-20` false-negative fix
remain P2 backlog items.
