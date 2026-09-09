<!-- NIVX-DOC
layer: TARGET_SPEC
status: AUTHORED
-->

> **TARGET** architecture. Where a stage is not yet real, its maturity is
> stated inline. Authoritative current-state numbers:
> `08_VALIDATION/REALITY_MATRIX.md` (generated).

# SYSTEM ARCHITECTURE

Adopts `memory/ARCHITECTURE_v2.md` (828 lines) and `memory/ARCHITECTURE.md`.
Provenance: `01_REFERENCE/DOC_PROVENANCE_LEDGER.md`.

## 1 · Architecture lock (non-negotiable)

**NivXRay XDR and NivXForge EDR are separate products with separate
logins, shells and rails, sharing one authoritative backend foundation.**

| | NivXRay XDR owns | NivXForge EDR owns |
|---|---|---|
| | cross-domain correlation, investigation, intelligence, incidents, prioritisation, orchestration, master response coordination | endpoint acquisition, endpoint detections, trajectory, process tree, live endpoint evidence, endpoint response **execution and verification** |

**XDR may orchestrate EDR. XDR must never duplicate EDR.**
This is what makes a second domain addable without rewriting the first.

## 2 · Plane model

```
                          NIVXRAY XDR
                               │
   ┌───────────────────────────┼───────────────────────────┐
   │                           │                           │
CONTROL PLANE           INTELLIGENCE PLANE            DATA PLANE
auth / RBAC             canonical evidence            connectors
tenancy                 IUE                           sensors
integrations            correlation                   APIs
policy                  verdict                       webhooks
approvals               IKG / evidence graph          syslog / CEF
automation              security state                files / batch
response coordination   causal intelligence           streaming
audit                   reachability
                        counterfactual
                        intervention optimiser
                               │
                               ▼
                        INCIDENT PLANE
        detection → correlation → prioritisation → incident
             → investigation → response → verification
                    → recomputed security state
```

Beneath the platform, every source is an implementation of **one**
integration contract (`02_ARCHITECTURE/INTEGRATION_ARCHITECTURE.md`):

```
NivXForge EDR ─┐   ├─ Linux sensor    REAL_ENDPOINT_VALIDATED
               │   └─ Windows sensor  NOT_IMPLEMENTED (no producer)
Network / NDR ─┤
DNS / SWG ─────┤
Email ─────────┼── INTEGRATION CONTRACT ──► COMMON PLATFORM APIs
Identity ──────┤
Cloud ─────────┤
SIEM ──────────┤
3rd-party EDR ─┤
Threat intel ──┘   OPERATIONAL (7 providers)
```

## 3 · The authoritative chain, with one SSOT per stage

Every stage names the **one** component allowed to be authoritative. A
second writer to any of these is an architecture violation.

| # | Stage | SSOT / authority | Maturity |
|---|---|---|---|
| 1 | acquisition | the producer's authenticated session | `REAL_ENDPOINT_VALIDATED` (Linux only) |
| 2 | parsing | `edr_raw_events` (raw, immutable, as-presented) | `END_TO_END_VALIDATED` |
| 3 | normalisation | normalisation pipeline | `END_TO_END_VALIDATED` |
| 4 | provenance | provenance stamped at normalisation | `OPERATIONAL` for events · **absent for incidents** |
| 5 | canonical evidence | `xdr_canonical_events` | `OPERATIONAL` |
| 6 | enrichment | enrichment + IOC providers | `OPERATIONAL` |
| 7 | detection | detection fabric (98 rules) | `REAL_ENDPOINT_VALIDATED` |
| 8 | correlation | correlation engine (10 rules) | `BACKEND_IMPLEMENTED` — **cannot be judged with one domain** |
| 9 | security state | security-state engine | `BACKEND_IMPLEMENTED` |
| 10 | causal reasoning | causal FSM | `BACKEND_IMPLEMENTED` — **no evidentiary standard yet** |
| 11 | prioritisation | prioritisation engine | `BACKEND_IMPLEMENTED` — no asset-value input |
| 12 | incident | `workspace_cases` | `OPERATIONAL` |
| 13 | investigation | **OPEN QUESTION** — IUE record or `workspace_cases`? | `END_TO_END_VALIDATED` in behaviour, unresolved in authority |
| 14 | intelligence | provider cache with provenance | `OPERATIONAL` |
| 15 | automation | approval lifecycle | approval `BACKEND_IMPLEMENTED`; engine `NOT_IMPLEMENTED` |
| 16 | approval | response service (`:8056`) | `OPERATIONAL` |
| 17 | response execution | the **source product**, never the platform | `OPERATIONAL` (`KILL_PROCESS`/Linux) |
| 18 | verification | independent probe bound to target identity | `OPERATIONAL` |
| 19 | evidence of outcome | `xdr_audit_log` | `OPERATIONAL` |
| 20 | recomputed security state | security-state engine | `BACKEND_IMPLEMENTED` |

**Stage 13 is an inherited unresolved question**, carried forward from
`memory/IUE_INVESTIGATION_SSOT_RECONCILIATION.md` rather than quietly
closed. See `INVESTIGATION_ARCHITECTURE.md`.

## 4 · Runtime topology

| Service | Port | Role | Supervisor |
|---|---|---|---|
| backend (FastAPI) | `8001` | platform APIs, all planes | yes |
| frontend (React) | `3000` | both consoles (`/xdr/*`, `/edr/*`) | yes |
| collector | `8055` | standalone syslog/CEF landing | yes |
| response service | `8056` | approval → dispatch → execute → verify lifecycle | yes |
| MongoDB | — | platform stores | external |
| response SSOT | — | SQLite execution store inside the response service | — |

All routes reach the backend via the `/api` prefix. **This is a preview
topology, not a production topology** — production topology is
`SPEC_PENDING` in `05_OPERATIONS/DEPLOYMENT_GUIDE.md`.

## 5 · API-first doctrine (NivXRay doctrine, adopted independently)

```
CAPABILITY → CONTRACT → API → REAL DATA / REAL EXECUTION → VALIDATION → UI
```

Explicitly **not**:

```
beautiful UI → fake objects → figure out the backend later
```

Cisco attribution for this pattern is `OWNER_ASSERTED` and unverified
(`SOURCE_REGISTER` A10); we adopt it on our own evidence. This repository
has a very large API surface against a small operational core (exact
counts: `08_VALIDATION/REALITY_MATRIX.md`), and the recurring defect
class has been *surfaces asserting
more than their API can prove*. API-first is the fix for our own observed
failure mode, not an imitation.

Consequences, enforced:

- **No React component may invent data.** No detections, asset counts,
  incidents, integration status, response status or severity decided
  client-side.
- **No surface may convert a named absence into an empty result.** The
  reference implementation is the `ENDPOINT_NOT_RESOLVED` contract:
  backend declares the state, three EDR surfaces render it explicitly.
- **A route is not a component.** An engine package is not automatically
  a capability. A UI page is not proof of an operational component.

## 6 · Invariants (guarded, not reviewed)

The programme's most durable lesson: a rule enforced by review recurs; a
rule enforced by a guard does not.

| Invariant | Enforcement | Status |
|---|---|---|
| **Endpoint identity resolution** — external identifier → tenant-scoped resolution → canonical identity + validated alias set → query | declared store contract + AST bypass guard + route-contract test + runtime proof | **guarded** (`backend/tests/edr/test_p0_2c_alias_invariant.py`) |
| **Response honesty** — no state may claim success without independent verification bound to target identity | lifecycle state machine + verification probe | **guarded** |
| **Single worklog SSOT** — `incident_state_history[]` only | review | *review-enforced* |
| **Tenant scoping on every route** | review | *review-enforced* — **should be guarded next** |
| **Documentation cannot contradict runtime** | `scripts/docs_reconcile.py` | **guarded** |

## 7 · Known architectural debt

1. **865 routes, no published convention or error taxonomy.** Surface
   area was built ahead of operational wiring.
2. **Two design authorities** (`NIVXRAY_VISUAL_GRAMMAR` +
   `VISUAL_LANGUAGE`), never diffed.
3. **Stage 13 investigation SSOT unresolved.**
4. **Integration health is not trustworthy** until the collector
   split-brain (P0-4) closes.
5. **No observability on going blind.** The platform lost telemetry for
   over 24 hours and nothing alerted. This is the strongest single
   argument for `05_OPERATIONS/OBSERVABILITY_GUIDE.md`.
6. **Incidents carry no provenance**, so real and seeded cannot be
   distinguished. Small fix, disproportionate value.
