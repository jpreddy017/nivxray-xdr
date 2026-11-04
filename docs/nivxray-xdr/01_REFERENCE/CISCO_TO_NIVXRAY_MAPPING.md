<!-- NIVX-DOC
layer: TARGET_SPEC
status: AUTHORED
-->

> Target mapping. Current-reality columns are sourced from
> `08_VALIDATION/REALITY_MATRIX.md` (generated) and are correct as of
> its stamp. **`ADOPT`/`WIRE` before `BUILD` — always.**

# CISCO → NIVXRAY MASTER MAPPING

Compared by **function, not name**. Action vocabulary:
`ADOPT` (use what exists) · `WIRE` (connect what exists) ·
`CONSOLIDATE` (merge duplicates) · `EXTEND` (add to what exists) ·
`DEPRECATE` · `BUILD` (only when repository evidence proves absence).

---

## Legend for "Current state"

Values come from the generated capability matrix: `OPERATIONAL`,
`END_TO_END_VALIDATED`, `GOLDEN_CORPUS_VALIDATED`,
`REAL_ENDPOINT_VALIDATED`, `BACKEND_IMPLEMENTED`, `UI_IMPLEMENTED`,
`CONTRACT_DEFINED`, `NOT_IMPLEMENTED`.

---

## 1 · Data plane / sources

| Cisco function | Cisco role | NivXRay equivalent | Current state | Missing connection | Required real data | UI surface | Action | GA gate |
|---|---|---|---|---|---|---|---|---|
| Endpoint source | Secure Endpoint integration | **NivXForge EDR · Linux sensor** | `REAL_ENDPOINT_VALIDATED` (process/file/network) | none for Linux; delivery has **stopped** | live sensor stream | EDR console | `ADOPT` + recover | LAB |
| Endpoint source | Secure Endpoint (Windows) | **Windows sensor** | `CONTRACT_DEFINED` / `NOT_IMPLEMENTED` | **no producer exists** | real Windows endpoint | EDR console | `BUILD` (proven absent) | LAB |
| Endpoint source | Secure Endpoint (macOS) | macOS sensor | `NOT_IMPLEMENTED` | no producer | — | — | defer | BETA |
| Network / NDR | NDR integration | collector `:8055` (syslog/CEF) | `BACKEND_IMPLEMENTED`, status split-brain (P0-4) | must prove a **genuinely independent** domain, not endpoint data re-wrapped | a real network/DNS/firewall source | Administration | `WIRE` | BETA |
| DNS / SWG | Umbrella integration | — | `NOT_IMPLEMENTED` | — | — | — | defer | BETA |
| Email | email integration | — | `NOT_IMPLEMENTED` | — | — | — | defer | PILOT |
| Identity | Identity Intelligence | identity pivot engine | `BACKEND_IMPLEMENTED` | no identity source | an IdP source | Investigate | `WIRE` | PILOT |
| Cloud | cloud integration | — | `NOT_IMPLEMENTED` | — | — | — | defer | PILOT |
| Third-party EDR | Cortex/other | vendor wizard + Cortex ingest fabric | `BACKEND_IMPLEMENTED` | unproven with a real tenant | a real third-party tenant | Administration | `WIRE` | PILOT |
| Threat intelligence | Talos/TI | **7 live IOC providers** | `OPERATIONAL` | provenance/staleness disclosure incomplete | none — already live | Intelligence | `EXTEND` | BETA |
| Bulk / custom source | 3-step upload API (A6) | `/api/v2/ingest` | `BACKEND_IMPLEMENTED` | no presigned-upload pattern | — | Administration | `EXTEND` | BETA |

## 2 · Common representation & evidence

| Cisco function | NivXRay equivalent | Current state | Action | Note |
|---|---|---|---|---|
| Common data representation (CTIM, `OWNER_ASSERTED`) | canonical evidence + canonical event schema + provenance | `OPERATIONAL` for the endpoint domain | `ADOPT` ours | **Do not adopt CTIM.** We have the primitive; it needs a second domain, not a new schema |
| Normalisation | normalisation pipeline | `END_TO_END_VALIDATED` (endpoint) | `ADOPT` | proven on real sensor events |
| Enrichment | enrichment + IOC providers | `OPERATIONAL` | `EXTEND` | disclose cache age and provider failure |
| Asset dedup/correlation (A4) | `device_identity` + validated alias set + tenant-constrained resolution | `OPERATIONAL` | `ADOPT` | **stronger than the reference requirement** — dedup is a guarded structural invariant, not a batch job |
| Asset value / criticality | — | `NOT_IMPLEMENTED` | `BUILD` | blocks Cisco-equivalent prioritisation (A14) |

## 3 · Detection → incident

| Cisco function | NivXRay equivalent | Current state | Missing connection | Action | GA gate |
|---|---|---|---|---|---|
| Detections / analytics | detection fabric, 98 rules | `REAL_ENDPOINT_VALIDATED` — detections derived from real events with `raw_id` + `canonical_event_id` | per-rule platform applicability unknown | `EXTEND` | LAB |
| Cross-source correlation | correlation engine, 10 rules | `BACKEND_IMPLEMENTED` | **only one real domain exists**, so cross-domain correlation cannot be demonstrated | `WIRE` after a second source | BETA |
| Prioritisation | prioritisation | `BACKEND_IMPLEMENTED` | no asset-value input | `EXTEND` | BETA |
| Incident | `workspace_cases` SSOT | `OPERATIONAL` | **no provenance label distinguishes real from seeded** | `EXTEND` — highest-value small fix | ALPHA |
| Worklog | `incident_state_history[]` append-only | `OPERATIONAL` | typed entry kinds pending | `EXTEND` | BETA |

## 4 · Investigation & intelligence

| Cisco capability | NivXRay equivalent | Current state | Action | Honest limit |
|---|---|---|---|---|
| `Observe` (sightings) | sighting/spread engines | `BACKEND_IMPLEMENTED` | `WIRE` | one domain: "not seen elsewhere" = coverage statement |
| `Deliberate` (disposition) | IOC providers | `OPERATIONAL` | `EXTEND` | must never infer `clean` |
| `Refer` (pivot/deep link) | 14 audited pivots, XDR↔EDR | `OPERATIONAL` | `ADOPT` | pivot contracts audited; one defect fixed |
| Graph / timeline / table | IKG, evidence graph, trajectory, process ancestry | `END_TO_END_VALIDATED` | `ADOPT` | renders real evidence on the one real endpoint |
| Judgement / verdict | verdict engine | `GOLDEN_CORPUS_VALIDATED` | `ADOPT` | — |
| Security state / causal | security-state + causal FSM | `BACKEND_IMPLEMENTED` | `EXTEND` | **no evidentiary standard for a causal claim yet** — highest over-claim risk in the product |

## 5 · Response & automation

| Cisco capability | NivXRay equivalent | Current state | Action | Note |
|---|---|---|---|---|
| `Respond` — distributed execution (A13) | XDR orchestrates → EDR executes | `OPERATIONAL` for `KILL_PROCESS` on Linux | `ADOPT` | **exceeds the reference pattern**: requires independent verification bound to process start identity before claiming success |
| Host isolation | `ISOLATE_ENDPOINT` | `CONTROL_DRIVER_MISSING` · `BLOCKED_ENVIRONMENT` (no `CAP_NET_ADMIN`) | `WIRE` when a capable host exists | never simulated |
| Release isolation | `RELEASE_ISOLATION` | `CONTRACT_DEFINED` | `WIRE` (P0-2B) | must reuse the same lifecycle |
| Action catalogue | 18 catalogued actions | **2 operational · 16 `NON_OPERATIONAL` stubs** | `CONSOLIDATE` / `DEPRECATE` | publishing 18 where 2 work is a product-honesty problem |
| Automation triggers (A8) | approval lifecycle only | `BACKEND_IMPLEMENTED` (approval) · rest `NOT_IMPLEMENTED` | decide engine vs fixed playbooks | large security surface |
| `Health` | integration health | `BACKEND_IMPLEMENTED`, split-brain (P0-4) | `WIRE` | health must be the authoritative probe |
| `Dashboards` (A3) | Control Center tiles | `UI_IMPLEMENTED` | `WIRE` to authoritative projections | **no tile may invent a number** |

## 6 · Platform / administration

| Cisco function | NivXRay equivalent | Current state | Action |
|---|---|---|---|
| Tenancy | tenant scope + RBAC | `OPERATIONAL`, proven for incidents and endpoint evidence | `EXTEND` to all routes |
| Credentials | secrets surface | `BACKEND_IMPLEMENTED` | `EXTEND` (rotation, audit) |
| Audit | `xdr_audit_log` | `OPERATIONAL` for response + incident state | `EXTEND` (tamper evidence) |
| Capability declaration per integration (A1) | capability registry (135 entries) | `OPERATIONAL` as a registry | **`ADOPT` — then make integrations declare against it** |

---

## 7 · The five findings that actually matter

1. **We are the inverse of Cisco's starting position.** Cisco had
   sources and built a platform. We have a platform (see
   `08_VALIDATION/REALITY_MATRIX.md` for the live inventory) and **one** real source.
   Everything in the roadmap follows from this.

2. **Nothing in section 2 needs building.** The common representation,
   normalisation and asset deduplication all exist and are proven —
   deduplication is arguably stronger than the reference requirement
   because it is a guarded invariant rather than a periodic job. The gap
   is **producers**, not primitives.

3. **Correlation cannot be judged yet.** 10 correlation rules exist and a
   second telemetry domain does not. Any rule requiring two domains
   silently never fires. This must be measured, not assumed
   (`02_ARCHITECTURE/CORRELATION_ARCHITECTURE.md`).

4. **The action catalogue over-promises.** 18 listed, 2 operational. The
   reference product's discipline is that a capability is *declared* per
   integration — so an action that cannot execute should not be offered.

5. **Asset value is the one genuinely missing prioritisation input.**
   Cisco combines detection risk with asset value (A14). We have no
   criticality source at all, so our priority is detection-risk-only and
   every surface showing "priority" must be honest about that.
