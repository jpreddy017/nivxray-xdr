<!-- NIVX-DOC
layer: TARGET_SPEC
status: AUTHORED
-->

> Describes the **external reference product**. No claim about NivXRay
> current reality. Evidence classes per `SOURCE_REGISTER.md`.

# CISCO COMPONENT CATALOG

One row per reference component. `OWNER_ASSERTED` unless marked; names
partially corroborated (`SOURCE_REGISTER` A1, A4, A9).

---

## Control Center

| | |
|---|---|
| **Purpose** | operational overview for the whole platform |
| **Objects** | dashboard tiles, metrics, counts |
| **Inputs** | projections supplied by integration `Dashboards` capability (`PUBLICLY_DOCUMENTED`, A3) |
| **Outputs** | read-only dashboard API |
| **Upstream** | every integration; incidents; assets; intelligence |
| **Downstream** | analyst attention only — nothing consumes it |
| **Owns** | nothing. It is a **pure consumer** |
| **Failure state** | an integration that supplies no data must show as *not integrated*, not as zero |
| **NivXRay equivalent** | XDR Control Center |
| **Our critical constraint** | tiles must be projections of authoritative APIs. The owner's mockup figures have no data source and must never be rendered as real |

## Incidents

| | |
|---|---|
| **Purpose** | the analyst work queue |
| **Objects** | incident, priority, status, assignee, worklog |
| **Inputs** | detections, correlation, prioritisation |
| **Outputs** | incident lifecycle API; worklog notes (`OWNER_ASSERTED`) |
| **Prioritisation** | detection risk combined with **asset value** (A14) |
| **Downstream** | Investigate, Automation/Response, reporting |
| **Owns** | incident lifecycle and priority |
| **Failure state** | an unprioritisable incident must still be visible, not dropped |
| **NivXRay equivalent** | XDR Incidents · `workspace_cases` SSOT · `incident_state_history[]` append-only worklog |
| **Delta** | we have no asset-value input at all — no CMDB, no criticality source. Our priority is therefore detection-risk-only, and must say so |

## Investigate

| | |
|---|---|
| **Purpose** | observable-centric investigation |
| **Objects** | observable, sighting, relationship, judgement |
| **Inputs** | `Observe` from every integration (local sightings) + `Deliberate` (global disposition) — `PUBLICLY_DOCUMENTED` |
| **Outputs** | graph, timeline, table views over relationships |
| **Owns** | the investigation session; not the underlying evidence |
| **Failure state** | an integration that cannot answer `Observe` must be shown as unqueried, not as "no sightings" |
| **NivXRay equivalent** | XDR Investigate · IUE / IKG / evidence graph / process ancestry |
| **Delta** | our sightings come from **one** domain, so "no sightings elsewhere" is currently a statement about coverage, not about the threat. This must be disclosed on the surface |

## Intelligence

| | |
|---|---|
| **Purpose** | reputation, disposition and threat context |
| **Objects** | disposition (`clean` / `malicious` / `suspicious` / `unknown` — `PUBLICLY_DOCUMENTED`, A5), indicator, campaign |
| **Inputs** | `Deliberate` from integrations; intelligence feeds |
| **Owns** | disposition sourcing and caching; **not** the verdict |
| **Failure state** | provider down or answer stale must never degrade to `clean` |
| **NivXRay equivalent** | XDR Intelligence · 7 live IOC providers |
| **Delta** | `unknown` as a first-class disposition is the discipline to copy: absence of a bad reputation is not evidence of safety |

## Assets / Devices *(was `Device Insights`)*

| | |
|---|---|
| **Purpose** | one unified asset view across products |
| **Objects** | device/asset, identity, alias set, source attribution |
| **Inputs** | integration `Assets` capability via REST full/delta sync or webhooks (`PUBLICLY_DOCUMENTED`, A4) |
| **Key behaviour** | **normalise → deduplicate → correlate** endpoint data from multiple products (A4) |
| **Owns** | asset identity and deduplication |
| **Failure state** | a device seen by two products must not appear twice |
| **NivXRay equivalent** | Assets · `edr_endpoints` · `services/edr/device_identity.py` |
| **Delta — and our strongest area** | deduplication across aliases is implemented as a *structural invariant* with a validated alias set and tenant-constrained resolution. What we lack is **multi-product** attribution, because we have one product |

## Automation

| | |
|---|---|
| **Purpose** | workflows and orchestration |
| **Objects** | workflow, trigger, playbook, approval |
| **Triggers** | Approval, Email, Incident, Schedule, Webhook (`PUBLICLY_DOCUMENTED`, A8) |
| **Outputs** | invocations of `Respond` on integrations |
| **Owns** | orchestration; **not** execution |
| **Failure state** | a workflow must never execute an action the operator could not have authorised manually |
| **NivXRay equivalent** | Automate · approval lifecycle inside the response service |
| **Delta** | we have approval gating but **no general workflow engine**. Open decision in `02_ARCHITECTURE/AUTOMATION_ARCHITECTURE.md` |

## Administration / Integrations *(Client Management)*

| | |
|---|---|
| **Purpose** | credentials, capability configuration, health, tenancy |
| **Objects** | integration, credential, capability declaration, health status |
| **Key behaviour** | each integration **declares which capabilities it supports** (`PUBLICLY_DOCUMENTED`, A1) |
| **Owns** | integration state and health truth |
| **Failure state** | health must reflect the authoritative probe, never a cached optimistic value |
| **NivXRay equivalent** | Administration · collector/vendor surfaces |
| **Delta** | a collector split-brain is a known open defect (P0-4): the console can read a different collector status than reality. Until it closes, **integration health is not trustworthy for administration decisions** |

## Data Ingestion *(cross-cutting)*

| | |
|---|---|
| **Purpose** | get product data into analytics |
| **Flow** | raw telemetry → data warehouse → detections → incidents (`PUBLICLY_DOCUMENTED`, A7) |
| **Custom source API** | create upload → `PUT` presigned URL → poll status (`PUBLICLY_DOCUMENTED`, A6) |
| **NivXRay equivalent** | sensor `/api/edr/agent/telemetry`; collector `:8055`; `/api/v2/ingest` |
| **Delta** | our ingest is real and proven for one producer. The **file-based bulk upload pattern** (A6) is a genuinely useful adoption candidate for offline/batch sources and does not exist here |

---

## Components we should NOT create just because Cisco has them

Compared by **function, not name** (owner rule):

| Cisco area | Do we need a new component? |
|---|---|
| Forensics | **No** — evidence retrieval belongs to the existing evidence plane |
| Live Query / Orbital | **Deferred** — requires real-time endpoint query, which is a sensor capability, not a new platform component |
| Analytics | **No** — this is the detection plane by another name |
| NDR | **No new component** — it is a *source* implementing the integration contract |
| Identity Intelligence | **No new component** — a source plus an asset/identity enrichment |

This table exists to prevent the failure the owner named: creating a
component because its Cisco name differs from ours.
