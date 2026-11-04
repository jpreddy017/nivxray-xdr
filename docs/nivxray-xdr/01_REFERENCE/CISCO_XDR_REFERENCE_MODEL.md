<!-- NIVX-DOC
layer: TARGET_SPEC
status: AUTHORED
-->

> **Scope of this document.** It describes the **external reference
> product** and informs our target architecture. It makes **no claim
> about NivXRay's current reality** — that lives only in
> `08_VALIDATION/REALITY_MATRIX.md`. Every claim carries its evidence
> class from `SOURCE_REGISTER.md`.

# CISCO XDR REFERENCE MODEL

## 1 · The one structural insight

Cisco XDR is **an integration and intelligence platform over multiple
security control planes** — not one large sensor.
`PUBLICLY_DOCUMENTED` (the integration capability model exists at all is
proof of this shape).

This is why Cisco Secure Endpoint remains a **product** while XDR
**consumes** its telemetry, detections, device data and response
capability. The endpoint product is not absorbed; it is integrated.

That maps exactly onto the NivXRay architecture lock: **NivXForge EDR is
a product; NivXRay XDR consumes and orchestrates it.** The lock is not a
stylistic preference — it is the shape that makes a second domain
addable without rewriting the first.

## 2 · Observable pipeline

```
security products / sources
  endpoint · network · firewall · DNS · email · identity · cloud
  applications · third-party EDR/SIEM · threat intelligence
        │
        ▼   integrations / product APIs / data ingestion
        ▼   common security data representation      [A11 · OWNER_ASSERTED]
        ▼   normalization + enrichment
        ▼   detections / analytics
        ▼   cross-source correlation
        ▼   incident prioritization                  [A14 · OWNER_ASSERTED]
        ▼
     INCIDENT
        ├──► INVESTIGATE   observables · relationships · graph · timeline
        │                  threat intelligence · product sightings
        └──► AUTOMATION / RESPONSE
                 └─► source product API ─► actual control plane
```

`OWNER_ASSERTED` as a whole-chain description; individual stages
(ingestion→warehouse→detections→incidents, and distributed response) are
`PUBLICLY_DOCUMENTED` per `SOURCE_REGISTER` A7 and A13.

## 3 · The integration capability model — the most important thing to copy

**Architecturally, not visually.** `PUBLICLY_DOCUMENTED` (A1–A8).

| Cisco capability | Purpose |
|---|---|
| **Data Ingestion** | send product data into XDR analytics; lands in a data warehouse that then generates detections and incidents |
| **Observe** | return sightings of an observable from the product's own data |
| **Deliberate** | return a disposition — clean / malicious / suspicious / unknown |
| **Refer** | deep-link / pivot menu into the owning product |
| **Respond** | execute an action in the source product's control plane |
| **Assets** *(was `Device Insights`)* | supply asset/device data; normalise, deduplicate and correlate it into a unified asset view via REST full/delta sync or webhooks |
| **Health** | prove the integration actually works |
| **Dashboards** *(was `Tiles`)* | supply dashboard metrics from the product |
| **Automation** | be a workflow target |

**Why this is the lesson:** Cisco does not write a bespoke architecture
per vendor. It makes products **conform to common capabilities**. Umbrella
— a completely different technology from an endpoint agent — implements
much of the same contract, and email products implement it again in a
third domain.

For NivXRay this means Windows EDR, Linux EDR, firewall, DNS, email,
identity and cloud all become **implementations of one platform
contract** rather than seven bespoke integrations. See
`02_ARCHITECTURE/INTEGRATION_ARCHITECTURE.md`.

**Two naming corrections** the owner's brief predates:
`Tiles → Dashboards`, `Device Insights → Assets` (A3, A4). Our contract
should use the current names.

## 4 · Component decomposition

`OWNER_ASSERTED`, component names partially corroborated (A9). Each is an
**operating domain**, not a page.

| Component | Owns | Notably does *not* own |
|---|---|---|
| **Control Center** | operational overview | detections — it **consumes** what other components produce, and its tiles are projections of real integration data |
| **Incidents** | the analyst work queue; prioritisation; lifecycle | evidence production |
| **Investigate** | observable-centric investigation: local sightings from integrations + global intelligence, presented as graph / timeline / table | detection authoring |
| **Intelligence** | reputation, disposition, Talos-style context | asset state |
| **Assets / Devices** | unified asset context from connected products | endpoint execution |
| **Automation** | event- and schedule-driven workflows, playbooks, reusable content | direct control-plane execution |
| **Administration / Integrations** | credentials, capability configuration, health, tenancy | analyst workflow |

Additional operational areas tracked separately: Identity Intelligence,
Sensors, Forensics, Analytics, Orbital, NDR. `OWNER_ASSERTED`.

**The Control Center lesson is the sharpest one for us.** A dashboard
tile is a **projection of real integration data** exposed through a
read-only API — it is *not* a number invented in the frontend. This is
the direct answer to the owner's dashboard mockup: same layout, real
projections, named absence where no integration exists.

## 5 · Distributed response

`PUBLICLY_DOCUMENTED` as a pattern (A13).

```
XDR            recommend / orchestrate / approve
  ↓
SOURCE PRODUCT execute
  ↓
XDR            record result
```

XDR may decide *block domain*, *quarantine email*, *isolate host*,
*block hash* — but the **action belongs to the integrated product**.

NivXRay already implements this shape: XDR orchestrates, NivXForge EDR
executes on the endpoint, and the platform records the outcome. Our
implementation goes one step further than the reference pattern requires
by demanding **independent verification** before an action may be called
successful (`02_ARCHITECTURE/RESPONSE_ARCHITECTURE.md`).

## 6 · Cisco did not start from zero — and neither do we

`OWNER_ASSERTED` (A12).

```
mature security portfolio + SecureX integration/orchestration (GA Jun 2020)
        ↓ common platform
        ↓ XDR detection/correlation architecture
        ↓ BETA (announced Apr 2023)
        ↓ customer / operational validation
        ↓ GA (31 Jul 2023)
        ↓ continuous integration expansion → NDR, forensics, AI, recovery
```

**The honest parallel and the honest difference.** Cisco entered XDR with
mature *products* and an existing *integration foundation*, then added
correlation. NivXRay has a mature **intelligence and console layer** and
**one** real telemetry producer. Our missing piece is the opposite of
Cisco's: they had sources and needed a platform; we have a platform and
need sources.

That single observation sets the operationalisation order in
`09_RELEASE/LAB_VALIDATION_PLAN.md`: **real sources before more
surface.**

## 7 · What we must NOT take

- Cisco's schema (CTIM) — we already have a canonical model; copying is
  both unnecessary and legally unwise.
- Cisco's IA as automatic truth for us — see the open rail conflict in
  `03_DESIGN/NAVIGATION_SPEC.md`.
- Cisco's feature count as a target. Parity is measured in **observable
  capability and operational discipline**, not in connector count.

## 8 · Reference gaps that block decisions

| Gap | Blocks | Class |
|---|---|---|
| Any Cisco screen capture (layout, columns, filters, empty states) | screen-level parity work | `REFERENCE_CAPTURE_REQUIRED` |
| Workflow step ordering and decision points | `01_REFERENCE/CISCO_WORKFLOW_CATALOG.md` | `REFERENCE_CAPTURE_REQUIRED` |
| CTIM specification | nothing — we are not adopting it | `REFERENCE_CAPTURE_REQUIRED` |
| API-first attribution | nothing — adopted as our own doctrine | `REFERENCE_CAPTURE_REQUIRED` |
