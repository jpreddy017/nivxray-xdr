# 07 · Target Independent EDR Architecture (design only)

> **Nothing here is authorized.** Per `/app/memory/EDR_ISOLATION_DIRECTIVE.md` the separation is on **HOLD** until step 1 of the mandatory sequence is complete. This file is a blueprint, not a plan of record.

## 7.1 Target topology

```mermaid
flowchart TB
    subgraph EP["Endpoints"]
        W["Windows sensors"]
        L["Linux sensors"]
    end
    subgraph EDR["EDR-owned product"]
        ING["EDR dedicated ingress<br/>(proposed) api.edr.nivxforge.com<br/>own rate limits + service identity"]
        APP["EDR-only FastAPI entrypoint<br/>21 EDR routers ONLY"]
        WRK["EDR-owned workers<br/>queue + canonical + detection"]
        EDB[("EDR-exclusive database<br/>own user, own credentials")]
        FE["edr.nivxforge.com<br/>EDR-owned frontend package"]
    end
    subgraph OTHER["Unchanged products"]
        XDR["NivXRay XDR"]
        WS["NivXMachines Workspace"]
    end

    W -- "HTTPS session" --> ING
    L -- "HTTPS session" --> ING
    ING --> APP --> WRK
    APP --> EDB
    WRK --> EDB
    FE --> ING
    APP <-. "authenticated, versioned,<br/>provenance-preserving API<br/>NO shared mutable SSOT" .-> XDR
    APP <-. "same contract" .-> WS

    classDef never fill:#f66,stroke:#900,color:#000
    NEVER["FORBIDDEN: direct cross-product MongoDB access<br/>or a shared mutable event SSOT"]:::never
```

**Definition of independent:** EDR can enrol agents, accept/store/process telemetry, detect, investigate endpoint evidence and execute its supported response actions **while XDR and Workspace are down**. Shared *code* via versioned packages is fine; shared *runtime state* is not.

## 7.2 Copy-first migration map

```mermaid
flowchart LR
    subgraph ORIG["Originals — NEVER modified"]
        O1["backend/edr_plane, edr_trajectory, edr_behavior,<br/>edr_investigation, edr_ml, routers/edr*, services/edr"]
        O2["agents/nivxforge-*"]
        O3["apps/.../src/nivxforge"]
        O4["shared: v2/ingestion, services/*, detection_content, security/*"]
        O5["XDR + Workspace code that imports EDR"]
    end
    subgraph COPY["EDR-owned boundary — copies only"]
        C1["edr backend modules (copied)"]
        C2["agents (copied)"]
        C3["edr frontend package (copied)"]
        C4["shared libs: copied WITH tests, or consumed as versioned packages"]
        N1["NEW: EDR-only ASGI entrypoint"]
        N2["NEW: EDR-scoped config/deps"]
        N3["NEW: EDR session/authorization authority"]
    end
    O1 -->|copy| C1
    O2 -->|copy| C2
    O3 -->|copy| C3
    O4 -->|copy with tests| C4
    O5 -.->|"untouched — keeps importing the ORIGINAL"| O5
```

### What must be newly authored (small, additive)

| # | Component | Replaces | Why it cannot be copied |
|---|---|---|---|
| N1 | EDR-only ASGI entrypoint owning worker + index startup | `server.py` composition root | `server.py` is shared by all three products; copying it would carry XDR/Workspace routers and tasks |
| N2 | EDR-scoped config/deps | `deps.py` 6 mandatory keys | EDR ingestion needs no LLM key or admin seeding — but fail-closed auth must be preserved, never weakened to make startup pass |
| N3 | EDR session/authorization authority | `routers.xdr_rbac` + 4 `/xdr/*` frontend calls | prohibition 4 forbids a new runtime dependency on XDR |

### Reverse dependencies — the inversion that must happen first

| Consumer (stays) | Imports | Required treatment |
|---|---|---|
| `detection_content.telemetry.nivxforge_sensor_dsm` | `edr_plane`, `edr_plane.canonical_bridge` | keeps importing the **original**; EDR's copy is additive. Later: a versioned sensor-shape package consumed by both |
| `detection_content.xdr_pipeline` | `edr_plane` | same |
| 8 XDR UI files | `src/nivxforge/*` | keep importing the original package; EDR's copy is separate until a published package exists |

**Never** cut these edges to make EDR independent — that is prohibition 2.

## 7.3 Dependency cutover order (one at a time, each reversible)

```mermaid
flowchart TB
    P0["Phase 0 · close A0 unknowns<br/>backend revision, Mongo identity, untraced packages,<br/>flags, collection ownership"] --> P1
    P1["Phase 1 · EDR-only runtime on an isolated staging DB<br/>synthetic fixtures only"] --> P2
    P2["Phase 2 · equivalence proof<br/>deterministic fixtures + API contracts + provenance + regression"] --> P3
    P3["Phase 3 · native endpoint acceptance<br/>fresh VM, ingest, reboot, outage, response"] --> P4
    P4["Phase 4 · independent G0–G6 verification"] --> P5
    P5["Phase 5 · cutover #1: configuration + auth"] --> P6
    P6["Phase 6 · cutover #2: ingress + agent endpoint"] --> P7
    P7["Phase 7 · cutover #3: database ownership<br/>one authoritative writer, checkpointed, reversible"] --> P8
    P8["Phase 8 · rollback period elapses, then retire legacy EDR binding only"]

    P0 -. "any gap" .-> HOLD["HOLD"]
    classDef hold fill:#f66,stroke:#900,color:#000
    class HOLD hold
```

## 7.4 Acceptance criteria for "independent"

1. EDR starts with **only** its own database, config and secrets; fail-closed auth verified, not bypassed.
2. Zero runtime calls from EDR to any `/xdr/*` or Workspace endpoint.
3. Enrolment, session, batch ingest, queue, canonical bridge, detection, Device Trajectory and Process Tree all pass on the isolated runtime.
4. Deterministic-fixture equivalence against the original: identical raw IDs, queue refs, canonical IDs, findings and trajectory rows — **zero unexplained missing or extra records**.
5. Native endpoint acceptance on a fresh VM, including reboot continuity and backend-outage recovery with no raw gaps.
6. XDR, Workspace and NivX Machines verified **unchanged** — their imports, routes and data still resolve to the untouched originals.
7. Rollback rehearsed and proven **before** any cutover.
8. Independent G0–G6 sign-off recorded with evidence.

## 7.5 Cost and isolation honesty

Separate logical databases/users on an existing MongoDB instance give **service isolation** cheaply; they do **not** give independent hardware failure domains. True production availability isolation has a hosting cost and must not be promised for free. Staging may legitimately run on the ASUS Hyper-V host with the VM powered off between sessions.
