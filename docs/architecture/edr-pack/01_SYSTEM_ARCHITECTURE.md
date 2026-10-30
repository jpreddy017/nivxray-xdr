# 01 · System Architecture — as it exists today

## 1.1 Whole-system view

```mermaid
flowchart TB
    subgraph ENDPOINTS["Managed endpoints"]
        WIN["Windows 11 endpoint<br/>NivXForgeSensor service<br/>sensor 0.3.0-windows"]
        LNX["Linux endpoint<br/>nivxforge-linux sensor"]
    end

    subgraph EDGE["Public edge"]
        VEDR["edr.nivxforge.com<br/>Vercel project nivxray-edr-production<br/>static SPA, scope=edr"]
        VXDR["xdr.nivxforge.com<br/>Vercel project nivxray-xdr-production<br/>static SPA, scope=xdr"]
        VWS["workspace.nivxmachines.com<br/>separate Vercel project<br/>CRA build"]
        CF["nivxray.nivxforge.com<br/>Cloudflare edge"]
    end

    subgraph RUNTIME["Single shared application runtime (Emergent-hosted)"]
        API["FastAPI app · backend/server.py<br/>875 OpenAPI paths<br/>86 /api/edr · 199 /api/xdr · auth · workspace"]
        WORKERS["EDR processing workers<br/>start_workers(worker_count=1)<br/>started at API startup"]
        SWEEP["FileStore retention sweeper<br/>+ content/bootstrap tasks"]
    end

    DB[("MongoDB<br/>one Motor client<br/>MONGO_URL / DB_NAME")]

    WIN -- "HTTPS, token session<br/>/api/edr/agent/*" --> CF
    LNX -- "HTTPS" --> CF
    VEDR -- "API origin baked at build" --> CF
    VXDR -- "same API origin" --> CF
    VWS  -- "same API origin" --> CF
    CF --> API
    API --> WORKERS
    API --> SWEEP
    API --> DB
    WORKERS --> DB

    classDef verified fill:#0f3,stroke:#060,color:#000
    classDef unknown fill:#fd7,stroke:#a60,color:#000
    class VEDR,VXDR,VWS,CF,API verified
    class DB unknown
```

**Green = verified live. Amber = identity unknown** (production MongoDB host/deployment and `DB_NAME` are not readable with current permissions).

### Verified facts behind the diagram

| Fact | Evidence | Class |
|---|---|---|
| `edr.nivxforge.com` → `307 → /edr`, `server: Vercel`, asset `/assets/index-Btpjue2F.js` | HTTP probe | DEPLOY-VERIFIED |
| EDR build provenance `{"product_scope":"edr","api_origin":"https://nivxray.nivxforge.com","built_at":"2026-10-28T16:15:44Z"}` | `GET /build-info.json` | DEPLOY-VERIFIED |
| XDR build provenance: same API origin, `built_at 2026-09-30T17:37:18Z` | `GET /build-info.json` | DEPLOY-VERIFIED |
| Workspace bundle targets the same API origin | bundle inspection | DEPLOY-VERIFIED |
| API origin is Cloudflare-fronted and Emergent-hosted (`__emg_vid`/`__emg_sid`) | response headers | DEPLOY-VERIFIED |
| One FastAPI app serves EDR + XDR + Workspace route families | `GET /api/openapi.json`, 875 paths | DEPLOY-VERIFIED |
| EDR agent plane fail-closed | `/api/edr/agent/whoami` → `401 SENSOR_UNAUTHENTICATED` | DEPLOY-VERIFIED |
| Backend deployment revision / SHA | no build stamp, no platform read | **UNKNOWN** |
| Production Mongo identity and `DB_NAME` | deployment secret, unreadable here | **UNKNOWN** |

## 1.2 Product boundary — where isolation does and does not exist

```mermaid
flowchart LR
    subgraph ISO["Isolated today"]
        A1["3 distinct Vercel projects"]
        A2["3 distinct DNS CNAME targets"]
        A3["3 distinct built artifacts"]
    end
    subgraph SHARED["Shared today"]
        B1["One FastAPI process"]
        B2["One Mongo client + database"]
        B3["One auth surface /api/auth/*"]
        B4["EDR workers inside shared process"]
        B5["One frontend source package"]
        B6["One vercel.json + one build script"]
        B7["EDR UI calls 4 /xdr/* endpoints"]
    end
    ISO -->|"the ONLY real boundary"| EDGE["static frontend edge"]
    SHARED -->|"single failure domain"| RUNTIME["backend runtime + data"]
```

The product boundary is produced by a **build flag**, not infrastructure: `scripts/vercel-build.sh` sets `NIVX_PRODUCT_SCOPE` (default `xdr`), and its own comment states that `productScope.js` + `ProductScopeGuard.jsx` are the only thing preventing `xdr.nivxforge.com/edr/trajectory` from rendering EDR on the XDR host.

## 1.3 Layer map

```mermaid
flowchart TB
    L1["L1 · Endpoint<br/>sensor, journal, outbox, local policy state"]
    L2["L2 · Transport<br/>HTTPS + enrollment token → credential → short-lived session"]
    L3["L3 · Ingest<br/>/api/edr/agent/telemetry[/batch] → edr_raw_events (immutable)"]
    L4["L4 · Queue<br/>edr_processing_queue stores (tenant_id, raw_id) REFERENCES only"]
    L5["L5 · Canonicalisation<br/>canonical_bridge → canonical events, observations, activities"]
    L6["L6 · Detection<br/>detection_content rules → edr_findings + evaluations"]
    L7["L7 · Projection<br/>edr_trajectory v3_presentation → trajectory, process tree"]
    L8["L8 · Presentation<br/>React/Vite EDR console"]
    L1 --> L2 --> L3 --> L4 --> L5 --> L6 --> L7 --> L8
```

Observed ingestion→canonicalisation latency in the lab: **3–6 minutes** (one marker took ~6 min). Any negative test must wait ≥7 minutes before declaring a miss.

## 1.4 Environments

| Environment | Frontend | Backend | Database | Status |
|---|---|---|---|---|
| Production | `edr.nivxforge.com` / `xdr.nivxforge.com` / `workspace.nivxmachines.com` | `nivxray.nivxforge.com` | identity UNKNOWN | live; deployment on HOLD |
| Preview (this workspace) | Vite dev server on `:3000` | supervisor FastAPI on `:8001` | local `mongodb://`, `DB_NAME=test_database` | active development |
| G4 lab | none | `127.0.0.1:8101` (candidate `d2f8b742`) | `nivx_g4_lab` | loopback only; no live route |
| G4-02 isolated VM lab | — | separate Emergent preview | local Mongo | reported, independent |

Production, preview and the local checkout serve a **byte-identical OpenAPI document** (`md5 a8c5abe0…`, 778,868 bytes). That proves identical API *schema only* — it cannot identify the deployed revision, because the frozen candidate changes response content, not schema.
