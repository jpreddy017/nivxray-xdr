# 02 · Flowcharts

All diagrams are Mermaid. Every flow below is SOURCE-VERIFIED unless marked otherwise.

## 2.1 Endpoint enrollment and session lifecycle

```mermaid
sequenceDiagram
    autonumber
    participant OP as Operator (authenticated)
    participant API as FastAPI /api
    participant VM as Windows endpoint
    participant DB as MongoDB

    OP->>API: POST /api/edr/enrollment/tokens {label, ttl_seconds ≤ 86400}
    API->>DB: store token HASH only
    API-->>OP: plaintext token (returned ONCE, never logged, never re-readable)
    Note over OP,VM: token carried out of band, fed on STDIN only
    VM->>VM: read_enrolment_secret(stdin) · refuse if secret appears in argv
    VM->>API: POST /api/edr/agent/enroll {tenant_id, enrollment_token, machine facts}
    API->>DB: create edr_endpoints + edr_agent_credentials (secret hash, auth epoch)
    API-->>VM: {endpoint_id, credential_id, agent_credential}
    VM->>VM: publish identity.json (SYSTEM/Administrators only)
    loop every cycle
        VM->>API: POST /api/edr/agent/session {tenant_id, agent_credential}
        API-->>VM: short-lived session_token
        VM->>API: POST /api/edr/agent/telemetry/batch (Bearer session)
    end
```

**Fail-closed proof (live):** `GET /api/edr/agent/whoami` with no token → `401 SENSOR_UNAUTHENTICATED`, and the refused payload is retained as a security signal, never as endpoint evidence.

## 2.2 Telemetry → evidence → detection → UI

```mermaid
flowchart TB
    S["Sensor collects<br/>Security · System · Sysmon channels"] --> J["Local journal + outbox<br/>durable, survives reboot/outage"]
    J --> T["POST /api/edr/agent/telemetry/batch"]
    T --> V{"Trust boundary<br/>session valid?"}
    V -- no --> R["edr_rejected_telemetry<br/>security signal, NOT evidence"]
    V -- yes --> RAW["edr_raw_events<br/>immutable raw document<br/>tenant + endpoint attribution"]
    RAW --> Q["edr_processing_queue<br/>(tenant_id, raw_id) REFERENCE only"]
    Q --> W["processing worker<br/>one authoritative writer"]
    W --> CB["canonical_bridge"]
    CB --> CEV["canonical delivery<br/>cev_*"]
    CB --> OBS["canonical observation<br/>obs_*"]
    CB --> ACT["canonical activity<br/>act_*"]
    CB --> XC["xdr_canonical_evidence<br/>v2_shadow_observations"]
    OBS --> DET["detection evaluation<br/>detection_content rules"]
    DET --> F["edr_findings + edr_finding_evaluations"]
    ACT --> TRAJ["edr_trajectory · v3_presentation.apply_findings()"]
    F --> TRAJ
    TRAJ --> UI["EDR console<br/>Device Trajectory · Process Tree · Events"]

    classDef shared fill:#fd7,stroke:#a60,color:#000
    class XC shared
```

Amber node = **cross-product data coupling**: the EDR canonical bridge writes into XDR-owned collections.

### Real traced example (G4 lab, read-only verification)

```text
Sysmon EID 1  "NIVX_G4_SYSMON_TEST"  2026-10-30 03:17:41 UTC
  raw_dc73bc44ce9417acdbac4411                 (raw landing)
     → cev_ca4c923e6284b529eaff0b38_0          (canonical delivery)
        → obs_4bb13bc9a03c                     (observation, SOURCE_PROCESS_GUID)
           → act_2a2a87354cf8577b4e90b335      (activity)
              → focus?observation_id=obs_…     → FOCUS_RESOLVED
elapsed raw → canonical: ~6 minutes
```

## 2.3 Finding association (the logic corrected by candidate `d2f8b742`)

```mermaid
flowchart TB
    IN["findings + trajectory rows"] --> LOOP{"for EVERY reference<br/>on EVERY finding"}
    LOOP --> CEV{"canonical delivery<br/>identity proven?"}
    CEV -- yes --> ATT["attach: detection, severity, ATT&CK"]
    CEV -- "alias only" --> AL{"legacy alias + canonical proof?"}
    AL -- yes --> ATT
    AL -- no --> REF["REFUSE<br/>evidence + provenance kept,<br/>no detection, no severity, no ATT&CK"]
    CEV -- "missing / contradictory" --> REF
    ATT --> OUT["e3_detections[] (plural)<br/>+ e3_detection = highest-severity compatible<br/>+ ATT&CK union"]
    REF --> OUT

    style LOOP fill:#0f3,stroke:#060,color:#000
```

The defect fixed: a `if not matched` short-circuit stopped evaluating later references once one finding attached, silently dropping legitimate mixed-reference findings (`attached=1` instead of `attached=2`). The green node is the correction — **every** reference is now evaluated, and refusal is decided only after all of them.

## 2.4 M1 Windows installation (clean-install-only contract)

```mermaid
flowchart TB
    A["Administrator pre-provisions<br/>bootstrap root + m1-config.json<br/>(installer NEVER creates the root)"] --> B["m1-install --m1-config <path><br/>token on STDIN"]
    B --> C{"load_config<br/>https origin? windows-default certs?<br/>non-admin-unwritable? no reparse points?"}
    C -- no --> X1["REFUSE: CONFIG_*"]
    C -- yes --> D{"clean_host_report<br/>service / task / worker / install_dir /<br/>state_dir / prior identity"}
    D -- "PRESENT or UNKNOWN" --> X2["REFUSE: HOST_NOT_CLEAN"]
    D -- "all ABSENT" --> E["create protected dirs<br/>read back DACLs"]
    E --> F["deliver payload<br/>verify manifest size + SHA-256"]
    F --> G["enrol → endpoint credential"]
    G --> H["create service DISABLED<br/>LocalSystem"]
    H --> I["apply + INDEPENDENTLY verify SD<br/>(AccessCheck + Authz)"]
    I --> J["start type DEMAND → start →<br/>verify RUNNING image digest"]
    J --> K["start type AUTO<br/>ACTIVATION_VERIFIED"]
    I -- unsafe --> X3["REFUSE, stays disabled"]
    J -- mismatch --> X4["REFUSE: SERVICE_IMAGE_UNVERIFIED"]

    classDef refuse fill:#f66,stroke:#900,color:#000
    class X1,X2,X3,X4 refuse
```

Service runtime command line (what the SCM actually invokes):

```text
"<install_dir>\NivXForgeSensor.exe" --m1-service-run --m1-config <path>\m1-config.json --state-dir <state_dir>
```

`m1_service_run()` verifies it really is LocalSystem, loads and validates the config **before** binding the state directory, and refuses `CONFIG_STATE_DIR_MISMATCH` if `--state-dir` disagrees with the approved config.

## 2.5 Build and deployment

```mermaid
flowchart LR
    SRC["apps/nivxray-xdr<br/>ONE source package"] --> BS["scripts/vercel-build.sh"]
    BS --> SC{"NIVX_PRODUCT_SCOPE<br/>default 'xdr'"}
    SC -- "edr" --> AE["artifact: nivxray-edr<br/>dist/ + build-info.json"]
    SC -- "xdr" --> AX["artifact: nivxray-xdr"]
    SC -- "unset/other" --> FAIL["FATAL: unscoped build refused"]
    BS --> ENV["REACT_APP_NIVXRAY_API_URL = XDR_PROD_API_ORIGIN<br/>default https://nivxray.nivxforge.com<br/>cross-product origins OFF by default"]
    AE --> PE["Vercel project: EDR → edr.nivxforge.com"]
    AX --> PX["Vercel project: XDR → xdr.nivxforge.com"]
    AE --> VER["scripts/verify-production-build.js<br/>guard: wrong-host render refused"]

    classDef refuse fill:#f66,stroke:#900,color:#000
    class FAIL refuse
```

Backend deploys via the Emergent pipeline to `nivxray.nivxforge.com` — **not** via Vercel. `apps/nivxray-xdr/vercel.json` has no `/api/*` routes; it is SPA rewrites plus two host-scoped `/` redirects only.

## 2.6 Governance gates (G0–G6) and the copy-first isolation sequence

```mermaid
flowchart TB
    D1["1 · map full direct + transitive dependency chain"] --> D2["2 · inventory modules, engines, config, schema, tests, workers, data"]
    D2 --> D3["3 · PRESERVE originals + verified recovery backup"]
    D3 --> D4["4 · COPY into EDR boundary — originals untouched"]
    D4 --> D5["5 · adapt copies to EDR auth / DB / config / runtime"]
    D5 --> D6["6 · prove equivalence: fixtures, contracts, provenance, regression"]
    D6 --> D7["7 · isolated end-to-end + native endpoint + failure simulation"]
    D7 --> D8["8 · independent G0–G6 verification"]
    D8 --> D9["9 · reversible cutover, ONE dependency at a time"]
    D9 --> D10["10 · keep legacy until rollback period completes"]
    D1 -. "incomplete chain / evidence / test / recovery" .-> HOLD["STOP · separation stays on HOLD"]

    classDef hold fill:#f66,stroke:#900,color:#000
    class HOLD hold
```

**Current position: step 1, incomplete → HOLD.**
