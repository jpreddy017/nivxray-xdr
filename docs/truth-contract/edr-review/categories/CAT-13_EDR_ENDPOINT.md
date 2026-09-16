# CAT-13 · EDR / Endpoint Capabilities (+ Sandbox)

> STRICT READ-ONLY deep-dive. Also carries the **Sandbox** row folded in from the prior taxonomy (master §B reconciliation).

## 1 · PRE-AG baseline (proven)

| Artifact | Evidence at `5d67934e` | What it is |
|---|---|---|
| `backend/routers/edr.py` | present; `router = APIRouter(prefix="/edr", tags=["edr"])` at `edr.py:24` | **explicitly a read-only projection** |
| `backend/detection_content/xdr_edr_adapter.py` | present | EDR adapter contract |
| Vendor adapters | `xdr_falcon_vendor_adapter.py`, `xdr_mde_vendor_adapter.py`, `xdr_sentinelone_vendor_adapter.py`, `xdr_cortex_*` | vendor-EDR ingest/act contracts |
| `services/activity/` `ActivityInventory` + `projector.build_inventory` | present | process parent/child graph primitive |
| `backend/services/die/csv_edr_analyzer.py` | present | offline EDR-CSV analysis |
| `backend/services/ida/acquisition.py` | present | acquisition |
| XDR console pages | `XdrEndpointsPage.jsx`, `XdrDeviceTrajectoryPage.jsx` | UI |
| Sysmon behavioural intake | `/api/behavioral/sysmon` (2 paths), `/api/behavioral/{attach,case}` | IMPLEMENTED |

### The self-declared honesty contract of `routers/edr.py:1-14` (verbatim)

```
Owner-locked rules (Slice 2 · P0 · 2026-08-29):
  - No native ``detections`` collection exists in the repository — we
    verified this by inspection.  Therefore Detections is a READ-ONLY
    projection derived from ``workspace_cases.verdict_stage2.evidence[]``.
    Every projected detection carries provenance so the analyst always
    knows the rule/source that generated it.
  - Process Tree reuses the existing canonical
    ``services.activity.ActivityInventory`` (parent_entity_id +
    child_entity_ids) that already backs Device Trajectory.  We do
    NOT introduce a second process-correlation model.
```

And `edr.py:29-45` `_extract_host()` — *"Returns None when the case has no endpoint context yet — never fabricated (rule #13)."*

**This is the clearest single example of the Honest-State rule enforced in backend code, PRE-AG.**

## 2 · AG delta

| Change | Type |
|---|---|
`detection_content/telemetry/windows_security_dsm.py` | **ADDED (AG)** — endpoint DSM |
`detection_content/telemetry/linux_auditd_dsm.py` | **ADDED (AG)** — endpoint DSM |
`detection_content/telemetry/sysmon_dsm.py` | **POST-AG-EMERGENT** (`869f7336`) |
`services/artifact_intelligence/analyzers/{archive,shellcode}.py`, `services/analyzers/security_controls.py` | ADDED (AG) |

**AG added endpoint *parsing*, not endpoint *control*.**

## 3 · Current state (live)

```
/api/edr/endpoints
/api/edr/detections          ← projection over workspace_cases.verdict_stage2.evidence[]
/api/edr/process-tree        ← ActivityInventory reuse
/api/edr/device-trajectory
/api/v2/cases/{id}/trajectory/device
/api/behavioral/sysmon (2) · /api/behavioral/{attach,case}
```

| Dimension | Verdict |
|---|---|
| Implemented | 🟡 projection + adapters + 3 endpoint DSMs |
| Registered | ✅ 4 `/api/edr/*` paths |
| Executed | ✅ |
| Runtime-proven | 🔴 no live endpoint telemetry (`edr_stream` kind declared, **0 configured** — CAT-12) |
| Production-ready | 🔴 **NOT an EDR.** It is an EDR-shaped read surface over case data |

### Endpoint response capability (from `/api/response/actions`, live)

| Action | Domain | `capability_available` |
|---|---|---|
`ENDPOINT_ISOLATE` | endpoint | **false** |
`ENDPOINT_RELEASE_ISOLATION` | endpoint | **false** |
`COLLECT_FORENSIC_SNAPSHOT` | endpoint | **false** |
`APPLICATION_ALLOW_LIST_ADD` | endpoint | **false** |
`PROCESS_EXCLUSION_ADD` | endpoint | **false** |
`PATH_EXCLUSION_ADD` | endpoint | **false** |
`THREAT_EXCLUSION_ADD` | endpoint | **false** |

**All 7 endpoint actions are registered and unavailable** — honestly reported, with the API's own note: *"Actions without a configured integration remain in the registry so decision engine + UI can honestly report 'capability unavailable'."*

### Sandbox

**NOT IMPLEMENTED.** No detonation, no glovebox, no dynamic-analysis runtime. `services/ioc_intelligence/providers/hybrid_analysis.py` provides *third-party* sandbox **lookup**, not detonation. Infrastructure-gated; unchanged by AG (spec docs only).

## 4 · Industry benchmark

| Vendor | Endpoint capability |
|---|---|
| **CrowdStrike** | Falcon sensor + **Real Time Response** — execute scripts on live endpoints for forensic collection, file remediation, process management; Fusion maps detection data (e.g. file paths) into RTR script inputs |
| **Cortex XDR** | XDR agent; **custom prevention rules on agent 7.2+ can terminate a malicious causality chain at the endpoint** |
| **Microsoft Defender for Endpoint** | Live Response, device isolation, AIR auto-remediation; attack disruption isolates workstations automatically, **time-limited and incident-scoped** |
| **SentinelOne** | Autonomous agent response + rollback |
| **Trellix** | Endpoint agent + TAuR quarantine |
| **Cisco XDR** | via integrated endpoint products |
| **Splunk** | 🔴 no native endpoint agent — the one benchmarked vendor comparable to NivXRay here |

## 5 · Gap

| Gap | Severity | NivXRay evidence |
|---|---|---|
| **No endpoint agent** | **P1 — but a strategic decision, not a bug** | `edr.py` is a projection by explicit owner lock. Splunk ES proves an XDR can succeed agentless *if* it ingests other vendors' endpoint telemetry — which is exactly what the 3 endpoint DSMs + 5 vendor adapters are for. **The honest positioning is "agentless XDR over third-party EDR", not "EDR"** |
| **No live endpoint response** | **P1** | 7/7 endpoint actions `capability_available: false`. Needs one vendor-EDR integration wired to the action executor (`xdr_response_executor.py` exists) |
| No live-response shell | P2 | CrowdStrike RTR is the benchmark; requires an agent. Out of scope while agentless |
| No sandbox / detonation | **P2** | infrastructure-gated; standing owner position. Recorded, not recommended |
| Endpoint telemetry not flowing | **P0 (inherited)** | CAT-12 — `edr_stream` + `sysmon_wef` + `windows_event_fwd` kinds declared, 0 configured |
| `/api/edr/detections` projects from `verdict_stage2`, not from detections — **and is structurally always empty** | **P1 (upgraded)** | Self-documented at `edr.py:3-8`. **CORRECTION 2026-09-05:** `verdict_stage2` is present on **0 of 484** `workspace_cases` documents (live `count_documents`), so this endpoint returns nothing regardless of input. Pipeline incidents write `verdict_card` instead (`xdr_incident.py:88-93`, *"compatible with verdict_stage2 shape"*). Recorded as master **DEV-8**; see `../NIVXRAY_XDR_P0_1_CASE_STORE_RECONCILIATION.md` §5 |

## 6 · Honest positive

NivXRay does not claim to be an EDR. `routers/edr.py` states in source that no native detections collection exists and that the surface is a projection with provenance. The 7 unavailable endpoint actions remain visible **specifically so the UI can say "capability unavailable"**. This is the correct behaviour under NO EVIDENCE → NO CLAIM.

## 7 · UNKNOWN

- U-13.1 — Whether any vendor adapter (Falcon/MDE/S1) has ever successfully ingested. `xdr_cortex_ingest_audit` = 95 docs suggests **Cortex** has been exercised; the other three have no audit collection. Not determinable read-only.
- U-13.2 — Whether `xdr_response_executor.py` can actually drive a vendor API once credentials exist, or is a contract-only stub. Requires execution.
