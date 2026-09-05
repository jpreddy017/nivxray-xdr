# NIVXFORGE EDR: TARGET UX ARCHITECTURE & AVAILABILITY TIER MATRIX
**Document ID:** `NIVXFORGE-EDR-TARGET-UX-ARCH-2026-09-05`  
**Classification:** Operational Design Contract & Target Capabilities  
**Status:** Approved Architectural Baseline  

---

## 1. Executive Summary & Design System Foundations

NivXForge EDR within NivXRay XDR delivers an evidence-first, causal, and deterministic endpoint investigation console. Rather than averaging vendor UIs, NivXForge synthesizes the highest-density operational patterns from industry leaders into a distinct NivXRay design language (*Deterministic Obsidian & Kinetic Amber*).

### 1.1 Core Epistemic & Visual Principles
1. **Evidence-First & Causal Truth**: Every displayed fact carries provenance. Unbacked claims are forbidden.
2. **Epistemic Glyph Vocabulary**:
   - `◆ EVIDENCE PRESENT` (`--nx-ep-present` / `#10B981`)
   - `◇ NO EVIDENCE` (`--nx-ep-none` / `#94A3B8`)
   - `? UNKNOWN` (`--nx-ep-unknown` / `#EAB308`)
   - `○ NOT RUN` (`--nx-ep-notrun` / `#64748B`)
   - `⊘ CAPABILITY UNAVAILABLE` (`--nx-ep-nocap` / `#F87171`)
3. **Decoupled Priority Ladder (P1–P5)**:
   - Priority and Verdict are visually decoupled from Epistemic States.
   - P1 Critical (`--nx-pri-1` / `#EF4444` red, `▰▰▰▰`), P2 High (`--nx-pri-2` / `#F97316` orange, `▰▰▰▱`), P3 Medium (`--nx-pri-3` / `#EAB308` amber, `▰▰▱▱`), P4 Low (`--nx-pri-4` / `#3B82F6` **blue**, `▰▱▱▱`), P5 Informational (`--nx-pri-5` / `#94A3B8` slate, `▱▱▱▱`).
   - **Correction applied 2026-09-05**: the priority ladder is NOT re-derivable by the design layer. It is fixed by owner mandate (P1 red / P2 orange / P3 amber / P4 **blue**) and already shipped in `/app/apps/nivxray-xdr/src/xdr/nx/nx-theme.css` lines 132–136 (light) and 213–217 (high-contrast). Any doc or component proposing `#14B8A6` teal for P4 is wrong and must be corrected against the token file.
4. **Honest Empty & Zero-State Principles**:
   - The operational runtime currently contains 0 enrolled endpoints. Zero-state is rendered as an explicit, high-clarity first-class state (`NO AUTHORITATIVE ENDPOINTS ENROLLED`), never populated with synthetic mock data.

---

## 2. Navigation Spine & Target IA Architecture

The investigation spine enforces a direct conceptual and operational flow:
$$\text{Incident} \longrightarrow \text{Endpoint Entity} \longrightarrow \text{NivXForge EDR} \longrightarrow \text{Device Trajectory}$$

### 2.1 The Resolver Flow for `/edr/trajectory`
To eliminate route dead-ends without creating a duplicate trajectory canvas:
- `/edr/trajectory` acts as an intelligent **Resolver Route**.
- When accessed with `?device=<id>` or `?device_iid=<iid>`, it resolves the authoritative `device_iid` (or hostname fallback with `INFERRED` tag) and performs an immediate client-side redirect to `/xdr/endpoints/:device/trajectory`.
- When accessed without parameters, it redirects to `/xdr/incidents` with an explicit toast: `"Select an endpoint entity from an incident record to open Device Trajectory."`

### 2.2 Device Identity Model: `device_iid` vs `hostname`
- **Authoritative Identifier**: `device_iid` (derived from IRG `v2_shadow_observations.event.device_iid` or entity graph IID).
- **Fallback Identifier**: `hostname` (used ONLY when `device_iid` is absent).
- **Visual Distinction**: Hostname-only entity badges carry an eyebrow pill labeled `INFERRED IDENTITY (NO IID)`.

---

## 3. Surface-by-Surface Availability Tier Matrix (37 Surfaces)

Every surface in the NivXForge EDR IA is explicitly assigned an Availability Tier to ensure no non-existent backend capability is falsely surfaced as operational.

| Surface ID & Name | Path | Availability Tier | Backing Engine / API State | Rendered UI Contract |
|---|---|---|---|---|
| **[1] EDR Overview** | `/edr` | `LIVE NOW` | `GET /api/edr/endpoints` + `GET /api/edr/detections` | Fleet summary projected from saved workspace cases. |
| **[2] Endpoint Fleet / Inventory** | `/xdr/endpoints` (redirects to `/xdr/incidents`) | `LIVE NOW` | `GET /api/edr/endpoints` | Projected list from `workspace_cases.ssot.investigation_object`. Renders Zero-Device state when empty. |
| **[3] Endpoint Entity 360** | `/edr/endpoints/:id/360` | `DESIGN-READY` | API Missing | Renders `⊘ CAPABILITY UNAVAILABLE · Sensor Entity 360 Engine Not Enrolled`. |
| **[4] Detections Queue** | `/edr/detections` | `LIVE NOW` | `GET /api/edr/detections?incident_id=` | Stage-2 verdict evidence projection. Read-only rule-id source. |
| **[5] Detection Detail** | `/edr/detections/:alertId` | `LIVE NOW` | Stage-2 evidence drawer | Projected evidence inspector drawer with rule rationale. |
| **[6] Incidents** | `/xdr/incidents` | `LIVE NOW` | `GET /api/incidents` | Core incident queue and investigation record. |
| **[7] Device Timeline** | `/edr/endpoints/:id/timeline` | `DESIGN-READY` | API Missing | Renders `⊘ CAPABILITY UNAVAILABLE · Device Event Log Engine Pending`. |
| **[8] Device Trajectory** | `/xdr/endpoints/:device/trajectory` | `LIVE NOW` | `GET /api/edr/device-trajectory` | 3-pane 5-lane timeline canvas. Aggregates detections + activity inventory. |
| **[9] Process Tree** | `/edr/process-tree` | `LIVE NOW` | `GET /api/edr/process-tree?incident_id=` | Root-first process ancestry tree derived from `ActivityInventory`. |
| **[10] Process Detail** | `/edr/processes/:processGuid` | `DESIGN-READY` | API Missing | Process inspection drawer stub. |
| **[11] Files & PE Artifacts** | `/edr/files` | `DESIGN-READY` | `EdrFilesPage` stub | Renders Reserved Page banner + `⊘ CAPABILITY UNAVAILABLE`. |
| **[12] File Detail** | `/edr/files/:sha256` | `DESIGN-READY` | API Missing | PE inspection layout defined in prototype. |
| **[13] Network Connections** | `/edr/network` | `DESIGN-READY` | `EdrNetworkPage` stub | Renders Reserved Page banner + `⊘ CAPABILITY UNAVAILABLE`. |
| **[14] DNS Query Activity** | `/edr/dns` | `DESIGN-READY` | API Missing | DNS activity log surface design. |
| **[15] Windows Registry** | `/edr/registry` | `DESIGN-READY` | API Missing | Registry modification surface design. |
| **[16] System Services** | `/edr/services` | `DESIGN-READY` | API Missing | Service manager surface design. |
| **[17] Users & Sessions** | `/edr/users-sessions` | `DESIGN-READY` | API Missing | User logon & session matrix design. |
| **[18] Persistence Mechanisms** | `/edr/persistence` | `DESIGN-READY` | API Missing | ASEP autostart matrix design. |
| **[19] Threat Hunting Workspace** | `/edr/hunting` | `DESIGN-READY` | `EdrHuntingPage` stub | KQL/SQL hunt workspace design. |
| **[20] Distributed Live Query** | `/edr/live-query` | `DESIGN-READY` | `EdrLiveQueryPage` stub | osquery distributed query design. |
| **[21] Forensics Artifacts & Triage** | `/edr/forensics` | `DESIGN-READY` | `EdrForensicsPage` stub | DFIR triage package collector design. |
| **[22] Memory / Volatile Evidence** | `/edr/memory` | `DESIGN-READY` | API Missing | Memory dump & unbacked segment inspector design. |
| **[23] Vulnerabilities & Exposure** | `/xdr/exposure` | `LIVE NOW` | `GET /api/xdr/cve` | Exposure and CVE tracking console. |
| **[24] Threat Intelligence & IOC Vault** | `/xdr/intelligence/threat` | `LIVE NOW` | `GET /api/threat-intel` | Threat actor dossiers and IOC match vault. |
| **[25] Response Command Center** | `/edr/response` | `DESIGN-READY` | `EdrResponsePage` stub | Central action orchestration & audit ledger design. |
| **[26] Host Isolation** | `/edr/response/isolation` | `DESIGN-READY` | API Missing | Safety-gated network isolation design. |
| **[27] Quarantine Vault** | `/edr/response/quarantine` | `DESIGN-READY` | API Missing | Encrypted file vault design. |
| **[28] Remote Response Console** | `/edr/response/terminal` | `DESIGN-READY` | API Missing | Live remote terminal design. |
| **[29] Agent / Sensor Management** | `/edr/agents` | `FUTURE` | Unimplemented | Fleet deployment & update rings. |
| **[30] Telemetry Health** | `/edr/telemetry-health` | `FUTURE` | Unimplemented | Pipeline throughput & sensor RAM/CPU metrics. |
| **[31] Detection Engineering** | `/xdr/rule-studio` | `LIVE NOW` | `GET /api/sigma` | Rule Studio for Sigma and YARA authoring. |
| **[32] Policies & Configuration** | `/edr/policies` | `FUTURE` | Unimplemented | Behavioral prevention policy manager. |
| **[33] MITRE ATT&CK Matrix Navigator**| `/xdr/intelligence/mitre` | `LIVE NOW` | `GET /api/mitre` | Interactive ATT&CK heatmaps and coverage matrix. |
| **[34] Attack Story Canvas** | `/xdr/investigations/:caseId` | `LIVE NOW` | `GET /api/attack-story` | Causal DAG investigation canvas. |
| **[35] Evidence Vault** | `/xdr/evidence-explorer` | `LIVE NOW` | `GET /api/attack-evidence` | Evidence Explorer & custody ledger. |
| **[36] Investigation Pivots** | `/xdr/incidents/:id` | `LIVE NOW` | `GET /api/evidence-inspector` | Pivot component matrix across hosts, files, IPs, processes. |
| **[37] UBAE Entity Context** | `/edr/ubae-context` | `FUTURE` | Unimplemented | Identity risk scoring & peer group anomaly baselines. |

---

## 4. Zero-Device Honest State Design

When querying `/api/edr/endpoints` or `/api/edr/device-trajectory` in an environment with no enrolled devices or zero matching cases:

```
┌─────────────────────────────────────────────────────────────────────────┐
| ⊘ NO AUTHORITATIVE ENDPOINTS ENROLLED IN TENANT SCOPE                    |
|                                                                         |
|  Reason: workspace_cases.ssot.investigation_object returned 0 host      |
|          records for the current tenant.                                |
|  Status: ◆ EVIDENCE PRESENT: 0  · ◇ NO EVIDENCE: 0  · ⊘ CAPABILITY: LIVE|
|                                                                         |
|  [ Ingest Incident Telemetry ]   [ View IRG Shadow Observations (223) ] |
└─────────────────────────────────────────────────────────────────────────┘
```
- **Never render fake host names** like `workstation-01.local` or `corp-dc-01`.
- Display exact backend reason (`no_matching_evidence`).
- Provide an operational bridge to real IRG shadow observations (`v2_shadow_observations` carries 223 device IIDs) to promote true host discovery.
