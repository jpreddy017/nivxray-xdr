# CAT-04 · Investigation / Analyst Workspace (+ Unified UI console)

> STRICT READ-ONLY deep-dive.
> **Owner framing enforced here explicitly:** the 8-tab Investigation Workspace **is not the XDR**. It is one experience over the planes audited in CAT-05 … CAT-17. Nothing in this file supports a claim about detection, correlation or telemetry capability.

## 1 · PRE-AG baseline (proven)

| Artifact | Evidence at `5d67934e` | Status |
|---|---|---|
| Main-SPA analyst workspace | `frontend/src/pages/AnalystWorkspacePage.jsx`, `WorkspacePage.jsx` | IMPLEMENTED |
| Standalone XDR shell | `apps/nivxray-xdr/` created `fcbcaed1` (2026-08-29), 6 days pre-AG; `src/xdr/XdrShell.jsx` present | IMPLEMENTED |
| 24 of the 27 `apps/nivxray-xdr/src/xdr/pages/*.jsx` | present at `5d67934e` | IMPLEMENTED |
| Investigation projection engine | `backend/detection_content/xdr_investigation.py` | IMPLEMENTED |
| Workspace investigation router | `backend/routers/workspace_investigation.py` (documents its own route map at `:17`) | IMPLEMENTED |
| Investigation SSOT / findings / activity | `xdr_investigations`, `xdr_investigation_findings`, `xdr_investigation_activity` | IMPLEMENTED |
| Evidence traversal | `backend/detection_content/xdr_evidence_traversal.py` | IMPLEMENTED |

**The Analyst Workspace concept, the standalone XDR shell, and the investigation engine are all PRE-AG NivXRay.**

## 2 · AG delta (exactly 6 files)

Added (`95b1c82a`):
- `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx` ← **the 8-tab workspace**
- `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationsListPage.jsx`
- `apps/nivxray-xdr/src/xdr/pages/XdrEvidenceExplorerPage.jsx`
- `frontend/src/v2/pages/SecurityStateTab.jsx`

Modified: `apps/nivxray-xdr/src/App.jsx`, `src/xdr/XdrShell.jsx`, `src/xdr/pages/incidents/record/RecordHeader.jsx`.

**Attribution rule applied:** the 8-tab workspace is **AG-added** and must never be cited as PRE-AG capability. The *shell it plugs into* and the *investigation engine it renders* are PRE-AG.

## 3 · Current state (live)

`XdrShell.jsx` nav groups (evidence, line numbers):

| Group | Tabs | Enabled? |
|---|---|---|
| Triage | `workspace` (:56), `mss-dashboard` (:65), `incidents` (:73), `my-queue` (:75) | ✅ |
| Triage | `sla-aging` (:76), `response` (:78) | ❌ `disabled: true` |
| Investigate | `investigations` (:86), `evidence-explorer` (:89), `entity-search` (:92), `attack-story-rollup` (:94) | ✅ mounted |
| Intelligence | `ti` (:102), `ioc` (:105), `command` (:108), `malware` (:111), `mitre` (:114), `kb` (:117) | ✅ |
| Telemetry | `telemetry-studio` (:126), `telemetry-health` (:129) | ✅ |
| Exposure | `exposure` (:140) ✅ · `assets` (:138), `vulnerabilities` (:139), `attack-paths` (:143), `critical-assets` (:144) | ❌ disabled |
| Detection | `rule-studio` (:151), `detection-registry` (:154), `correlation-rules` (:157), `detections` (:160) | ✅ |
| Automation | `playbooks` (:169), `automation-rules` (:172), `approvals` (:175) | ✅ mounted |
| Admin | integrations, data-sources, collectors, agents, parsers, normalization, detection-rules, response-policies (:189-199) | ✅ · `sdl` (:195) ❌ disabled |

Backing APIs proven live: `/api/incidents/{id}/investigation`, `/investigation/findings`, `/investigation/executions`, `/api/investigations/{iid}/timeline`, `/api/investigation/{case_id}/{iocs,hunting}`, `/api/v2/cases/{case_id}/*` (16 paths).

| Dimension | Verdict |
|---|---|
| Implemented | ✅ |
| Registered | ✅ 27 pages, 9 nav groups |
| Executed | ✅ |
| Runtime-proven | 🟡 renders; honest empty states confirmed by prior UI-repair work; **7 tabs are explicitly disabled** |
| Production-ready | 🔴 — **two coexisting analyst consoles** (main SPA + standalone app) |

## 4 · Industry benchmark

| Vendor | Analyst investigation experience |
|---|---|
| **Microsoft Defender XDR** | Unified portal; entity-centric investigation pages; Automated Investigation & Remediation; Activities tab; guided + advanced hunting modes |
| **Cortex XDR** | **Causality view** (process tree via Causality ID → Causality Group Owner) + **Timeline**; XQL search inline in the investigation |
| **SentinelOne** | **Storyline** auto-stitches process/file/network/identity into one visual narrative; 365-day EDR context; Purple AI zero-click Agentic Investigation with auditable evidence chain |
| **CrowdStrike** | Threat Graph pivots (`get_ran_on`, `get_vertices`, `get_edges`) + Real Time Response shell |
| **Cisco XDR** | AI-generated incident summary, attack graph, recommended response steps; classic view toggle |
| **Splunk ES** | Mission Control; findings/finding-group investigation (max 100 findings/investigation) |
| **Trellix** | Investigation guides that adapt per case |

## 5 · Gap

| Gap | Severity | NivXRay evidence |
|---|---|---|
| **Two coexisting analyst consoles** | **P1** | main-SPA `AnalystWorkspacePage.jsx` + `apps/nivxray-xdr/` workspace. Stage-11 feature-parity migration is the standing plan |
| 7 nav tabs disabled | P1 | `XdrShell.jsx:76,78,138,139,143,144,195` — honest, but the console advertises structure it cannot serve |
| No in-workspace query/pivot | **P0** (inherited) | CAT-09 — no executable hunting language; `entity-search` tab exists with **0 entity API paths** behind it (CAT-10) |
| Investigation renders empty counters | P1 | `/api/v2/cases` → `event_count: 0, entity_count: 0`; `v2_case_events`/`v2_case_entities` = 0 docs |
| Security State invisible to the analyst | P2 | 81 AG files + 14 endpoints; only `frontend/src/v2/pages/SecurityStateTab.jsx` surfaces it, in the **frozen** main SPA, not the active XDR console. `security_states` = 3 docs |
| No process-tree causality view in the XDR console | P2 | `/api/edr/process-tree` and `/api/v2/cases/{id}/trajectory/device` exist and are not composed into a Cortex-style causality view |

## 6 · UNKNOWN

- U-04.1 — Functional parity between the two consoles (master U-6). Requires interactive testing → outside read-only audit.
- U-04.2 — Which of the 27 pages bind to live data vs render honest-empty. Prior UI-repair work asserts honest empty states; per-page binding was **not** re-verified here.
