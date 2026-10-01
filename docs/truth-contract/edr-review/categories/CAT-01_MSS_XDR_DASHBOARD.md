# CAT-01 · MSS / XDR Dashboard

> STRICT READ-ONLY deep-dive. Boundary: PRE-AG = `5d67934e`, AG import = `95b1c82a`. See master §A.
> **Framing:** the dashboard is an **experience over the XDR planes**, not the architecture. Nothing in this file may be read as evidence about detection, correlation or telemetry capability.

## 1 · PRE-AG baseline (proven)

| Artifact | Evidence | Status |
|---|---|---|
| `backend/routers/xdr_mss.py` | present at `5d67934e`; untouched by AG | IMPLEMENTED |
| `backend/routers/xdr_dashboard.py` | present at `5d67934e`; `router = APIRouter(prefix="/xdr/dashboard")` at `xdr_dashboard.py:27` | IMPLEMENTED |
| `apps/nivxray-xdr/src/xdr/pages/XdrMssDashboardPage.jsx` / `XdrDashboardPage.jsx` | present at `5d67934e` (app created `fcbcaed1`, 2026-08-29) | IMPLEMENTED |
| MSS shell tab | `apps/nivxray-xdr/src/xdr/XdrShell.jsx:65` `{ key: "mss-dashboard", label: "MSS Dashboard", to: "/xdr/mss-dashboard" }` | REGISTERED |

## 2 · AG delta

**NONE.** No file under `backend/routers/xdr_mss.py`, `xdr_dashboard.py`, or the MSS/Dashboard pages appears in `git diff --name-status 95b1c82a^ 95b1c82a`. The dashboard is **100% PRE-AG NivXRay**.

## 3 · Current state (live)

8 MSS endpoints + 1 dashboard endpoint, all mounted:

```
/api/xdr/mss/kpis                 /api/xdr/mss/soc-queue
/api/xdr/mss/analyst-workload     /api/xdr/mss/state-distribution
/api/xdr/mss/auto-investigation   /api/xdr/mss/detection-overview
/api/xdr/mss/customer-operations  /api/xdr/mss/recent-activity
/api/xdr/dashboard/tiles
```

**RUNTIME-PROVEN** (authenticated live call, 2026-09-05):

- `GET /api/xdr/mss/kpis` → `groups[].tiles[]` with `count`, **`count_source: "live"`**, `lens_href`, `tone`.
- `GET /api/xdr/dashboard/tiles` → same tile shape plus an explicit invariant string:
  > `"Dashboard tiles are pure projections of live incident data · no cached counters · no fabricated numbers · tile count == queue count for the same lens."`
- Observed live values: `critical: 0`, `high_priority: 7`. Non-zero, non-fabricated, and consistent with the incident store.

| Dimension | Verdict |
|---|---|
| Implemented | ✅ |
| Registered | ✅ (mounted, 9 live paths) |
| Executed | ✅ |
| Runtime-proven | ✅ |
| Production-ready | 🟡 — tiles are honest projections, but they project a store that is itself split (master §G DEV-3) |

**Honest-state compliance: EXEMPLARY.** `count_source` and the tile invariant are exactly the NO EVIDENCE → NO CLAIM contract expressed in the API payload rather than only in the UI.

## 4 · Industry benchmark

| Vendor | Documented dashboard capability |
|---|---|
| **Microsoft Defender XDR** | Unified incident queue with a Defender Queue Assistant producing a **0-100 ML priority score** from severity, asset criticality, MITRE techniques and attack-disruption signals; filtering by service/detection source, status, sensitivity label, device group (learn.microsoft.com/defender-xdr/incident-queue) |
| **Cisco XDR** | Incident Manager centralises correlated high-priority alerts; **asset value assignment feeds incident priority scoring**; AI-generated incident/asset summaries (docs.xdr.security.cisco.com) |
| **Cortex XDR** | Issue/incident dashboards over the Cortex Native Data Lake |
| **CrowdStrike** | Fusion SOAR execution-history and KPI dashboards |
| **SentinelOne** | Singularity console with Storyline-driven views |
| **Splunk ES** | Mission Control + risk-based finding/finding-group views with cumulative risk score |
| **Trellix** | XDR console with Insights-driven prioritisation by sector/geography |

## 5 · Gap

| Gap | Severity | Justification (NivXRay-evidence-led, not vendor-led) |
|---|---|---|
| No asset-criticality input to tile prioritisation | P2 | `xdr_cve_assets` = 24 docs exist, so the data exists but does not reach the dashboard. Cisco/MS both monetise exactly this join |
| No exec/board or MSS-customer reporting surface | P2 | `/api/xdr/mss/customer-operations` exists but there is no report artifact; `xdr_executive_summary.py` exists un-surfaced |
| Tiles project a split case store | P0 (inherited) | 484 `workspace_cases` vs 1 `xdr_incidents` — see master DEV-3. Tile *honesty* is fine; tile *meaning* is ambiguous |
| No coverage/posture tile (MITRE coverage, source health) | P1 | `/api/mitre/heatmap` and `/api/xdr/collector/telemetry-health` both exist and are not on the dashboard — a pure projection away |

## 6 · UNKNOWN

- U-01.1 — Whether the MSS tenant/customer dimension is enforced or cosmetic. `/api/xdr/mss/customer-operations` exists; **0 of 733 live paths contain `tenant`**. Resolving this requires executing the isolation tests → out of read-only scope.
