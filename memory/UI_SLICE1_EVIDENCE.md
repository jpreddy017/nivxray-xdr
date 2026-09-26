# UI SLICE 1 — EVIDENCE (owner review)

2026-09-18. Scope executed: **S1-A design system · S1-B global shell ·
S1-C/D/E Data Sources, Add wizard, Health/Verify.** Nothing else in the SPA
was modernised. W1 CLOSED/FROZEN untouched. W2-1 untouched.

## 1 · Files changed (start HEAD `3ae41185` → end HEAD `eace2a90` + working tree)

**New (nx design system)** `xdr/nx/NxDataTable.jsx`, `NxFlyout.jsx`,
`NxStatus.jsx` (NxStatus · NxHealthVerdict · NxMetric), `NxTabs.jsx`,
`nx-datatable.css`.
**New (feature)** `xdr/datasources/dsApi.js`, `DataSourcesPage.jsx`,
`SourcesAndCollectors.jsx`, `IntegrationsAndAdd.jsx`.
**Modified** `xdr/nx/index.js` (exports), `xdr/nx/NxSurface.jsx` (icon-less KPI
fix), `App.jsx` (2 routes + lazy import), `xdr/XdrShell.jsx` (rail primary).
**Renamed** `xdr/design/CortexOnboardingWizard.jsx` →
`xdr/design/NxIntegrationWizard.jsx` with its 2 importers updated
(`IntegrationControlCenter.jsx`, `design/index.js`) — behaviour, props and
imports preserved; no global string rename was performed.
**Not touched:** backend, collector, W1 artefacts, W2 harness, every other SPA
route.

## 2 · Design-system consolidation map (`xdr/nx/` is authoritative)
| existing | verdict | action taken |
|---|---|---|
| `NxPageShell`, `NxSurface`, `NxKpi`, `NxChip`, `NxEmpty`, `NxSkeleton`, `NxProvenance`, `nx-tokens/nx-theme/nx-page.css` | **ADOPT** | reused unchanged by every Slice-1 screen |
| missing table / flyout / tabs / status grammar | **BUILD** | added as nx primitives, exported from `@/xdr/nx` |
| `xdr/design/tokens.css` (2nd token set), `*V2` components | **MIGRATE-LATER** | untouched; no Slice-1 screen imports them. Deletion only after their consumers move |
| `xdr/components/` + duplicate `components/incidents/` | **MIGRATE-LATER** | untouched — they belong to the Incidents slice |
| `CortexOnboardingWizard` | **RENAMED** | now `NxIntegrationWizard` |

**Design-system defect found and fixed for the whole platform:** `.nx-kpi` is a
`32px | 1fr` grid for its icon, so *any* icon-less KPI dropped its body into the
32px column and wrapped one word per line. Caught in the first screenshot pass,
fixed with a `nx-kpi--noicon` modifier applied by `NxKpi` and `NxMetric`. This
was a pre-existing defect, not one introduced here.

## 3 · Global shell
One permanent rail; **Data Sources is now a rail primary** between Assets and
Client Management, not a page buried in Administration. No second permanent
navigation column was added. Depth is rail → page tabs → flyout → full page.
**Route compatibility:** nothing was removed or redirected. `/xdr/admin/*`
telemetry surfaces still resolve exactly as before; Slice 1 only *adds*
`/xdr/data-sources` and `/xdr/data-sources/:tab`.

## 4 · Data Sources IA implemented
`Overview · Sources · Collectors · Integrations · Coverage · Health · Verify`,
plus the `Choose → Recommended setup → Configure/deploy → Verify → Ready`
wizard. It consolidates the fragmented workflow as a *reading* surface: it does
not create a ninth telemetry screen and does not duplicate the admin bodies.

## 5 · API → UI provenance map (every displayed field)
| displayed | authoritative source |
|---|---|
| Sources NivXRay can interpret · source list · DSM · aliases | `GET /api/xdr/collectors/sources/catalog` |
| Accepted events, per-source telemetry state, coverage by DSM | `GET /api/xdr/ingest/routing/summary` |
| Collectors, state, authorised sources, events received, last event | `GET /api/xdr/collectors` |
| Collector runtime, version, heartbeat | collector plane `GET /collectors` |
| Transports, ingest state | collector plane `GET /telemetry-health` |
| Queue depth, oldest queued, dead letter, delivered, retrying, worker | collector plane `GET /outbox/health` |
| Integration catalog transports, capabilities, credentials | collector plane `GET /source-types`, `GET /connectors` |
| Canonical evidence proof in Verify | `GET /api/xdr/ingest/routing/deliveries?result=ACCEPTED&limit=1` → `evidence_ref` |
| Tenant | active tenant (`X-Tenant-Id`), never a default |

Live values observed in the screenshots: **9** declared sources, **9**
receiving, **47,150** accepted events, **0** collectors in the selected tenant,
**13** catalog cards, **3** transports — all real, none typed in.

## 6 · Honest unavailable states (BUILD contracts, declared not faked)
`Events per second` · `Collection latency P50/P95/P99` · `Evidence
completeness (COLLECTION_GAP)` · `Dropped events` · `Rules consuming this
source` · `parser_ok/normalized_ok as measured values` · `dedupe
observability`. Each renders a dashed chip plus the reason — e.g.
*"COLLECTION_GAP records are not implemented yet (W2 contract C-4)"*. Zero
fabricated numbers were introduced.

## 7 · W2 separation held
The wizard's Windows step states plainly: *"Sysmon telemetry is already proven
into production. Additional Windows channels — Security, PowerShell, Defender,
AppLocker, WMI, Task Scheduler — are not claimed here until the W2 acquisition
engine proves them."* No multi-channel capability is implied anywhere.

## 8 · Engineering acceptance
| check | result |
|---|---|
| production build (`yarn build`) | **PASS** — exit 0, twice, `DataSourcesPage` chunk 32.14 kB gzip 9.51 kB |
| route/deep-link regression | **PASS** — no route removed or redirected; `/xdr/data-sources/:tab` deep-links (overview/sources/health verified live) |
| light mode | **PASS** (screenshots) |
| dark mode | **PASS** (screenshot, dark flyout + wizard) |
| loading / empty / error states | implemented in `NxDataTable` + `NxEmpty` + `nx-dt-error`; loading skeletons and honest chips observed |
| accessibility basics | `role=tablist/tab/dialog/status/alert`, `aria-selected`, `aria-modal`, `aria-label` on close and checkboxes, keyboard `Enter` on table rows, visible `:focus-visible` rings |
| tenant context | preserved — all reads go through `lib/api` / `collectorApi` interceptors; no page sends a default tenant |
| RBAC + API auth | unchanged; no new endpoint, no new credential path |
| W1 collector presentation | still truthful — collector state renders from `state`/`state_reason` only |
| fake production telemetry | **none introduced** |
| W1 untouched · W2-1 untouched | **PASS** — `git status` shows only `apps/nivxray-xdr/src/**` |
| `data-testid` coverage | every interactive element and status (tabs, table controls, rows, cards, wizard steps, verify rows, KPIs) |

**Not claimed:** no automated frontend test suite exists in this app, so
"frontend tests pass" cannot be asserted — evidence here is the production
build plus live screenshots against real APIs. A `NxDataTable` test harness is
proposed for Slice 2 rather than pretended now.

## 9 · Screenshots captured
`/tmp/s1_overview_light.png` · `s2_sources.png` · `s3_verify.png` ·
`s5_integrations.png` · `s6_wizard_deploy.png` · `s7_dark.png` ·
`s8_overview_final.png` · `s9_health.png` (before/after of the KPI defect is
`s4`→`s8`).

## 10 · Recommended Slice 2 (proposal only — not authorised)
1. **Incidents** onto the same shell/table/flyout, collapsing the duplicate
   incident component tree.
2. Retire `xdr/design/tokens.css` once its consumers are migrated.
3. Consolidate the 3 dashboards, then the 2 rule studios and 3 KB routes.
4. Add the first BUILD contract the UI is already asking for — per-stream
   counters + computed latency — so Verify and Health stop showing dashes.
