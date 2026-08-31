# Layer 2 · Incident Queue Visual/Product Rebuild — Mandate

**Locked** · Owner directive · 2026-02-32
**Status** · Pending · fresh session · full-context delivery required

## Explicit scope guard

> Layer 2 is a **visual / product-quality rebuild** of the Incident
> Queue, **not a cosmetic patch**.  Build the queue presentation
> layer from scratch around the existing authoritative data.

## References (UX benchmarks · never clone)

- Microsoft Defender XDR — Incident Queue · https://learn.microsoft.com/en-us/defender-xdr/incident-queue
- Microsoft Defender XDR — Manage Incidents · https://learn.microsoft.com/en-us/defender-xdr/manage-incidents
- Microsoft Defender XDR — Investigate Incidents · https://learn.microsoft.com/en-us/defender-xdr/investigate-incidents
- ServiceNow SIR — Workspace Landing · https://www.servicenow.com/docs/r/security-management/security-incident-response/sir-workspace-landing-page.html
- ServiceNow SIR — New UI · https://www.servicenow.com/docs/r/xanadu/security-management/security-incident-response/sir-new-ui.html

## Theme lock (**IMPORTANT · overrides current dark-only styling**)

The current all-dark theme is **not** a design constraint.  Ask the right question:

> *What theme gives an SOC analyst the best readability, information density and visual hierarchy?*

If that is light — use light.  If dark — use dark.  If hybrid (light workspace + dark drawers, or Defender-style neutral surfaces) — use hybrid.  **Provide Light / Dark / System theme support** where it improves analyst ergonomics.

### 🔒 2026-02-32 · Owner clarification · full visual-system unlock

Do **NOT** treat the current black/dark background as a fixed NivXRay
constraint.  For Analyst Operations / Incident Queue / Incident Record
work, do not stick to the existing black theme simply because NivXRay
currently uses it.

Use the Microsoft Defender XDR + ServiceNow SIR references as
**authoritative UX benchmarks for the overall visual language**,
including every one of the following:

- colour / theme
- background and surface colours
- typography hierarchy
- spacing and density
- cards and panels
- borders / dividers
- buttons
- dropdowns
- filters
- chips / pills / badges
- tables
- tabs
- toolbars
- side panes / drawers
- hover / selected / active states
- empty states
- information hierarchy
- responsive behaviour

Do not assume NivXRay must remain black.  Evaluate the references and
choose the theme that produces the most professional, readable,
analyst-friendly SOC experience.  A light, dark, or hybrid treatment
is acceptable — this is a **design decision**, not an inherited
constraint.

**Reference UX patterns to derive** (never clone branding · logos ·
proprietary assets · pixel layouts):
- Defender's priority-score model, configurable columns, time-range
  selection, filters, search, and incident summary pane.
- ServiceNow SIR's quick filters, personalized/sortable incident
  lists, peek/preview views, quick actions, and tabbed incident
  experience.

Create a **distinct NivXRay visual system** derived from the best
ideas in those references — think like a **product designer + SOC
architect**, not like someone applying a dark-theme cosmetic patch.

**Engineering constraint stays absolute**: zero changes to the
existing investigation engine fabric.  Presentation/workflow layers
consume existing APIs, canonical evidence, and existing engine
outputs only.  Missing engine data → honest empty/unknown state.
Never fabricate data merely to make the UI look complete.

## Target layout

```
┌───────────────────────────────────────────────────────────────────┐
│ NivXRay XDR                       Search       Time     Actions   │
├───────────────────────────────────────────────────────────────────┤
│ Incidents                                                         │
│                                                                   │
│ [Critical] [High] [Unassigned] [My Queue] [SLA] [On Hold] [New] [Updated] │
├───────────────────────────────────────────────────────────────────┤
│ Search │ Filters │ Saved View │ Customize Columns │ Export        │
├───────────────────────────────────────────────────────────────────┤
│ All │ New │ In Progress │ On Hold │ Resolved │ Closed             │
├───────────────────────────────────────────────────────────────────┤
│ □ │ Priority │ Severity │ Incident │ Verdict │ Customer │ …       │
│───┼──────────┼──────────┼──────────┼─────────┼─────────┼──────────│
│ □ │ P1       │ CRITICAL │ INC-…    │ MALICIOUS│ ACME    │ …       │
│ □ │ P2       │ HIGH     │ INC-…    │ UNKNOWN  │ ACME    │ …       │
│ □ │ P3       │ MEDIUM   │ INC-…    │ —        │ …       │ …       │
└───────────────────────────────────────────────────────────────────┘
                            selecting a row → right-side preview drawer
```

## Required components

### Chip / badge families (build as reusable components in `xdr/components/chips/`)

| Family | Values | Style |
|---|---|---|
| **Priority** | `P1` red · `P2` orange · `P3` amber · `P4` green · `P5` gray | filled pill · monospace |
| **Severity** | `CRITICAL` · `HIGH` · `MEDIUM` · `LOW` · `INFO` · `UNKNOWN` | filled badge · uppercase |
| **Verdict** | `MALICIOUS` red · `SUSPICIOUS` orange · `BENIGN` green · `UNKNOWN` gray | filled pill |
| **State** | `NEW` · `TRIAGED` · `INVESTIGATING` · `CONTAINMENT` · `ERADICATION` · `RECOVERY` · `RESOLVED` · `CLOSED` | outlined pill |
| **Side-state** | `WAITING_CUSTOMER` · `WAITING_EVIDENCE` · `WAITING_VENDOR` | outlined pill · dashed border |
| **Domain tag** | `EDR` · `NDR` · `ITDR` · `EMAIL` · `IDENTITY` · `CLOUD` · `NETWORK` · `ENDPOINT` · `CTEM` | small outlined tag · never fabricated |

### Layout components
1. **Priority strip** — 8 compact interactive tiles above the toolbar (Critical · High · Unassigned · My Queue · SLA Risk · On Hold · New · Updated).  Click → apply filter.
2. **Toolbar** — Search · Filters · Saved Views · Customize Columns · Export CSV · Refresh.  All right-aligned except Search.
3. **State-tab strip** — All · New · In Progress · On Hold · Resolved · Closed.  URL-persisted.
4. **Time selector** — Last 24 h · 3 days · 1 week · 30 days · 6 months · custom.  Default = last 7 days (Defender parity).
5. **Filter chip row** — active filters as removable chips.  (already partially built in Phase 2.)
6. **Sticky table header** on vertical scroll.
7. **Multi-select column** (checkbox) — left of Priority.
8. **Bulk-action toolbar** — appears when ≥1 row selected · already built in Phase 2 (Assignee + State only).
9. **Customize Columns dropdown** — checkbox list + drag reorder.  Persisted per saved view.
10. **Right-side preview drawer** — click row (not the incident name) → drawer opens:
     - Priority pill · Verdict pill · Confidence %
     - Customer · Detection Source
     - Executive Summary excerpt
     - Auto-Investigation status
     - Evidence / Techniques / Engine Results counts
     - `[Open Investigation]` button
     - Up / down navigation arrows (matches Defender)
    Click the incident name → navigate to full detail (unchanged).
11. **CSV export** — top 10 000 rows · matches Defender cap.
12. **Responsive horizontal scroll** for the dense table.

### Default visible columns (high-value analyst set · 10)
`Priority · Severity · Incident (name) · Verdict · Customer · Detection Source · Evidence · MITRE · SLA · Owner`

### Hidden by default (via Customize Columns · 5)
`Confidence · Aging · State · Last Activity · Auto-Investigation · Engine Results`

## Anti-fabrication contract (unchanged)

| Data absent | Render |
|---|---|
| No evidence | `NO EVIDENCE` |
| No enrichment | `NOT AVAILABLE` |
| No engine execution | `NOT RUN` |
| No MITRE | `—` |
| No SLA | `—` |
| No verdict | `UNKNOWN` |
| Engine failed | `FAILED` |

Never fabricate hashes · IPs · users · processes · verdicts · techniques · engine results · enrichment · recommendations · timelines.

## Engine fabric — NEVER touched

The UI is a consumer.  Never modify / rename / duplicate: IDA · IUE · UAIE · VEEE · DIE · ICE · IEDDE · UIL · Interpreter · Recipe · Recursive · Artifact Intel · PE · Behavioral · Fingerprint · Technique · IOC Intel · CEM · Provenance · SSOT · KB · MITRE · LOLBAS · Sigma · TI · OSINT · Evidence-Driven Mitigation · 43 UAIE plugins.

## Acceptance — 6 screenshots required

Before declaring Layer 2 complete, visually verify on the deployed URL and provide screenshots of:

1. Full queue (KPI strip + toolbar + dense table)
2. KPI strip + toolbar close-up
3. Customize Columns dropdown open
4. Filtered queue (chip visible, results filtered)
5. Right-side incident preview drawer
6. Bulk-selection state (multi-row selected + bulk-action bar visible)

## Delivery expectation

Fresh session · full context budget · single well-scoped commit · six screenshots · deploy verification on `https://nivxray-xdr.vercel.app/xdr/incidents`.

Do **not** interpret this mandate as another cosmetic patch.
