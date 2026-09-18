# E2E-UX0 · WAVE 1 ACCEPTANCE PACKAGE — GLOBAL SHELL · INCIDENTS QUEUE · INCIDENT WORKSPACE

Returns items 1–16 of the owner directive §39. **Prototype only. No production
route replaced.**

Route: **`/xdr/_ux0-preview/workspace`** (additive, `Protected`, badged
`DESIGN-STATE PREVIEW` in the title strip).
Earlier prototype `/xdr/_ux0-preview` is retained untouched for comparison.

---

## 1 · Primary reference
Owner-supplied **Cortex XDR** split-view Incident Workspace screenshot
(Investigation → Incidents, "Advanced view"; product build not determinable
from the image, recorded as `unknown`).
Catalogue rows 1–3 of `E2E_UX0_REFERENCE_CATALOGUE.md`.
**Cortex XDR is the shell/layout authority for this surface. It is NOT the
NivXRay capability authority.**

## 2 · Structural breakdown measured off the reference, and what was built
| # | Reference element | Reimplemented | Notes |
|---|---|---|---|
| 1 | Page title strip `Incidents` + italic `Found N results` + right-side `Alerts Table` / icon cluster | ✅ | `.cx-top` |
| 2 | Persistent left queue ≈27% width, own scroll, sticky `Sort:` bar | ✅ | `.cx-queue`, 27% / min 320 / max 460 |
| 3 | Queue row: italic "Updated …" right-aligned, severity letter tile, `Score N`, assignee, state (outlined `NEW` chip), bold ID + title, mono device/user context line | ✅ | `.cx-row`; selected row gets a 3px accent inset + selected surface |
| 4 | Detail header: severity▾ · ★ · `ID - NNNN` · divider · "Add incident name" · right cluster Score / assignee▾ / status▾ / ⋮ | ✅ | `.cx-hdr` |
| 5 | Italic one-line incident sentence | ✅ | `.cx-sentence` |
| 6 | Stat cluster row: alerts donut ring with centre count + `Sources:` glyph row, Host tile + count, Users tile + count, right-aligned `Open for N days / Created on …` panel | ✅ | `.cx-stats`, conic-gradient ring |
| 7 | Tab row, underline-active, left-aligned, horizontally scrollable | ✅ | `.cx-tabs`, 36px, 2px underline |
| 8 | `Incidents by MITRE \| ATT&CK  · N Tactics and N Techniques` lead line + right-side checkbox | ✅ (checkbox replaced) | see §5 difference D3 |
| 9 | 14-column ATT&CK tactic strip, count above label, non-zero in red, vertical dividers | ✅ | `.cx-attck`, enterprise tactic order |
| 10 | `Timeline` section with `Show More` and a horizontal lifecycle rail of icon nodes joined by lines | ✅ | `.cx-rail` |
| 11 | Four equal panels with `Show More`, `Total N`, donut + severity legend bars, source tree, host list, user list | ✅ (illustration substituted) | see §5 difference D2 |
| 12 | Independent scrolling: queue scrolls under a sticky sort bar; detail scrolls independently | ✅ | |

## 3 · Screenshots captured
| viewport | theme | content |
|---|---|---|
| 1920×1080 | LIGHT | queue + INC-2916 selected + Overview (header, stats, tabs, ATT&CK strip, lifecycle rail, 4-panel grid) |
| 1920×1080 | DARK | same, pre-correction |
| 1920×1080 | DARK | same, **post-correction** (contrast pass) |
| 1440×900 | LIGHT | same — confirms the queue stays scannable and the ATT&CK strip / lifecycle rail scroll horizontally rather than breaking |
Interaction verified in the same runs (see §7).
Not yet captured: 2560×1440 — **declared as a gap**, see §9.

### Second correction pass (found at 1440×900)
4. **Queue `Score NOT AVAILABLE` wrapped onto two lines** at narrow queue
   widths → `white-space: nowrap` on the value.
5. **Lifecycle rail was clipped without a scroll affordance** at 1440 →
   `overflow-x: auto` on the rail (the ATT&CK strip already scrolled).

### Production-route regression check (executed)
`/xdr/incidents` and `/xdr/intelligence/command` both still render with the
shell, tenant pill and theme toggle intact. The prototype is additive.

## 4 · Correction pass performed (§28 contrast gate)
Three defects were found in DARK on the first render and fixed before this
package was written:
1. **Queue severity letter tile** — white glyph on a saturated amber/red fill
   was unreadable at 9.5px. Changed to the theme-aware `*-bd` fill with a
   near-black glyph.
2. **Header severity pill** — solid `--nx-critical` fill produced red text on
   red in DARK. Changed to the standard theme-aware bg/text/border triad, which
   is legible in both themes. *We did not reproduce the reference's
   low-contrast behaviour.*
3. **Zero-count ATT&CK tactic labels** — `--nx-muted` was too close to the
   surface in DARK. Raised to `--nx-text-dim`; hit/no-hit remains distinguished
   by colour **and** by the count value, never by colour alone (§14).

## 5 · Remaining visual differences vs the reference — declared, not hidden
| id | difference | reason | closable? |
|---|---|---|---|
| D1 | Typeface glyph shapes differ | Cortex uses a licensed brand face; we use the Nx type stack (Outfit / IBM Plex Sans / JetBrains Mono). Scale, weight and rhythm match. | No — licensing |
| D2 | The 3D "stacked layers" illustration in the Sources panel is replaced by a source-count row + `3 OF 5 CONTRIBUTING` chip | proprietary artwork; also the honest state is more useful than decoration | No — IP boundary |
| D3 | `Include Incident Insights` checkbox replaced by an `EVIDENCE-BACKED ONLY` chip | NivXRay has no "insights" toggle; the chip states the actual ATT&CK policy | No — capability truth |
| D4 | Alerts donut is a CSS conic ring with a centre count, not a segmented SVG chart with hover | Wave 1 scope; the segment ratio is real (high/medium) | Yes, Wave 2 |
| D5 | Queue has no bulk-select checkbox column yet | hover-revealed selection is specified in the blueprint but not built in Wave 1 | Yes, Wave 2 |
| D6 | `Legacy view / Advanced view` toggle and `Feedback` link not reproduced | vendor-specific product features, not NivXRay capabilities | No — intentional |
| D7 | Exact hex values approximate the reference | a compressed screenshot only permits approximate sampling; all colour comes from Nx tokens so both themes work | No — measurement limit |
| D8 | Detail pane leaves vertical whitespace below the grid at 1080p | reference fills it with an events table that is Wave 2 (Alerts & Insights / Detections) | Yes, Wave 2 |

## 6 · NivXRay capabilities preserved
All **ten** investigation capabilities are present in the tab strip:
`Overview · Attack Story · Timeline · Evidence · Entities · Detections ·
MITRE · Response · Activity · Report` — five more than the reference screen
shows. **Nothing was consolidated and nothing was deleted** to gain visual
similarity. Tabs beyond Overview render an explicit "scheduled for Wave N,
primary reference X" empty state rather than a mock, so no decorative control
implies a capability that does not exist.
Also preserved: permanent single left rail (no second rail), tenant pill,
global search, theme toggle, Ribbon — the existing `XdrShell` is reused, not
re-created.

## 7 · Interaction verification (executed, not asserted)
- queue row click → right pane re-renders (`INC-2919` sentence confirmed, then
  back to `INC-2916`) with the selected row visually distinct
- `Sort:` control present and operable
- tab switch `Overview → Attack Story → Overview` with no loss of queue state
- entity pivot: host `FIN-WS-014` → `NxFlyout` opens over the workspace with an
  `Open full page` escape; close returns to the workspace, queue intact
- theme toggle LIGHT ⇄ DARK, layout stable in both
- all `data-testid` hooks resolve: `cx-workspace-page`, `cx-queue` (5 rows),
  `cx-detail`, `cx-incident-header`, `cx-tabs` (10), `cx-attck-strip` (14
  tactics), `cx-lifecycle-rail`, `cx-overview-grid`, `cx-open-for`, `cx-flyout`

## 8 · Unavailable UI fields and the backend reason
| UI field | reference meaning | NivXRay state | reason |
|---|---|---|---|
| `Score 87` | Cortex incident risk score | `NOT AVAILABLE` (dashed chip, reference position kept) | NivXRay computes no incident score; no authoritative API field exists |
| `Resolved` lifecycle node | resolution timestamp | `NOT OBSERVED` | incident is open; the node is not fabricated |
| Sources contributing | source count | `3 OF 5 CONTRIBUTING` | identity + email telemetry not connected; `CONNECTED` requires real telemetry |
| ATT&CK counts | technique counts per tactic | evidence-backed only; zero ≠ unmapped ≠ unknown | only techniques that can cite an artifact are counted (D-11) |
| every other panel | — | **DESIGN-STATE fixture**, badged in the title strip | Wave 1 is a visual acceptance environment; no fixture is persisted |

## 9 · Declared gaps in this package
1. 2560×1440 capture not taken (1920×1080 light+dark and 1440×900 light were).
2. No automated side-by-side image-diff tooling; the comparison in §2/§5 is a
   manual structural measurement, stated as such.
3. Keyboard focus-visible and responsive behaviour below 1180px were not
   systematically exercised.
4. Wave 1 covers the workspace **Overview** tab only; the other nine tabs are
   honest Wave-2/3/4 placeholders.
5. The Incidents *queue page* (`/xdr/incidents`) itself is not yet rebuilt —
   Wave 1 delivers the queue **as the workspace's left pane**, which is the
   reference's own model.

## 10 · Build / test results
- Vite dev server: compiles clean; no new `Internal server error` entries after
  these files were added (the 48 historical entries predate this work).
- Backend untouched by Lane A. Decoder suites unchanged from the R-1/R-3
  package (277 passed + 22 acceptance + 7 from the testing agent).
- No production route altered; `git status` shows only `App.jsx` (two additive
  lazy imports + two `Route` lines) plus new files under `src/xdr/ux0/`.

## 11 · Files
**New:** `Ux0CortexWorkspace.jsx`, `cortexFixtures.js`, `ux0-cortex.css`,
`memory/E2E_UX0_REFERENCE_CATALOGUE.md`, `memory/CI_DISCOVERY_R4_R5.md`.
**Modified:** `apps/nivxray-xdr/src/App.jsx` (additive only).

## 12 · Repository state
```
branch : feature/rc2-alignment
start HEAD : 6caa3698
end   HEAD : 6caa3698   (platform commits between steps; no manual commit made)
worktree   : M App.jsx · new ux0 files · new memory docs
             ?? memory/AUTHORITATIVE_XDR_yarn.lock (pre-existing, unrelated)
```

## 13 · Boundaries held
W1 untouched · W2-1 untouched · RBAC-1+ not started · no second auth/tenant
authority · Response approval authority untouched · no decoder semantics
changed by Lane A · no route deleted or redirected · no corpus gate weakened ·
no fabricated data · `xdr/nx/` remains the only design system (`NxFlyout`,
`NxEmpty`, `XdrShell` reused; no new token system, table library, flyout or
page shell created).

## STOP
Wave 1 delivered for owner **visual and functional** review.
No production promotion. Wave 2 (Attack Story · Timeline · Evidence · Entities
· Detections · MITRE · Activity) does not start without approval.
