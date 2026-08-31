# NivXRay Enterprise UX Gap Analysis · v1

> **Status**: Phase A of the Enterprise Visual System work. No
> implementation begins until this document is signed off by the
> product owner.
>
> **Purpose**: honestly compare the current NivXRay XDR surfaces
> against Microsoft Defender XDR (primary benchmark) and ServiceNow
> Security Incident Response Workspace (secondary benchmark), then
> commit to specific design decisions for each area of the product
> so that subsequent phases are focused execution, not exploration.
>
> **Absolute constraints** (unchanged from every earlier round):
>   1. Engines are not touched.
>   2. NOT_RUN · NO EVIDENCE · NOT AVAILABLE · UNKNOWN · em-dash
>      remain honest. No fabricated data.
>   3. NivXRay must not clone Defender or ServiceNow.  Both are
>      references for design language and interaction patterns —
>      neither is a template.

---

## 0 · Self-critique of the current state

Before proposing where to go, an honest read of what shipped.

**What is genuinely good**

- Consistent information architecture across queue, record, tabs.
- Evidence-first content model that resists fabrication (four-state
  evidence semantics, honest empty states).
- Deep-navy chrome + warm workspace + white cards is a workable
  foundation.  Purple identity survives.
- Backend / engine fabric is untouched — the data model is not the
  problem.

**What is genuinely weak**

- **Visual monotony**.  Cards look like cards look like cards.  The
  page → surface → section → object → metadata hierarchy is not
  visible; everything reads at the same weight.
- **Cards are decoration, not information architecture**.  On the
  MITRE page every technique box has identical weight, so nothing
  says "this is the primary object", "this is correlated", "this
  is merely context".
- **Typography is passive**.  `CRITICAL`, `105 incidents`,
  `workspace_cases.evidence`, and `Last synced 2 min ago` all render
  in almost the same treatment.  A commercial analyst product
  encodes meaning in the type ramp itself.
- **Semantic colour is applied to text but not to the surrounding
  affordances** (border, icon, chip, hover, selected state, focus
  ring, small indicator).  A "malicious" chip and a "benign" chip
  do not feel meaningfully different at a glance.
- **The product does not respond to the analyst**.  Hover produces
  no context.  Selection produces no depth.  There is no peek/detail
  behaviour on the MSS Dashboard.  Priority chips have no
  explainer-on-hover.  SLA does not visibly tick down.
- **The sidebar is a nav tree, not a designed navigation surface**.
  No collapsed mode, no workspace context, no notification indicators,
  no keyboard focus polish, no contextual sub-navigation.
- **The top bar is generic SaaS**.  It should read as an analyst
  command surface — the search should feel like a security search
  with entity suggestions, and the utility slots should be
  meaningful (time, workspace, notifications with counts).
- **MSS Dashboard is a KPI grid, not a command center**.  Tiles show
  numbers but do not drive investigation.  Nothing is clickable in a
  way that produces a filtered queue.
- **The incident record is structurally good but reads like a form**,
  not an investigation workspace.  Tabs are visually identical;
  contextual actions live only in the header; the sidebar has no
  "current case" awareness.
- **No visual signature**.  If a screenshot were shown to a stranger
  they could not tell this from any other well-behaved light SaaS.
  There is no NivXRay-specific idiom that says: "this is a
  deterministic evidence-first XDR".

Everything below is the plan to close that gap.

---

## 1 · Reference distillation (interaction patterns, not pixels)

### Microsoft Defender XDR — what to extract

Defender's documentation confirms the following as the load-bearing
patterns of its Unified Security Operations experience, and they are
the ones NivXRay must match at a language level:

1. **Priority-driven triage**.  The queue is oriented around a
   priority score that rolls up severity, verdict, entity criticality,
   evidence, MITRE stage.  Analysts explicitly work top-down.
2. **Filter → column → time**.  Every list surface offers filter set,
   configurable columns and a time selector as first-class controls.
3. **Contextual summary panes**.  Selecting a row opens a right-side
   pane that shows priority factors, entities, evidence and
   recommended actions — with previous / next navigation without
   leaving the list.
4. **Attack-story-first investigation**.  The record centres on the
   narrative (assets, alerts, evidence, techniques) rather than on
   raw form fields.
5. **Recommended actions on the entity**.  Every entity (device,
   user, file, IP) exposes a small set of high-signal actions
   contextually.
6. **Configurable analyst workspace**.  Column visibility,
   saved views, density and pane state are user-settable and
   persistent.

### ServiceNow SIR — what to extract

SIR's Security Analyst Workspace documentation confirms:

1. **Workspaces, not pages**.  The incident record is a workspace
   with tabs, quick actions, related lists, and configurable
   information cards.
2. **Quick filters + saved lists**.  Fast filter chips sit above
   the list; lists themselves are personalisable and shareable.
3. **List/card toggle + peek view**.  Analysts can flip from a
   list to a card layout, and peek at a record without leaving the
   list.
4. **Explicit lifecycle and SLA**.  State transitions, ownership,
   assignment, and SLA are surfaced continuously — not hidden in a
   form.
5. **Contextual quick actions**.  Every record surfaces a compact,
   priority-ordered action set (assign, change state, add note,
   escalate, close).
6. **Composable dashboards**.  Widgets are drillable — clicking a
   count produces the corresponding filtered list.

### What NivXRay adds that neither has

1. **Evidence-first, deterministic verdict** with negative
   explainability (`NOT_RUN`, `NO EVIDENCE`, `NOT CONNECTED`,
   `NOT AVAILABLE`, `UNKNOWN`, em-dash).
2. **Investigation-aware queue** that never fabricates outcomes.
3. **Auto-Investigation provenance** — every claim will trace to
   an engine execution + observation once Phase 4 lands.
4. **IKG-backed cross-domain evidence** across endpoint · identity ·
   files · network · email · cloud.
5. **MITRE ATT&CK coverage as a first-class navigation surface**.

The design language must make these four contributions the parts of
the interface that feel distinctively NivXRay.

---

## 2 · Gap analysis matrix

For each area: **Current NivXRay** (honest) · **Defender pattern**
(what to borrow at a language level) · **SIR pattern** (what to
borrow at a language level) · **NivXRay decision** (my design call).

### 2.1 Application chrome (topbar + sidebar)

| Aspect | Current NivXRay | Defender | SIR | NivXRay decision |
| --- | --- | --- | --- | --- |
| Topbar role | Utility strip | Command surface with global search, workspace switch, notifications | Command surface with search, filters, help, avatar | **Analyst command surface**: entity-aware global search (incidents · hosts · users · hashes · IOCs · CVEs · techniques), workspace picker, live-clock, refresh state, unread notification count, help, tenant, avatar. |
| Search | Placeholder input | Entity typeahead with categories | Entity typeahead with categories | Grouped typeahead by kind (Incident · Host · User · Hash · IP · Domain · CVE · Technique) with keyboard nav and recent history. |
| Sidebar hierarchy | Flat sections with all-caps labels | 2-level nav with pinnable favourites, section separators | Grouped with contextual sub-nav inside a record | Two-tier nav with **collapsible sections**, **pinned items**, and **selected rail** (3 px purple + subtle wash + bold + purple icon). |
| Sidebar density | Fixed 220 px | Adjustable / collapsible to icon rail | Collapsible workspace nav | Collapsed-to-icon mode with hover flyout labels; persists per-user. |
| Active-state affordance | Left border + wash | Left rail bar + background + icon fill | Left rail bar + subtle background | 3-px purple rail + purple icon + white text + subtle purple wash. |
| Notifications | Static bell | Bell with unread count | Bell with unread count | Bell with numeric badge that drives a notifications drawer. |
| Workspace context | None | Explicit tenant switcher | Explicit workspace switcher | Compact tenant pill in topbar that is also a switch trigger. |

### 2.2 Workspace surfaces & elevation

| Aspect | Current | Defender | SIR | Decision |
| --- | --- | --- | --- | --- |
| Surface levels | 2 (bg, card) | 4 (chrome · page · elevated · popover) | 4 | **5 tokens**: chrome · workspace · elevated · popover · inline-inset. |
| Elevation | Flat | 0-1-2-3 shadow ramp | 0-1-2 shadow ramp | 0-1-2-3 ramp; use elevation only when it earns hierarchy. |
| Corner radius | 6 px uniform | 4 / 6 / 8 by context | 4 / 6 by context | 4 px chips · 6 px cards · 8 px major sections. |
| Divider treatment | 1 px neutral | 1 px + `--divider-strong` on major seams | Same | Two divider tokens: `--divider` and `--divider-strong` for major seams. |

### 2.3 Typography

| Level | Current | Defender / SIR | NivXRay decision |
| --- | --- | --- | --- |
| Display / entity | 22 px 700 | 24 px 700 tracked -1% | `display` 24 px 700 -1% |
| H1 page title | 22 px 700 | 20 px 700 | `h1` 20 px 700 -0.5% |
| H2 section | 15 px 700 | 14 px 700 | `h2` 14 px 700 |
| H3 subsection | 10.5 px 800 uppercase 0.5px | 11 px 700 uppercase 0.5px | `eyebrow` 11 px 800 uppercase 0.6px |
| KPI value | 22 px monospace 800 | 24 px monospace 800 | `kpi` 24 px monospace 800 |
| Body | 12.5 px 400 | 13 px 400 1.5 | `body` 13 px 400 1.55 |
| Metadata / provenance | 10.5 px mono | 11 px mono muted | `meta` 11 px mono `--faint` |
| Micro-label | 9.5 px 700 uppercase | 10 px 700 uppercase | `micro` 10 px 800 uppercase 0.5px |

**Rule**: typography carries meaning.  Provenance always looks like
provenance (mono, `--faint`); a KPI always looks like a KPI
(display-mono, semantic colour).  No collision.

### 2.4 Semantic colour language

Each meaning gets a *system* (text · bg · border · icon · chip ·
hover · focus · dot), not just a text colour.

| Meaning | Text | Bg | Border | Chip idiom |
| --- | --- | --- | --- | --- |
| Critical | `#991B1B` | `#FEE2E2` | `#F87171` | filled red |
| High | `#EA580C` | `#FFEDD5` | `#FB923C` | filled orange |
| Medium | `#D97706` | `#FEF3C7` | `#FCD34D` | filled amber |
| Low / Info | `#2563EB` | `#DBEAFE` | `#93C5FD` | outline blue |
| Malicious | `#DC2626` | `#FEF2F2` | `#FCA5A5` | filled red |
| Suspicious | `#EA580C` | `#FFF7ED` | `#FDBA74` | filled orange |
| Benign | `#059669` | `#ECFDF5` | `#A7F3D0` | filled green |
| New | `#2563EB` | `#EFF6FF` | `#93C5FD` | outline blue |
| In progress | `#6D4EE0` | `#EDE7FF` | `#C7B7FF` | filled purple |
| On hold | `#6B7280` | `#F3F4F6` | `#D1D5DB` | outline neutral |
| Resolved | `#059669` | `#ECFDF5` | `#A7F3D0` | outline green |
| Closed | `#4B5563` | `#F3F4F6` | `#D1D5DB` | outline neutral |
| SLA risk | `#DC2626` | `#FEF2F2` | `#FCA5A5` | pulse red |
| Evidence available | `#0D9488` | `#CCFBF1` | `#5EEAD4` | filled teal |
| No evidence | `#D97706` | `#FEF3C7` | `#FCD34D` | outline amber |
| Not connected | `#6B7280` | `#F3F4F6` | `#D1D5DB` | dashed neutral |
| AI running | `#6D4EE0` | `#EDE7FF` | `#C7B7FF` | pulse purple |
| AI complete | `#059669` | `#ECFDF5` | `#A7F3D0` | filled green |

**Rule**: never *only* colour the text.  Every semantic state carries
a chip, an icon, a border tone, and (where relevant) a status dot.

### 2.5 Interaction states

Every interactive component gets **8 states**: default · hover ·
selected · active · focus · disabled · loading · empty (or
error).  Missing any state is a bug.

| Component | Current | Target |
| --- | --- | --- |
| Sidebar nav item | default · hover · active · disabled | + focus ring · loading (chunk boot) · keyboard-active |
| Queue row | default · hover · selected | + previewed (adjacent to peek) · focus ring · action-menu-open |
| KPI tile | default · hover | + selected (drives filter) · focus · pressed |
| Chip | default | + hover · focus · with-remove · with-explainer-tooltip |
| Tab | default · active | + hover · focus · with-count · with-dot-indicator |
| Table cell | default | + hover-column · hover-row · action-visible |
| Drawer | closed · open | + prev/next enabled · loading · dirty |

### 2.6 Queue

| Aspect | Current | Defender | SIR | Decision |
| --- | --- | --- | --- | --- |
| KPI strip | 8 tiles, semi-static | Priority pivots that filter | Quick filters | Tiles become **filter buttons** with a selected state; clicking sets `?lens=…`. |
| Filters | Modal side sheet | Inline pill row + advanced panel | Facet pane | Inline pill row for common facets + advanced side sheet. |
| Column mgmt | Drag re-order + toggle | Column picker with search + reset | Column picker | Keep; add **column search input** and **saved column presets** (`My triage`, `Executive review`). |
| Sort | Header click | Header click + `Sorted by X ↑` marker | Same | Add persistent "Sorted by X" chip near toolbar so sort state is discoverable. |
| Row selection | Checkbox column | Checkbox + shift-range + Cmd-A | Same | Add shift-range and Cmd/Ctrl-A. |
| Preview | Right drawer | Right drawer with prev/next, tabs inside preview | Peek modal | Right drawer with prev/next **and** a compact tab set (Overview · Entities · Evidence · Actions). |
| Bulk actions | Assign, state | Assign · state · escalate · comment · tag | Same | Add tag + comment + escalate. |
| Density | Comfortable only | Compact / comfortable | Compact / comfortable / cozy | Three-mode toggle: `Comfort · Compact · Ultra` with row heights 40 / 32 / 28. |
| Empty state | Text | Illustrated + suggestion | Illustrated + link | Compact copy + primary CTA (e.g. `Reset filters`) + never-fabricate rule preserved. |

### 2.7 Preview / peek drawer

| Aspect | Current | Defender | SIR | Decision |
| --- | --- | --- | --- | --- |
| Structure | Single scroll | Tabbed (Summary · Entities · Evidence · Actions) | Tabbed | **4 lightweight tabs** inside the drawer. |
| Nav | Prev/next | Prev/next + counter | Prev/next | Add position counter `3 of 27`. |
| Actions | Open Investigation | Open · Assign · Change state · Add note | Same | Compact action row on drawer footer, mirroring the record header. |
| Explainers | None | Hover explains priority factors | Hover shows source | Tooltip on Priority + Verdict + Confidence showing contributing signals + provenance path. |

### 2.8 Incident record

| Aspect | Current | Defender | SIR | Decision |
| --- | --- | --- | --- | --- |
| Header hierarchy | Flat 8-cell meta | Identity → status → owner → SLA → actions | Identity → workflow → tabs | **Three bands**: identity band · status band · investigation-nav band.  Actions dock to the identity band. |
| Chips | Filled pills | Filled + explainer-on-hover | Filled + status | Chips carry hover explainer (top contributing factors). |
| Lifecycle | Stepper | Compact stepper + reason on transition | State pill + guarded transitions | Stepper with **transition reason capture** modal for every backward move. |
| Sub-navigation | 11 identical tabs | Contextual — Investigation surfaces feel different from Case surfaces | Same | Two visual tab families: **Investigation** (Executive, Technical, Evidence, MITRE, Attack Story, Auto-Investigation, Recommendations) and **Case** (Notes, Timeline, Related, Closure).  Investigation tabs use the workspace surface; Case tabs use the inset surface. |
| Contextual actions | Header only | Header + entity-scoped + row-level | Header + record-scoped | Dock a **contextual action bar** to whichever tab is active — e.g. Evidence tab exposes `Search similar cases`, `Add to hunt`. |
| Sidebar during record | Same as anywhere | Adds "This incident" context | Adds "This record" context | Sidebar sprouts a **case context group** at the top listing owner, SLA, and jumping targets. |

### 2.9 Dashboard (MSS)

| Aspect | Current | Defender | SIR | Decision |
| --- | --- | --- | --- | --- |
| KPI tiles | Static numbers | Drillable pivots | Drillable widgets | Every tile is a **link** to the corresponding queue lens (`Critical`, `Unassigned`, `SLA Risk`). |
| Grouping | Triage / Ownership / Risk | Priority-first, then coverage | Priority · Category · State · SLA | Keep NivXRay's Triage / Ownership / Risk groups + add **Auto-Investigation** and **MITRE coverage** groups. |
| Distribution charts | Stacked bars | Interactive bars, hover breakdown | Interactive breakdown | Hover shows exact counts; click filters the queue. |
| Analyst / customer tables | Static | Sortable, drillable rows | Sortable | Drillable rows — click an analyst → their queue; click a customer → tenant queue. |
| Auto-Investigation section | Static metric grid | N/A (Defender concept differs) | N/A | Keep honest NOT_RUN treatment but make each metric drillable to queue filtered by AI status. |
| Empty state | Blank | Suggestion + link | Suggestion + link | `NO OPEN HIGH-PRIORITY INCIDENTS · view resolved →` etc. |

### 2.10 MITRE surface

| Aspect | Current | Defender | SIR | Decision |
| --- | --- | --- | --- | --- |
| Command bar | 4 KPI tiles | Coverage / observed / rules with drill | N/A | Keep + add **tactic navigator** immediately below the command bar. |
| Tactic groups | 14 columns of technique boxes | Grouped, ranked by observed volume | N/A | Reorder tactics by "most observed" by default; sticky ATT&CK order behind a toggle. |
| Technique card | Uniform 4-line card | Rich card: id · name · variant · observed · confidence · rules · detections | N/A | Redesigned card: `T1059 · Command and Scripting Interpreter` · sub-line `PowerShell · CMD · Bash` · right rail `Observed n · Conf x · Rules r · Detections d` with icons + semantic colours. |
| Drilldown | None | Click → related incidents + evidence | N/A | Click a technique → right drawer with the incident list filtered by that technique. |
| Empty | Small text | Illustrated + link | N/A | Explicit "This tactic has 0 detections in the current window" with a `configure detection` link. |

### 2.11 Threat Intelligence + Intelligence family

| Aspect | Current | Defender | SIR | Decision |
| --- | --- | --- | --- | --- |
| Landing | Reserved-only card | Search-first: IOC / entity search | Search-first | Even in reserved state, render the **shape** of the product: search bar (IP / Domain / Hash / URL / Email / CVE / Malware) + honest empty rails for Recent intelligence, Malware families, Active campaigns, Indicator sightings. |
| Reserved copy | "Not available" | Coming-soon w/ preview | Coming-soon w/ preview | Preserve the honest reserve state, but make it *productive*: show the surface, not a blank card. |

### 2.12 Empty states

| Kind | Current | Target |
| --- | --- | --- |
| No incidents | Text | Compact illustration + primary CTA (Reset filters / Change time range) |
| No evidence | Text | Compact card with `configure integration` link where applicable |
| Reserved capability | Grey card | Product-shape preview with honest reserved chip |
| Loading | Text `LOADING…` | Skeleton rows matching the target layout |
| Error | Red bar | Actionable error with retry + link to logs |

### 2.13 Density modes

Three modes for every list surface, persisted per-user:

- **Comfort** (default): 40 px rows · 14 px cell padding · body 13 px.
- **Compact**: 32 px rows · 10 px cell padding · body 12.5 px.
- **Ultra**: 28 px rows · 8 px cell padding · body 12 px, mono for numeric.

### 2.14 Iconography

| Kind | Current | Target |
| --- | --- | --- |
| Library | Lucide | Lucide (keep) |
| Sizes | Ad-hoc | `13 · 14 · 16 · 18 · 20` scale |
| Stroke width | Default (2) | 1.75 on nav; 2 on chips; 1.5 on illustrations |
| Semantic colouring | Sometimes | Always tied to a token (`--danger`, `--success`, `--info`, `--purple`, `--muted`) |
| Status dots | None | 6 px filled dots as a compact status idiom on rows and cards |

### 2.15 Visual signature (what makes it feel NivXRay)

1. **Evidence-provenance micro-line** appears under every value that
   has an authoritative source path — a 10 px monospace faint line
   that reads `workspace_cases.evidence` or `rc2-orchestrator`.
   This *is* the NivXRay idiom; no competitor has it.
2. **Deterministic honesty chip**: `NOT_RUN`, `NO EVIDENCE`,
   `NOT CONNECTED`, `NOT AVAILABLE`, `UNKNOWN` all render as
   **dashed-border chips** — visually distinct from filled semantic
   chips, so honesty is a first-class visual state, not an
   afterthought.
3. **IKG cross-link icon** on any entity that participates in the
   Investigation Knowledge Graph — a subtle purple node-glyph next
   to the entity id.
4. **Purple pulse** for anything currently *running* against an
   incident (auto-investigation, response execution).  Never
   decorative; always meaningful.

Those four idioms together are the visual signature.

---

## 3 · Sequenced execution plan

No implementation is proposed inside this document beyond decisions.
Sequencing:

**Phase A** *(this document)* — approved gap analysis.

**Phase B** — **Design system tokens + components**.  Create
`design-system.css` and a small React primitive library
(`NxCard`, `NxKpi`, `NxChip`, `NxStatus`, `NxDataGrid`,
`NxToolbar`, `NxFilterBar`, `NxPeekPanel`, `NxTimeline`,
`NxEntity`, `NxEvidenceCard`, `NxMetric`, `NxEmptyState`,
`NxActivity`, `NxCommandBar`, `NxSection`, `NxTabs`, `NxDrawer`).
Add Storybook-style demo route for the primitives.

**Phase C** — **Chrome**: redesign topbar + sidebar + workspace
header using the Phase-B primitives.  Sidebar collapse, contextual
sub-nav, notifications drawer.

**Phase D** — **Queue**: adopt primitives, add inline filter pill
row, drillable KPI strip, saved column presets, three-mode
density, preview-drawer tabs.

**Phase E** — **Dashboard**: convert MSS tiles into drillable
filter buttons, hover breakdowns, drillable analyst / customer
rows, add MITRE coverage + Auto-Investigation blocks.

**Phase F** — **Incident Record**: identity/status/investigation-nav
bands, tab-family split (Investigation vs Case), contextual action
bar per tab, sidebar case-context group.

**Phase G** — **MITRE surface**: command bar + tactic navigator +
rich technique card + drilldown drawer.

**Phase H** — **Empty states + reserved surfaces**: skeletons,
product-shape previews for reserved capabilities, actionable
error rails.

**Phase I** — **Interaction polish**: hover explainers on chips,
prev/next counters, keyboard shortcuts, purple-pulse for running
work, IKG cross-link glyphs, evidence-provenance micro-line.

**Phase J** *(deferred to after visual acceptance)* — Phase 3
Lifecycle / SLA engine and Phase 4 Auto-Investigation provenance.
These are not started until the visual system is signed off.

---

## 4 · Acceptance criterion

A stranger opening any NivXRay surface should be able to say, in
plain language:

> **"This looks and behaves like a serious enterprise XDR product,
> and I can tell it is not Microsoft Defender or ServiceNow."**

That is the bar.  A green `yarn build` is not acceptance; a lighter
background is not acceptance; adding more cards is not acceptance.
Acceptance is measured by whether the design idioms are present and
whether the product *responds* to the analyst.

---

## 5 · Explicit non-goals for the visual redesign

- Do not modify any engine or SSOT.
- Do not fabricate data anywhere.
- Do not replace functional APIs with mocks.
- Do not clone Defender or ServiceNow chrome.
- Do not add animation for decoration.
- Do not start Phase 3 / Phase 4 backend work while this is in flight.

---

## 6 · Awaiting sign-off

I am pausing here.  Before writing any code for Phase B I need one
of three signals from the product owner:

  1. **Approve** — proceed straight into Phase B (design system
     tokens + Nx-primitives) exactly as above.
  2. **Approve with amendments** — adjust specific rows in the gap
     matrix or the sequence, then proceed.
  3. **Change scope** — different priority (e.g. do the MITRE
     surface first, or delay the sidebar collapse).

Once signed off, subsequent phases are focused execution with no
further preference questions.

---

## 7 · Amendments · v1.1 (owner-locked · 2026-02-34)

Phase A approved with amendments.  These corrections override any
conflicting item earlier in the document.

**A1 · Provenance is selective, not universal.**
The evidence-provenance micro-line appears only under values that
are **authoritative** (produced by an engine SSOT), **derived**
(computed from evidence with a traceable path), **correlated**
(cross-domain rollups), or **decision-critical** (drives an analyst
action).  It does **not** appear under freeform metadata, timestamps,
labels, or copy.  Rule of thumb: if removing the provenance would
reduce trust in a decision-relevant value, keep it; otherwise omit it.

**A2 · Truth-state chip system is locked as a load-bearing rule.**
- **Filled** semantic chip = state is *known / observed*
  (`CRITICAL`, `MALICIOUS`, `IN PROGRESS`, `RESOLVED`, `HIGH FIDELITY`,
  `EVIDENCE AVAILABLE`, `AI COMPLETE`, …).
- **Dashed** chip = state is *absent / uncertain / not run*
  (`UNKNOWN`, `NOT_RUN`, `NO EVIDENCE`, `NOT CONNECTED`,
  `NOT AVAILABLE`, `AWAITING EVIDENCE`).

This is *the* core NivXRay grammar rule.  It applies everywhere and
must never be relaxed for aesthetics.

**A3 · Purple pulse only represents genuine execution.**
Reserved for four states: `AUTO-INVESTIGATION RUNNING`,
`ENRICHMENT RUNNING`, `RESPONSE ACTION RUNNING`, `ENGINE EXECUTION
RUNNING`.  No decorative animation, no "attention hover", no
"pulse-to-highlight".

**A4 · IKG glyph is an interaction affordance, not decoration.**
Renders **only** next to entities that actually participate in the
Investigation Knowledge Graph (backend-flagged, not inferred from
UI).  Hover → `View in Investigation Graph`.  Click → drawer /
navigation.  If an entity is not IKG-linked, the glyph is absent —
not greyed, not "coming soon".

**A5 · Reduce cards.  Not everything needs a container.**
Structure comes from typography, spacing, alignment, semantic
colour, subtle divider, focus/hover state.  A card only appears
when it *earns* a container (the object inside has its own state
and actions).  Metadata, KV pairs, sub-labels do not deserve their
own card.

**A6 · Light-first ≠ white everywhere.**
Layered neutral palette (see Visual Grammar §1).  Application
background is warm neutral, workspace is a slightly different
neutral, elevated surfaces are white, selected states pick up a
subtle purple tint, investigation surfaces get stronger contrast.
Never white-inside-white-inside-white.

**A7 · Grammar first, components second.**
Do not begin writing `NxCard` / `NxKpi` / `NxChip` before the
visual grammar is documented and locked (see
`/app/memory/NIVXRAY_VISUAL_GRAMMAR.md`).  Every component name
must be traceable to a specific rule in the grammar.

**A8 · Every interaction state is explicit.**
`default · hover · selected · focus · active · disabled · loading
· empty · error · unknown · not_run · no_evidence · not_connected`.
Missing any state on a load-bearing component is a bug.

**A9 · Study interaction patterns, not screenshots.**
Defender = primary reference for XDR investigation / queue /
triage / evidence / contextual workflows.  ServiceNow SIR =
secondary reference for workspace / list / peek / ownership /
lifecycle / SLA / workflow patterns.  Absorb the *pattern*,
never copy the pixel.

**A10 · The queue is the primary analyst instrument.**
It gets more design attention than the dashboard.  Its table,
filters, preview, selection, SLA visualisation, semantic states,
density modes and contextual row actions are the highest-quality
surface in the product.

**A11 · The dashboard must be operational.**
Every KPI value leads to an actionable, filtered queue.  Analyst
and customer rows drill.  MITRE coverage drills.  Auto-Investigation
metrics drill.  The dashboard answers *"what needs my attention
right now?"* — not *"here are numbers"*.

**A12 · Start density with Comfort + Compact only.**
Ultra mode is deferred until real usage justifies it.  Do not
build preference UI that no one has asked for.

**A13 · NivXRay identity locked as five signatures.**
1. Evidence provenance (selective — A1).
2. Truth-state chips (filled vs dashed — A2).
3. IKG relationship affordance (A4).
4. Execution-state pulse (A3).
5. **Evidence-first interaction** — important values are clickable
   and lead the analyst back to evidence.  *This is the strongest
   NivXRay differentiator.*

**A14 · Sequencing lock.**
Post-Phase-B, redesign in this order:
`Queue → Incident Record → MSS Dashboard → MITRE → Evidence`.
Phase 3 (Lifecycle/SLA) and Phase 4 (Auto-Investigation
provenance) do not start until these five screens read as one
mature enterprise XDR product.
