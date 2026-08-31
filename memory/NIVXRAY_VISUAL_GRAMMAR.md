# NivXRay Visual Grammar · v1

> **Status**: locked design specification.  Every future
> implementation phase must implement this grammar; no phase
> introduces its own rules.
>
> **Companion to**: `NIVXRAY_ENTERPRISE_UX_GAP_ANALYSIS.md` (v1.1).
>
> **Non-negotiable rule**: the grammar is defined first, in prose
> and rules.  Components are named and built *after* the grammar,
> and every component name must trace back to a specific rule
> below.

---

## 1 · Surface hierarchy

Five surfaces.  No more, no fewer.  A screen with more than five
nested surfaces is a design bug, not a feature.

| # | Surface | Role | Colour | Elevation | Corner |
| --- | --- | --- | --- | --- | --- |
| 1 | **Application** | global chrome (topbar + sidebar) | Deep navy `#0F172A` / `#111827` | 0 | 0 |
| 2 | **Workspace** | primary analyst canvas | Warm neutral `#FAFAF9` | 0 | 0 |
| 3 | **Elevated** | cards / panels requiring attention | White `#FFFFFF` | shadow-1 | 8 |
| 4 | **Contextual** | drawers · popovers · command surfaces | White or navy-tinted | shadow-3 | 8 or 10 |
| 5 | **Data** | tables · lists · timelines | Workspace or elevated depending on density | 0 or shadow-1 | 6 |

**Rules**

- No white-on-white nesting.  Elevated surfaces exist to introduce
  a card *only when the object earns it*.  Metadata does not deserve
  a card.
- Selected data rows carry a **subtle purple tint** (`--purple-dim`)
  and a **3-px purple left rail** — never a full purple background.
- Investigation surfaces (attack story, MITRE, evidence) may raise
  contrast (deeper text, stronger divider) to signal *this is
  where analysts think*.  Case surfaces (notes, timeline, closure)
  stay softer.

---

## 2 · Hierarchy grammar

Every page reads top-to-bottom in this order:

1. **Page identity** — who / what is this page?
2. **Primary decision surface** — the analyst's next action.
3. **Operational controls** — filters, time, refresh, view.
4. **Primary data** — the table, list, or investigation content.
5. **Context / evidence** — supporting detail.
6. **Secondary metadata** — provenance, source paths, timestamps.

A page missing any of levels 1–4 is under-designed.  A page that
puts metadata at level 3 is misdesigned.  Level 6 must be
visually recessive; if a viewer's eye lands on level 6 first,
the hierarchy is wrong.

---

## 3 · Type ramp

Nine roles.  Each has a single, invariant treatment.

| Token | Size | Weight | Case | Tracking | Family |
| --- | --- | --- | --- | --- | --- |
| `display` | 24 px | 700 | Title | -1% | sans |
| `h1` (page title) | 20 px | 700 | Title | -0.5% | sans |
| `h2` (section) | 14 px | 700 | Title | 0 | sans |
| `eyebrow` (subsection) | 11 px | 800 | UPPER | 0.6px | sans |
| `kpi` | 24 px | 800 | numeric | 0 | mono |
| `body` | 13 px | 400 | sentence | 0 | sans |
| `meta` | 11 px | 500 | sentence | 0 | mono |
| `micro` | 10 px | 800 | UPPER | 0.5px | sans |
| `code` | 11.5 px | 500 | as-is | 0 | mono |

**Meaning rules** — the type ramp encodes meaning:

- Anything **authoritative / numeric** uses `kpi` or `code` in mono.
- Anything **provenance-like** uses `meta` mono `--faint`.
- Anything **status-like** (chip label, badge) uses `micro`.
- Anything **decision-critical** is never smaller than `body`.
- Never mix two ramps for the same conceptual role on one page.

---

## 4 · Colour · semantic system

Every semantic meaning is a **system** of tokens: text · bg ·
border · icon · chip · hover · focus · dot.  A colour never
appears alone.

Semantic families (see gap analysis §2.4 for the full palette):

- **Priority**: `critical · high · medium · low`.
- **Verdict**: `malicious · suspicious · benign · unknown`.
- **Lifecycle**: `new · in_progress · on_hold · resolved · closed`.
- **SLA**: `on_track · at_risk · breached`.
- **Evidence**: `available · searched · no_evidence · not_connected`.
- **Execution**: `not_run · running · complete · partial · failed`.

**Neutral palette (layered light):**

- App: `#0F172A` navy.
- Workspace: `#FAFAF9`.
- Workspace-alt: `#F5F5F4`.
- Elevated: `#FFFFFF`.
- Divider: `#E7E5E4`.
- Divider-strong: `#D6D3D1`.
- Text: `#111827`.
- Text-dim: `#4B5563`.
- Muted: `#6B7280`.
- Faint: `#9CA3AF`.

**Rule** — never use pure black (`#000`) or pure white on a data
surface.  Warmth is intentional.

---

## 5 · Truth-state grammar (NivXRay signature #2)

Locked, load-bearing.

| Form | Meaning | Examples |
| --- | --- | --- |
| **Filled** chip · semantic bg + solid border + weighted label | The state is *known / observed* | `CRITICAL`, `MALICIOUS`, `IN PROGRESS`, `RESOLVED`, `HIGH FIDELITY`, `EVIDENCE AVAILABLE`, `AI COMPLETE` |
| **Dashed** chip · neutral bg + dashed border + `--muted` label | The state is *absent / uncertain / not run* | `UNKNOWN`, `NOT_RUN`, `NO EVIDENCE`, `NOT CONNECTED`, `NOT AVAILABLE`, `AWAITING EVIDENCE` |

**Rules**

- Never use a filled chip to represent absence.  Never soften a
  filled chip's border to hint uncertainty.
- A dashed chip **never** becomes filled purely for visual
  balance.  Balance is achieved by hierarchy, not by lying.
- Dashed chips are colour-neutral by default; a specific meaning
  may pick up a subtle tint (`amber` for `NO EVIDENCE`, `blue`
  for `AWAITING EVIDENCE`) but the *dashed border and neutral
  weight remain*.
- Dashed chip label uses `micro`, colour `--muted` unless tinted.

---

## 6 · Provenance grammar (NivXRay signature #1)

Selective — see amendment A1.

**Include provenance under a value when the value is:**

- Authoritative (produced by an engine SSOT).
- Derived (traceably computed from evidence).
- Correlated (rolls up multiple sources).
- Decision-critical (drives an analyst action).

**Omit provenance under:**

- Freeform metadata (timestamps, IDs, labels).
- Static copy.
- Chip labels or micro-labels.
- Values already carrying an explainer tooltip.

**Visual treatment** — `meta` mono `--faint`, prefixed with
`Source · `, positioned directly below the value with 2-px top
margin.  Optional icon: a small link glyph.

Example
```
105
Open Incidents
Source · workspace_cases.live
```

---

## 7 · IKG affordance (NivXRay signature #3)

- Renders only on entities the backend flags as IKG participants
  (`entity.ikg_linked = true`).  Never inferred, never decorative.
- Glyph: a two-node graph icon in `--purple`, `12 × 12` px, offset
  4 px to the right of the entity id.
- Hover → tooltip `View in Investigation Graph`.
- Click → drawer or route to the IKG visualiser.
- Focus ring on keyboard nav.
- Never coloured red / amber; never grey-out.  Its presence *is*
  the affordance — its absence *is* the honest state.

---

## 8 · Execution-state pulse (NivXRay signature #4)

- Reserved for four backend-flagged states:
  `AUTO-INVESTIGATION RUNNING`, `ENRICHMENT RUNNING`,
  `RESPONSE ACTION RUNNING`, `ENGINE EXECUTION RUNNING`.
- Visual: 8-px purple dot with a soft 2-s pulse.  Sits *inside*
  the corresponding truth-state chip (which is a *filled* chip
  because execution is a known/observed state).
- Never used for hover, selection, attention-grabbing, marketing,
  or empty-state polish.
- Stops immediately when the backend transitions the state to
  `COMPLETE`, `PARTIAL`, or `FAILED`.

---

## 9 · Evidence-first interaction (NivXRay signature #5 · strongest)

Every important value on the interface is a **navigation edge back
to evidence**.  This is the differentiator no competitor has.

**Rules**

- Priority chip → click → tooltip / peek explaining contributing
  signals + provenance path.
- Verdict chip → click → verdict factors panel.
- Evidence count → click → filtered evidence tab / drawer.
- Technique badge → click → MITRE tab focused on that technique.
- Entity id → click → entity context drawer.
- SLA remaining → click → SLA history panel.
- Analyst / customer row on dashboard → click → filtered queue.
- Auto-Investigation metric → click → filtered queue by AI status.

**Rule** — if a decision-critical value has *no* onward path, that
is a design bug.  The interface must *lead* the analyst.

---

## 10 · Interaction-state grammar

Every load-bearing component implements the following states.  Any
missing state on a load-bearing component is a bug.

| State | Rule |
| --- | --- |
| `default` | Base treatment. |
| `hover` | Elevate +1 shadow tier, tighten border to `--border-sf`, no colour change unless semantic. |
| `selected` | Purple `--purple-dim` tint bg + 3-px `--purple` left rail + text weight +100. |
| `focus` | 3-px `--purple-ring` glow.  Visible via keyboard nav. |
| `active` | Pressed feedback: -1 shadow, translateY(1px). |
| `disabled` | 0.4 opacity, cursor not-allowed, no hover. |
| `loading` | Skeleton in the target layout — never a text-only spinner on load-bearing surfaces. |
| `empty` | Product-shape empty state (see §11) — never a blank card. |
| `error` | `--danger` band with retry + link to logs. |
| `unknown` / `not_run` / `no_evidence` / `not_connected` | Dashed truth-state chip in place of the value (see §5). |

---

## 11 · Empty & reserved surfaces grammar

Empty is a *state*, not an absence.

- **Filter empty** — compact copy + primary CTA (`Reset filters`).
- **Domain empty** (evidence tab, integration missing) — compact
  card with `configure integration` link + honest reason.
- **Reserved capability** — render the *shape* of the product
  (search bar, honest section rails) with a dashed `RESERVED ·
  PHASE n` chip in the header.  Do not fabricate rows.
- **Loading** — skeleton in the target layout.
- **Error** — inline actionable band, not a modal.

---

## 12 · Density grammar

Two modes only (amendment A12).

| Mode | Row | Cell padding | Body | Table numerics |
| --- | --- | --- | --- | --- |
| `Comfort` | 40 px | 14 px | 13 px sans | mono |
| `Compact` | 32 px | 10 px | 12.5 px sans | mono |

Persisted per-user under `xdr.pref.density`.

---

## 13 · Component consequences

**Only now** — after §§1-12 are locked — do component names
follow.  Every name traces to a section above.

- `NxSurface` (§1) — declarative wrapper for the five surfaces.
- `NxHierarchy` (§2) — page shell enforcing the six-level order.
- `NxType` (§3) — the nine typographic roles.
- `NxChip` (§5) — truth-state chip in filled or dashed form.
- `NxProvenance` (§6) — selective provenance sub-line.
- `NxIkgGlyph` (§7).
- `NxExecPulse` (§8).
- `NxLink` (§9) — evidence-first click affordance wrapping any
  decision-critical value.
- `NxInteractive` (§10) — mixin/contract every interactive
  component consumes.
- `NxEmpty` / `NxReserved` / `NxError` / `NxSkeleton` (§11).
- `NxDensity` (§12) — user-settable density context.

Downstream *screen* components (queue table, incident record
header, MSS dashboard tile, etc.) consume the above.  They do
**not** invent their own colour, chip, elevation, or spacing
rules.  Any deviation is a grammar violation.

---

## 14 · Grammar acceptance test

A screen passes grammar review when:

1. Every value on the page can be located in one of the six
   hierarchy levels (§2).
2. Every truth chip is either filled or dashed by rule (§5).
3. Provenance appears only under authoritative / derived /
   correlated / decision-critical values (§6).
4. Every interactive element implements all eleven interaction
   states (§10).
5. Decision-critical values are clickable and route back to
   evidence (§9).
6. No surface nests inside its own colour (§1).
7. No card exists purely to hold metadata (§1, amendment A5).
8. The visual signature (§§5-9) is visible somewhere on the
   screen without being decorative.
MDEOF
---

## 15 · Phase A.1 · Enterprise Product Refinement Layer

The grammar (§§1-14) is authoritative but not sufficient by
itself.  Every screen must additionally satisfy the following
refinement rules; a screen that satisfies the grammar but fails
these rules is a "prototype-shaped" screen and must not ship.

**R1 · Surface depth is tonal, not decorative.**
No gradients.  No large shadows.  Depth comes from three tonal
neutrals (workspace · inset · elevated) plus a single `shadow-1`
on cards.  Never `shadow-3` on a persistent surface — only on
overlays.

**R2 · Density is deliberate.**
No empty cards, no giant tiles wrapping one number.  A KPI tile's
count is the primary read; provenance is a *secondary* read
rendered smaller and dimmer.  Whitespace is used to separate
*meaning-groups*, not to pad decoration.

**R3 · Typography carries hierarchy, not the border.**
On a compact table row, the incident title reads at `body 13/600`,
metadata at `meta 11/500 mono faint`, chips at `micro 10/800`.
The eye lands on the title, then the chip, then the metadata.
If the eye lands elsewhere first, weight is wrong.

**R4 · Monospace communicates technical identity — nowhere else.**
Mono is reserved for hashes, IPs, host/user ids, process names,
command lines, event ids, timestamps, IOC values, provenance
paths, evidence ids.  Free-text names / labels / descriptions
use `body` sans.  Mixing them makes the interface look like a
developer console.

**R5 · Table rows are analyst instruments.**
- Row height obeys density tokens (§12).
- Row `hover` — subtle inset tint, no border move, no shadow.
- Row `selected` — 3-px purple left rail + `--purple-dim` tint.
- Row `previewed` (adjacent to drawer) — same as selected + a
  faint mono `→` glyph on the right edge showing the row that
  drives the drawer.
- Cell padding must not exceed the density token.  Wider cells
  break the "instrument" feel.

**R6 · Purple has a single meaning: investigation intelligence.**
Purple is reserved for: selected navigation · active rail ·
focused investigation · IKG relationship · running investigation
· interactive affordances · selected entities · investigation
transitions.  Never used for KPI values, severity, verdict,
lifecycle state, SLA, or empty/loading polish.

**R7 · Evidence-first is a visual composition rule.**
Any authoritative or derived value on any screen must render as a
`value → provenance` block, not as a bare number:
```
MALICIOUS
Evidence · 14 artifacts · Verdict Engine v3.1b
```
Provenance uses `meta` mono, dim.  The provenance line is
*intentional composition*, not "debug metadata".

**R8 · Empty is intentional, not blank.**
Empty state at row level → dashed honesty chip inside the row
(§5).  Empty state at section level → compact `nx-empty` with
a one-line reason (§11).  Empty state at page level → product-
shape preview (§11).  There is no such thing as a blank card in
this product.

**R9 · Motion is restrained.**
Only three animations exist:
1. `nx-shimmer` on skeleton loaders.
2. `nx-pulse` on the running-state dot (§8).
3. 120-160 ms colour / shadow transitions on hover / focus.
No slide-ins on cards.  No fade-ins on rows.  No decorative
motion on chips.  If it moves without meaning, it is a bug.

**R10 · The eye follows attention hierarchy, not container
boundaries.**  Attention hierarchy per screen:
identity → primary decision surface → operational controls →
primary data → context → metadata (§2).  Borders are the last
tool used to establish hierarchy — typography, spacing, semantic
colour, and alignment come first.  A screen that establishes
hierarchy primarily through cards is under-designed.

**R11 · Cross-screen visual coherence is a release criterion.**
Queue, Record, MSS, MITRE, Evidence must feel like the same
product.  A component that appears on two screens must look and
behave the same on both.  Divergence between screens is a bug.

**Acceptance test (§14 + R1..R11) must pass before the screen
moves on to the next in the sequenced plan.**
