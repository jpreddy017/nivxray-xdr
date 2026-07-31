# NivXRay Lab 2.0 — Architectural Design Specification

> **Status**: Design specification · **Scope**: Lab tab (the analyst workspace)
> **Companion documents**: ADR-0014 (Canonical Investigation Object), Slice-A/B/C shipped code
> **Voice**: Critical, opinionated, first-principles. Everything must earn its place.

---

## Preamble · What was reviewed

Two artefacts were meant to be attached:

1. **72-page PDF proposal** — *not present in the artefact bundle.* Any statement I make about the PDF is inferred from the HTML prototype and the operator's summary. Where a PDF-only concept is referenced (Verdict Ledger detail, Report Lens, Timeline Lens, keyboard map, motion spec, design tokens, etc.) I flag the review as *blocked pending PDF*.
2. **HTML prototype** (`nivxray-lab-ui.html`) — fully reviewed. Static single-page canvas: Case Spine (elided) · Lensbar (4 lenses: Source / Story / Behavior / ATT&CK) · Findings panel (elided) · Evidence Bar (elided). All decorative CSS + one hand-drawn 860×468 SVG.

The rest of this document is grounded in three sources: (a) the HTML I could actually read, (b) the CIO/Slice-C code base we control, (c) 20 years of DFIR / MDR analyst workflow patterns.

---

## Volume 1 · Critical Review of the PDF *(blocked — PDF not attached)*

Cannot be produced without the source document. What I *would* review, once the PDF is re-attached:

- Product philosophy claims vs. actual analyst workflows
- Information-architecture completeness (are all seven lenses justified, is there a lens that shouldn't exist, is there a lens missing)
- Verdict Ledger data model vs. our Slice-C `VerdictNode` shape
- Report Lens output vs. our planned `cio.summary.executive`
- Keyboard model vs. real analyst-throughput bottlenecks
- Design tokens vs. dark-mode SOC lighting reality
- Motion spec vs. sustained-use fatigue
- Accessibility posture (WCAG level, keyboard-only tour, screen-reader traversal)
- Whether the seven-lens taxonomy actually maps onto the CIO or is a parallel model that will drift

**Action**: re-attach and I will produce Volume 1 in full.

---

## Volume 2 · Critical Review of the HTML prototype

### 2.1 · What the HTML actually is

A **presentation shell**. Zero data plumbing. Every value is hard-coded literal text in the DOM. The Behavior graph is a hand-drawn SVG at fixed viewBox `0 0 860 468`. Every lens button is an `<a>`-like `<button>` with no ARIA role.

### 2.2 · What is genuinely strong (keep)

| Pattern | Why it works |
|---|---|
| **Story lens as default** | Analyst reads a narrative first, evidence second. Aligns with ADR-0014 §1.1.18 (event-first, not IOC-first). Correct product philosophy. |
| **Inline `ev-XX` evidence tokens** | Every clause in the prose is a click-target that scrolls the evidence bar. This is the CIO's ReasoningStep model surfaced as citations. It's the most important interaction pattern in the entire prototype. |
| **Lenses over tabs** | Same investigation, N angles. No tab-hell. Directly enables §1.1.4 (Lab + Workspace consume same CIO). |
| **Capability lanes in Behavior graph** | Vertical position carries semantic meaning (tactic band). This is a real analytical primitive, not decoration. |
| **"CHAIN drives verdict" callout** | One-line binding of evidence chain → verdict decision. The visual analogue of Slice-C's `verdict.reason`. Keep verbatim. |
| **ATT&CK as observed-only, columnar** | Refuses to render the entire Navigator matrix for a 3-technique case. Signal-to-noise wins. |
| **Story footer strip (Observations · Behaviors · Techniques · Unknowns · Elapsed)** | Correct primitives, correct order (Unknowns before Elapsed is honest). |
| **Explicit "none observed" for empty tactic columns** | Instead of hiding the column. Communicates *what was checked and not found* — a trust-building move. |
| **Elapsed time surfaced** | Trust primitive. Analysts distrust systems that hide latency. |

### 2.3 · What will break at scale (challenge or replace)

| Concern | Failure mode | Recommendation |
|---|---|---|
| **Hand-drawn SVG graph** | Cannot scale beyond ~10 nodes without a code change | Replace with data-driven WebGL/Canvas graph engine (Sigma.js WebGL renderer, or Cytoscape.js with `cytoscape-cxtmenu` and WebGL rendering). Consume `cio.evidence_graph.{nodes,edges}` directly. |
| **Only 4 lenses named — Entity + Report + Timeline missing** | The prototype cannot become an investigation OS with four views | Extend to seven lenses (Story / Source / Behavior / Timeline / ATT&CK / Entity / Report), keyboard `1`-`7`. |
| **No collaboration primitives** | Enterprise DFIR is multi-analyst. Single-user model dies on day two | Presence indicators, `@mention` on evidence nodes, pinned comments per node, shared cursor. |
| **No investigation persistence** | Prototype is stateless — no case save, no replay, no versioning | The CIO already supports this: deterministic `cio_id`, reasoning-step stream, timeline. Wire it. |
| **No case comparison / similar-cases** | An analyst investigating 40 phishing lures/week desperately needs "have I seen this before?" | Case-similarity search over CIO fingerprint (Levenshtein on graph node kinds + IOC set intersection). |
| **Unknowns as a number only** | Footer shows "Unknowns: 2" but doesn't surface *what* or *why* | Unknowns is a first-class lens. `?` key. Lists every ADR-0007 gate that fired and every enrichment provider that failed. |
| **Keyboard model limited to 1-4** | Real analysts live on the keyboard | Full vim-style keymap: `1-7` lens, `j/k` evidence-token nav, `.` cycle verdict contributors, `/` search, `?` help, `g g` case start, `G` case end, `c` comment, `m` mark, `[` `]` case prev/next. |
| **No responsive strategy** | The 860×468 SVG + fixed columns die on 13" laptops and tablets | 3-breakpoint layout: `≥1440` (3-rail), `1024-1439` (2-rail), `<1024` (stacked lenses). |
| **Only `data-theme="daylight"`** | Enterprise SOCs are 24/7 — dark mode is not optional | Semantic tokens (`--bg-canvas`, `--evidence-token`, `--verdict-crit`) — never hex in components. Auto-follow `prefers-color-scheme`. |
| **No ARIA / focus rings / a11y** | Prototype fails WCAG AA at every audit | `role="tablist"/"tab"/"tabpanel"` on lenses, `aria-current`, visible focus rings, `aria-live="polite"` on the narrative when it updates during live investigations. |
| **No motion spec** | Ad-hoc animation = jitter under load | Motion tokens: `--motion-quick: 120ms`, `--motion-narrative: 260ms`, `--motion-graph-reveal: 380ms`. Applied per-property. Never `transition: all`. |
| **Evidence Bar elided** | The most important widget in the workspace — the perpetual context. Prototype hides it. | Full spec required (see Volume 9). |
| **Findings + Recommendations panel elided** | Same — prototype ends at `<!-- FINDINGS PANEL -->`. Where §1.1.18 (Impact + Recommendations) live. | Full spec required. |
| **Fixed pixel widths in CSS** | Any zoom, any assistive-tech scale, breaks | Rem-only measurements. Design tokens for spacing (`--space-1` through `--space-8`). |
| **No error / loading / empty states** | Only happy path shown | Every lens must have: empty (no data), loading (streaming), degraded (partial data), error (with retry) states. |

### 2.4 · The one thing to replace, not improve

**The Behavior lens's static SVG is a dead-end.** Every additional node requires a code change. This must become a **data-driven graph renderer** consuming `cio.evidence_graph.{nodes,edges}` directly, with lane-assignment computed either client-side (via a stable layout algorithm) or, better, in the backend as a `graph.layout.lane_order` field on the CIO. Building an "investigation OS" on a hand-drawn SVG is like building a database on Excel.

---

## Volume 3 · Strengths (worth preserving)

1. **Story-first mental model.** Correct.
2. **Evidence citations inline in prose.** Correct.
3. **Lens paradigm (same investigation, multiple angles).** Correct.
4. **Explicit "none observed" for empty categories.** Correct.
5. **Verdict-driving chain visualisation.** Correct.
6. **Unknowns surfaced as a category, not hidden.** Correct.
7. **Elapsed time in the footer.** Trust primitive. Correct.
8. **Keyboard-first navigation intent.** Correct direction, insufficient depth.
9. **ATT&CK observed-only rendering.** Correct.
10. **Decode Ladder with L0/L1/L2 rungs + typed transforms.** This is a superior analog to CyberChef's step display. Correct.

---

## Volume 4 · Weaknesses (must fix before implementation)

1. **Design without data binding.** Every value is hard-coded.
2. **Graph engine is static SVG.**
3. **Only four lenses named; the workspace requires more.**
4. **No collaboration.**
5. **No persistence / replay / versioning.**
6. **No accessibility posture.**
7. **No motion spec.**
8. **No dark mode.**
9. **No responsive strategy.**
10. **No error/loading/empty states.**
11. **No design-token system.**
12. **No keyboard-map depth beyond 1-4.**
13. **No integration point for AI narrative overlay (the LLM should be an opt-in overlay on Story, never replacing the deterministic backbone).**
14. **No cross-case correlation surface.**
15. **No live-vs-static mode distinction.**

---

## Volume 5 · Gap Analysis (prototype vs. CIO/backend architecture we control)

The backend already emits data the prototype does not surface. Wiring gap:

| Backend field (available today) | Prototype surface | Verdict |
|---|---|---|
| `cio.evidence_graph.nodes[].id` | `ev-XX` tokens (hard-coded) | Wire it |
| `cio.evidence_graph.nodes[].kind` | Behavior lens lane assignment | Wire it |
| `cio.evidence_graph.nodes[].confidence` | Confidence dots on tactic cards | Wire it |
| `cio.reasoning_steps[].rule` + `explanation` | Story lens paragraphs | Wire it |
| `cio.reasoning_steps[].timestamp` | *No timeline lens exists* | Build Timeline lens |
| `cio.verdict.label` + `confidence_pct` | *Not visible in prototype* | Add Verdict Ribbon |
| `cio.verdict.reason` | *Not visible* | Add to Verdict Ledger |
| `cio.verdict.contributors[]` | "CHAIN drives verdict" callout | Wire the callout to real contributors |
| `cio.verdict.not_counted[]` | *Not visible* | Add to Verdict Ledger's "Ignored" section |
| `cio.metadata.normalised_via` | *Not visible* | Wire the "Normalised By" badge (already shipped in current Lab) |
| `cio.decode_chain[]` | Decode Ladder | Wire it |
| `cio.summary.artifact/incident/executive` (Slice-D pending) | *Story lens prose is hard-coded* | Wire once Slice-D lands |

**Punchline**: the prototype's information architecture is 80% right; the prototype's implementation surface is a demo with zero backend binding. Bridging the two is the entire scope of Lab 2.0.

---

## Volume 6 · Features Missing From Both

### Missing from prototype AND (likely) PDF

1. **Timeline Lens** — reasoning steps have timestamps; there is no timeline UI.
2. **Entity Lens** — pivot by host / user / hash / IP. Table + graph + per-entity history.
3. **Report Lens** — the export surface. Must render from `cio.summary.executive` (Slice-D).
4. **Verdict Ledger detail view** — full contributor table with weights, confidences, reasoning-step links.
5. **Unknowns Lens** — full breakdown of ADR-0007 gates that fired, enrichment providers that failed, why confidence was reduced.
6. **Investigation Replay** — scrubber over the reasoning-step stream. Watch the investigation reconstruct.
7. **Analyst Notebook** — free-form notes bound to evidence nodes. Survives across sessions. Full-text search across all notebooks.
8. **Case Comparison** — side-by-side two CIOs. Diff the graphs. Diff the verdicts.
9. **Similar-Case Search** — over CIO fingerprint. "You investigated 3 similar cases in the last 90 days."
10. **Cross-Case IOC Correlation** — one SHA surfaces in N cases → shows the campaign.
11. **Live vs Static mode** — reasoning steps appear as computed. Toggle in the top bar.
12. **Multi-analyst presence** — cursor / selection / active-lens indicators.
13. **Detection-Coverage panel** — what the engine looked for and didn't find.
14. **Blind-Spot Analysis** — categories of evidence not in this CIO but statistically expected.
15. **Confidence Evolution** — line chart of aggregate confidence across reasoning steps. Shows the moment the verdict crystallised.
16. **Root-Cause Explorer** — from any evidence node, walk backwards to the artifact.
17. **AI Copilot integration point** — opt-in LLM overlay on Story. Never replaces deterministic backbone. Uses CIO as evidence bundle (ADR-0014 §1.1.5).
18. **Executive View** — a single scrollable page for a non-analyst reader.
19. **SOC View** — case queue + verdict badges + SLA countdowns.
20. **DFIR View** — same case, all seven lenses, no queue chrome.
21. **Case-Templating** — save "phishing lure with PS -EncodedCommand" as a reusable investigation preset.
22. **Report collaboration** — inline comments on the export before it leaves the org.
23. **Command Palette** (`⌘K` / `Ctrl+K`) — jump to any lens, any evidence node, any recent case.
24. **Global Selection** — click any entity anywhere → all lenses filter to it.

### Ideas that do not yet exist in commercial products

1. **Reasoning-Step Diff** — for retesting: "if we replay this CIO with an updated rule pack, what changes?"
2. **Confidence Certificate** — a signed manifest of every reasoning step + evidence node + verdict decision. Downloadable. Court-admissible.
3. **Analyst Skill-Level Adaptive UI** — Tier-1 sees a single verdict + recommendation; Tier-3 sees the graph. Toggle.
4. **Explainability Prompt** — "Explain this to a CISO" / "Explain this to a customer" / "Explain this to a regulator" — deterministic templating over CIO fields.
5. **Retrospective Attack-Path Prediction** — given this CIO, predict the next reasoning-step categories a real attacker would trigger. Uses the graph shape, not an LLM.
6. **Investigation-as-Code** — the CIO is exportable/importable as YAML. Shift-left threat modelling.
7. **Delta Analyst Notes** — every change to an analyst's notes is a versioned event on the reasoning-step stream. Full audit trail.

---

## Volume 7 · Recommended Information Architecture

Seven lenses, one Case Spine, one Evidence Bar, one Findings panel, one Verdict Ribbon.

```
┌─────────────────────────────────────────────────────────────────────────┐
│  TOPBAR · Case name · Verdict Ribbon · Live/Static · Presence · ⌘K     │
├──────────────┬──────────────────────────────────────────────────┬───────┤
│              │   LENSBAR   1 Story · 2 Source · 3 Behavior      │       │
│  CASE SPINE  │             4 Timeline · 5 ATT&CK · 6 Entity     │FINDINGS│
│              │             7 Report                               │        │
│  · Now       ├──────────────────────────────────────────────────┤ · Verd │
│  · Recent    │                                                    │ · Rec  │
│  · Similar   │           ACTIVE LENS CANVAS                      │ · Unk  │
│  · Tags      │                                                    │ · Notes│
│  · Filters   │                                                    │        │
│              ├──────────────────────────────────────────────────┤        │
│              │  EVIDENCE BAR · Selected node · Provenance chain  │        │
└──────────────┴──────────────────────────────────────────────────┴────────┘
```

**Lens taxonomy** (locked):
1. **Story** — narrative + inline evidence tokens. Default.
2. **Source** — Decode Ladder + Normalised-By badge + raw artifact.
3. **Behavior** — data-driven graph (capability lanes preserved from prototype).
4. **Timeline** — reasoning-step scrubber + confidence-evolution line.
5. **ATT&CK** — observed-only tactic columns + Navigator export.
6. **Entity** — host / user / hash / IP pivot with graph and history.
7. **Report** — export surface (executive / incident / artifact from `cio.summary`).

**Case Spine** (left rail):
- Now (current case)
- Recent (last N cases)
- Similar (fingerprint-nearest cases)
- Tags (analyst-added)
- Filters (kind, tactic, verdict-label, confidence-range, has-unknowns)

**Findings panel** (right rail):
- Verdict block (label, confidence, contributor summary)
- Recommendations (from `cio.recommendations`)
- Unknowns (from ADR-0007 gates + failed enrichments)
- Analyst Notes (persistent notebook)

**Evidence Bar** (bottom):
- Currently-selected evidence node
- Provenance chain (which reasoning step created it, from which input node)
- Category (from `ioc_classifier`)
- Weight (from `evidence_priority`)
- Actions: copy value / cite in note / open in Entity lens / mark as reviewed

---

## Volume 8 · Recommended Interaction Model

### 8.1 · Global Selection
Any click on an entity (evidence token, graph node, tactic card, timeline event, entity row) sets **global selection**. Every lens filters or highlights to that entity. `Esc` clears.

### 8.2 · Keyboard Map (full)

| Key | Action |
|---|---|
| `1`-`7` | Switch lens |
| `⌘K` / `Ctrl K` | Command palette |
| `/` | Search within case |
| `?` | Help overlay |
| `j` / `k` | Next / prev evidence node |
| `.` | Cycle verdict contributors |
| `,` | Cycle unknowns |
| `g g` | Case start |
| `G` | Case end |
| `c` | Comment on selected node |
| `m` | Mark selected node reviewed |
| `[` `]` | Prev / next case |
| `t` | Toggle live/static |
| `d` | Duplicate case as template |
| `e` | Export current view |
| `r` | Open Report lens |

### 8.3 · Motion vocabulary

| Token | Value | Applied to |
|---|---|---|
| `--motion-quick` | 120ms ease-out | Hover, focus, active |
| `--motion-narrative` | 260ms ease-in-out | Lens switch, panel reveal |
| `--motion-graph-reveal` | 380ms cubic-bezier(.2,.7,.2,1) | Graph-node reveal |
| `--motion-scrubber` | 60ms linear | Timeline scrubber tick |

Never `transition: all`. Every animated property named explicitly.

### 8.4 · Empty / loading / degraded / error states

Every lens declares four states. Loading is the **reasoning-step stream animating live**, not a spinner. Degraded shows what data is present + which enrichments failed. Error shows the failure cause + retry.

---

## Volume 9 · Recommended Component Library

Token-first. Semantic naming. Twenty components maximum.

### 9.1 · Design tokens (excerpt)

```
--bg-canvas         (light) hsl(60 6% 97%)    (dark) hsl(220 15% 10%)
--bg-panel          (light) hsl(60 6% 100%)   (dark) hsl(220 15% 13%)
--fg-primary        (light) hsl(220 15% 15%)  (dark) hsl(60 6% 92%)
--fg-quiet          (light) hsl(220 8% 45%)   (dark) hsl(220 8% 60%)
--border            (light) hsl(220 12% 88%)  (dark) hsl(220 15% 22%)
--verdict-critical  hsl(354 76% 55%)
--verdict-suspect   hsl(30 90% 55%)
--verdict-info      hsl(210 70% 55%)
--evidence-token    hsl(160 60% 45%)
--space-1..8        (0.125rem × 2^n)
--motion-quick      120ms
--motion-narrative  260ms
```

### 9.2 · Component roster

1. `TopBar` — case name, verdict ribbon, live/static toggle, presence, command-palette trigger
2. `CaseSpine` — grouped list with keyboard focus and virtualised long lists
3. `LensBar` — tablist with `role="tab"` and `aria-current`
4. `LensCanvas` — routed slot per active lens
5. `EvidenceBar` — always-visible bottom bar; syncs to global selection
6. `FindingsPanel` — collapsible right rail with four sub-panels
7. `VerdictRibbon` — top-of-canvas summary (label + confidence + top contributor)
8. `EvidenceToken` — inline `<button>` used in prose; opens Evidence Bar
9. `DecodeLadder` — L0..Ln rungs with typed transforms
10. `BehaviorGraph` — data-driven; capability lanes; hover reveals node detail
11. `TimelineScrubber` — reasoning-step timeline with confidence-evolution overlay
12. `ATTACKGrid` — observed-only columnar view; keyboard navigable
13. `EntityTable` + `EntityGraph` — for the Entity lens
14. `ReportSheet` — printable / exportable artefact for the Report lens
15. `Notebook` — analyst notes bound to nodes; versioned
16. `CommandPalette` — `⌘K` fuzzy jump
17. `HelpOverlay` — `?` keyboard reference
18. `ConfidenceDots` — 5-dot horizontal (○●●●●) with `aria-label`
19. `CategoryBadge` — coloured pill for ioc_classifier categories
20. `EmptyState` / `LoadingState` / `ErrorState` — three primitives reused everywhere

### 9.3 · What we explicitly do NOT build

- Any chart library heavier than what Timeline actually needs
- Any drag-and-drop dashboard editor
- Any theming UI (theme is auto-detected)
- Any modal that isn't the Command Palette or Help Overlay

---

## Volume 10 · Recommended Frontend Architecture

### 10.1 · Framework baseline

- React 19 (already installed) + TypeScript (**recommend adopting**)
- React Router v6 for case URL routing (`/lab/case/:cio_id/:lens?`)
- Zustand for global selection + presence + case queue (small, no boilerplate)
- TanStack Query for CIO fetching + caching + streaming
- Radix UI primitives under our own component wrappers
- Framer Motion for lens transitions (already-installed dependency)
- **Sigma.js (WebGL)** for the Behavior graph; **Cytoscape.js** as second candidate
- Playwright for E2E; Vitest for unit
- Tailwind CSS with **exclusively** the semantic tokens above (no arbitrary values)

### 10.2 · Data flow

```
Backend CIO endpoint
        │
        ▼
TanStack Query cache  (keyed on cio_id)
        │
        ▼
useCIO()  ── selectors ──▶  useVerdict() / useTimeline() / useGraph() / ...
        │
        ▼
Lens components (pure)
        │
        ▼
Global selection ────────▶ Zustand store  ◀──────── Presence, notes, filters
```

Every lens is a **pure function of the CIO**. Never composes reasoning. Never invents data. Renders what the backend provides.

### 10.3 · Streaming / live mode

When the backend emits reasoning steps incrementally (SSE / WebSocket), the graph, timeline, and story lens all update **in place**. No page reload. Confidence-evolution line animates. This is unique to NivXRay — no commercial product does this well.

### 10.4 · Performance targets

- Time-to-verdict-visible: **≤ 500ms** on a cached CIO
- Time-to-story-visible: **≤ 800ms**
- Graph render for 200 nodes: **≤ 250ms** on mid-range hardware
- Lens switch: **≤ 120ms** perceived latency
- Bundle size (initial): **≤ 220KB gzipped** (excluding graph engine)

### 10.5 · Accessibility posture

- WCAG 2.2 AA baseline
- Keyboard-only navigation for every capability
- Screen-reader traversal of Story lens (aria-live on narrative updates in live mode)
- Reduced motion honoured (`prefers-reduced-motion: reduce` disables all narrative animations)
- Color-vision fallbacks (verdict never conveyed by colour alone)

### 10.6 · Testing strategy

- **Unit** — every lens is a pure function of CIO fixture; snapshot pass
- **Component** — Playwright component tests for keyboard traversal, focus rings, aria states
- **E2E** — one full case per lens: paste incident → verdict visible → Story readable → drill through evidence
- **Regression** — CIO golden fixtures produce identical rendered DOM across days

---

## Volume 11 · Lab 2.0 Final Blueprint

The workspace is:

> **A single deterministic investigation object, viewed through seven lenses, backed by an evidence graph, governed by a unified verdict engine, and served through a token-driven presentation layer that never composes reasoning.**

Concretely:

1. **Case-in-context**. Every screen shows the case. The chrome (spine, findings, evidence bar) always reflects the same CIO.
2. **Story is the front door**. Analysts read; they don't dig.
3. **Every claim is cited**. Inline evidence tokens. Click → Evidence Bar populates.
4. **Verdict is explainable at all times**. Verdict Ribbon shows label + confidence + top contributor at every scroll position.
5. **Unknowns are honest**. Never hidden.
6. **Live is native**. Static is a mode.
7. **Collaboration is a first-class primitive**, not a plugin.
8. **Every export is court-admissible**. Confidence Certificate downloadable per case.
9. **The frontend is a pure function of the CIO**. Not a reasoning engine.
10. **Keyboard-first, mouse-second, touch-third**.

---

## Volume 12 · Phased Implementation Roadmap

**Phase gate**: Slice-D (Backend Summary Composer) must land first. Without `cio.summary.artifact/incident/executive`, the Story lens has nothing durable to render.

### Phase A · Foundation (2 sessions)
- TypeScript adoption in `frontend/src/nivxforge/`
- Semantic token system (`--bg-canvas`, etc.) + Tailwind wiring
- CIO data-flow scaffold: `useCIO()` hook, TanStack Query cache
- Verdict Ribbon component + Findings panel skeleton
- Command Palette + Help Overlay

### Phase B · Seven Lenses (3-4 sessions)
- Story lens (wired to `cio.summary.executive` + inline evidence tokens)
- Source lens (Decode Ladder wired to `cio.decode_chain`)
- Behavior lens (Sigma.js WebGL; capability lanes; `cio.evidence_graph`)
- Timeline lens (reasoning-step scrubber; confidence-evolution line)
- ATT&CK lens (observed-only columnar view)
- Entity lens (table + entity graph)
- Report lens (executive / incident / artifact export)

### Phase C · Enterprise primitives (2 sessions)
- Analyst Notebook (per-node notes; versioned)
- Case Comparison (side-by-side diff)
- Similar-Case Search (CIO fingerprint)
- Cross-Case IOC Correlation

### Phase D · Live + Collaboration (2 sessions)
- SSE / WebSocket reasoning-step streaming
- Presence indicators
- `@mention` on evidence nodes
- Shared selection state

### Phase E · Court-admissibility (1 session)
- Confidence Certificate export
- Investigation-as-Code (YAML export/import)
- Report collaboration flow

### Phase F · Intelligence overlays (1-2 sessions, DEFERRED until Phase B stable)
- AI Copilot integration on Story (opt-in overlay, deterministic backbone preserved)
- Retrospective Attack-Path Prediction
- Analyst Skill-Level Adaptive UI

---

## Volume 13 · Risk Analysis

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Slice-D churn — the design assumes CIO summary fields that Slice-D might shape differently | Medium | Medium | Freeze Slice-D output schema in a Pydantic model reviewed with the design brief before Phase A |
| Sigma.js / Cytoscape.js scale | Low | High | Load-test with 500-node CIO before committing; fall back to server-rendered SVG snapshot if WebGL fails on older analyst machines |
| TypeScript migration friction | Medium | Low | Adopt gradually — Phase A converts only new files; legacy stays JS |
| Analyst rejection of keyboard model | Medium | Medium | Ship with a two-week soft-launch: analysts opt-in to `data-lab-version="2.0"` and can fall back |
| Motion causing sustained-use fatigue | Medium | Low | `prefers-reduced-motion` honoured; all narrative animations under 400ms |
| AI Copilot creeping into deterministic backbone | High | Very High (breaks ADR-0014 §1.1.5) | Overlay-only architecturally enforced: Copilot writes to a separate `cio.summary.llm_overlay` field that is *never* consulted by verdict / weight / classification |
| Enterprise deploy fatigue if we ship a full redesign at once | High | High | 6 phases, each independently valuable, each releasable behind a flag |
| Design bikeshedding | High | Medium | Every decision cites a Volume in this document. Debate must reference it or produce a superseding ADR |

---

## Volume 14 · Future Vision

Three years out.

1. **The investigation writes itself.** Live mode + case-templating + retrospective attack-path prediction combine into a system where an analyst pastes a lure and 30 seconds later the CIO is complete, the Story is written, the Report is exportable, and the Notebook has already suggested three related past cases.
2. **The graph is the primary artefact.** Story becomes a *view*; the graph becomes the durable memory. Analysts navigate cases as they navigate their inbox.
3. **Court-admissible investigations by default.** Every case exports a signed Confidence Certificate + full reasoning-step audit trail. NivXRay outputs are accepted in enterprise IR reports without additional evidence collection.
4. **Cross-case intelligence is the flywheel.** Every case adds to the fingerprint index. Six months in, the platform tells analysts *"this attacker has been in your environment before, here's the previous investigation"*.
5. **Team-native.** Multi-analyst cases with role separation (Tier-1 triage → Tier-3 deep dive → IR lead) is the default. Presence, `@mentions`, and shared selection are as expected as they are in Figma.
6. **A single deterministic object per case, forever.** The CIO is the durable artefact. UIs come and go; the CIO's reasoning-step audit trail is the memory of your SOC.

---

## Appendix · Concrete asks of the human operator

Before Phase A starts, we need three decisions from you:

1. **TypeScript**: adopt gradually (only new files) or defer? *Recommendation: adopt gradually.*
2. **Graph engine**: Sigma.js (WebGL, faster for large N) or Cytoscape.js (richer API, better layout algorithms)? *Recommendation: Sigma.js.*
3. **Live mode transport**: SSE (simpler) or WebSocket (bidirectional)? *Recommendation: SSE — presence is the only bidirectional need and can ride Zustand + a lightweight WS side-channel later.*

And re-attach the missing PDF so Volume 1 can be produced.

---

*End of specification.*
