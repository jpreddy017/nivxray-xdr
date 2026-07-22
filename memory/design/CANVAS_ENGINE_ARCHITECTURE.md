# NivXRay · Investigation Canvas Engine · Architecture Specification
_Reusable engine that powers Device Trajectory, Process Ancestry, File / Network / Registry / Identity Timelines, Attack Chain, and Investigation Graph._

**Status**: Specification. Nothing implements this yet.
**Depends on**: `UX_REVERSE_ENGINEERING.md` (interaction model), `GAP_ANALYSIS.md` (delta from current state).
**Constraint**: Does not modify RC5, Semantic Engine, Investigation Engine, or Report Generator. Visualization layer only.

---

## 1 · Architectural Goals

1. **Shared Platform Component** — the engine is a **first-class NivXRay platform component**, not a page-local helper. Every investigation view is a thin adapter on top:

```
                    Investigation Canvas Engine
                     (shared platform component)
                                │
       ┌──────────┬────────────┼────────────┬──────────┬──────────┬──────────┐
       ▼          ▼            ▼            ▼          ▼          ▼          ▼
    Device    Process       File       Registry    Network    Identity    Attack
   Trajectory  Ancestry   Trajectory   Timeline   Timeline   Timeline     Chain
                                                                          │
                                                                          ▼
                                                             Investigation Graph
                                                                          │
                                                                          ▼
                                                            Future Investigation
                                                                     Views
```

   No view may re-implement pan / zoom / selection / minimap / virtualization. All roads lead through this engine.
2. **Entity-first data model** — entities own lifetimes; events attach to them; relations connect them.
3. **60 FPS on 100 000 events** — enterprise scale, not demo scale.
4. **Deterministic layout** — same data → same visual → screenshotable in tests.
5. **Framework-agnostic core** — the engine's math and state layer must run outside React (so we can port to Vue / Svelte / server-side render in the future).
6. **Test-driven interaction** — every gesture (pan, zoom, marquee, select) is a unit-testable pure function on input state.

---

## 2 · Module Layout

```
/app/frontend/src/v2/canvas_engine/
├── index.ts                  ─ public entry point (all exports)
├── types.ts                  ─ Entity / Event / Relation / Viewport contracts
├── core/                     ─ framework-agnostic (pure TS/JS)
│   ├── viewport.ts           ─ pan / zoom / fit math (immutable state)
│   ├── time.ts               ─ tsForX / xForTs / tick generation
│   ├── layout.ts             ─ row assignment, band grouping, clustering
│   ├── selection.ts          ─ selection store (mini state machine)
│   ├── history.ts            ─ selection undo/redo
│   ├── clusterer.ts          ─ event clustering by zoom level
│   ├── virtualization.ts     ─ visible-set computation
│   └── shortcuts.ts          ─ keyboard-event → intent mapping
├── react/                    ─ React bindings (JSX components)
│   ├── InvestigationCanvas.tsx   ─ root component
│   ├── layers/
│   │   ├── GridLayer.tsx
│   │   ├── BandLayer.tsx
│   │   ├── LifelineLayer.tsx
│   │   ├── RelationLayer.tsx
│   │   ├── EventLayer.tsx
│   │   ├── OverlayLayer.tsx        (glow, hover halo)
│   │   └── InteractionLayer.tsx    (pointer capture, marquee)
│   ├── overlays/
│   │   ├── Minimap.tsx
│   │   ├── Scrollbars.tsx
│   │   ├── CanvasControls.tsx      (FIT / +/- / %)
│   │   ├── Tooltip.tsx
│   │   └── ContextMenu.tsx
│   ├── hooks/
│   │   ├── useViewport.ts
│   │   ├── useSelection.ts
│   │   ├── useKeyboardNav.ts
│   │   ├── useWheel.ts
│   │   ├── useResizeObserver.ts
│   │   └── useCanvasStore.ts       (Context provider)
│   └── icons/                       (activity glyph SVGs, NivXRay-original)
└── konva/                    ─ Konva renderers (used by react/ layers)
    ├── renderLifeline.ts
    ├── renderEvent.ts
    ├── renderRelation.ts
    └── shadowCache.ts        (Konva shadow bitmaps for perf)
```

The `core/` folder is **zero-React**. Any React front-end can drive the engine by feeding it data + subscribing to state.

---

## 3 · Data Contracts (`types.ts`)

The following types are the **stable rendering contract** for every current and future investigation view. Adapters (Device Trajectory, Process Ancestry, File Trajectory, Network Timeline, Identity Timeline, Attack Chain, Investigation Graph) MUST project their domain data into these exact shapes before handing to the engine. No view is allowed to invent its own primary object model.

The umbrella type is `InvestigationEntity` — every entity, regardless of domain (process, file, url, user, registry key…), speaks this shape:

```ts
export type EntityKind =
  | "process" | "binary" | "file" | "url" | "ip" | "domain"
  | "user" | "registry_key" | "service" | "task" | "network_flow";

export type Verdict = "benign" | "suspicious" | "malicious" | "blocked";

export interface TimeRange { start: number | string; end: number | string; }

// Every entity state defined in INTERACTION_STATE_MACHINES.md is enumerated
// here. Renderers key their visual decisions off this field.
export type VisualState =
  | "idle" | "hover" | "focus" | "selected" | "pinned"
  | "emphasized" | "dimmed" | "bookmarked" | "compared" | "terminated";

// ── The stable rendering contract ────────────────────────────────────
export interface InvestigationEntity {
  id           : string;                 // stable, unique across the case
  type         : EntityKind;
  label        : string;                 // "cmd.exe" · never "proc_shadow_…"
  lifetime     : TimeRange;              // for the lifeline
  worstVerdict : Verdict;
  band         : string;                 // grouping key
  events       : InvestigationEvent[];   // attached to lifeline
  relationships: Relationship[];         // outbound edges
  visualState  : VisualState;            // engine-driven; see state machines
  provenance?  : { source?: string; adapter?: string; rule_id?: string };
  meta?        : Record<string, unknown>;
}

export type EventKind =
  | "execute" | "create" | "delete" | "modify" | "read"
  | "network" | "file" | "registry"
  | "detect"  | "compromise" | "exploit" | "scan" | "restore" | "quarantine";

export interface InvestigationEvent {
  id          : string;
  entityId    : string;                  // owning lifeline
  ts          : number | string;
  kind        : EventKind;
  verdict     : Verdict;
  label?      : string;
  mitre?      : string[];
  confidence? : number;
  raw?        : Record<string, unknown>;
  provenance? : { rule_id?: string; artifact_iid?: string; adapter?: string };
  visualState : VisualState;
}

export type RelationshipKind =
  | "spawn" | "load" | "write" | "read" | "connect"
  | "authenticate" | "impersonate" | "modify_reg" | "signal";

export interface Relationship {
  from    : string;                     // entityId
  to      : string;                     // entityId
  ts?     : number | string;
  kind    : RelationshipKind;
  verdict?: Verdict;
  label?  : string;
  meta?   : Record<string, unknown>;
  visualState: "idle" | "highlighted" | "dimmed";
}

export interface Viewport {
  offset : { x: number; y: number };
  scale  : number;
  size   : { w: number; h: number };
}

export interface CanvasStore {
  entities   : InvestigationEntity[];
  events     : InvestigationEvent[];    // union of entity.events (indexed)
  relationships: Relationship[];
  selection  : { entityId?: string; eventId?: string; multi?: string[] };
  viewport   : Viewport;
  timeWindow?: [number, number];
  expertMode : boolean;
  reduceMotion: boolean;
}
```

The former `Entity / Event / Relation` names are aliased to the new names during migration:

```ts
export type Entity   = InvestigationEntity;
export type Event    = InvestigationEvent;
export type Relation = Relationship;
```

Rule: **every renderer consumes `InvestigationEntity[]` + `InvestigationEvent[]` + `Relationship[]`. No view invents its own primary shape.** If a domain has fields the base type doesn't capture, put them in `meta` — never in a parallel structure.

---

## 4 · Public React API

```tsx
import { InvestigationCanvas, CanvasProvider } from "@nivx/canvas_engine";

<CanvasProvider
  entities={entities}
  events={events}
  relations={relations}
  onSelectionChange={(sel) => { /* right panel etc. */ }}
  onViewportChange={(vp) => { /* scrubber sync */ }}
  timeWindow={[start, end]}
  expertMode={expert}
  tokens={NX}
>
  <InvestigationCanvas
    minimap
    scrollbars
    controls={{ fit: true, zoom: true, presets: ["1H","24H","7D","30D"] }}
    onOpenEntity={(iid) => nav(`/v2/ancestry/${caseId}/${iid}`)}
    onEventDoubleClick={(ev) => …}
    emptyState={<CustomEmpty/>}
  />
</CanvasProvider>
```

`useCanvasStore()` inside sibling components (rail, right panel, scrubbers):

```tsx
const { selection, setSelection, entities, events } = useCanvasStore();
```

Sibling components dispatch selection changes to the same store — that's how the scrubbers, rail, right panel, and canvas stay in sync.

---

## 5 · State Machine (Selection)

```
             ┌──────────┐
       ┌─────│   IDLE   │◀──────── Escape
       │     └────┬─────┘
       │          │ pick event
       │          ▼
       │   ┌────────────┐
       │   │  EV_SELECT │──── shift-click ┐
       │   └─────┬──────┘                 │
       │         │ pick entity            ▼
       │         ▼                 ┌───────────────┐
       │  ┌────────────┐           │ MULTI_SELECT  │
       │  │ ENT_SELECT │──shift-…─▶│               │
       │  └─────┬──────┘           └──────┬────────┘
       │        │ click empty                │
       └────────┴────────────────────────────┘
```

The store exposes:
* `set(ev)`, `set(entity)`, `add(ev)`, `remove(ev)`, `clear()`
* `undo()`, `redo()` — history stack size 32.
* `subscribe(cb)` — for React-external consumers.

---

## 6 · Rendering Strategy

**Konva stage** with layered redraws:

| Layer | Contents | Redraw trigger |
|-------|----------|---------------|
| gridBg          | vertical hour tick lines | zoom change only |
| bandStripes     | band header rectangles + labels | entities change / expert-mode toggle |
| lifelines       | dashed entity lifelines | rows in viewport change / selection change |
| relations       | dashed edges between entities | edges in viewport change |
| events          | tiny glyphs (individual + clustered) | virtualized set change / selection glow |
| overlays        | hover halo, marquee rect, tween cursors | mouse move / drag state |
| interactionCap  | invisible; captures pointer | never redraws |

The engine keeps a **dirty bit** per layer. `stage.batchDraw()` only redraws dirty layers. On steady state (hover across an unchanged canvas) 0 layers redraw at 60 FPS.

---

## 7 · Viewport Math (`core/viewport.ts`)

Pure functions, no dependencies:

```ts
export const clamp = (v: number, lo: number, hi: number) => …;

export const clampOffset = (o, s, size, content) => { … };

export const zoomAround = (
  vp: Viewport, factor: number, pointer: {x:number;y:number}
): Viewport => { … };            // anchor-preserving zoom

export const fit = (
  contentRect: {w:number;h:number}, size: {w:number;h:number}, pad = 20
): Viewport => { … };

export const isInViewport = (
  x: number, y: number, vp: Viewport, marginPx = 200
) => …;
```

Same math is used by tests, minimap, and the React binding. Zero React imports.

---

## 8 · Layout Engine (`core/layout.ts`)

Given `entities + expertMode`, computes:
* `bands[]` — [{ label, rows[], top, height }]
* `rowY[entity_iid]` — vertical position
* `contentH`, `contentW`
* `entityIndex` — Map<string, entity>

Deterministic sort:
1. by `band` order
2. within band by `first_seen` ascending
3. tie-break by `label` locale-compare

Same input → same output. Feeds directly into `renderLifeline` and virtualization.

---

## 9 · Clustering (`core/clusterer.ts`)

At low zoom, individual events overlap into unreadable smudges. The clusterer merges close events on the same lifeline into a single visual token.

```ts
cluster(events: Event[], vp: Viewport, xForTs, minPxGap = 6): Cluster[]
```

Rules:
* Same `entity_iid` events within `minPxGap` merge.
* Merged cluster inherits **worst verdict** of children.
* Cluster carries a `count` badge overlay when > 1.
* Click on cluster → **zoom in** to a scale where the cluster splits, anchored on cluster centre.
* Selection propagates: clicking a cluster selects its worst-verdict child.

Threshold `minPxGap` is user-tunable (default 6 px) — matches Cisco's "chunk aggregation" pattern.

---

## 10 · Virtualization (`core/virtualization.ts`)

```ts
export interface VisibleSet {
  entities: Entity[];        // rows intersecting viewport ± 200 px vertical margin
  events:   Event[];         // events inside viewport ± 200 px on both axes
  relations:Relation[];      // edges where either endpoint is visible
}

visibleSet(store: CanvasStore, vp: Viewport, xForTs): VisibleSet
```

Memoized with a `WeakMap` key on `(store.epoch, vp.offset, vp.scale)` so repeat calls in the same frame return the same array reference — React child memoization then skips render.

Result set never exceeds the render budget: on 100k events at typical zoom, `visible.events.length ≈ 500–2000`.

---

## 11 · Keyboard Navigation (`core/shortcuts.ts`)

Table-driven map from `KeyboardEvent` to a `CanvasIntent`:

```ts
type CanvasIntent =
  | { type: "PAN";  dx: number; dy: number }
  | { type: "ZOOM"; factor: number; anchor?: {x:number;y:number} }
  | { type: "FIT" }
  | { type: "PRESET"; k: "1H"|"24H"|"7D"|"30D" }
  | { type: "NEXT_EVENT" | "PREV_EVENT" }
  | { type: "NEXT_ENT_EVENT" | "PREV_ENT_EVENT" }
  | { type: "PLAY_TOGGLE" }
  | { type: "OPEN_SELECTED" }
  | { type: "CLEAR_SELECTION" }
  | { type: "UNDO_SELECTION" }
  | { type: "FOCUS_SEARCH" }
  | { type: "TOGGLE_EXPERT" }
  | { type: "SHOW_HELP" };

export const mapKey = (e: KeyboardEvent): CanvasIntent | null => …;
```

React binding subscribes to `window.keydown`, converts, and dispatches through the store. This design makes keyboard behavior identical for every future view without re-implementing shortcuts.

---

## 12 · Animation Manager

`Konva.Tween` isn't enough — we need coordinated multi-node tweens (selection cascade: event glow + lifeline brighten + others dim simultaneously).

```ts
interface AnimationHandle { cancel(): void; done: Promise<void>; }

animate(
  targets: { node: Konva.Node; from: any; to: any }[],
  opts: { duration: number; easing?: EasingFn; }
): AnimationHandle
```

Respects `prefers-reduced-motion`: sets `duration = 0`, snap on end frame.

---

## 13 · Tooltip System

* Delayed reveal (250 ms default).
* Cancelled on pointer-move > 8 px within delay window.
* Rendered as a portalized DOM element (not Konva) — DOM handles rich HTML tooltips better than canvas text.
* Positioned above pointer, clamped to viewport edges.

Content is consumer-provided:

```tsx
<InvestigationCanvas
  tooltipFor={(ev) => <EventTooltip event={ev} />}
/>
```

---

## 14 · Context Menu

Right-click on entity or event → context menu with actions. Actions are **consumer-registered** so each view can offer different options:

```tsx
<InvestigationCanvas
  contextActions={[
    { label: "Open Process Ancestry",  when: t => t.kind === "entity",  do: e => nav(...) },
    { label: "Copy IID",               when: () => true,                do: e => copy(e.entity_iid) },
    { label: "Filter to this entity",  when: t => t.kind === "entity",  do: e => setFilter(...) },
    { label: "Bookmark",               when: t => t.kind === "event",   do: e => bookmark(e) },
    // …
  ]}
/>
```

---

## 15 · Panel Synchronizers

The engine exposes two synchronizer hooks that consumers wire into their layout:

```tsx
// Left rail — mirrors selection
const rail = useEntityRailSync();
// { entities, selectedIid, scrollIntoView, onPickEntity }

// Right panel — mirrors evidence
const evidence = useEvidenceSync();
// { selected: Event | null, related: Event[], onPickRelated }
```

These hooks subscribe to the same store — no prop drilling.

---

## 16 · Minimap Component

Second, small Konva stage.
* 168 × 96 px default.
* Renders entity rows as 1-px stripes, events as 0.9-px dots.
* Draws viewport rectangle in blue on top.
* Click → jump viewport centre.
* Drag rectangle → live viewport reposition.
* Toggleable via prop `minimap={boolean}`.

---

## 17 · Scrollbars

Synthetic (not native `overflow`). Rationale: Konva can't be `overflow:auto`; we own the scroll math anyway.

* Track: 6 px thick.
* Thumb: proportional to `viewport.size / content.size`.
* Position: bottom-right corner.
* Drag = repositions viewport.

Hidden when content fits entirely.

---

## 18 · Performance Model

Budget (per frame, 60 FPS = 16 ms):
* Konva `batchDraw` — target 6 ms
* React reconciliation (rail, evidence panel) — target 4 ms
* Store dispatch + subscriber notifications — target 1 ms
* Slack — 5 ms

Instrumentation:
* `performance.mark("canvas:frame:start")` + `mark("canvas:frame:end")` around every draw.
* Dev-mode overlay showing FPS + frame time (`Ctrl+Alt+D`).
* Slow-frame log to console when frame > 20 ms.

Load-time budget:
* Fetch trajectory → first paint under 200 ms on 5k events.
* 100k events → progressive load in 400 ms chunks; canvas paints partially as data arrives.

---

## 19 · Testing Strategy

Unit tests (Vitest / Jest, zero DOM):
* `core/viewport.ts` — pan clamp, zoom anchor math.
* `core/layout.ts` — deterministic band + row ordering.
* `core/clusterer.ts` — cluster boundaries at edge zooms.
* `core/virtualization.ts` — visible-set correctness on grid of test entities.
* `core/shortcuts.ts` — every key → intent mapping.

Snapshot tests (Playwright):
* Fixed dataset → canvas SVG-serialisation snapshot at zoom presets `Fit / 1H / 24H`.
* Selection cascade → after clicking event `ev_abc`, canvas snapshot matches `ev_abc_selected.snap`.

Interaction tests (Playwright):
* Pan drag from `(500,300)` to `(700,320)` → viewport offset increased by `(200, 20)`.
* Ctrl+wheel at `(600,400)` down → scale reduced, point under cursor unchanged.
* Marquee from `(100,100)` to `(400,300)` → selection contains expected event IIDs.

Storybook stories:
* Empty, 100 events, 1000 events, 10 000 events, 100 000 events synthetic dataset — for perf inspection.

---

## 20 · Rollout Plan

Because the engine is new and non-trivial, and because **you cannot validate a UX that doesn't exist yet**, the milestone order was corrected on user review:

**Milestone 0 — Architecture** ✅ **COMPLETE**
* All four normative design documents signed off. Locked decisions Q1–Q9. Stable rendering contract (`InvestigationEntity + InvestigationEvent + Relationship + VisualState`).
* This is the point implementation opens.

**Milestone 1 — Core canvas engine skeleton** (implementation gate):
* Add TypeScript toolchain to the frontend workspace.
* Scaffold `/app/frontend/src/v2/canvas_engine/{core,react,konva}` per §2 module tree.
* Implement `types.ts` + `core/*` (viewport / time / layout / selection / history / virtualization).
* Ship `react/InvestigationCanvas.tsx` with `LifelineLayer` + `EventLayer` only.
* Green unit tests on viewport / layout math.
* **Marquee multi-select included** (locked decision Q1).
* **Feature Freeze Rule (hard):**

  > No investigation feature may be added until the existing interaction model behaves correctly.

  In practice, during M1 through M3:
  * ❌ No new MITRE badges, chips, or overlays.
  * ❌ No new filter categories or dropdowns.
  * ❌ No new side panels or tabs.
  * ❌ No AI / summarisation widgets.
  * ❌ No new visualisations or embellishments.
  * ✅ Only work that makes the canvas feel professional is in scope.

**Milestone 2 — Interaction complete**:
* Selection cascade + gentle auto-scroll.
* Keyboard nav (every shortcut from `INTERACTION_STATE_MACHINES.md` §5).
* Shift-select + context menu + minimap + scrollbars.
* Every state machine transition in `INTERACTION_STATE_MACHINES.md` implemented end-to-end.

**Milestone 2.5 — Golden UX Validation** (now positioned to evaluate a *working* prototype):
* Pick one canonical DFIR case (Bumblebee → AdaptixC2 → Akira).
* Open Cisco Secure Endpoint (reference) on one monitor, the new NivXRay canvas on another.
* Walk through the six analyst tasks:
  1. Find the parent process of the first malicious execution.
  2. Locate the first malicious execution timestamp.
  3. Trace all spawned child processes of that parent.
  4. Follow every registry-key modification in the incident window.
  5. Inspect all outbound network connections from suspicious binaries.
  6. Review detections and their MITRE technique attribution.
* Measure `TASKS × { CLICKS · TIME · CTX_SW · SCROLL · ZOOM }` on both tools.

**M2.5 Quantitative UX Gates** — every one must pass, else M3 does not open:

| Category                | Gate                                            |
|-------------------------|-------------------------------------------------|
| Workflow efficiency     | Within **10–15%** of the reference on every task metric |
| **Framerate**           | **≥ 60 FPS** during pan, zoom, marquee-drag, selection cascade |
| **Input latency**       | **< 16 ms** pointer-down → visual feedback      |
| **Zoom smoothness**     | No visible frame jumps during continuous wheel zoom |
| **Auto-scroll**         | No abrupt camera jumps · always eased or snap-in-reduced-motion |
| **Selection response**  | Highlight visible within **100 ms** of click     |
| **Right-panel sync**    | Evidence panel updates within **100 ms** of selection |
| **Cold load**           | Canvas paints < **1 second** for 5 000 entities |
| **Memory**              | No progressive heap growth over a **30-minute** interactive session |

**M2.5 Qualitative Analyst Heuristics** — every task must let the tester answer YES to each:

1. Can I immediately identify the root process without hunting?
2. Can I follow parent → child execution without searching?
3. Can I tell which entities are currently selected at a glance?
4. Can I distinguish historical events from active context?
5. Can I navigate the canvas without losing spatial orientation?
6. Can I recover to a known state after zooming or panning aggressively?
7. Is the investigation flow obvious without training?

* If any task is >15% behind on numbers OR fails a heuristic, that specific gap goes to the top of the M3 backlog before general work.
* Output artifact: `/app/memory/design/GOLDEN_UX_VALIDATION.md` with the matrix + heuristic answers + top-3 gap remediation items.

**Milestone 2.75 — Analyst Dogfooding** (new; runs immediately after M2.5):
* Recruit 3–5 SOC analysts (or colleagues familiar with investigations).
* Have each perform the same six tasks unassisted.
* Observe (do not coach) and record answers to:
  * Can you find the initial execution quickly?
  * Can you trace process ancestry naturally?
  * Is the selected entity obvious?
  * Do you lose your place while navigating?
  * Is panning / zooming intuitive?
  * Does the right panel expose the information you expect?
* Output artifact: `/app/memory/design/ANALYST_DOGFOODING.md` with observations, verbatim quotes, and top-3 friction items.
* **Every friction item observed by ≥ 2 analysts** is added to the M3 backlog before general perf work begins.

**Milestone 3 — Performance**:
* Clustering (configurable `clusterRadiusPx`, `expandThreshold`, `collapseThreshold`).
* Viewport virtualization (only draw items in `viewport ± margin`).
* Cached shadow bitmaps for selection glow.
* Dev-mode FPS overlay (`Ctrl+Alt+D`).
* Load-time budget: 100 k events in < 400 ms progressive chunks.
* Any friction item bubbled up from M2.5 / M2.75 is addressed here before general perf work.

**Milestone 4 — Device Trajectory rebuild**:
* Trajectory page becomes ~150 LOC (chrome only).
* Old `DeviceTrajectory.jsx` + `DeviceTrajectoryV2.jsx` deleted.

**Milestone 5 — Process Ancestry migration**:
* Ancestry page consumes the same engine with a different Entity/Relationship feed.
* No new rendering engine (locked decision Q4).

**Milestone 6 — File Trajectory**:
* Third consumer of the same engine.
* **Only after** Device + Process + File are all successfully sharing the engine, evaluate extracting it into a standalone `nivx-canvas-engine` workspace with independent versioning + Storybook.
* Until then, the engine stays at `/app/frontend/src/v2/canvas_engine/` — early extraction would prematurely freeze an abstraction that has only served one consumer.

**Milestone 7 — Additional views**:
* Network Trajectory, Registry Timeline, Identity Timeline, Attack Chain, Investigation Graph — each is a new adapter that projects domain data into `InvestigationEntity[]`.

**Milestone 8 — Phase 2 · Live streaming ingest**:
* Canvas grows as a case is being ingested (locked decision Q5).

Each milestone is independently shippable and reviewable.

---

## 21 · Locked Decisions

The following decisions are **frozen** as of user sign-off. Any deviation requires an explicit revision.

| # | Decision | Locked value |
|---|---|---|
| Q1 | Marquee multi-select                    | **In Milestone 1** (MVP, not v2)                          |
| Q2 | Cluster thresholds                      | **Configurable**: `clusterRadiusPx=8`, `expandThreshold=0.75`, `collapseThreshold=0.45` — all overridable via props. No hardcoded values. |
| Q3 | Chronological playback (`Space` bar)    | **Backlog** — post-MVP                                   |
| Q4 | Ancestry / Attack Chain / Graph views   | **Reuse Canvas Engine.** Never build a second renderer.   |
| Q5 | Live streaming ingest                   | **Phase 2** — after core rollout complete                |
| Q6 | Language / typing                       | **TypeScript** for the engine core. Non-negotiable.      |
| Q7 | Rendering library                       | **React Konva**. Confirmed.                              |
| Q8 | Data fetch                              | **External to the engine.** Canvas receives normalized data (Entity/Event/Relation arrays) via props. It does not fetch, and it does not know about `axios`, API endpoints, or case IDs. |
| Q9 | Theming                                 | **Design tokens** — consumer passes a `tokens` prop; engine has zero hardcoded colors. |

Any future proposal to change these must be a written revision that supersedes this section.

---

## 22 · Sign-off Gate

**No code lands until sections 1-21 are signed off AND Milestone 0 (Golden UX Validation) completes.** After both gates pass, Milestone 1 opens implementation.

Interaction state definitions for every entity / event state (idle / hover / focus / selected / expanded / pinned / compared / dimmed) live in the companion document `/app/memory/design/INTERACTION_STATE_MACHINES.md`. That document is normative — the engine implementation must honor every state transition it specifies.
