# NivXRay · Investigation Canvas Engine · Architecture Specification
_Reusable engine that powers Device Trajectory, Process Ancestry, File / Network / Registry / Identity Timelines, Attack Chain, and Investigation Graph._

**Status**: Specification. Nothing implements this yet.
**Depends on**: `UX_REVERSE_ENGINEERING.md` (interaction model), `GAP_ANALYSIS.md` (delta from current state).
**Constraint**: Does not modify RC5, Semantic Engine, Investigation Engine, or Report Generator. Visualization layer only.

---

## 1 · Architectural Goals

1. **One engine, many views** — Device Trajectory is one of at least eight consumers.
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

```ts
export type EntityKind =
  | "process" | "binary" | "file" | "url" | "ip" | "domain"
  | "user" | "registry_key" | "service" | "task" | "network_flow";

export type Verdict = "benign" | "suspicious" | "malicious" | "blocked";

export interface Entity {
  entity_iid  : string;              // stable, immutable
  kind        : EntityKind;
  label       : string;              // display name; "Unknown Process" for unresolved
  first_seen  : number | string;     // ms epoch or ISO
  last_seen   : number | string;
  worst_verdict: Verdict;
  band        : string;              // grouping key ("System" | "Files & Network" | …)
  provenance? : { source?: string; adapter?: string; rule_id?: string };
  meta?       : Record<string, unknown>;
}

export type EventKind =
  | "execute" | "create" | "delete" | "modify" | "read"
  | "network" | "file" | "registry"
  | "detect"  | "compromise" | "exploit" | "scan" | "restore" | "quarantine";

export interface Event {
  event_iid   : string;
  entity_iid  : string;              // owning lifeline (must match an Entity)
  ts          : number | string;
  kind        : EventKind;
  verdict     : Verdict;
  label?      : string;
  mitre?      : string[];
  confidence? : number;
  raw?        : Record<string, unknown>;
  provenance? : { rule_id?: string; artifact_iid?: string; adapter?: string };
}

export type RelationKind =
  | "spawn" | "load" | "write" | "read" | "connect"
  | "authenticate" | "impersonate" | "modify_reg" | "signal";

export interface Relation {
  from    : string;                  // entity_iid
  to      : string;                  // entity_iid
  ts?     : number | string;         // relation moment (optional)
  kind    : RelationKind;
  verdict?: Verdict;
  label?  : string;
  meta?   : Record<string, unknown>;
}

export interface Viewport {
  offset : { x: number; y: number };
  scale  : number;                    // 1.0 = 100%
  size   : { w: number; h: number };  // pixel dims of the canvas element
}

export interface CanvasStore {           // owned by the engine
  entities  : Entity[];
  events    : Event[];
  relations : Relation[];
  selection : { entityIid?: string; eventIid?: string; multi?: string[] };
  viewport  : Viewport;
  timeWindow?: [number, number];       // scrubber-controlled
  expertMode: boolean;
  reduceMotion: boolean;
}
```

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

Because the engine is new and non-trivial:

**Milestone 1 — core skeleton** (no visual polish):
* `types.ts` + `core/*` + `react/InvestigationCanvas.tsx` with `LifelineLayer` + `EventLayer` only.
* Wired via `CanvasProvider` — sibling stub components can subscribe.
* Green unit tests for viewport / layout math.

**Milestone 2 — interaction complete**:
* Selection cascade + auto-scroll + gentle-scroll.
* Keyboard nav.
* Marquee + shift-select + context menu.

**Milestone 3 — perf**:
* Clustering, virtualization, cached shadow bitmaps, dev FPS overlay.

**Milestone 4 — Device Trajectory rebuild**:
* Trajectory page becomes ~150 LOC (chrome only).
* Old `DeviceTrajectory.jsx` + `DeviceTrajectoryV2.jsx` deleted.

**Milestone 5 — Process Ancestry migration**:
* Ancestry page consumes the same engine with a different Entity/Relation feed.

**Milestone 6 — new views**:
* File Trajectory, Network Trajectory, Attack Chain, Investigation Graph.

Each milestone is independently shippable and reviewable.

---

## 21 · Approval Gate

**No code lands until sections 1-20 are signed off.** After sign-off, Milestone 1 opens implementation.

Open questions for the user:
* Q1 (from UX doc): Marquee multi-select — MVP or v2?
* Q6: TypeScript vs plain JS for the engine — the whole codebase is JS today, but the engine is the strongest candidate for TS (types are the whole point). Add TS toolchain, or stay JS with JSDoc types?
* Q7: React Konva vs raw Konva + custom reconciler — react-konva adds ~30 KB and works today. Raw Konva is faster but doubles implementation time.
* Q8: Data-fetch layer — the engine expects entities pre-computed. Do we add a `useTrajectoryData(caseId)` hook inside the engine, or keep fetch orthogonal (current pattern)?
* Q9: Colors — should the engine own its palette, or accept tokens (`props.tokens`) so every consumer can theme it independently? (Current design: accept tokens.)
