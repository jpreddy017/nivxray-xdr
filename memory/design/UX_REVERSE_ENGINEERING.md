# NivXRay · Device Trajectory UX Reverse Engineering
_Analysis of the professional investigation workflow we must achieve. Source material: Cisco Secure Endpoint public documentation + user-provided screenshots._

**Status**: Design specification. No implementation until §21 sign-off.
**Scope**: Interaction model, information architecture, and analyst workflow. **Never** branding, icons, fonts, colors, or code.

---

## 1 · Overall Layout Architecture

The workspace is a **six-band vertical stack** with an inner three-column workspace. Every band's height is fixed except the timeline canvas which absorbs all remaining space.

```
┌────────────────────────────────────────────────────────────────┐  ← 100vh
│ [1] Global header       ~ 6%   product · case · search · zoom  │
├────────────────────────────────────────────────────────────────┤
│ [2] Filter row          ~ 6%   compact single line             │
├────────────────────────────────────────────────────────────────┤
│ [3] Day scrubber        ~ 8%   density curve · critical dots   │
├────────────────────────────────────────────────────────────────┤
│ [4] Hour scrubber       ~ 8%   24-hour · hatched future zone   │
├──────────────┬──────────────────────────────┬──────────────────┤
│ [5a] Entity  │ [5b] Timeline canvas         │ [5c] Right panel │
│    rail      │      (dominant, ≥55%)        │                  │
│   ~ 12%      │                              │      ~ 18%       │
├──────────────┴──────────────────────────────┴──────────────────┤
│ [6] Status footer       ~ 4%   viewport · counts · shortcuts   │
└────────────────────────────────────────────────────────────────┘
```

Non-negotiables:
* Canvas dominates. Everything else compresses to make room.
* Bands 3 and 4 are **scrubbers**, not just headers — they set the canvas window.
* Bands 5a, 5b, 5c are **live-synchronized siblings** — selection in one updates the other two atomically.

---

## 2 · Information Hierarchy

Reading order for a new analyst opening the workspace:

1. **Global context** (band 1): "Which case am I looking at? How many events? How many entities?"
2. **Temporal density** (band 3): "When did activity peak? Any critical marker days?"
3. **Zoom in** (band 4): "Within the selected day, when was suspicious activity concentrated?"
4. **Entity list** (band 5a): "Which processes / binaries were involved?"
5. **Timeline canvas** (band 5b): "How did they interact over time? What's the causal chain?"
6. **Evidence** (band 5c): "What did this specific event actually do? What's the raw evidence?"

Layout must reinforce this ordering by **spatial adjacency** — no analyst should scroll past scrubbers to reach the canvas.

---

## 3 · Timeline Model

The timeline is a **time-scaled 2D coordinate space**, not an event list.

* **X axis** — logical time. Bounds derived from data (`minTs`, `maxTs`) plus optional user-set window from the scrubber.
* **Y axis** — entity slots. Rows are stable across zoom.
* **Time unit conversion**: `pxPerMs = f(scale)`. The canvas engine owns `xForTs(ts)` and `tsForX(x)` as inverse projections.
* **Zoom** stretches X; it never changes row height on Y (analyst muscle memory relies on stable row positions).
* Ticks appear at natural boundaries: hour, day, week — chosen by `pxPerHour`. Grid lines are near-invisible until zoomed in.

Rendering approach: **Konva/Canvas** (not divs). Divs cannot handle 100k+ events at 60 FPS.

---

## 4 · Entity Model

The core object is an **Entity**, not an Event.

```
Entity {
    entity_iid   : "bin:cmd.exe" | "url:evil.com" | "user:svc-backup" ...
    kind         : process | binary | file | url | ip | domain | user | key | service
    label        : "cmd.exe"                    // display name
    first_seen   : ts                            // lifeline start
    last_seen    : ts                            // lifeline end
    worst_verdict: benign | suspicious | malicious
    band         : "System" | "Files & Network" // grouping
    provenance   : { source, adapter, rule, ... }
    events       : Event[]                       // attached to lifeline
    relations    : Relation[]                    // outbound edges
}
```

Every row on the canvas represents ONE entity's **lifetime**. The horizontal line = the lifeline itself. Events are decorations on that line. Relations are edges to other entities' lifelines.

**Critical insight**: `proc_shadow_<hash>` internal IIDs are never displayed. They resolve to `Unknown Process` labels; the IID stays as the technical key.

---

## 5 · Lifeline Model

Each entity gets **one horizontal band**. The band contains a **dashed lifeline** stretching from `first_seen` to `last_seen`.

States:
* **Idle**       — 0.4 opacity, 0.8 px stroke, neutral color
* **Hover**      — 0.7 opacity, cursor changes to pointer
* **Selected**   — 0.95 opacity, 1.4 px, blue glow, adjacent entities' lifelines dim
* **Malicious**  — red stroke instead of neutral
* **Suspicious** — amber stroke
* **Killed**     — line terminates with a small `×` at `last_seen`

Lifelines never overlap vertically. If two entities share a row, they get **stacked sub-rows** (rare but must be handled — e.g. an unnamed process forking under a known binary label).

---

## 6 · Event Rendering Model

An event is a **point decoration** on a lifeline at time `ts`.

```
Event {
    event_iid  : "ev_<hash>"
    entity_iid : parent lifeline
    ts         : timestamp
    kind       : execute | create | delete | network | file | registry
               | detect | compromise | exploit | scan | restore
    verdict    : benign | suspicious | malicious
    label, mitre, raw, provenance…
}
```

Rendering rules:
* **11 px** diameter maximum. Never larger than a lowercase letter.
* Fill = dark background (matches canvas). Stroke = verdict color.
* Inner glyph = white SVG symbol (execute ▷, create +, delete ×, …).
* Malicious events swap the circle for a **hex shield** shape (semantic escalation).
* Selected event = 12 px, blue drop-shadow, adjacent 20 px halo, hover cursor.

Events near each other in time **merge into an event cluster** at low zoom (`pxPerHour < 30`) — cluster is drawn as one glyph with a small counter overlay. Zooming in expands the cluster.

---

## 7 · Selection Behavior

One event may be selected at a time (single-select MVP). Selection triggers a **synchronized cascade**:

1. Event glyph → glow (blue shadow).
2. Owning entity lifeline → brighten to selected state.
3. Related entities (parent, spawn children, target of relation) → subtle emphasis (`0.8` opacity, no glow).
4. All non-related entities → dim to `0.25`.
5. Left rail → the entity row scrolls into view + highlights.
6. Right panel → switches to `Evidence` tab; renders the event's evidence dossier.
7. Canvas viewport → **gentle** auto-scroll: pans only if the event's on-canvas coordinate falls outside a 60 px inset of the viewport rect. Uses eased tween (~300 ms).

Multi-select (future): shift-click adds. Selected set drives the evidence panel via aggregate view.

---

## 8 · Hover Behavior

Hover is **preview-only** — no state mutation, purely informational.

* Event glyph → scales to 1.3, cursor pointer, floating tooltip renders after 250 ms delay showing `ts` + `label` + verdict.
* Entity row (left rail) → row background lightens; the corresponding lifeline on the canvas gets a **thin brightening rectangle** across its full width to help the eye trace it.
* Lifeline segment → nothing (hover-through to events).
* Relation edge → highlights both endpoints subtly.

Hovers are debounced. Rapid mouse movement across the canvas never triggers cascading tooltips.

---

## 9 · Drag Behavior

Three drag modes:
* **Pan** (default, empty canvas or spacebar-held) — cursor `grabbing`, moves the whole viewport. Momentum-free (deliberate — analysts don't want the canvas to keep moving after release).
* **Marquee select** (Shift + drag on empty canvas) — draws a selection rectangle; on release, every event inside becomes selected (multi-select).
* **Scrubber drag** (in bands 3 & 4) — dragging the day / hour scrubber cursor updates the visible time window. Canvas re-projects.

Dragging an event or lifeline is **not** interactive drag-drop; the objects are immutable evidence. Clicks on them route to selection instead.

---

## 10 · Pan Behavior

Pan is **infinite in principle**. The canvas engine computes a `contentRect` from data bounds + a 10% margin on all sides. The stage transform (`x`, `y`, `scale`) is clamped so the viewport never fully leaves the content rect (there's always something visible).

Pan sources:
* Click-and-drag on empty canvas → primary.
* Two-finger trackpad → identical to click-and-drag.
* Arrow keys → nudges by 80 CSS px in the arrow direction (respects zoom).
* Minimap click → jumps the viewport centre to the clicked minimap location.
* Auto-scroll on selection (§7) → tween.
* Scrollbar drag → maps thumb position to `offset.{x,y}`.

State model: a single `{x, y, scale}` triple owned by the canvas engine. Everything else is derived.

---

## 11 · Zoom Behavior

Zoom is **anchor-preserving** — the point under the cursor stays under the cursor as the world scales.

Sources:
* Mouse wheel with Ctrl / Cmd / Alt → smooth zoom in/out (factor `0.92 / 1.08` per wheel tick).
* Two-finger trackpad pinch → same math.
* Buttons `+` `−` in the canvas overlay → factor `1.15`.
* `FIT` button → computes `scale` such that `contentRect` fits into the viewport with a 20 px inset.
* `1H / 24H / 7D / 30D` presets → set `scale` such that the current time window fits exactly.
* Double-click on canvas → zoom in by 1.5, anchored on click point.
* Double-click on entity row → zoom to that lifeline (fit its `[first, last]` window horizontally).
* `f` key → FIT. `+` / `-` → 1.15 factor.

Clamp: `0.15 ≤ scale ≤ 6.0`. Extreme zoom-out shows month density; extreme zoom-in exposes millisecond ordering.

---

## 12 · Scroll Behavior

The canvas has **two independent scroll axes** — horizontal (time) and vertical (entities).

Wheel routing:
* Bare wheel        → vertical scroll (entity list).
* Shift + wheel     → horizontal scroll (time).
* Ctrl / Cmd + wheel → zoom (see §11).
* Trackpad 2-finger → routes to the pointer's dominant axis.

Synthetic scrollbars are always present when content overflows the viewport. Their thumb positions are read/write bindings to `offset.{x,y}`.

Vertical scroll never affects zoom. Horizontal scroll never affects zoom. This orthogonality is a Cisco-verified principle and matches Figma / Draw.io / Google Maps expectations.

---

## 13 · Panel Synchronization

Three siblings, one selection state:

```
┌───────── Entity Rail ─────────┐    ┌───────── Right Panel ─────────┐
│                               │    │                               │
│       selected: entity_iid ◀──┼────┼──▶ selected: event_iid       │
│                               │    │                               │
└───────────────────────────────┘    └───────────────────────────────┘
                    ▲                        ▲
                    │                        │
                    └────────┬───────────────┘
                             │
                    ┌────────┴────────┐
                    │ Timeline Canvas │
                    └─────────────────┘
```

Every selection is a **single dispatch** to a central selection store (Context / Zustand). Each sibling subscribes and rerenders **only its affected slice**.

Update budget: 16 ms per selection (60 FPS). This is achievable because:
* Rail rerender is small (list of ~100 rows).
* Canvas mutates only the affected event's Konva node + owning lifeline.
* Right panel is DOM but simple (evidence dossier is ~15 lines of text).

---

## 14 · Process Grouping

Entities are grouped into **bands** for cognitive chunking.

**Analyst view (default, 2 bands):**
* `System` — SYSTEM · PROCESS · REGISTRY lanes
* `Files & Network` — FILE · NETWORK lanes

**Expert view (5 bands, toggle):**
* `SYSTEM` · `PROCESS` · `FILES` · `NETWORK` · `REGISTRY`

Bands render as stripe headers on the canvas, matched by identical stripes on the left rail. Sort within a band is by `first_seen` ascending; ties broken by label.

Groups collapse (all rows hide, band header remains, glyph count aggregates) — future feature; MVP shows all rows.

---

## 15 · Investigation Workflow

Canonical analyst path:

1. **Land on case** — Trajectory opens. Day scrubber shows event density peak.
2. **Click peak day** — day scrubber updates, hour scrubber renders that day's hours.
3. **Click active hour** — canvas auto-pans to that hour.
4. **Scan the swimlane** — spot red hex shields (malicious). Click one.
5. **Evidence panel opens** — read description, MITRE, command line, parent process.
6. **Follow parent** — click parent process in evidence panel → left rail highlights that entity, canvas pans to its lifeline.
7. **Repeat backward in time** — chain of `child ← parent ← grandparent`.
8. **Deep dive** — right-click entity → **Open Process Ancestry** → new tab with the ancestry graph (uses the same Canvas Engine).
9. **Generate report** — status-bar `REPORT` action → R4 deterministic report with all cited artifacts.

The workflow is **anchor and traverse** — analysts anchor on a suspicious event, then traverse causal relations. The UI must make traversal frictionless.

---

## 16 · Navigation Flow

Global navigation (outside the canvas):
* Header case dropdown → jump case.
* Nav bar → Workspace / Trajectory / Dashboard / …
* URL structure: `/v2/trajectory/:case_id` — deep-linkable.
* `?ev=<event_iid>` query param → auto-selects on load (share link).

Within the canvas:
* Left rail → click entity → row selection + pans canvas.
* Canvas → click event → event selection cascade (§7).
* Right panel → `parent` field → click → jumps to parent entity.
* Right panel → `mitre` chips → filter chip toggles on filter row.
* Right panel → `related events` list → click → traversal.

`Escape` clears selection everywhere. `Backspace` on canvas walks selection history.

---

## 17 · Keyboard Shortcuts

| Key           | Action                                     |
|---------------|--------------------------------------------|
| `/`           | Focus search                               |
| `f`           | Fit content                                |
| `+` `-`       | Zoom in / out                              |
| `1`..`5`      | Zoom presets (Fit, 1h, 24h, 7d, 30d)       |
| `arrow keys`  | Pan by 80 px                               |
| `j` / `k`     | Next / previous event chronologically      |
| `n` / `p`     | Next / previous **selected-entity** event  |
| `Space`       | Play/pause chronological playback          |
| `Enter`       | Open selected event in evidence panel      |
| `Escape`      | Clear selection                            |
| `Backspace`   | Undo selection                             |
| `Ctrl/Cmd+F`  | Search box                                 |
| `Ctrl/Cmd+G`  | Toggle expert-view grouping                |
| `Shift+drag`  | Marquee select                             |
| `Shift+click` | Add to selection                           |
| `?`           | Show shortcut cheat-sheet                  |

---

## 18 · Performance Considerations

Enterprise targets:
* **100 000 events** loaded, **10 000 entities**, **1 000 relations**, held in memory.
* **60 FPS** during pan / zoom / selection.
* **< 200 ms** to first meaningful paint on cold navigation.
* **< 16 ms** selection response.
* **< 5 MB** JS heap growth per case load.

Achieved via:
* Konva canvas rendering (not divs).
* Viewport virtualization (only draw entities + events inside `viewport ± margin`).
* Cluster events at low zoom (single glyph per cluster).
* React memoization at layer boundaries (`React.memo`, `useMemo`, stable references).
* Off-thread computation of derived indices (Web Worker if bottlenecked; MVP skips).
* Streaming ingest (page 200 events at a time from the API; backfill background).

---

## 19 · Rendering Strategy

Layered Konva stages:

```
Stage
├── Layer · gridBg          (static; redraw on zoom only)
├── Layer · bandStripes     (static per rows-set)
├── Layer · lifelines       (draw only visible rows)
├── Layer · relations       (draw only edges intersecting viewport)
├── Layer · events          (virtualized; individual events)
├── Layer · overlays        (selection glow, hover halo)
└── Layer · interactive     (empty capture layer for pan/marquee)
```

Layers redraw independently. Static layers cache to bitmap after first paint. Interactive layer captures pointer events and dispatches to the app.

Minimap = a second, small `Stage` reading the same `entities`/`events` at 8% scale, with an overlay rectangle representing the main viewport.

Scrubbers are **not** on Konva — they're plain SVG since they're small and static-ish. Sync with canvas via shared time-window store.

---

## 20 · Accessibility Considerations

* **Keyboard-first** — every interaction reachable without mouse (§17).
* **Focus ring** — the canvas has one focusable outer container. Inside, we render a hidden focusable listbox mirror of the entity list, so screen readers can traverse. Events are announced via `aria-live` on selection change.
* **Contrast** — verdict colors AA-compliant against canvas bg. Red / amber / green never encode meaning alone; also carry a symbol.
* **Motion** — respect `prefers-reduced-motion`: disable tween, snap on auto-scroll.
* **Zoom** — CSS `zoom` and `text-size-adjust` do not break canvas math (we compute in raw px).
* **Language** — right-to-left support (future); MVP LTR.
* **Screen reader** — an accompanying `<table>` mirror of visible events (`sr-only`) so JAWS/NVDA users can inspect.

---

## 21 · Approval Gate

**Nothing gets implemented until sections 1-20 are signed off.** Once approved, this document is the specification for the Investigation Canvas Engine (see `CANVAS_ENGINE_ARCHITECTURE.md`).

Open questions to resolve before implementation:
- Q1: Marquee multi-select in MVP or v2?
- Q2: Cluster-glyph threshold — `pxPerHour < 30`, or tunable per-user?
- Q3: Chronological playback (`Space` bar) — must-have or backlog?
- Q4: Ancestry graph — reuse the canvas engine or ship a dedicated graph view?
- Q5: Real-time streaming (case being ingested LIVE) — MVP or v2?
