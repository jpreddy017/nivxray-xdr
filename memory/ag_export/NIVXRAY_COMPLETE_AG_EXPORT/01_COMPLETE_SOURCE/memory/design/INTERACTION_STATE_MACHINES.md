# NivXRay · Interaction State Machines
_Normative specification for every entity / event / relation / canvas interaction state. The Investigation Canvas Engine MUST honor every transition and every visual rule defined here. If a future view wants to add a new state, it extends this document — it does not redefine states locally._

**Status**: Specification. Companion to `CANVAS_ENGINE_ARCHITECTURE.md`.
**Scope**: Every visual/behavioral state a canvas object (entity, event, relation) or the canvas itself can be in, plus every transition between them.

---

## 0 · Style conventions

Each state row defines nine columns. Any implementation that omits or reinterprets a column is out of spec.

| Column | Meaning |
|---|---|
| **Cursor**             | The pointer glyph when the mouse is over an object in this state |
| **Glow**               | `shadowColor` × `shadowBlur` × `shadowOpacity` on the Konva node |
| **Border / Stroke**    | Stroke color + width for the primary shape |
| **Opacity**            | Whole-node opacity (0..1) |
| **Related highlight**  | What other entities / relations / events do when THIS one enters the state |
| **Right panel sync**   | What the right-side panel does when THIS is the active state |
| **Keyboard behavior**  | Keys that transition OUT of this state |
| **Animation timing**   | Duration + easing for the transition INTO this state |
| **Accessibility**      | `aria-*` attributes / `role` / screen reader announcement |

All colors reference `tokens.*` (`token.link`, `token.critical`, etc.) — no hardcoded hex. Timing defaults are overridable via `props.animationDurations`.

---

## 1 · Entity States

### 1.1 · Idle
Default state for every entity when the canvas loads.

| Field | Value |
|---|---|
| Cursor              | `default` |
| Glow                | none |
| Border / Stroke     | `token.lifelineDim`, 0.8 px, `dash [2, 3]` |
| Opacity             | `0.42` |
| Related highlight   | none |
| Right panel sync    | none |
| Keyboard behavior   | hover keys transition to §1.2 |
| Animation timing    | on load: 200 ms fade-in, `ease-out` |
| Accessibility       | `role="listitem"` inside rail's `role="listbox"` |

### 1.2 · Hover
Mouse pointer is over the entity row (rail) or lifeline (canvas). Preview only.

| Field | Value |
|---|---|
| Cursor              | `pointer` |
| Glow                | none |
| Border / Stroke     | `token.lifeline`, 1 px, `dash [2, 3]` |
| Opacity             | `0.7` |
| Related highlight   | Left rail row background lightens to `token.hover`. A thin brightening rectangle spans the canvas width across the lifeline's row. |
| Right panel sync    | none |
| Keyboard behavior   | leaving hover returns to §1.1 unless focused |
| Animation timing    | 150 ms, `ease-out` |
| Accessibility       | `aria-describedby` points to tooltip node after 250 ms delay |

### 1.3 · Focus
Keyboard focus lands on the entity. Distinct from hover so keyboard users get a visible ring.

| Field | Value |
|---|---|
| Cursor              | inherited |
| Glow                | none |
| Border / Stroke     | 2 px outline in `token.link` around the rail row; `dash [2, 3]` unchanged on the canvas lifeline |
| Opacity             | `0.85` |
| Related highlight   | canvas viewport auto-scrolls if the lifeline is off-screen (gentle) |
| Right panel sync    | none — focus does not select |
| Keyboard behavior   | `Enter` → §1.4 · Selected · `ArrowDown` / `ArrowUp` shift focus to sibling entity |
| Animation timing    | 100 ms, `ease-out` |
| Accessibility       | `:focus-visible`, `aria-current="true"` on the rail row |

### 1.4 · Selected
The primary selected entity. Every canvas state cascades from here.

| Field | Value |
|---|---|
| Cursor              | `pointer` |
| Glow                | `token.selectGlow`, blur 8, opacity 0.9 |
| Border / Stroke     | `token.lifeline` on canvas lifeline, 1.4 px, `dash [2, 3]` |
| Opacity             | `0.95` |
| Related highlight   | Every entity in the ancestry chain (parents up to root + immediate spawn children) → §1.6 · Emphasized. Every OTHER entity → §1.7 · Dimmed. Every Relation with either endpoint on this entity → §3.2 · Highlighted. |
| Right panel sync    | Right panel switches to **Overview** tab showing entity's aggregate view (all its events + verdict counts + related entities) |
| Keyboard behavior   | `Escape` → §1.1 · `Shift+Click` on another entity → §1.5 · `Enter` on evidence panel row → selects that event (§2.4) |
| Animation timing    | 220 ms, `ease-in-out` |
| Accessibility       | `aria-selected="true"` on rail row; SR announces `"{label} selected, {N} events, verdict {V}"` |

### 1.5 · Pinned (multi-select)
User has Shift-clicked or marquee-selected multiple entities. State applies to each pinned entity.

| Field | Value |
|---|---|
| Cursor              | `pointer` |
| Glow                | `token.link`, blur 5, opacity 0.7 |
| Border / Stroke     | `token.link`, 1.2 px, `dash [2, 3]` |
| Opacity             | `0.9` |
| Related highlight   | Union of ancestry chains for every pinned entity → §1.6. Non-pinned & non-related → §1.7. |
| Right panel sync    | Right panel enters **Compare** mode: renders an aggregate matrix `entity × event-kind × count` |
| Keyboard behavior   | `Escape` → clear all · `Shift+Click` on a pinned entity → unpins · `Enter` → open the highest-verdict event across pinned set |
| Animation timing    | 180 ms, `ease-in-out` |
| Accessibility       | `aria-multiselectable="true"` on the listbox; each pinned row `aria-selected="true"` |

### 1.6 · Emphasized (related to selection)
An entity NOT primarily selected but part of the ancestry / relation chain of the currently selected entity.

| Field | Value |
|---|---|
| Cursor              | `pointer` |
| Glow                | none |
| Border / Stroke     | `token.lifeline` at `0.8` opacity, 1 px |
| Opacity             | `0.85` |
| Related highlight   | n/a (self-derived) |
| Right panel sync    | none |
| Keyboard behavior   | acts as Idle on its own |
| Animation timing    | 180 ms cross-fade from Idle |
| Accessibility       | `data-related="true"` on rail row |

### 1.7 · Dimmed (unrelated to selection)
Every entity that is neither selected nor in the emphasized set.

| Field | Value |
|---|---|
| Cursor              | `pointer` |
| Glow                | none |
| Border / Stroke     | `token.lifelineDim`, 0.6 px, `dash [2, 3]` |
| Opacity             | `0.25` |
| Related highlight   | n/a |
| Right panel sync    | none |
| Keyboard behavior   | still selectable — click transitions to §1.4 (breaks current selection) |
| Animation timing    | 180 ms cross-fade from Idle |
| Accessibility       | `aria-hidden="false"` (still discoverable) but visually recessive |

### 1.8 · Bookmarked
Entity has been explicitly bookmarked by the analyst for later reference. Persists across selection changes.

| Field | Value |
|---|---|
| Cursor              | `pointer` |
| Glow                | none |
| Border / Stroke     | left-rail gets a **1.5 px vertical bar** in `token.link` on the far left; the canvas lifeline is unchanged |
| Opacity             | inherits current state |
| Related highlight   | none |
| Right panel sync    | Bookmarked entities appear in a dedicated `Bookmarks` sub-tab of Overview |
| Keyboard behavior   | `b` toggles bookmark on the currently focused / selected entity |
| Animation timing    | 120 ms, `ease-out` |
| Accessibility       | `aria-label` suffix `", bookmarked"` |

### 1.9 · Compared (side-by-side)
Two entities placed into a compare drawer. Each compared entity gets this state simultaneously.

| Field | Value |
|---|---|
| Cursor              | `pointer` |
| Glow                | `token.link`, blur 4, opacity 0.6 |
| Border / Stroke     | `token.link`, 1.2 px |
| Opacity             | `0.9` |
| Related highlight   | Every entity that is a common ancestor or common child of BOTH compared entities → §1.6 |
| Right panel sync    | Right panel enters **Diff** view: matrix of shared vs unique event kinds |
| Keyboard behavior   | `Escape` exits compare · `c` while an entity is focused enters compare (max 2 concurrently) |
| Animation timing    | 200 ms, `ease-in-out` |
| Accessibility       | `data-compare-slot="A"` / `data-compare-slot="B"` |

### 1.10 · Killed / Terminated
Entity's lifetime has ended (child process exited, service stopped, file deleted). Visual marker on the lifeline itself.

| Field | Value |
|---|---|
| Cursor              | inherits |
| Glow                | none |
| Border / Stroke     | lifeline terminates in a small `×` marker at `last_seen` in the current stroke color |
| Opacity             | inherits |
| Related highlight   | none |
| Right panel sync    | Evidence panel `last_seen` field shows `terminated at {ts}` |
| Keyboard behavior   | n/a |
| Animation timing    | drawn on load; no transition |
| Accessibility       | `aria-label` suffix `", terminated"` |

---

## 2 · Event States

### 2.1 · Idle
Default state for every event.

| Field | Value |
|---|---|
| Cursor              | inherits (canvas cursor) |
| Glow                | none |
| Border / Stroke     | ring in verdict color (§token.textDim / warning / critical), 1.1 px |
| Opacity             | `1.0` |
| Related highlight   | none |
| Right panel sync    | none |
| Keyboard behavior   | `j`/`k` walk chronologically |
| Animation timing    | 120 ms fade-in on load |
| Accessibility       | announced by the sr-only `<table>` mirror row |

### 2.2 · Hover
Mouse pointer over the event glyph.

| Field | Value |
|---|---|
| Cursor              | `pointer` |
| Glow                | none |
| Border / Stroke     | ring unchanged; **scale 1.3** applied to the whole group |
| Opacity             | `1.0` |
| Related highlight   | tooltip appears above pointer after 250 ms containing `ts + label + verdict + kind` |
| Right panel sync    | none |
| Keyboard behavior   | none |
| Animation timing    | 150 ms scale-up, `ease-out` |
| Accessibility       | `aria-describedby` set to tooltip once shown |

### 2.3 · Focus
Keyboard focus is on an event.

| Field | Value |
|---|---|
| Cursor              | inherits |
| Glow                | outline ring in `token.link`, 1 px, outside the event |
| Border / Stroke     | ring unchanged |
| Opacity             | `1.0` |
| Related highlight   | canvas viewport gently scrolls if off-screen |
| Right panel sync    | none (focus ≠ selection) |
| Keyboard behavior   | `Enter` → §2.4 · `Escape` → §2.1 |
| Animation timing    | 100 ms, `ease-out` |
| Accessibility       | `:focus-visible`; SR announces label |

### 2.4 · Selected
The primary selected event. Canvas cascades into full "focus mode".

| Field | Value |
|---|---|
| Cursor              | `pointer` |
| Glow                | `token.selectGlow`, blur 10, opacity 0.9. Halo circle (20 px) at 0.15 opacity around the event. |
| Border / Stroke     | ring in `token.selectGlow`, 1.5 px, glyph scale 1.15 |
| Opacity             | `1.0` |
| Related highlight   | Owning entity → §1.4. Every event on the SAME lifeline → subtle brightening (0.9 opacity). All OTHER events → §2.6 · Dimmed. Every Relation whose endpoint is this event's entity → §3.2 · Highlighted. |
| Right panel sync    | Switches to **Evidence** tab showing the ordered dossier (spec §12 UX doc). Rail scrolls the owning entity into view. |
| Keyboard behavior   | `Escape` → §2.1 · `n`/`p` → next/previous event on the **same entity** · `j`/`k` → next/previous chronologically across all entities · `a` → open ancestry graph on owning entity |
| Animation timing    | 220 ms, `ease-in-out` |
| Accessibility       | `aria-selected="true"`; SR announces `"Event {label} at {ts}, verdict {V}, on {entity}"` |

### 2.5 · In Cluster
Event has been merged into a visual cluster because pxPerMs was below threshold. State applies to the cluster as a whole.

| Field | Value |
|---|---|
| Cursor              | `pointer` |
| Glow                | ring uses **worst verdict** of merged children |
| Border / Stroke     | ring 1.2 px + a small count badge overlay (e.g. `+12`) |
| Opacity             | `1.0` |
| Related highlight   | none |
| Right panel sync    | click transitions to §2.4 on the WORST-verdict child |
| Keyboard behavior   | `Enter` → zoom in to the timestamp of the cluster centre (§ canvas §Z) · `Shift+Enter` → open a cluster-explorer popover |
| Animation timing    | on cluster creation/dissolution: 150 ms cross-fade |
| Accessibility       | `role="button"`, `aria-label="Cluster of N events at {ts}"` |

### 2.6 · Dimmed (non-selected during a selection)
Every event that is not selected while a selection is active. Prevents visual noise.

| Field | Value |
|---|---|
| Cursor              | `pointer` |
| Glow                | none |
| Border / Stroke     | ring unchanged |
| Opacity             | `0.25` |
| Related highlight   | n/a |
| Right panel sync    | none |
| Keyboard behavior   | still clickable — click transitions to §2.4 (breaks current selection) |
| Animation timing    | 180 ms cross-fade |
| Accessibility       | `aria-hidden="false"` — still discoverable |

### 2.7 · Bookmarked
Analyst has bookmarked this event. Persists across selection changes.

| Field | Value |
|---|---|
| Cursor              | `pointer` |
| Glow                | small `token.link` dot indicator on top-right of the glyph |
| Border / Stroke     | ring unchanged |
| Opacity             | inherits |
| Related highlight   | none |
| Right panel sync    | Appears in `Bookmarks` sub-tab of Overview |
| Keyboard behavior   | `b` toggles |
| Animation timing    | 120 ms pop-in, `ease-out` |
| Accessibility       | `aria-label` suffix `", bookmarked"` |

### 2.8 · Blocked / Prevented
Event was blocked by the endpoint (e.g. exploit prevention). Distinct verdict, distinct glyph decoration.

| Field | Value |
|---|---|
| Cursor              | `pointer` |
| Glow                | none |
| Border / Stroke     | ring in `token.success`, 1.2 px + inner shield glyph |
| Opacity             | `1.0` |
| Related highlight   | none |
| Right panel sync    | evidence shows `verdict: blocked`, `blocked_by: {rule_id}` |
| Keyboard behavior   | acts as Idle on its own |
| Animation timing    | 120 ms fade-in |
| Accessibility       | `aria-label` includes `", blocked"` |

---

## 3 · Relation States

### 3.1 · Idle
Default state for every relation edge between entities.

| Field | Value |
|---|---|
| Cursor              | inherits |
| Glow                | none |
| Border / Stroke     | `token.border`, 0.8 px, `dash [3, 3]` |
| Opacity             | `0.6` |
| Related highlight   | none |
| Right panel sync    | none |
| Keyboard behavior   | not directly focusable in MVP |
| Animation timing    | drawn on load; no per-item transition |
| Accessibility       | not in reading order |

### 3.2 · Highlighted (related to selection)
A relation whose `from` or `to` matches the currently selected entity / event's entity.

| Field | Value |
|---|---|
| Cursor              | inherits |
| Glow                | `token.selectGlow`, blur 4, opacity 0.5 |
| Border / Stroke     | `token.selectGlow`, 1.2 px, `dash [3, 3]` |
| Opacity             | `0.95` |
| Related highlight   | n/a |
| Right panel sync    | none |
| Keyboard behavior   | n/a |
| Animation timing    | 200 ms brighten, `ease-out` |
| Accessibility       | n/a |

### 3.3 · Dimmed
Every relation edge NOT connected to the current selection.

| Field | Value |
|---|---|
| Cursor              | inherits |
| Glow                | none |
| Border / Stroke     | `token.border`, 0.6 px, `dash [3, 3]` |
| Opacity             | `0.12` |
| Related highlight   | n/a |
| Right panel sync    | none |
| Keyboard behavior   | n/a |
| Animation timing    | 200 ms fade, `ease-out` |
| Accessibility       | n/a |

---

## 4 · Canvas Global States

### 4.1 · Idle
No interaction; passive display.

| Field | Value |
|---|---|
| Cursor              | `grab` on empty canvas |
| Behavior            | pan+zoom armed, no active drag |

### 4.2 · Panning
User is click-and-dragging empty canvas.

| Cursor | `grabbing` |
| Behavior | viewport `offset.{x,y}` follows pointer; momentum disabled |
| Transition out | pointer-up → §4.1 |
| Animation timing | none (direct mapping) |

### 4.3 · Zooming
User is scrolling with Ctrl/Cmd or pinching.

| Cursor | `zoom-in` / `zoom-out` (browser-provided) |
| Behavior | anchor-preserving scale change; layers redraw at end of gesture |
| Transition out | gesture end → §4.1 |
| Animation timing | 60 fps continuous |

### 4.4 · Marquee
User is Shift-dragging empty canvas.

| Cursor | `crosshair` |
| Behavior | dashed rectangle follows drag; on release, every event in rect enters §2.4 or §2.5 (multi) |
| Transition out | pointer-up |
| Animation timing | none |

### 4.5 · Auto-scrolling
Selection cascade triggered a gentle pan.

| Cursor | inherit |
| Behavior | tween from current `{x,y}` to target `{x,y}` — 300 ms `ease-in-out` unless `prefers-reduced-motion` |
| Transition out | tween end → §4.1 |
| Animation timing | 300 ms; 0 ms in reduced-motion mode |

### 4.6 · Playing (backlog, not MVP)
Chronological playback active.

| Cursor | inherit |
| Behavior | canvas auto-scrolls left→right at rate `playSpeed × pxPerMs`; each new event enters §2.2 then §2.1 |
| Transition out | `Space` toggles back to §4.1 |
| Animation timing | 60 fps advance |

---

## 5 · Transition Table (canonical)

Rows list every user gesture; columns are the entity/event before/after states. This is the source of truth for the state-machine tests in `core/selection.ts`.

| Gesture                              | Entity before → after                                    | Event before → after                  | Canvas |
|--------------------------------------|----------------------------------------------------------|---------------------------------------|--------|
| Idle load                            | (—) → §1.1                                               | (—) → §2.1                            | §4.1   |
| Mouse over entity                    | §1.1 → §1.2 (leave → §1.1)                               | —                                     | §4.1   |
| Mouse over event                     | —                                                        | §2.1 → §2.2                           | §4.1   |
| Tab focus on entity                  | §1.1 → §1.3                                              | —                                     | §4.1   |
| Click entity                         | §1.1|§1.3 → §1.4                                         | §2.1 → §2.6 (others)                  | §4.5   |
| Shift-click entity                   | §1.4 → §1.5 · new → §1.5                                 | others → §2.6                         | §4.1   |
| Click event                          | owning → §1.4 · others → §1.7                            | target → §2.4 · others → §2.6         | §4.5   |
| Shift-click event                    | owning stays; adds to multi                              | target → §2.4 with prior kept         | §4.1   |
| Escape                               | any → §1.1                                               | any → §2.1                            | §4.1   |
| Backspace                            | pops last selection off history                          | pops                                   | §4.5 if popped target off-screen |
| `b` on focused                       | toggles §1.8 / §2.7                                      | toggles                                | §4.1   |
| `c` on focused entity                | §1.4 → §1.9 (fills compare slot)                         | —                                     | §4.1   |
| `Enter` on focused event             | § event's entity → §1.4                                  | §2.3 → §2.4                            | §4.5   |
| `j` / `k`                            | may switch owning entity                                 | walk chronologically                   | §4.5 if off-screen |
| `n` / `p`                            | same entity                                              | walk within entity                     | §4.5 if off-screen |
| Ctrl+wheel                           | —                                                        | —                                      | §4.3   |
| Drag empty canvas                    | —                                                        | —                                      | §4.2   |
| Shift+drag empty canvas              | items inside rect → §1.5 / §2.4                          | items → §2.4                           | §4.4   |
| `f` key / FIT button                 | selection preserved                                       | selection preserved                    | §4.5 (or snap in reduced-motion) |
| `+` `-` keys                         | —                                                        | —                                      | §4.3   |
| Double-click event                   | owning → §1.4                                            | target → §2.4                          | §4.3 (zoom to 1.5×) |
| Double-click entity row              | target → §1.4                                            | —                                      | §4.3 (fit lifeline window) |
| Right-click                          | opens context menu                                        | opens context menu                     | §4.1   |
| `Ctrl+G`                             | expert-mode toggle → recomputes bands                     | positions preserved                    | §4.1   |
| `?`                                  | opens shortcut cheat-sheet overlay                        | —                                      | §4.1   |
| Filter chip changes                  | filtered-out entities → hidden (removed)                  | events for hidden entities → hidden    | selection preserved if still visible; else cleared |
| Search text                          | matching entities → §1.6 (Emphasized); non-matching → §1.7 | —                                    | selection preserved |

---

## 6 · Timing Reference

All animation durations are proposed defaults. Consumers may override via `props.animationDurations` on the canvas engine.

| Interaction                          | Default | Reduced motion |
|--------------------------------------|--------:|:--------------:|
| Hover in / out                       |  150 ms | 0              |
| Focus ring                           |  100 ms | 0              |
| Selection cascade (glow + dim)       |  220 ms | 0              |
| Auto-scroll on selection             |  300 ms | 0              |
| Zoom preset (FIT / 1H / …)           |  350 ms | 0              |
| Cluster expand / collapse            |  180 ms | 0              |
| Bookmark toggle                      |  120 ms | 0              |
| Tooltip appear delay                 |  250 ms | 0              |
| Marquee rectangle draw               | direct  | direct         |
| Panning                              | direct  | direct         |

---

## 7 · Compliance Checklist (must pass before Milestone 1 sign-off)

- [ ] Every entity state has visible visual differentiation from every other entity state (audit at 1×, 2×, and 0.3× zoom).
- [ ] Every event state has audible SR announcement.
- [ ] `Escape` reaches Idle from every state in ≤ 1 keypress.
- [ ] `prefers-reduced-motion` disables all timing rows in §6.
- [ ] State transitions in §5 have a matching unit test.
- [ ] Konva-level implementation of `token.selectGlow` uses a **cached shadow bitmap** (per `shadowCache.ts`) to keep 60 FPS during multi-selection.
- [ ] Focus order in the rail listbox is `first_seen` ascending within band; `Tab` never traps.
- [ ] No state uses hardcoded color values. Every color reads from `tokens.*`.
- [ ] Every state's `Related highlight` behavior is symmetric: pinning A + B produces the same visual regardless of order.

Failure of any checklist item blocks Milestone 1.
