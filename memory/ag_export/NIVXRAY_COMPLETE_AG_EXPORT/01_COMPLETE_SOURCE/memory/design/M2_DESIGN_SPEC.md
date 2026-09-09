# M2 · Device Trajectory · Design Specification
_Cisco Device Trajectory investigation methodology, reverse engineered — NivXRay identity retained._

This spec is normative for the redesign. No implementation may deviate. If an engineering decision would violate this spec, escalate for a spec change first.

---

## 0 · Product principle
> **The canvas is the story. The right panel is the evidence.**
> If the analyst has to open the right panel to know where the attack started, the canvas has failed.

Every design choice below serves that principle.

---

## 1 · Investigation workflow (how DFIR analysts actually work)

1. **Land** — open a case. First glance answers: is this dead-quiet or on fire?
2. **Orient** — find the loudest lifeline (most red events, most children). That is patient zero.
3. **Descend** — walk the ancestry down: parent → children → grandchildren. Read the story top-to-bottom.
4. **Cross-cut** — pick a suspicious moment, drop a playhead, see everything happening across all lifelines at that instant.
5. **Attribute** — click one event. Right panel loads full evidence (command line, SHA256, MITRE, disposition).
6. **Widen** — filter to one activity type (network / file / registry) to see the *shape* of that activity.
7. **Freeze** — snapshot the case. Move on.

Steps 1–4 must be possible **without ever opening the right panel**. Steps 5–7 use the right panel.

---

## 2 · Information hierarchy (what the eye must find, in this order)

| Priority | Visual asset | Rendering rule |
|:---:|---|---|
| 1 | **Malicious events** | Red 6-px filled dot, subtle red halo, only visible red on the canvas |
| 2 | **Root process** (first execution) | Left-anchored top row, name in bolder weight |
| 3 | **Long-lived lifelines** | Continuous 1-px line spanning many events → visually longer than short ones |
| 4 | **Ancestry connectors** | 1-px L-line from parent lifeline to child, at spawn timestamp |
| 5 | **Entity labels** | Small 11-px sans in sticky left gutter |
| 6 | **Event symbols** | 4-px monochrome glyphs, coloured only if malicious |
| 7 | **Time axis / grid** | Muted 10-px monospace, hair-thin lines |
| 8 | **Band separators** | Barely visible 0.5-px rule with tiny uppercase label |

Anything not on this list must render at ≤ 40 % opacity.

---

## 3 · Entity hierarchy

```
Device (case root)
└── Process (Executable IID)
    ├── Child Process
    │   └── Grandchild Process
    ├── File (created / modified / deleted by this process)
    ├── Registry key (touched by this process)
    └── Network conn (opened by this process)
```

Rules:
- Rows are grouped by **owning process**, not by lane.
- File/Registry/Network events are children of the process that touched them, rendered as *inline event glyphs on that process's lifeline*, not as separate rows.
- Only **processes** get their own row.
- A row exists per unique `process.iid`. If ancestry data is missing, all processes render as siblings under a synthetic `<unknown parent>` root row.

This is the biggest departure from the current implementation. Today we make a row for every entity kind. Cisco makes a row only for **processes**, and hangs everything else off the owning process. That is what makes the canvas readable.

---

## 4 · Timeline model

- The canvas has a **single time axis** at the top. No day scrubber, no hour scrubber, no scrubber-of-scrubbers.
- **Adaptive units**: when total span < 10 s, axis reads `T+0.0s T+0.5s T+1.0s`. When span < 10 min, `HH:MM:SS`. When < 24 h, `HH:MM`. Otherwise `MMM-DD`.
- **Density curve** overlays the axis as a 24-px-tall sparkline showing events-per-tick. This replaces both the day scrubber and hour scrubber.
- **Playhead** = a full-height 1-px vertical line rendered at the selected event's timestamp. Rendered on top of everything, subtle blue.
- **Zoom** is **horizontal-only**. Rows never change height when zooming time. This preserves reading pace.
- **Pan**: click-drag on empty canvas. Middle-mouse also pans. Space+drag also pans. No modifiers required for the most common action.

---

## 5 · Interaction model

### 5.1 Row hover
- Row background lifts to `#F1F5F9`.
- Row lifeline thickens from 1 → 1.5 px.
- The entity gutter label bolds.

### 5.2 Event hover
- Event symbol scales 1 → 1.4× over 120 ms.
- Tooltip appears at cursor after 300 ms delay (no delay if already hovering an adjacent event).
- Tooltip content: verdict pill · kind · label · UTC timestamp · MITRE chips.

### 5.3 Event selection (click)
- Event gets a 1.5 px selection ring.
- **Playhead line** drops at that timestamp, full canvas height.
- All events on all rows at the same timestamp (± 100 ms tolerance) get a subtle blue outline — *co-occurring events*.
- Entity gutter label of the owning row highlights.
- Right panel opens to the Evidence tab, populated.

### 5.4 Row selection (click on gutter label)
- Owning entity's lifeline is highlighted.
- All ancestors up to root and all descendants get a subtle blue tint (ancestry chain visible).
- Right panel opens to the Entity tab.

### 5.5 Traversal (keyboard)
- `↑` / `↓` — walk to prev / next event in time order.
- `←` / `→` — pan the timeline.
- `Enter` — focus selected event and open evidence.
- `F` — fit to content.
- `+` / `−` — zoom time.
- `H` — jump to parent (up the ancestry tree).
- `L` — jump to first child.
- `Esc` — deselect.

### 5.6 Filtering
Filters *collapse* filtered-out rows. If a row has 0 events left after filtering, the row is hidden entirely. Density is preserved. Filter chips: `Create · Execute · Move · Delete · Network · Registry · Detect · Compromise` (activity) and `Benign · Suspicious · Malicious` (disposition).

---

## 6 · Layout specification

```
┌────────────────────────────────────────────────────────────────────┐
│  HEADER · 36 px                                                    │  <- one row: logo · case picker · search · zoom · fit
├────────────────────────────────────────────────────────────────────┤
│  TIME AXIS + DENSITY · 40 px                                       │  <- axis with sparkline overlay
├───────────────┬─────────────────────────────────────────┬──────────┤
│ ENTITY GUTTER │           CANVAS                        │  RIGHT   │
│  (sticky-X)   │       (thin lifelines,                  │  PANEL   │
│    180 px     │        events on lines,                 │  360 px  │
│               │        ancestry connectors,             │          │
│  process      │        playhead,                        │  tabs:   │
│  names,       │        band separators)                 │  Evidence│
│  indented     │                                         │  Entity  │
│  by ancestry  │                                         │  MITRE   │
│               │                                         │  History │
├───────────────┴─────────────────────────────────────────┴──────────┤
│  STATUS · 22 px                                                    │  <- counts · zoom % · time range
└────────────────────────────────────────────────────────────────────┘
```

Absolute pixel values are firm.

**No day scrubber. No hour scrubber. No filter row.** Filters live as a slide-out drawer opened by pressing `\`, and as compact chips in the header.

---

## 7 · Visual hierarchy (contrast budget)

To keep the canvas readable, the design budgets contrast rigorously:

| Element | Colour | Weight | Contrast vs bg |
|---|---|---|---|
| Page background | `#FAFBFD` | — | baseline |
| Row background (hover) | `#F1F5F9` | — | 1.05 : 1 |
| Row lifeline (idle) | `#94A3B8` | 1 px | 3.2 : 1 |
| Row lifeline (selected) | `#0F172A` | 1.5 px | 12.6 : 1 |
| Event · benign | `#94A3B8` | 4 px dot | 3.2 : 1 |
| Event · suspicious | `#B7791F` | 4 px triangle | 5.4 : 1 |
| Event · malicious | `#DC2626` | 6 px dot + halo | 6.7 : 1 |
| Ancestry connector | `#CBD5E1` | 1 px | 2.0 : 1 |
| Playhead | `#2563EB` @ 60% | 1 px | 4.1 : 1 |
| Time axis label | `#64748B` | 10 px mono | 5.0 : 1 |
| Entity gutter label | `#0F172A` | 11 px sans | 12.6 : 1 |
| Band separator | `#E2E8F0` | 0.5 px | 1.2 : 1 |

**Only red is allowed to draw the eye.** Amber is used for suspicious but at 5.4:1 contrast, below red's 6.7:1 by design. Blue is reserved for playhead and selection. Nothing else uses colour.

---

## 8 · What we are NOT copying from Cisco
- Their brand name, wordmark, or logo.
- Their exact hex values.
- Their icon set (we use LucideReact / custom SVG).
- Their font stack (we use Inter + IBM Plex Mono).
- Their specific menu labels or copy.

## 9 · What we ARE copying from Cisco (methodology only)
- The thin-lifeline abstraction.
- The sticky entity gutter.
- The DFS-ancestry row order.
- The event-on-lifeline attachment rule.
- The playhead behaviour on selection.
- Filter-collapses-rows behaviour.
- Compact typography and 18-px row height.
- Contrast budget that reserves red for malicious.

---

## 10 · Acceptance criteria for M2 (must all be true)

1. First glance on a real 500-event case: the analyst can point at the malicious lifeline within 3 seconds.
2. Second glance: the analyst can name the root process without opening the right panel.
3. Ancestry: parent → child → grandchild is legible from indentation and L-connectors alone.
4. Density: at least 30 rows visible in a 900-px viewport without scrolling.
5. Selection: clicking a malicious event drops a playhead and highlights every co-occurring event across all rows.
6. Filter: selecting "Network only" collapses to a 5-row dense view with zero empty rows.
7. Missing ancestry: the empty-state banner tells the analyst that parent data is unavailable, and offers a "sort by time only" fallback.
8. Zoom: horizontal-only. Row height never changes on zoom.

If any of these are false at review, M2 has not shipped.
