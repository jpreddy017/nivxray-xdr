# NivXRay · Device Trajectory · Gap Analysis
_Honest comparison of the current NivXRay implementation vs the target investigation experience defined in `UX_REVERSE_ENGINEERING.md`._

**Verdict (headline)**: We are **~15–25% of the target**. The chrome (header, filters, scrubbers, rail, right panel, status footer) exists and is close. The **investigation canvas itself is fundamentally wrong** — it renders events, not entities, and lacks the interaction model that makes Cisco Secure Endpoint feel like a professional workspace.

Categories: **A** = Missing feature · **B** = Wrong interaction · **C** = Layout diff · **D** = Workflow diff · **E** = Missing investigation capability.

---

## A · Missing Features

| # | Feature (target) | Current NivXRay | Impact |
|---|---|---|---|
| A1 | **Entity model** — canvas draws entities, events attach to entity lifelines | Draws events directly; no first-class entity object | 🔴 CRITICAL — everything else derives from this |
| A2 | **Event clustering at low zoom** (single glyph + counter when density is high) | Draws every event individually; overlaps become unreadable | 🔴 CRITICAL |
| A3 | **Related-entity dimming** on selection (unrelated lifelines fade to 0.25) | No dim/emphasis cascade | 🟠 HIGH |
| A4 | **Relationship edges** parent-→-child rendered as first-class visual objects | Approximate spawn arcs on the old page; new engine hides them | 🟠 HIGH |
| A5 | **Marquee multi-select** (Shift-drag rectangle) | Single-select only | 🟡 MEDIUM |
| A6 | **Chronological playback** (Space bar walks events forward in time) | Absent | 🟡 MEDIUM |
| A7 | **`?ev=<iid>` deep link** to a specific event | URL is case-only | 🟠 HIGH |
| A8 | **Undo selection history** (`Backspace` walks back) | Absent | 🟡 MEDIUM |
| A9 | **Zoom presets `1H / 24H / 7D / 30D`** actually restrict the time window | Buttons render as visual pills only | 🟠 HIGH |
| A10 | **Cluster tooltip after 250 ms hover** with `ts + label + verdict` | No hover tooltip | 🟡 MEDIUM |
| A11 | **Cheat-sheet overlay** (`?` shortcut) | Absent | 🟢 LOW |
| A12 | **Reduce-motion respect** — snap instead of tween | Ignored | 🟢 LOW |
| A13 | **Screen-reader `<table>` mirror** for a11y | Absent | 🟠 HIGH (compliance) |
| A14 | **Focus ring** on canvas outer container | Absent | 🟠 HIGH (a11y) |
| A15 | **Aggregate evidence view** when multi-selected | N/A | 🟢 LOW |
| A16 | **Streaming ingest** (canvas grows as data arrives) | Snapshot-only fetch | 🟡 MEDIUM |

---

## B · Wrong Interactions

| # | Behavior (target) | Current NivXRay | Impact |
|---|---|---|---|
| B1 | **Pan is momentum-free** — canvas stops on release | Konva default has slight inertia (correct-ish) | 🟢 LOW |
| B2 | **Wheel routing** — bare = vertical, Shift = horizontal, Ctrl/Cmd = zoom | Engine honours Shift/Cmd correctly; bare wheel currently zoom-vertical scroll is right | 🟢 LOW (verify) |
| B3 | **Anchor-preserving zoom** (point under cursor stays under cursor) | Engine implements this correctly ✅ | 🟢 OK |
| B4 | **Selection cascade** — event → entity → related → dim others | Only event glow is implemented; no related highlighting, no dimming | 🔴 CRITICAL |
| B5 | **Gentle auto-scroll** — pan only if off-screen | Engine implements this ✅ | 🟢 OK |
| B6 | **Right panel Evidence auto-opens** on event click | Engine wires this ✅ | 🟢 OK |
| B7 | **Double-click event → 1.5× zoom anchored** | Absent | 🟡 MEDIUM |
| B8 | **Double-click entity row → zoom to lifeline window** | Absent | 🟠 HIGH |
| B9 | **Hover on rail row → brightening rectangle across the canvas** to trace | Absent | 🟠 HIGH — critical for eye-tracking a lifeline across the width |
| B10 | **`j / k / n / p` chronological walk shortcuts** | Absent | 🟡 MEDIUM |
| B11 | **Rail row scrolls into view when selected via canvas** | Absent | 🟠 HIGH |
| B12 | **Shift-click adds to selection** | Absent (single-select MVP) | 🟢 LOW (v2) |
| B13 | **Marquee select on empty canvas** | Absent | 🟡 MEDIUM |
| B14 | **Escape clears selection everywhere** | Partial (canvas only) | 🟡 MEDIUM |
| B15 | **Minimap click jumps viewport** | Implemented ✅ | 🟢 OK |
| B16 | **Minimap drag repositions viewport live** | Click-only, no drag | 🟡 MEDIUM |
| B17 | **Trackpad two-finger pinch = zoom** | Depends on browser; not explicitly wired | 🟡 MEDIUM |
| B18 | **Marquee & Pan mode on same drag** — Shift toggles marquee | N/A | 🟡 MEDIUM |
| B19 | **Right-click entity → context menu** (Open Ancestry, Copy IID, Filter to Row) | Absent | 🟠 HIGH |

---

## C · Layout Differences

| # | Spec target | Current NivXRay | Impact |
|---|---|---|---|
| C1 | Header ≈ 6% viewport height | ~40 px on 900 px viewport = 4.4% | 🟢 close |
| C2 | Filter row ≈ 6% | 36 px = 4% | 🟢 close |
| C3 | Day scrubber ≈ 8% | 64 px = 7% | 🟢 close |
| C4 | Hour scrubber ≈ 8% | 44 px = 4.9% | 🟡 short |
| C5 | Canvas ≥ 55% | Currently ~55% ✅ | 🟢 OK |
| C6 | Status footer ≈ 4% | 24 px = 2.7% | 🟢 close |
| C7 | Left rail — narrow, no wasted horizontal space | 168 px ✅ | 🟢 OK |
| C8 | Right panel ~ 18% width (`300 px` at 1600 px viewport) | 288 px ✅ | 🟢 OK |
| C9 | Right panel tabs order: **Activity, Evidence, Overview, MITRE, Reference** | Engine implements ✅ | 🟢 OK |
| C10 | Activity is default; Evidence auto-selects on event click | ✅ | 🟢 OK |
| C11 | Scrubbers span from below filter row to canvas top with no gap | ✅ | 🟢 OK |
| C12 | Band stripes appear both on rail AND in the canvas at identical heights | Rail has them; canvas engine has them ✅ | 🟢 OK |
| C13 | Selected day gets a WHITE-bordered ring on the day scrubber | ✅ | 🟢 OK |
| C14 | Selected hour gets a WHITE vertical line on the hour scrubber | ✅ | 🟢 OK |
| C15 | Hatched pattern on hours with no data | ✅ | 🟢 OK |
| C16 | Blue density curve on day scrubber | ✅ | 🟢 OK |
| C17 | Red critical dots on day scrubber (malicious event days) | ✅ | 🟢 OK |
| C18 | Grid disappears near-fully at low zoom | Engine draws faint 48 px stripes, correct behaviour but needs opacity ramp | 🟢 close |

Layout is the **strongest area of the surrounding chrome** — but this only measures header, filters, scrubbers, rail, right-panel tabs, and footer *dimensions*. It does **not** signal that the investigation workspace itself is close. See the "Honest Rollup" section below.

---

## D · Workflow Differences

| # | Target workflow step | Current NivXRay | Impact |
|---|---|---|---|
| D1 | Land on case → **canvas auto-fits** and centres on the event-density peak | Canvas fits but does not centre on density peak | 🟠 HIGH |
| D2 | Click day scrubber peak → **updates hour scrubber to that day** | Day scrubber is display-only currently | 🔴 CRITICAL |
| D3 | Click hour cell → **canvas pans to that hour** | Hour scrubber display-only | 🔴 CRITICAL |
| D4 | Click malicious hex on canvas → evidence panel opens, parent chain visible in `parent` field of evidence | Evidence opens with parent field ✅ | 🟢 OK |
| D5 | Click **parent** in evidence → jumps to parent entity + selects its most-recent event | No handler on the parent link | 🔴 CRITICAL |
| D6 | Right-click entity row → context menu with `Open Process Ancestry` | Absent | 🟠 HIGH |
| D7 | Bottom status → `REPORT` action → opens R4 report modal | Report button exists in header of old page; new page hasn't wired it | 🟠 HIGH |
| D8 | MITRE chip click in evidence → filters canvas to matching events | Filters exist but only via dropdown, not evidence-chip triggered | 🟡 MEDIUM |
| D9 | Backwards traversal (child ← parent ← grandparent) is one-click | Requires guessing IIDs | 🔴 CRITICAL |
| D10 | Share link: `URL?ev=<iid>` opens the workspace with that event pre-selected | Not wired | 🟠 HIGH |
| D11 | Filter changes preserve selection | Selection may lose visual highlight when filtered out | 🟡 MEDIUM |
| D12 | Empty case shows a helpful zero-state, not an unlabelled empty grid | Engine shows "No investigation data" ✅ | 🟢 OK |
| D13 | Loading state: skeleton for the scrubbers + canvas | Currently blank flash | 🟡 MEDIUM |
| D14 | Error state: banner across the top, retry button | Simple red banner exists ✅ | 🟢 OK (minimal) |

---

## E · Missing Investigation Capabilities

| # | Capability | Status |
|---|---|---|
| E1 | **Multi-entity selection**: pick 3 processes → canvas dims everything else → evidence shows aggregate | Absent |
| E2 | **Time-window brush**: drag a range on the hour scrubber → canvas restricts | Absent (scrubbers are inert) |
| E3 | **Follow parent-chain automatically**: chevron `⤴` button → walks up ancestry until root | Absent |
| E4 | **Diff view**: compare 2 cases side-by-side | Absent |
| E5 | **Playback / scrub**: press Space, canvas plays events forward at 5× | Absent |
| E6 | **Bookmark events** during investigation, generate a report of just bookmarks | Absent |
| E7 | **Annotate**: attach an analyst note to an entity or event (`Ctrl+/`) | Absent |
| E8 | **Search-jump**: typing into the search box highlights matching entities on the canvas | Filter narrows the set but does not highlight; jump-to is absent |
| E9 | **Export selection as .csv / .json** for external tools | Absent |
| E10 | **Filter by MITRE tactic** (not just technique) — group T1078 + T1136 under Privilege Escalation | Absent |
| E11 | **NIST IR phase overlay** on the day scrubber (colored bands for Preparation / Detection / Containment / …) | Absent (depends on R3 Enrichment Kit) |
| E12 | **Show blocked / prevented events** distinctly from malicious | Absent |
| E13 | **Case sidebar drawer**: recent cases, saved views, pinned entities | Absent |
| E14 | **Live case streaming**: watch a case as it's being ingested | Absent |
| E15 | **Time-of-day heatmap** overlay on the hour scrubber | Absent |
| E16 | **Signal-to-noise slider**: minimum-confidence filter (0.0 → 1.0) | Absent |
| E17 | **Rule-provenance popover**: hover a glyph → shows the RC5 rule that fired | Absent |
| E18 | **Artifact-cited evidence**: evidence panel lists `artifact_iid`s with links (needs R2.1) | Partial — evidence panel has `Artifact` field but not linkified |

---

## Category Summary (rollup)

| Category | Items | Critical | High | Medium | Low |
|----------|------:|---------:|-----:|-------:|----:|
| A · Missing features             | 16 |  2 |  4 |  6 | 4 |
| B · Wrong interactions           | 19 |  1 |  6 |  9 | 3 |
| C · Layout differences           | 18 |  0 |  0 |  1 | 17 (mostly ✅) |
| D · Workflow differences         | 14 |  4 |  4 |  4 | 2 |
| E · Missing investigation caps   | 18 |  — |  — |  — | (all backlog) |
| **Total items**                  | 85 |  7 | 14 | 20 | 44 |

**Top-7 critical items (must-fix before we can honestly call this a Cisco-class experience):**
1. B4 — Selection cascade to related entities + dim others
2. D2 — Day scrubber clicks update hour scrubber
3. D3 — Hour scrubber clicks pan canvas
4. D5 — Evidence panel `parent` link triggers traversal
5. D9 — One-click backwards traversal chain
6. A1 — Rebuild data model around entities (events attach to lifelines)
7. A2 — Event clustering at low zoom

Everything else is meaningful but ships in the fast-follow milestones.

---

## Honest Rollup (revised per user feedback)

The **surrounding UI chrome** — header, search, filter row, day/hour scrubbers, left rail band structure, right-panel tab set, status footer — is **reasonably aligned** with the target. Structural gap in that ring is small.

The **investigation workspace itself** — the canvas, its data model, its selection cascade, its scrubber ↔ canvas interactivity, and the entire analyst traversal workflow — **still requires substantial redesign**. The category C table below is not a signal that "layout is close"; it only measures the *chrome dimensions*, not the workspace *behavior*.

In other words: the frame around the painting looks about right. The painting itself is still a sketch. Do not read column C as a proxy for readiness.

---

## Signals Suggesting a Rewrite (Rather Than Iteration)

* The canvas engine internal model is `Row + Event + Edge`, but the *right* model is `Entity + Event + Relation`. Renaming isn't enough; the semantics differ (see A1).
* Scrubbers are visually correct but functionally inert — they should be **the primary time-window controller**, not decorations.
* The selection store is per-page state. It should be a **canvas-engine-wide store** so future views (Ancestry, Attack Chain, Investigation Graph) participate in the same selection lifecycle.

Recommendation captured in `CANVAS_ENGINE_ARCHITECTURE.md`.
