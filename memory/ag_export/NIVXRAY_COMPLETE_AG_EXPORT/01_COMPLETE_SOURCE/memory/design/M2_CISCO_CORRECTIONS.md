# M2 · Cisco Reference Corrections
_Sources: Cisco Secure Endpoint User Guide (PDF, pp. 324–366) + Success Capsule video (2025-03-12, 9:27 min)._

This file overrides `M2_DESIGN_SPEC.md` and the first mockup batch wherever they conflict with the referenced Cisco material. If a spec statement is not corrected here, it stands.

## Verbatim quotes from Cisco (the axioms)
1. > "Device Trajectory shows activity on specific computers that have deployed the connector. It tracks file, network, and connector events, such as policy updates in chronological order."
2. > "Running processes are represented by a solid horizontal line and lines derived from this horizontal line, which mean that the process is secondary or that the file was started from the main process."
3. > "Yellow bands that represent a critical event or the hours during which more events may have occurred."
4. > "The top tape shows the last 30 days and the miniature line charts shown at the top indicates all the activity peaks. The red dots represent the occurrence of compromise events."
5. > "At the bottom, we see a line representing the 24 h of the selected day."
6. > "If we see a plus, it is a creation activity, we see copied, moved, executed etc. We also see in green if the event has a benign disposition. Or in red, if it is malignant."
7. > "Clicking on the compromise event will also highlight the individual events that triggered it with a blue halo."

Each numbered axiom below points back to one of these quotes.

---

## Corrections to `M2_DESIGN_SPEC.md`

### C-1 · Two-level time navigator (replaces Section 4)
The top of the workspace holds **two synchronized strips**, not one adaptive axis:

- **Top strip · 30-day density.** ~32 px tall. Each day is a column. Column height = event count sparkline. **Red dots** overlay each column where a compromise indicator fired. Hovering a column reveals the date and event/compromise count. Clicking a column focuses that day.
- **Bottom strip · 24-hour lens.** ~28 px tall. Represents the selected day. **Yellow bands** shade the hour ranges where compromise events occurred (axiom 3). Draggable window rectangle sets the horizontal zoom range for the canvas below.

Adaptive relative-seconds mode still applies **inside the canvas time ruler**, but the two strips above always exist and show the case timespan.

### C-2 · Yellow compromise bands (new · replaces the "co-occurrence highlight" idea)
Compromise hours get a **yellow vertical band** overlaid on the canvas across all rows. Opacity 8–12%. The band's edges are the compromise start/end timestamps. Multiple compromises → multiple bands.

### C-3 · Blue halo on trigger events (replaces Section 5.3 "co-occurring events")
When the analyst clicks a **compromise indicator row**, every event that triggered that indicator gets a **1.5 px blue halo ring** (Cisco term: "blue halo"). This is the audit trail that explains "why did the compromise fire?" — it points at the causally-linked events, not at co-occurring events by timestamp.

The **playhead** concept I proposed in v1 is **removed**. Cisco does not use one. Selection sync goes to the right panel; ancestry sync goes into the blue-halo mechanism.

### C-4 · Disposition color is the event FILL (replaces Section 7's contrast budget)
The *shape* of the glyph indicates activity (`+` create, `▶` execute, `×` delete, arrow network, square registry). The *fill color* of the glyph indicates disposition:

| Disposition | Fill |
|---|---|
| Benign      | `#059669` green |
| Unknown     | `#94A3B8` gray  |
| Malicious   | `#DC2626` red   |

We drop "amber = suspicious" entirely. Cisco is a three-state model. The custom-detection product we ship layers a **suspicious flag chip** on the row, not a fourth event color. Amber lives only in the yellow compromise-band overlay and in flag chips.

### C-5 · Source vs acted-upon dual-glyph (new)
Two circle variants:
- **Double circle** (outer ring + inner dot) = the entity was **the source** of the activity (e.g. `cmd.exe` *executed* `powershell.exe` — cmd is the source)
- **Single circle** (solid dot only) = the entity was **acted upon** (powershell is the target)

This is the single most-used glyph in Cisco Trajectory and I omitted it entirely.

### C-6 · Five filter categories (replaces the two-category chip strip)
Filter drawer must expose **all five**, and analysts must pick at least one item from each:

1. **Activity** — File, Network, Connector activity
2. **System** — Compromises, reboots, policy/definition updates, scans, uninstalls
3. **Disposition** — Malicious, clean, unknown
4. **Flags** — Modifier flags: unquarantined-malicious warning, incomplete-scan, custom-detection, etc.
5. **File Type** — Executable, PDF, MS Cabinet, MS Office, Archive, SWF, plain text, RTF, Script, Installer, Others

Filter chips in the header stay, but the drawer is required to reach category 4/5.

### C-7 · Zoom range (replaces Section 4's zoom rule)
Range: **8-hour columns → 2-second intervals**. Zoom is X-only (rows never resize). Presets: 30d, 7d, 1d, 8h, 1h, 5m, 2s.

### C-8 · Compromise indicator = own row (new)
When a compromise fires, it appears as a **dedicated row in the canvas** (not just a red dot). The row's left-gutter label reads e.g. "Reflective DLL Injection" and its lifeline spans the compromise time window with a **red bar + yellow shading**. Clicking that row highlights all trigger events with a blue halo.

### C-9 · Right panel = "Event Details pane" (rename)
The right panel is the **Event Details pane** in Cisco parlance. On click it shows:
- File name
- File path
- Parent process
- File size
- Execution context
- Hashes (SHA-256, SHA-1, MD5)
- Command line (if capture policy enabled)
- Disposition
- Detection name / engine / quarantine action
- MITRE tactics + techniques
- For network events: destination IP + port + protocol

This is verbatim from the PDF pp. 325–342.

---

## Corrections to the first mockup batch

| Scene | Fix required |
|---|---|
| 01 Landing | Add top 30-day density strip with red compromise dots; add bottom 24h strip with yellow compromise bands; drop amber from event fill; adopt double-circle/single-circle |
| 02 Event hover | Keep tooltip; drop the "co-occurring outline" — that's not a Cisco pattern |
| 03 Selected event | **Remove the playhead** entirely. Selection just highlights the event + populates the Event Details pane |
| 04 Ancestry focus | Keep, but rename to "Trigger-event highlight" and use **blue halo** rings on the child events, not blue L-connectors |
| 05 Filter drawer | Expand to 5 category groups (add System, Flags, File Type) |
| 06 Missing ancestry | Keep as-is — this remains our honest empty-state improvement over Cisco |
| 07 Adaptive axis | Keep the inner ruler adaptive but always render the two outer strips |
| 08 Dense case | Add a yellow compromise band across all rows for the ransomware window |
| 09 Landing card | Keep |
| 10 Registry drill-down | Keep as an *addition* to Cisco (this is our differentiator — Cisco doesn't have it) |
| 11 Before/After | Keep as a delta showcase; update the "after" to include the two-strip nav |
| 12 Chrome header | Keep single-row header + minimap; but the header must link into the 5-category filter drawer, not display 5 loose chips |

---

## What we deliberately keep from our own design (not Cisco patterns)
These stay because they *improve* the analyst experience without contradicting Cisco:

1. **Honest missing-ancestry empty state** (Scene 06). Cisco silently fails; we tell the truth.
2. **Registry drill-down popover** (Scene 10). Cisco expands each key inline; we compress N mutations into one glyph with a drill-in.
3. **Adaptive relative-seconds ruler** on the *inner* canvas when the case is sub-second. Cisco jumps straight to HH:MM which is useless for a 0.7-second case.
4. **MITRE chips inline in the tooltip.** Cisco puts MITRE in the Event Details pane only.
5. **Dark-mode option** (planned Scene 23). Cisco is light-only.

---

## Approval gate
This corrections file must be read alongside `M2_DESIGN_SPEC.md`. When the mockup revision batch lands, the acceptance criteria in the design spec are amended by C-1 through C-9.

**Next design deliverable** (only if this direction is approved):
- `trajectory-mockups-v2.html` — 6 corrected scenes (01, 02, 03, 04, 08, 11) showing the two-strip nav, yellow compromise bands, blue trigger halos, three-state disposition, double/single-circle glyphs, and the 5-category filter drawer.
