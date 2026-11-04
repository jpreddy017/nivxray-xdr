# M2 · Device Trajectory · Honest Audit
_Reviewer role: Senior UX Researcher · Senior DFIR Analyst · Principal Product Designer_

## Verdict up front
The current canvas is a **flowchart of colored capsules**, not an investigation timeline. The engineering is fine. The design is wrong. Every problem below is a design decision, not a rendering bug.

## 1 · The lifeline abstraction is broken
Cisco's Device Trajectory renders each entity as a **thin, quiet horizontal line** that runs the full width of the case. Events land on the line as tiny symbols. The line is scaffolding — the *events* are the story.

We render each entity as a **thick 26-pixel-tall rounded pill** filled with a coloured tint and stroked with a coloured border. The pill visually **screams louder than the events on it**. The eye reads pills, not events. Every row looks equally important because every row is a big colored block.

**Consequence:** the analyst cannot answer "where did the attack start?" without reading labels. In Cisco's UI the answer is obvious because 19 lines are quiet and 1 line has three angry red dots on it.

## 2 · Row order buries the story
Rows are sorted by `band → worst-verdict → firstTs → label`. That means malicious rows sit at the top of every band, but the **causal order — who spawned whom — is destroyed**.

Cisco's row order reads top-to-bottom as an ancestry tree. Ours reads top-to-bottom as "sorted list, most severe first." Those are different products.

## 3 · No visible ancestry
Cisco indents child rows under their parent, and draws a **1-pixel L-connector** from the parent's lifeline down and right to the child's lifeline at the exact spawn timestamp. That single L-line answers "who launched whom?" without a click.

We ship an `edges` prop, we compute edges from `parent.iid`, and we render nice L-connectors when data is available — but the seeded case has **zero parent IIDs**, so zero edges render, so the analyst sees zero ancestry. The visualization silently degrades to "unrelated rows" and never tells the user "there is no ancestry data here."

## 4 · Labels are in the wrong place
We place the entity name as a **floating text tag above each bar**. In a case with 20 rows that means 20 floating tags cascading diagonally across the canvas. The eye has to hop diagonally to read process names. There is no aligned left column.

Cisco puts the entity name in a **sticky left gutter** — a fixed column of process names that scrolls vertically with the canvas but does not move horizontally when you pan time. The name of a process is always at x=0. Ours is at `xForTs(firstTs)`, which moves with the timeline. That's wrong.

## 5 · Empty space is enormous
We render 20 rows × 32 px = 640 px of canvas height. The rest of the ~700 px viewport is empty gray. Cisco packs 40–60 rows into the same vertical budget by keeping rows at ~18 px and eliminating decorative padding around bars.

The bar padding, the label above, and the fat corner-radius all consume vertical real estate. A Cisco analyst working a real 500-event incident would run out of screen in 60 seconds with our density.

## 6 · Events don't lead the eye
Our EventGlyph is a `12 px` disc with a coloured tint fill, a coloured ring, a coloured symbol inside, and a MITRE tick above. That is **four visual attributes on one event**. On a busy row it turns into visual mush.

Cisco events are a single 4–6 px symbol. Compromise events get a subtle red halo. Everything else is monochrome. Because 95% of events are visually identical, the 5% that aren't grab the eye immediately.

## 7 · Time axis says the wrong thing
Our top axis reads `13:04:54 13:04:54 13:04:54 13:04:54` twelve times because the seed data spans <1 second. It communicates "time is broken" rather than "time is compressed here." Cisco would render a **relative axis** — `T+0.0s  T+0.1s  T+0.2s` — when the absolute span is sub-second, and switch to `HH:MM` only when the span justifies it.

## 8 · Right panel and canvas don't cooperate
Selection sync exists but is invisible. When you click an event, the right panel updates, but the canvas does not draw a **playhead** — a vertical line at that timestamp across all rows — so the analyst cannot see "what else was happening at this moment?" That moment-in-time cross-row correlation is the number-one Cisco Trajectory workflow.

## 9 · Filters exist but are cosmetic
Filter chips update the row/event set but don't restructure the canvas. Cisco's filters *collapse* filtered-out rows entirely, so a filter for "network only" leaves an ultra-dense view of only network activity. Ours dims events but leaves empty rows in place.

## 10 · The chrome is louder than the canvas
The top nav ("NIVXRAY · Device Trajectory"), filter row, day scrubber, hour scrubber, status footer, left rail, right panel, and minimap consume more visual weight than the canvas itself. Cisco's chrome is compressed to a single row above the timeline. Ours is five rows.

## Grade
- Engineering quality: **B+** (correct viewport math, deterministic layout, working pan/zoom, marquee, keyboard nav)
- Design quality: **D** (invents its own visual language instead of reconstructing Cisco's investigation methodology)
- Analyst-fitness for real DFIR work: **D-** (would fail on a 500-event case within a minute)

## What needs to change (not code, design)
1. Kill the pill-shaped lifeline. Replace with a **1 px continuous line** per row, spanning the full case width.
2. Move the entity label into a **sticky left gutter** column.
3. Compress row height to **~18 px**.
4. Shrink event symbols to **4–6 px** monochrome, reserve colour for **compromise/detection** only.
5. Introduce **indentation** to represent parent→child ancestry, plus the L-connector.
6. Sort rows in **DFS-ancestry order**, not by verdict severity.
7. When ancestry is missing, **say so** with an explicit empty-state note, don't render a broken tree silently.
8. Draw a **playhead** on selection.
9. Switch time-axis to a **relative-seconds** mode when the span is short.
10. Kill decorative padding from every chrome element. Compress the top bars to one row.

These are the twelve moves that would turn a "colored flowchart" into "an investigation timeline." Everything else in the current implementation stays.
