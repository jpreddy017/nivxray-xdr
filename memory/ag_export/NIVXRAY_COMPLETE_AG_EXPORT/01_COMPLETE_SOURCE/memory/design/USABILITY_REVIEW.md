# Usability Review · M2 Hero · Six Analyst Tasks
_Method: dogfooding the live build at `/v2/trajectory` against the case
`case_dfir_bumblebee_akira_2026` (53 events, 4 compromises, 13 processes)._

**Purpose of this document.** Determine whether the current investigation workflow is
already effortless, or whether specific P0 hardening items must ship before P1 begins.
Each task below scores **PASS**, **PASS-with-polish**, or **FAIL**. Anything that isn't
a clean PASS becomes a P0 checklist item.

---

## Task 1 · Locate the initial execution
**Expected:** analyst opens the page → sees where the attack begins.

**Observed on live build.**
- Attack chain sidebar leads with `01 · EXECUTION` (top-left, most prominent card).
- Canvas ancestry gutter leads with `msiexec.exe` (topmost process row).
- Sidebar text: "cmd.exe · executed · powershell.exe" · `T1059.001`.
- Time compass leftmost region shows benign density before the yellow compromise
  window fires at T+0.26s.

**Verdict: PASS.** Zero clicks to know the attack starts at `msiexec.exe` and pivots
through `cmd → powershell`.

---

## Task 2 · Trace parent–child execution
**Expected:** analyst walks the tree from root down through descendants.

**Observed.**
- Rows render with indent glyphs (`├─`, `└─`, `│`) and increasing indent depth per
  first-seen delay heuristic.
- **However:** the heuristic is a proxy for real ancestry; seed data ships **zero**
  `parent.iid` values (`0/53` frames). L-connectors that visually thread parent →
  child cannot draw because no edges exist.
- The gutter labels look tree-shaped, but the shape is guessed from time not from
  causality.

**Verdict: PASS-with-polish.** The visual affordance is correct; the *data* is not.
This is the primary reason P1 (Adapter Ancestry) is elevated to highest engineering
priority — it turns the heuristic tree into a real one without changing the UI.

**P0 dependency on P1.** P0 checkbox #2 ("Parent-child ancestry completely accurate")
cannot check without P1.

---

## Task 3 · Identify persistence
**Expected:** registry autoruns / IFEO / scheduled tasks visible.

**Observed.**
- Registry band renders when the case contains `lane == "registry"` frames.
- Seed data currently emits registry mutations under `process` lane (attached to
  `reg.exe` / `cmd.exe` rather than as their own band rows).
- Result: **the REGISTRY band does not appear** for this case, even though
  Run-key + IFEO persistence *did* occur in the seed narrative.

**Verdict: PASS-with-polish.** UI is ready; adapters must emit registry mutations as
`lane == "registry"` events with the touched key path as the row label. Same story
as file activity — it exists but is currently subsumed into process rows.

---

## Task 4 · Identify outbound communication
**Expected:** find TOR/C2/SMB destinations in a single glance.

**Observed.**
- Two Network rows visible at bottom of canvas: `45.147.230.15:443` (green benign
  arrows) and `185.220.101.42:80 (TOR)` (red arrows).
- Network band header renders with the row count and event count.
- Right pane on click shows destination IP, port, and protocol.

**Verdict: PASS.** TOR exit is unmistakable — the only red arrows on the whole
Network band.

---

## Task 5 · Locate impact
**Expected:** ransomware / data destruction / exfil immediately visible.

**Observed.**
- Sidebar stage `05 · IMPACT ★` with text "locker.exe · encrypted_files ·
  locker.exe target" · `T1486 · T1490`.
- Canvas: `locker.exe` row + `*.locked` file row cluster red on the Files band.
- Compromise indicator row "IMPACT · T1486" with amber lifetime bar spans the
  ransomware encryption window.

**Verdict: PASS.** Impact reads in under 2 seconds from landing.

---

## Task 6 · Understand attack chronology
**Expected:** analyst reads the case as a narrative in a fixed order.

**Observed.**
- Sidebar numbers stages 01 → 06 in MITRE tactic order.
- Canvas time axis flows left → right.
- Yellow compromise window column pins the moment of critical activity.
- Summary card: "Ransomware kill chain · complete · 6 stages · 4 malicious".
- **However:** the inner canvas ruler shows `T+0.0s T+0.0s T+0.0s …` when every
  event lands in the same sub-second — the seed data is timestamped inside a 0.63 s
  window so relative-seconds ticks all round to `T+0.0s`. The story is still
  readable but the axis label repeats.

**Verdict: PASS-with-polish.** One ruler-label fix (higher precision when span
< 1 s → `T+0.00s`, `T+0.05s`, `T+0.10s`) closes this.

---

## Summary scorecard

| # | Task                         | Verdict            | Blocker |
|:-:|------------------------------|--------------------|---------|
| 1 | Locate initial execution     | PASS               | —       |
| 2 | Trace parent–child execution | PASS-with-polish   | P1      |
| 3 | Identify persistence         | PASS-with-polish   | Adapter |
| 4 | Identify outbound comms      | PASS               | —       |
| 5 | Locate impact                | PASS               | —       |
| 6 | Attack chronology            | PASS-with-polish   | Ruler   |

**Two of three "PASS-with-polish" items unblock at P1 (Adapter Ancestry).**
The third is a small ruler fix on the canvas (< 20 LoC) that can ship immediately.

---

## Concrete P0 checklist derived from this review

Items ordered by highest analyst impact.

1. **Ruler precision at sub-second span.** Emit `T+0.00s / T+0.05s / …` when
   total span < 10 s. Fixes Task 6's repeated-tick label.
2. **Selection performance.** Click any event → Evidence pane populates in
   < 60 ms end-to-end. (Verify.)
3. **Hover-tooltip stability.** No dropped tooltips on fast mouse movement across
   the compromise-window column boundary. (Verify.)
4. **Focus-follows-stage.** Clicking a sidebar stage should horizontally
   auto-pan the canvas to that stage's time window. Currently only the yellow
   band redraws. (Small addition.)
5. **Keyboard traversal.** Wire `↑ ↓` to walk events in time order; `F` to fit;
   `⌘\` to open filter drawer; `?` to open the shortcut card. (New surface.)
6. **Adapter ancestry contract.** P1. Emit `entity.iid`, `parent.iid`,
   `root.iid`, `process_start`, `process_end` on every event. Turns Task 2 into
   a clean PASS.
7. **Registry / file lane classification.** Ensure registry mutations emit
   under `lane: "registry"` and files under `lane: "file"` so the Registry and
   Files bands actually populate. Turns Task 3 into a clean PASS.

Items 1–5 are UX/UI hardening. Item 6 is P1 (backend adapters). Item 7 is a
shared backend + adapter contract cleanup.

---

## Release gate
The M2 Hero is *not* release-quality until items 1–5 above are complete **and**
items 6–7 land. Only then does the "definition of done" clause — fewer clicks,
less scrolling, less cognitive effort — evaluate cleanly.

## Milestone close
- **Completed.** M2 Hero design + implementation shipped; six-task usability
  review performed against live build.
- **Screenshot.** `/tmp/hero_glassy.png` (previous message).
- **Blockers.** None hard. Two soft blockers (P1 ancestry, adapter lane
  classification) — both unblock 2 of 3 PASS-with-polish items.
- **Single next priority.** P0 item 1 (ruler precision) — smallest, highest-
  leverage UX fix. Ship it, screenshot the axis, then move to P0 items 2–5.
