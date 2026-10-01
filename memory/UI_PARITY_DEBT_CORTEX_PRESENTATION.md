# UI PARITY DEBT · Cortex-XDR-class presentation (owner escalation, 2026-06)

## What the owner saw, and why

The owner's verdict on `Data Sources → Windows`: *"the UI is like AI
designed/build. I need Cortex XDR UI."* They were right, and the cause was
not a missing capability — it was mine.

* **Channels** and **Devices** tabs were built on the real design system
  (`nx/NxDataTable`, `nx/NxFlyout`) and read like a console.
* **Overview**, **Coverage**, **Health** and **Configuration** were
  hand-rolled with page-local CSS (`wx-*` in
  `xdr/datasources/windows/windows.css`) and raw
  `<table class="wx-kv">` two-column key/value dumps.

Resulting defects, verbatim from the screenshots:
1. a tall EMPTY white card band under the four KPI tiles (an `NxSurface`
   wrapping a grid with nothing in it);
2. long monospace sentences as body text, low-contrast grey on white;
3. Attention and ATT&CK sections as borderless key/value rows — no
   columns, no alignment, no sort, no hover, no density control;
4. pale pastel chips that do not read as status at enterprise density,
   four in a row with no column semantics;
5. identical blocker phrases repeated on every row instead of grouped;
6. no containment, no filter/summary rail, inconsistent vertical rhythm.

## The rule this violated

**Never hand-roll presentation when `nx/` already owns it.** The design
system is the contract; a page-local CSS file is a symptom. Any new
primitive belongs in `nx/`, never in a page folder.

## Blueprint

`design_agent` produced `/app/design_guidelines.json` (Cortex-parity
information architecture): dense `NxDataTable` grids for all four tabs, a
new shared `NxDimensionStrip` for the five independent dimensions (without
implying a composite score), `NxBlockerGroup` for deduplicated blockers,
a standardised chip treatment for the 9-value operational vocabulary +
4-value coverage vocabulary, and explicit rules for rendering a
deliberately absent measurement (`—` / `NOT AVAILABLE`) so it reads as
rigour rather than as a bug.

## Status

**BLUEPRINT ONLY — NOT IMPLEMENTED.** The next pass must:
1. add `NxDimensionStrip` + `NxBlockerGroup` to `nx/` (not to the windows
   folder);
2. rebuild Overview / Coverage / Health / Configuration on `NxDataTable`
   with the column sets in the blueprint;
3. delete `windows.css` and every `wx-*` class as those consumers move;
4. keep the Channels/Devices tabs' behaviour, and keep every truth
   semantic intact — no state may be merged, softened or inferred to make
   a layout tidier.

Applies to the Event Explorer page too: it imports the same `wx-*`
primitives and inherits the same debt.
