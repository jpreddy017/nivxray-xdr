"""The filter taxonomy — registered honestly, NOT reconstructed.

Owner decision 4B: *locate the exact 43 items in the repo; never invent.*

**Search performed** (2026-06) across `docs/`, `memory/`, `apps/` and
`backend/`: the five CATEGORY names are present in
`docs/uiux/NIVXFORGE_EDR_TARGET_UX_ARCHITECTURE.md` (279 lines), but the
**verbatim 43-item list is NOT in this repository**. The original 551-line
specification that contained it was never committed here.

Therefore, per the owner's instruction, the items were **not** reproduced
from general product knowledge. The taxonomy is registered as:

    CONTRACT DEFINED · ITEM LIST PENDING OWNER INPUT

with `gap_class = OWNER_INPUT_PENDING`. The categories are frozen; the
item list has exactly one legal way to be populated, which is
`register_baseline_items()` with the owner's verbatim list.

Any code that filters endpoint activity must consult
`baseline_is_complete()` first and disclose an incomplete baseline rather
than silently filtering on a partial taxonomy — a filter set that
silently omits items is a visibility gap wearing a UI.
"""
from __future__ import annotations

from typing import Optional

BASELINE_CATEGORIES: tuple[str, ...] = (
    "Activity", "System", "Disposition", "Flags", "File Types",
)

BASELINE_EXPECTED_ITEM_COUNT = 43

#: Populated ONLY by register_baseline_items(). Never seeded with guesses.
BASELINE_ITEMS: dict[str, list[str]] = {c: [] for c in BASELINE_CATEGORIES}

BASELINE_STATE = "CONTRACT_DEFINED · ITEM_LIST_PENDING_OWNER_INPUT"

BASELINE_PROVENANCE = (
    "Five categories located in docs/uiux/"
    "NIVXFORGE_EDR_TARGET_UX_ARCHITECTURE.md. The verbatim 43 items are "
    "absent from this repository and were deliberately not reconstructed "
    "from memory (owner decision 4B)."
)

#: Directive §11: the 43 items are the MINIMUM, not the ceiling. These are
#: the NivXForge extension dimensions, which are ours and therefore may be
#: declared here without owner input. They EXTEND; they never replace.
EXTENSION_DIMENSIONS: tuple[str, ...] = (
    "Process", "File", "Network", "DNS", "Registry", "Service",
    "Scheduled Task", "Persistence", "Identity", "USB", "Driver", "Module",
    "Memory", "Container", "Browser", "Cloud", "Sensor", "Response",
    "Detection", "MITRE",
)


def baseline_is_complete() -> bool:
    return (sum(len(v) for v in BASELINE_ITEMS.values())
            == BASELINE_EXPECTED_ITEM_COUNT)


def register_baseline_items(items: dict[str, list[str]], *,
                            attested_by: str) -> dict:
    """Install the owner's verbatim 43 items.

    Refuses a partial list. A taxonomy declared "the mandatory baseline"
    must be complete or explicitly pending — there is no third state.
    """
    unknown = set(items) - set(BASELINE_CATEGORIES)
    if unknown:
        raise ValueError(
            f"unknown categories {sorted(unknown)}; the five baseline "
            f"categories are frozen: {list(BASELINE_CATEGORIES)}")
    total = sum(len(v) for v in items.values())
    if total != BASELINE_EXPECTED_ITEM_COUNT:
        raise ValueError(
            f"the baseline is exactly {BASELINE_EXPECTED_ITEM_COUNT} items; "
            f"got {total}. Directive §11 forbids reducing it, and a partial "
            f"list registered as complete would be a false claim.")
    for cat in BASELINE_CATEGORIES:
        BASELINE_ITEMS[cat] = list(items.get(cat, []))
    global BASELINE_STATE
    BASELINE_STATE = f"BASELINE_REGISTERED · attested_by={attested_by}"
    return status()


def status() -> dict:
    return {
        "state": BASELINE_STATE,
        "complete": baseline_is_complete(),
        "expected_item_count": BASELINE_EXPECTED_ITEM_COUNT,
        "registered_item_count": sum(len(v) for v in BASELINE_ITEMS.values()),
        "categories": list(BASELINE_CATEGORIES),
        "items": {k: list(v) for k, v in BASELINE_ITEMS.items()},
        "extension_dimensions": list(EXTENSION_DIMENSIONS),
        "provenance": BASELINE_PROVENANCE,
        "disclosure": (
            None if baseline_is_complete() else
            "The mandatory 43-item baseline is NOT loaded. Any filter UI "
            "must disclose this rather than present a partial filter set as "
            "complete."),
    }
