"""
P0.16 · Behavior Knowledge Base · CI Coverage Gate
────────────────────────────────────────────────────

Strengthened CI gate that prevents the BKB from silently
becoming incomplete as new classifier labels are introduced or
existing labels are renamed.  Every assertion below MUST pass on
every commit or the build fails.
"""
from __future__ import annotations

import re
import pytest

from services.knowledge import behavior_registry as bkb
from services.ice.correlate import tactic_for


# ══════════════════════════════════════════════════════════════════
# 1. Every non-generic classifier label must exist in the BKB.
# ══════════════════════════════════════════════════════════════════
# The classifier's deliberate catch-all fallback is the only
# unmapped label we accept.  Any additional gap fails CI.
_ALLOWED_UNMAPPED = {"Command execution", "Uncategorised"}


def _labels_emitted_by_classifier():
    """Extract every `return "..."` string literal from both
    classifier producers.  This is a deterministic static-analysis
    check — we don't run the classifier, we scan its source so a
    new label added tomorrow gets caught immediately."""
    labels: set[str] = set()
    for path in ("services/ida/report_extractors.py",
                     "services/ida/behaviors.py"):
        try:
            with open("/app/backend/" + path) as f:
                text = f.read()
        except FileNotFoundError:
            continue
        # `return "Label"` on a single line.
        for m in re.finditer(r'return\s+"([^"\\]{3,80})"', text):
            lbl = m.group(1)
            # Skip obvious control strings.
            if any(ch in lbl for ch in "{}\n\t"):
                continue
            # Skip enum-ish snake_case identifiers.
            if re.fullmatch(r"[a-z_][a-z0-9_]+", lbl):
                continue
            labels.add(lbl)
    return labels


def test_every_non_generic_classifier_label_is_in_bkb():
    emitted = _labels_emitted_by_classifier()
    covered = set(bkb.labels())
    gap = sorted(emitted - covered - _ALLOWED_UNMAPPED)
    assert not gap, (
        f"{len(gap)} classifier label(s) not in BKB: {gap}. "
        f"Add entries in services/knowledge/behavior_registry.py.")


# ══════════════════════════════════════════════════════════════════
# 2. Every BKB entry has the required structure.
# ══════════════════════════════════════════════════════════════════
def test_every_entry_has_canonical_techniques():
    for label in bkb.labels():
        spec = bkb.lookup(label)
        assert spec.canonical_techniques, f"{label!r}: no canonical_techniques"


def test_every_entry_has_canonical_tactics():
    for label in bkb.labels():
        spec = bkb.lookup(label)
        assert spec.canonical_tactics, f"{label!r}: no canonical_tactics"


def test_every_entry_has_severity_display_name_category():
    for label in bkb.labels():
        spec = bkb.lookup(label)
        assert spec.display_name, f"{label!r}: no display_name"
        assert spec.category,     f"{label!r}: no category"
        assert spec.severity in ("low", "medium", "high", "critical"), \
            f"{label!r}: bad severity {spec.severity!r}"


# ══════════════════════════════════════════════════════════════════
# 3. No duplicate canonical techniques inside a single entry.
# ══════════════════════════════════════════════════════════════════
def test_no_duplicate_techniques_per_entry():
    for label in bkb.labels():
        spec = bkb.lookup(label)
        ids = [t["id"] for t in spec.canonical_techniques]
        assert len(ids) == len(set(ids)), \
            f"{label!r}: duplicate techniques {ids}"


# ══════════════════════════════════════════════════════════════════
# 4. Every canonical technique belongs to a declared tactic.
# ══════════════════════════════════════════════════════════════════
def test_every_technique_belongs_to_declared_tactic():
    for label in bkb.labels():
        spec = bkb.lookup(label)
        declared = set(spec.canonical_tactics)
        implied = {tactic_for(t["id"]) for t in spec.canonical_techniques
                        if tactic_for(t["id"])}
        # Every implied tactic MUST be declared (no orphans).
        orphans = implied - declared
        assert not orphans, \
            f"{label!r}: techniques imply undeclared tactics {orphans}"


# ══════════════════════════════════════════════════════════════════
# 5. The unmapped allow-list is fixed and small.
# ══════════════════════════════════════════════════════════════════
def test_unmapped_allow_list_is_pinned():
    # Any change to this set is a deliberate policy decision — the
    # CI gate should fail so a reviewer sees it.
    assert _ALLOWED_UNMAPPED == {"Command execution", "Uncategorised"}


# ══════════════════════════════════════════════════════════════════
# 6. Registry lower-bound count — prevents accidental deletion.
# ══════════════════════════════════════════════════════════════════
def test_registry_size_is_at_or_above_the_current_floor():
    assert len(bkb.labels()) >= 80, \
        "BKB shrank below the pinned floor · was an entry accidentally deleted?"
