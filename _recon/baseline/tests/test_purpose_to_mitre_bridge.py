"""P0.14 · Trajectory-gap fix · purpose→MITRE bridge + on-read enrichment.

Regression guards:
    1. Purpose-labelled clusters with empty ``mitre[]`` receive their
       deterministic MITRE mapping (never invents — only uses
       ``_PURPOSE_TO_MITRE``).
    2. ``mitre_tactics[]`` (canonical plural) is always populated
       when ``mitre[]`` carries at least one tactic-bearing entry.
    3. The bridge is idempotent — running it twice never changes
       the result.
    4. Unknown purpose labels stay empty (no hallucination).
"""
from __future__ import annotations

import pytest

from services.ice.correlate import (
    enrich_clusters_in_place,
    _mitre_from_purpose,
    _PURPOSE_TO_MITRE,
)


# ══════════════════════════════════════════════════════════════════
# Purpose → MITRE bridge
# ══════════════════════════════════════════════════════════════════
def test_bridge_covers_three_previously_dropped_purposes():
    """The three purposes that dropped nodes on the 'Mapping' saved
    case — must all bridge to their canonical technique."""
    assert any(m["id"] == "T1572" for m in
                  _mitre_from_purpose("Reverse SSH tunnel"))
    assert any(m["id"] == "T1562.001" for m in
                  _mitre_from_purpose("Software uninstall (defense evasion)"))
    ids = {m["id"] for m in _mitre_from_purpose(
                            "Data staging / exfil (rclone-style)")}
    assert ids >= {"T1567.002", "T1020"}


def test_bridge_returns_empty_for_unknown_label():
    assert _mitre_from_purpose("Definitely Not A Known Purpose") == []
    assert _mitre_from_purpose("") == []
    assert _mitre_from_purpose(None) == []  # type: ignore[arg-type]


def test_every_bridge_entry_carries_a_resolvable_tactic():
    """Any technique the bridge emits must resolve to a tactic
    via ``tactic_for`` — otherwise the projection will drop it."""
    for label, entries in _PURPOSE_TO_MITRE.items():
        bridged = _mitre_from_purpose(label)
        assert len(bridged) == len(entries), (
            f"bridge produced fewer entries than mapped: {label}")
        for b in bridged:
            assert b["tactic"], (
                f"bridge emitted {b['id']!r} for {label!r} "
                "but no tactic resolved")


# ══════════════════════════════════════════════════════════════════
# On-read enrichment · the "Mapping" case scenario
# ══════════════════════════════════════════════════════════════════
def _mapping_case_clusters():
    """Faithful reproduction of the incident.behaviors[] stored on
    the 'Mapping' case — three empty-mitre clusters plus three that
    were already tagged."""
    return [
        {"label": "Reverse SSH tunnel",                       "mitre": []},
        {"label": "Software uninstall (defense evasion)",     "mitre": []},
        {"label": "Data staging / exfil (rclone-style)",      "mitre": []},
        {"label": "Shadow copy deletion",
         "mitre": [{"id": "T1490", "name": "", "tactic": "impact"}]},
        {"label": "MSI execution",
         "mitre": [{"id": "T1218.007", "name": "", "tactic": "defense_evasion"}]},
        {"label": "MSI installer child (embedded)",
         "mitre": [{"id": "T1218.007", "name": "", "tactic": "defense_evasion"}]},
    ]


def test_enrich_fills_empty_mitre_from_purpose():
    clusters = _mapping_case_clusters()
    changed = enrich_clusters_in_place(clusters)
    assert changed == 3, (
        f"expected 3 clusters to receive a bridged mapping, got {changed}")
    for c in clusters:
        assert c["mitre"], (
            f"cluster {c['label']!r} still has empty mitre[] after enrichment")


def test_enrich_populates_canonical_mitre_tactics_plural():
    clusters = _mapping_case_clusters()
    enrich_clusters_in_place(clusters)
    for c in clusters:
        assert c.get("mitre_tactics"), (
            f"cluster {c['label']!r} did not receive mitre_tactics[]")
    tactics_union = {t for c in clusters for t in c.get("mitre_tactics") or ()}
    # Must cover 4 distinct MITRE tactics — the whole point of the fix.
    assert tactics_union == {
        "Command and Control",
        "Defense Evasion",
        "Exfiltration",
        "Impact",
    }, f"unexpected tactic union: {sorted(tactics_union)}"


def test_enrich_is_idempotent():
    """Running the enrichment twice must produce a byte-identical
    result — architecturally critical because the on-read path may
    re-materialise the same case object during a single request."""
    import copy
    a = _mapping_case_clusters()
    enrich_clusters_in_place(a)
    b = copy.deepcopy(a)
    changed_second = enrich_clusters_in_place(b)
    assert changed_second == 0, (
        "second pass wrongly reported changes — enrichment is not idempotent")
    assert a == b


def test_enrich_does_not_invent_for_unknown_labels():
    """A truly unknown label with empty mitre must stay empty —
    never invented — so audit trails remain trustworthy."""
    clusters = [{"label": "Some future TTP we don't know yet",
                    "mitre": []}]
    enrich_clusters_in_place(clusters)
    assert clusters[0]["mitre"] == []
    # mitre_tactics is derived — must be empty too.
    assert clusters[0].get("mitre_tactics", []) == []


def test_enrich_leaves_existing_mitre_intact():
    """When a cluster already carries MITRE, enrichment must NEVER
    overwrite it — the analyst-authored / DIE-authored mapping is
    the source of truth."""
    clusters = [{
        "label": "MSI execution",
        "mitre": [{"id": "T9999.999",
                     "name": "analyst override",
                     "tactic": "impact"}],
    }]
    enrich_clusters_in_place(clusters)
    assert clusters[0]["mitre"] == [
        {"id": "T9999.999", "name": "analyst override", "tactic": "impact"}]
    # And the plural must reflect the analyst override, not the bridge.
    assert clusters[0]["mitre_tactics"] == ["Impact"]


# ══════════════════════════════════════════════════════════════════
# Contract · every purpose the classifier emits should be bridgeable
# ══════════════════════════════════════════════════════════════════
_CLASSIFIER_PURPOSES_TO_COVER = (
    "Reverse SSH tunnel",
    "Software uninstall (defense evasion)",
    "Data staging / exfil (rclone-style)",
    "Shadow copy deletion",
    "MSI execution",
    "MSI installer child (embedded)",
    "Registry Run-key persistence",
    "Registry modification",
    "Self-deletion of stager",
    "Archive extraction",
    "Account / group discovery",
    "Current-user discovery",
    "Host discovery",
    "Lateral movement via PsExec",
    "PowerShell in-memory execution",
    "PowerShell download-and-execute",
    "PowerShell encoded command",
    "Microsoft Edge launch (extension load — Edgecution)",
)


@pytest.mark.parametrize("purpose", _CLASSIFIER_PURPOSES_TO_COVER)
def test_every_material_purpose_has_a_bridge(purpose: str):
    """Guard against silent drift — if the classifier emits any of
    these labels and the bridge doesn't cover it, the projection
    loses a node.  Adding a new purpose to the classifier without
    updating the bridge should fail this test."""
    assert _mitre_from_purpose(purpose), (
        f"purpose {purpose!r} has no bridge entry — Trajectory diagram "
        "will drop it")
