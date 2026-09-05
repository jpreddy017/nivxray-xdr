"""Phase 4 · T4.4 — NO-generic-recommendation-fallback (P4-FW3).

`project_recommendations` MUST return [] + a mandatory reasoning note
when SSOT has no MITRE evidence. It MUST NOT emit the generic
"IMMEDIATE / THREAT HUNTING / CONTAINMENT" template.
"""
from __future__ import annotations

import json

from canonical.projections import project_recommendations


BANNED_TEMPLATE_TOKENS = (
    "IMMEDIATE",
    "THREAT HUNTING",
    "CONTAINMENT",
    "Isolate the host",
    "isolate_host",
    "quarantine_the_host",
)


def _flatten_strings(o):
    if isinstance(o, str):
        yield o
    elif isinstance(o, dict):
        for v in o.values():
            yield from _flatten_strings(v)
    elif isinstance(o, list):
        for v in o:
            yield from _flatten_strings(v)


def test_t4_4_empty_ssot_yields_empty_recommendations_with_note(ssot_empty):
    out = project_recommendations(ssot_empty)
    assert out["items"] == [], "no MITRE ⇒ items MUST be empty"
    assert len(out["notes"]) == 1
    note = out["notes"][0]
    assert note["projection"] == "project_recommendations"
    assert "no evidence-derived" in note["note"].lower()


def test_t4_4_ioc_only_ssot_yields_empty_recommendations(ssot_iocs_only):
    """IOC-only SSOT (no MITRE) MUST still return empty recommendations."""
    out = project_recommendations(ssot_iocs_only)
    assert out["items"] == []
    assert out["notes"], "notes must document why items are empty"


def test_t4_4_no_generic_template_ever_appears(ssot_empty, ssot_iocs_only,
                                                ssot_commands, ssot_mitre,
                                                ssot_rich):
    """Across every SSOT variant, the banned generic template is absent."""
    for ssot in [ssot_empty, ssot_iocs_only, ssot_commands, ssot_mitre,
                 ssot_rich]:
        blob = json.dumps(project_recommendations(ssot),
                          sort_keys=True, ensure_ascii=False)
        for banned in BANNED_TEMPLATE_TOKENS:
            assert banned not in blob, (
                f"project_recommendations emitted banned template "
                f"token {banned!r} for ssot {ssot.id!r}"
            )


def test_t4_4_mitre_ssot_yields_evidence_derived_items(ssot_mitre):
    """SSOT with MITRE ⇒ non-empty, per-technique recommendations."""
    out = project_recommendations(ssot_mitre)
    assert out["items"], "MITRE evidence must yield recommendations"
    ids = {item["technique_id"] for item in out["items"]}
    assert "T1059.001" in ids
    assert "T1218.010" in ids
    # Every item must trace back to a technique + evidence node.
    for item in out["items"]:
        assert item["technique_id"]
        assert item["evidence_id"].startswith("ev.mitre.")
        assert item["rationale"]
