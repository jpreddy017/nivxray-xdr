"""Phase 4 · T4.2 — Firewall (P4-FW2).

Projections MUST NOT mutate the authoritative tier.
"""
from __future__ import annotations

import copy
from dataclasses import asdict

from canonical.projections import (
    project_activity,
    project_analyst_summary,
    project_attck,
    project_attack_chain,
    project_attack_story,
    project_canonical,
    project_evidence_bundle,
    project_evidence_graph_view,
    project_executive_summary,
    project_iocs,
    project_lolbas,
    project_recommendations,
    project_reports,
    project_timeline,
    project_verdict,
)


ALL_PROJECTIONS = [
    project_activity, project_analyst_summary, project_attck,
    project_attack_chain, project_attack_story, project_canonical,
    project_evidence_bundle, project_evidence_graph_view,
    project_executive_summary, project_iocs, project_lolbas,
    project_recommendations, project_reports, project_timeline,
    project_verdict,
]


AUTHORITATIVE_FIELDS = (
    "input_raw", "input_profile", "input_health", "iue_decision",
    "plan", "execution_trace", "artifacts", "evidence_graph",
    "reasoning_steps", "context", "metadata",
)


def _snapshot_authoritative(ssot):
    """Return a deep snapshot of authoritative fields for comparison."""
    d = ssot.to_dict()
    return {k: copy.deepcopy(d.get(k)) for k in AUTHORITATIVE_FIELDS}


def test_t4_2_projection_never_mutates_authoritative_fields(ssot_rich):
    """Running any projection preserves every authoritative field bit-for-bit."""
    before = _snapshot_authoritative(ssot_rich)
    fp_before = ssot_rich.fingerprint()
    for fn in ALL_PROJECTIONS:
        fn(ssot_rich)
    after = _snapshot_authoritative(ssot_rich)
    fp_after = ssot_rich.fingerprint()
    assert before == after, "authoritative fields mutated by a projection"
    assert fp_before == fp_after, "fingerprint drifted post-projection"


def test_t4_2_frozen_ssot_still_frozen(ssot_rich):
    assert ssot_rich.is_frozen()
    for fn in ALL_PROJECTIONS:
        fn(ssot_rich)
    assert ssot_rich.is_frozen()


def test_t4_2_projection_outputs_do_not_share_authoritative_lists(ssot_rich):
    """Projection outputs are copies, not aliases of authoritative lists."""
    bundle = project_evidence_bundle(ssot_rich)
    # Mutating bundle.nodes must not affect the SSOT's nodes.
    original_len = len(ssot_rich.evidence_graph.nodes)
    bundle["nodes"].append({"id": "hacked", "kind": "x", "label": "x",
                            "attrs": {}, "provenance": None})
    assert len(ssot_rich.evidence_graph.nodes) == original_len
