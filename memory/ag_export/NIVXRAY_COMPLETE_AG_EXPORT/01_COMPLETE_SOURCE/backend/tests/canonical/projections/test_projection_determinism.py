"""Phase 4 · T4.1 + T4.5 — Determinism (100 replays per projection).

Each projection returns a byte-identical (or dataclass-identical) result
across 100 successive calls with the same SSOT (P4-FW1 · pure).
"""
from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass

import pytest

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
    ("activity",           project_activity),
    ("analyst_summary",    project_analyst_summary),
    ("attck",              project_attck),
    ("attack_chain",       project_attack_chain),
    ("attack_story",       project_attack_story),
    ("canonical",          project_canonical),
    ("evidence_bundle",    project_evidence_bundle),
    ("evidence_graph_view", project_evidence_graph_view),
    ("executive_summary",  project_executive_summary),
    ("iocs",               project_iocs),
    ("lolbas",             project_lolbas),
    ("recommendations",    project_recommendations),
    ("reports",            project_reports),
    ("timeline",           project_timeline),
    ("verdict",            project_verdict),
]


def _canonical(v):
    """Canonicalise projection output for byte-identity comparison."""
    if v is None:
        return "null"
    if is_dataclass(v):
        v = asdict(v)
    return json.dumps(v, sort_keys=True, ensure_ascii=False,
                      default=str, separators=(",", ":"))


@pytest.mark.parametrize("name,fn", ALL_PROJECTIONS)
def test_t4_1_determinism_100_replays_rich(ssot_rich, name, fn):
    baseline = _canonical(fn(ssot_rich))
    for _ in range(100):
        assert _canonical(fn(ssot_rich)) == baseline, \
            f"{name} not deterministic on ssot_rich"


@pytest.mark.parametrize("name,fn", ALL_PROJECTIONS)
def test_t4_1_determinism_100_replays_empty(ssot_empty, name, fn):
    baseline = _canonical(fn(ssot_empty))
    for _ in range(100):
        assert _canonical(fn(ssot_empty)) == baseline


@pytest.mark.parametrize("name,fn", ALL_PROJECTIONS)
def test_t4_5_projections_regenerable_from_ssot_only(ssot_rich, name, fn):
    """T4.5 · Rebuild idempotence — projections are regenerable purely from
    the SSOT (no hidden state)."""
    first = _canonical(fn(ssot_rich))
    # Roundtrip through to_dict/from_dict to ensure zero hidden state.
    from canonical.ssot import AuthoritativeSSOT
    reloaded = AuthoritativeSSOT.from_dict(ssot_rich.to_dict())
    second = _canonical(fn(reloaded))
    assert first == second, f"{name} not regenerable from SSOT dict alone"
