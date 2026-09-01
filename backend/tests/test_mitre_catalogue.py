"""
Regression tests for the ATT&CK Enterprise catalogue + coverage
resolver.  Owner rules under test:

  1. Catalogue is the projection of the v16.1 STIX bundle:
     14 tactics · 203 techniques · 453 sub-techniques.
  2. Every technique has a stable external id and (when it is a
     sub-technique) a parent_id.
  3. Coverage resolver never fabricates observations.  A technique
     with zero observations is `NO_EVIDENCE` regardless of parent.
     Parent aggregate_count sums parent + observed children only.
  4. `resolve_name()` maps every catalogue-published NAME to its
     canonical id (case- and whitespace-insensitive), and does NOT
     map arbitrary strings.
"""
from __future__ import annotations
import json
import pathlib
import re

import pytest

from services.mitre_catalogue import (
    get_catalogue, resolve_coverage, CoverageState,
)
from services.mitre_catalogue.service import MitreCatalogue


ATTACK_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def test_catalogue_shape_matches_v16_1():
    cat = get_catalogue()
    assert cat.version == "16.1"
    assert len(cat.tactics) == 14
    parents = cat.parents()
    subs    = cat.sub_techniques()
    assert len(parents) == 203
    assert len(subs)    == 453
    assert cat.stats == {
        "tactic_count":         14,
        "technique_count":     203,
        "sub_technique_count": 453,
        "total_row_count":     656,
    }


def test_every_technique_has_a_canonical_id_and_url():
    cat = get_catalogue()
    for t in cat.techniques:
        assert ATTACK_RE.match(t["external_id"]), t["external_id"]
        assert t["url"] and "attack.mitre.org/techniques" in t["url"]


def test_every_sub_technique_wires_to_a_real_parent():
    cat = get_catalogue()
    for s in cat.sub_techniques():
        parent = s["parent_id"]
        assert parent, s["external_id"]
        p = cat.technique(parent)
        assert p is not None
        assert p["is_sub"] is False


def test_resolve_name_matches_case_and_whitespace_variants():
    cat = get_catalogue()
    assert cat.resolve_name("PowerShell")             == "T1059.001"
    assert cat.resolve_name("  powershell  ")         == "T1059.001"
    assert cat.resolve_name("Ingress Tool Transfer")  == "T1105"
    assert cat.resolve_name("RUNDLL32")               == "T1218.011"
    # Non-catalogue rationale text must NOT resolve.
    assert cat.resolve_name(
        "CMD /C OR /K FRAGMENT CHAINING EXECUTION PRIMITIVES"
    ) is None


def test_coverage_zero_observations_is_no_evidence_everywhere():
    projection = resolve_coverage({})
    for tactic in projection["tactics"]:
        assert tactic["parent_observed"] == 0
        assert tactic["sub_observed"]    == 0
        assert tactic["aggregate_detections"] == 0
        for p in tactic["techniques"]:
            assert p["coverage_state"] == CoverageState.NO_EVIDENCE.value
            assert p["observed_count"]     == 0
            assert p["aggregate_count"]    == 0
            assert p["observed_sub_count"] == 0
            for s in p["subs"]:
                assert s["coverage_state"] == CoverageState.NO_EVIDENCE.value
                assert s["observed_count"] == 0


def test_aggregate_count_sums_parent_plus_subs_only():
    """Observations on 3 rows: T1059 (parent) once, T1059.001 twice,
    T1059.006 once.  Aggregate on T1059 must be 4; T1059.003 (no
    evidence) must remain NO_EVIDENCE, independent of the parent."""
    projection = resolve_coverage({
        "T1059":     1,
        "T1059.001": 2,
        "T1059.006": 1,
    })
    execution = next(t for t in projection["tactics"]
                              if t["shortname"] == "execution")
    parent = next(p for p in execution["techniques"]
                              if p["external_id"] == "T1059")
    assert parent["observed_count"]  == 1
    assert parent["aggregate_count"] == 4
    assert parent["observed_sub_count"] == 2
    assert parent["coverage_state"]  == CoverageState.OBSERVED.value

    subs = {s["external_id"]: s for s in parent["subs"]}
    assert subs["T1059.001"]["observed_count"] == 2
    assert subs["T1059.001"]["coverage_state"] == CoverageState.OBSERVED.value
    assert subs["T1059.006"]["observed_count"] == 1
    assert subs["T1059.006"]["coverage_state"] == CoverageState.OBSERVED.value
    # A sibling sub with no evidence stays NO_EVIDENCE.
    assert subs["T1059.003"]["observed_count"] == 0
    assert subs["T1059.003"]["coverage_state"] == CoverageState.NO_EVIDENCE.value


def test_totals_reflect_only_real_observations():
    projection = resolve_coverage({
        "T1059": 1,          # parent-only
        "T1105": 1,          # parent-only
        "T1059.001": 1,      # sub only
    })
    assert projection["totals"]["techniques"]         == 203
    assert projection["totals"]["sub_techniques"]     == 453
    # T1059 and T1105 are two distinct parents observed.
    assert projection["totals"]["techniques_observed"] == 2
    assert projection["totals"]["sub_techniques_observed"] == 1
    assert projection["totals"]["aggregate_detections"] == 3


def test_name_index_file_exists_and_is_consistent():
    path = pathlib.Path("/app/backend/mitre_catalogue/name_index.json")
    assert path.exists(), "run build_name_index.py"
    raw = json.loads(path.read_text())
    assert raw["catalogue_version"] == "16.1"
    assert raw["count"] >= 500
    # Every value in the name index must be a real catalogue id.
    cat = get_catalogue()
    for v in raw["name_to_external_id"].values():
        assert cat.technique(v) is not None, v


def test_iter_technique_ids_uses_name_fallback_for_new_incidents():
    """A future incident whose stack leaks a NAME (no T####) must
    still count toward coverage — the name resolver is the safety
    net that makes the catalogue self-updating."""
    from routers.mitre_catalogue import _iter_technique_ids
    inc = {
        "id": "future-inc-1",
        "mitre": [
            {"technique_name": "PowerShell"},          # name-only
            {"technique_id":   "T1105"},                # canonical
        ],
        "evidence": [
            {"attack_id":      "T1027.010"},
        ],
    }
    ids = sorted(set(_iter_technique_ids(inc)))
    assert ids == ["T1027.010", "T1059.001", "T1105"]
