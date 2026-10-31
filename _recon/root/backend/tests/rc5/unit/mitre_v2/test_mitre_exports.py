"""Phase 5 · Navigator + STIX export tests.

Verifies the exports are deterministic, contain the expected structural
fields, and every technique referenced by a MitreMapping appears in the
Navigator layer and the STIX bundle.
"""
from __future__ import annotations

import json
import pytest

from engine.exec_graph import Behavior, TacticKind
from engine.detectors.mitre_mapper import map_behaviors_to_mitre
from engine.detectors.mitre_navigator_export import (
    build_navigator_layer, NAV_LAYER_VERSION, ATTACK_DOMAIN,
)
from engine.detectors.mitre_stix_export import build_stix_bundle, STIX_VERSION


def _b(tactic, sub, params, conf=100, nid="n_x", recon=""):
    return Behavior(tactic=tactic, sub_kind=sub, evidence_nodes=(nid,),
                    reconstructed=recon or f"{tactic.value}:{sub}",
                    confidence=conf, parameters=params or {})


# ── Navigator export ──────────────────────────────────────────────────
def test_navigator_layer_empty_when_no_mappings():
    lay = build_navigator_layer([])
    assert lay["versions"]["layer"] == NAV_LAYER_VERSION
    assert lay["domain"] == ATTACK_DOMAIN
    assert lay["techniques"] == []


def test_navigator_layer_contains_expected_technique_ids():
    b1 = _b(TacticKind.execution, "process_spawn",
            {"image": "powershell.exe"}, nid="n_p")
    b2 = _b(TacticKind.command_and_control, "download",
            {"image": "curl.exe"}, nid="n_c")
    lay = build_navigator_layer(map_behaviors_to_mitre([b1, b2]))
    tids = {t["techniqueID"] for t in lay["techniques"]}
    assert "T1059.001" in tids  # subtechnique preferred over parent
    assert "T1105" in tids


def test_navigator_layer_is_json_serialisable():
    b = _b(TacticKind.execution, "process_spawn",
           {"image": "powershell.exe"}, nid="n_p")
    lay = build_navigator_layer(map_behaviors_to_mitre([b]))
    json.dumps(lay)  # must not raise


def test_navigator_layer_deterministic():
    b = _b(TacticKind.execution, "process_spawn",
           {"image": "powershell.exe"}, nid="n_p")
    mm = map_behaviors_to_mitre([b])
    a = json.dumps(build_navigator_layer(mm), sort_keys=True)
    c = json.dumps(build_navigator_layer(mm), sort_keys=True)
    assert a == c


def test_navigator_score_matches_confidence():
    b = _b(TacticKind.execution, "process_spawn",
           {"image": "powershell.exe"}, conf=50, nid="n_p")
    lay = build_navigator_layer(map_behaviors_to_mitre([b]))
    t = next(x for x in lay["techniques"] if x["techniqueID"] == "T1059.001")
    assert t["score"] == 50


def test_navigator_comment_contains_evidence_ids():
    b = _b(TacticKind.execution, "process_spawn",
           {"image": "powershell.exe"}, nid="n_evi")
    lay = build_navigator_layer(map_behaviors_to_mitre([b]))
    t = next(x for x in lay["techniques"] if x["techniqueID"] == "T1059.001")
    assert "n_evi" in t["comment"]


def test_navigator_case_id_appears_in_name():
    lay = build_navigator_layer([], case_id="CASE-42")
    assert "CASE-42" in lay["name"]


def test_navigator_gradient_5_colors():
    lay = build_navigator_layer([])
    assert len(lay["gradient"]["colors"]) == 5


# ── STIX 2.1 export ───────────────────────────────────────────────────
def test_stix_bundle_empty_when_no_mappings():
    bundle = build_stix_bundle([])
    assert bundle["type"] == "bundle"
    # Only the identity SDO — no attack-patterns / mappings / report.
    assert all(o["type"] == "identity" for o in bundle["objects"])


def test_stix_bundle_has_expected_object_types():
    b = _b(TacticKind.execution, "process_spawn",
           {"image": "powershell.exe"}, nid="n_p")
    bundle = build_stix_bundle(map_behaviors_to_mitre([b]))
    types = {o["type"] for o in bundle["objects"]}
    assert {"identity", "attack-pattern", "x-nivxray-mapping", "report"} <= types


def test_stix_attack_pattern_id_points_at_mitre():
    b = _b(TacticKind.execution, "process_spawn",
           {"image": "powershell.exe"}, nid="n_p")
    bundle = build_stix_bundle(map_behaviors_to_mitre([b]))
    ap = next(o for o in bundle["objects"] if o["type"] == "attack-pattern")
    ext = ap["external_references"][0]
    assert ext["source_name"] == "mitre-attack"
    assert ext["external_id"] == "T1059.001"
    assert "attack.mitre.org/techniques/T1059/001" in ext["url"]


def test_stix_mapping_preserves_evidence():
    b = _b(TacticKind.execution, "process_spawn",
           {"image": "powershell.exe"}, nid="n_evi_x")
    bundle = build_stix_bundle(map_behaviors_to_mitre([b]))
    m = next(o for o in bundle["objects"] if o["type"] == "x-nivxray-mapping")
    assert "n_evi_x" in m["evidence_node_ids"]
    assert m["evidence_behavior_ids"]


def test_stix_bundle_deterministic():
    b = _b(TacticKind.execution, "process_spawn",
           {"image": "powershell.exe"}, nid="n_p")
    mm = map_behaviors_to_mitre([b])
    a = json.dumps(build_stix_bundle(mm), sort_keys=True)
    c = json.dumps(build_stix_bundle(mm), sort_keys=True)
    assert a == c


def test_stix_bundle_id_is_stable_uuid_form():
    bundle = build_stix_bundle([])
    assert bundle["id"].startswith("bundle--")
    _, uid = bundle["id"].split("--", 1)
    assert len(uid) == 36 and uid[8] == "-"


def test_stix_report_object_refs_include_all_mappings_and_patterns():
    b1 = _b(TacticKind.execution, "process_spawn",
            {"image": "powershell.exe"}, nid="n_1")
    b2 = _b(TacticKind.command_and_control, "download",
            {"image": "curl.exe"}, nid="n_2")
    bundle = build_stix_bundle(map_behaviors_to_mitre([b1, b2]))
    report = next(o for o in bundle["objects"] if o["type"] == "report")
    aps = [o["id"] for o in bundle["objects"] if o["type"] == "attack-pattern"]
    mps = [o["id"] for o in bundle["objects"] if o["type"] == "x-nivxray-mapping"]
    for ref in aps + mps:
        assert ref in report["object_refs"]


def test_stix_kill_chain_phase_matches_tactic():
    b = _b(TacticKind.persistence, "autorun_registration",
           {"key_hint": r"hkcu\software\microsoft\windows\currentversion\run"},
           nid="n_kc")
    bundle = build_stix_bundle(map_behaviors_to_mitre([b]))
    ap = next(o for o in bundle["objects"] if o["type"] == "attack-pattern")
    kcp = ap["kill_chain_phases"][0]
    assert kcp["kill_chain_name"] == "mitre-attack"
    assert kcp["phase_name"] == "persistence"


def test_stix_spec_version_field_is_2_1():
    b = _b(TacticKind.execution, "process_spawn",
           {"image": "powershell.exe"}, nid="n_sv")
    bundle = build_stix_bundle(map_behaviors_to_mitre([b]))
    for o in bundle["objects"]:
        if o["type"] not in ("bundle",):
            assert o.get("spec_version") == STIX_VERSION


def test_stix_case_id_in_report_name():
    b = _b(TacticKind.execution, "process_spawn",
           {"image": "powershell.exe"}, nid="n_ci")
    bundle = build_stix_bundle(map_behaviors_to_mitre([b]), case_id="CASE-77")
    report = next(o for o in bundle["objects"] if o["type"] == "report")
    assert "CASE-77" in report["name"]
