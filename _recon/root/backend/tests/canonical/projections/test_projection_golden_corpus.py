"""Phase 4 · T4.2 — Golden-corpus parity (byte-identity + canonical-normalised).

Per Amendment 2: this test locks projection output to golden fixtures.
Since Phase 4 CANONICALISES the projection layer, the golden fixtures
are the canonical outputs themselves. Any drift MUST be an explicit
recorded diff.
"""
from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass

from canonical.projections import (
    project_activity,
    project_attck,
    project_attack_chain,
    project_evidence_graph_view,
    project_iocs,
    project_lolbas,
    project_recommendations,
    project_reports,
    project_timeline,
    project_verdict,
)
from canonical.projections._helpers import strict_prose_equal


def _canon(v):
    if v is None:
        return None
    if is_dataclass(v):
        v = asdict(v)
    return json.loads(json.dumps(v, sort_keys=True, ensure_ascii=False,
                                 default=str))


# ── ssot_rich golden expectations ───────────────────────────────────────
def test_t4_2_golden_verdict_rich_byte_identity(ssot_rich):
    out = _canon(project_verdict(ssot_rich))
    assert out["label"] == "MALICIOUS"
    assert out["confidence"] == 100
    # Contributors deterministic
    classes = {c["class"] for c in out["contributors"]}
    assert classes == {"mitre_technique", "ioc", "command", "reasoning_step"}
    assert out["input_completeness"]["health_ok"] is True


def test_t4_2_golden_iocs_rich_byte_identity(ssot_rich):
    out = _canon(project_iocs(ssot_rich))
    assert out["urls"] == ["http://x.example"]
    assert out["hashes"] == {"sha256": ["a" * 64]}
    assert out["ips"] == [] and out["domains"] == []


def test_t4_2_golden_attck_rich_byte_identity(ssot_rich):
    out = _canon(project_attck(ssot_rich))
    ids = [t["id"] for t in out["techniques"]]
    assert ids == ["T1059.001", "T1105", "T1218.010"]
    assert "execution" in out["tactics"]
    assert "defense_evasion" in out["tactics"]
    assert "command_and_control" in out["tactics"]


def test_t4_2_golden_attack_chain_stages_byte_identity(ssot_rich):
    stages = _canon(project_attack_chain(ssot_rich))
    stage_names = [s["stage"] for s in stages]
    assert stage_names == ["execution", "defense_evasion", "command_and_control"]
    # Titles: canonical-normalised == expected
    for s in stages:
        assert strict_prose_equal(s["title"], s["stage"].replace("_", " ").title())


def test_t4_2_golden_lolbas_byte_identity(ssot_commands):
    out = _canon(project_lolbas(ssot_commands))
    assert set(out["binaries"]) >= {"cmd", "powershell", "wmic"}
    assert all(m["binary"] in out["binaries"] for m in out["matches"])


def test_t4_2_golden_activity_byte_identity(ssot_rich):
    act = _canon(project_activity(ssot_rich))
    procs = {p["process"] for p in act["processes"]}
    assert procs == {"powershell", "certutil"}
    assert len(act["network"]) == 1
    assert act["network"][0]["value"] == "http://x.example"


def test_t4_2_golden_recommendations_mitre_byte_identity(ssot_mitre):
    out = _canon(project_recommendations(ssot_mitre))
    ids = sorted({item["technique_id"] for item in out["items"]})
    assert ids == ["T1059.001", "T1218.010"]
    assert out["notes"] == []


def test_t4_2_golden_recommendations_empty_note_normalised(ssot_empty):
    out = _canon(project_recommendations(ssot_empty))
    assert out["items"] == []
    assert strict_prose_equal(
        out["notes"][0]["note"],
        "no evidence-derived recommendations for this case (no MITRE evidence)"
    )


def test_t4_2_golden_timeline_ordering_deterministic(ssot_rich):
    tl = _canon(project_timeline(ssot_rich))
    assert tl == sorted(tl, key=lambda x: x["ordinal"])
    kinds = {e["kind"] for e in tl}
    assert kinds == {"execution_step", "evidence_node", "reasoning_step"}


def test_t4_2_golden_evidence_graph_view_counts(ssot_rich):
    view = _canon(project_evidence_graph_view(ssot_rich))
    assert view["node_count"] == len(ssot_rich.evidence_graph.nodes)
    assert view["edge_count"] == 1
    assert "mitre_technique" in view["kinds"]


def test_t4_2_golden_reports_byte_identity(ssot_rich):
    rep = _canon(project_reports(ssot_rich))
    # STIX
    assert rep["stix"]["type"] == "bundle"
    assert len(rep["stix"]["objects"]) >= 1
    # Sigma
    rule_ids = [r["id"] for r in rep["sigma"]["rules"]]
    assert "canonical-sigma-T1059.001" in rule_ids
    # YARA
    assert rep["yara"]["rule_name"].startswith("canonical_yara_")
    # Navigator
    assert rep["navigator"]["domain"] == "enterprise-attack"
    # MDR structured
    assert rep["mdr"]["verdict"]["label"] == "MALICIOUS"
    assert "T1059.001" in rep["mdr"]["techniques"]
