"""§ 12.6 — `--no-ai` mode produces byte-identical deterministic output.

Phase 1: this test asserts the *contract mechanism* by exercising the
`origin` discriminator + confidence rule 6.6. When there is no
deterministic pipeline yet to compare against, we assert:

  1. An advisor-origin node carries the discriminator.
  2. Advisor-origin nodes CANNOT enter a verdict-math path (encoded as
     an assertion that verdict-math helpers reject `origin="advisor"`).
  3. When we build two identical graphs — one with an advisor-origin
     narrative sibling, one without — the deterministic subgraph is
     byte-identical.

Phase 4+ will extend this test to run the full corpus twice (with & without
AI advisor) and diff the JSON of every deterministic field.
"""
from engine.exec_graph import ExecGraph, ExecNode, NodeKind


def _det_only(g: ExecGraph) -> ExecGraph:
    """Return a graph with all advisor-origin nodes removed."""
    return ExecGraph(
        nodes=tuple(n for n in g.nodes if n.origin == "deterministic"),
        schema_version=g.schema_version,
    )


def test_origin_discriminator_defaults_deterministic():
    assert ExecNode(kind=NodeKind.decode).origin == "deterministic"


def test_advisor_origin_marked_explicit():
    n = ExecNode(kind=NodeKind.decode, origin="advisor")
    assert n.origin == "advisor"


def test_deterministic_subgraph_byte_identical_with_or_without_advisor():
    """
    Build two graphs:
      G1 = decode → var_bind → process_spawn
      G2 = decode → var_bind → process_spawn + AI narrative sibling
    Assert their deterministic subgraphs are byte-identical when
    serialised to JSON.
    """
    d = ExecNode(kind=NodeKind.decode, reconstructed="base64-decode")
    v = ExecNode(kind=NodeKind.var_bind, inputs=(d.id,), reconstructed="SET X=notepad.exe")
    p = ExecNode(kind=NodeKind.process, inputs=(v.id,),
                 reconstructed="start notepad.exe", confidence=100)
    advisor = ExecNode(
        kind=NodeKind.decode, origin="advisor",
        reconstructed="AI narrative: sample launches notepad",
        confidence=100,
    )
    g1 = ExecGraph().add_node(d).add_node(v).add_node(p)
    g2 = ExecGraph().add_node(d).add_node(v).add_node(p).add_node(advisor)

    j1 = _det_only(g1).model_dump_json()
    j2 = _det_only(g2).model_dump_json()
    assert j1 == j2, "advisor node leaked into deterministic subgraph"


def test_advisor_nodes_dont_change_deterministic_count():
    d = ExecNode(kind=NodeKind.decode)
    ad = ExecNode(kind=NodeKind.decode, origin="advisor")
    g_no_ai = ExecGraph().add_node(d)
    g_with_ai = ExecGraph().add_node(d).add_node(ad)
    assert len(_det_only(g_no_ai).nodes) == len(_det_only(g_with_ai).nodes) == 1


def test_verdict_math_helper_rejects_advisor(monkeypatch):
    """When Phase 7 lands verdict math, this test locks the contract.

    Today we simulate the helper: given a list of nodes, sum confidences
    of deterministic-origin nodes only. If any advisor node's confidence
    is accidentally counted, the assertion fires.
    """
    def _det_conf_sum(nodes):
        return sum(n.confidence for n in nodes if n.origin == "deterministic")

    det = ExecNode(kind=NodeKind.decode, confidence=80)
    adv = ExecNode(kind=NodeKind.decode, origin="advisor", confidence=100)
    assert _det_conf_sum([det, adv]) == 80
    assert _det_conf_sum([det]) == 80
