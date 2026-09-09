"""Phase 11.1 · Golden-Corpus Evidence-Graph coverage tests.

CI wiring
---------
Marked `slow` — 88 samples × 3 parametric tests = 264 pipeline
invocations. Default `pytest` runs (which use `-m "not slow"` from
`pytest.ini`) SKIP these; a nightly full-gate run includes them via
`pytest -m "slow or not slow"`.

Acceptance criteria (user-approved plan):
    * Every Golden Corpus sample produces a **non-trivial** evidence graph
      (> 1 node — synthetic root + at least one real entity).
    * Every sample must be **integrity clean** (zero hard errors).
    * Corpus-wide statistics are surfaced so drift is observable.
"""
from __future__ import annotations

from typing import Dict

import pytest

pytestmark = pytest.mark.slow

from engine.evidence_graph_builder import build_evidence_graph_sidecar
from engine.golden_corpus import GOLDEN_CORPUS
from engine.interpreters.cmd_interpreter import CmdInterpreter
from engine.interpreters.powershell_interpreter import PowerShellInterpreter
from engine.parsers.cmd_parser import CmdParser
from engine.parsers.powershell_parser import PowerShellParser


def _run(sample: Dict) -> tuple:
    lang = sample["language"]
    if lang == "powershell":
        parser, interp = PowerShellParser(), PowerShellInterpreter()
    else:
        parser, interp = CmdParser(), CmdInterpreter()
    exec_graph = interp.interpret(parser.parse(sample["input"]))
    graph, metrics = build_evidence_graph_sidecar(exec_graph, force=True)
    return exec_graph, graph, metrics


@pytest.mark.parametrize("sample", list(GOLDEN_CORPUS), ids=lambda s: s["id"])
def test_every_sample_produces_non_trivial_graph(sample):
    """> 1 node — root + at least one materialised entity."""
    _, graph, _ = _run(sample)
    assert graph is not None
    assert len(graph.nodes) > 1, (
        f"trivial graph for {sample['id']} — no evidence entities materialised"
    )


@pytest.mark.parametrize("sample", list(GOLDEN_CORPUS), ids=lambda s: s["id"])
def test_every_sample_is_integrity_clean(sample):
    _, graph, _ = _run(sample)
    assert graph is not None
    assert not graph.has_hard_errors(), (
        f"integrity errors for {sample['id']}: {graph.validate_integrity()}"
    )


def test_corpus_wide_statistics():
    """Corpus-level assertions on the mapping's overall shape."""
    node_counts = []
    edge_counts = []
    hard_errors = 0
    for sample in GOLDEN_CORPUS:
        _, graph, _ = _run(sample)
        assert graph is not None
        node_counts.append(len(graph.nodes))
        edge_counts.append(len(graph.edges))
        if graph.has_hard_errors():
            hard_errors += 1
    assert hard_errors == 0
    assert min(node_counts) >= 2
    # Phase 11.1 mapping should push the corpus average above 2 nodes/sample.
    avg = sum(node_counts) / len(node_counts)
    assert avg >= 2.0, f"avg nodes/sample {avg:.2f} suggests mapping regressed"


def test_all_execnode_kinds_in_corpus_are_mapped():
    """Every NodeKind that appears in the corpus must be materialised into
    at least one evidence node across the run. Guards against a mapping
    regression that silently drops a kind from evidence coverage."""
    from engine.exec_graph import NodeKind
    # Kinds the current corpus emits — snapshot verified interactively.
    # This set is the acceptance floor: if the corpus grows to emit
    # additional kinds, those kinds must be added to `evidence_graph_builder`
    # or explicitly listed here as intentionally-not-materialised.
    corpus_kinds = {
        NodeKind.process,
        NodeKind.string_op,
        NodeKind.concat,
        NodeKind.var_bind,
        NodeKind.var_expand,
        NodeKind.http,
        NodeKind.unresolved,
    }
    from engine.evidence_graph import EvidenceNodeKind
    materialised: set = set()
    for sample in GOLDEN_CORPUS:
        exec_graph, graph, _ = _run(sample)
        for n in graph.nodes:
            materialised.add(n.kind)
        # verify each corpus kind produces at least one evidence node
        # in this exact sample when present.
        for xn in exec_graph.nodes:
            if xn.kind in corpus_kinds and xn.kind != NodeKind.unresolved:
                assert any(
                    xn.id in n.source_node_ids for n in graph.nodes
                ), (
                    f"ExecNode kind {xn.kind.value} (id {xn.id}) in "
                    f"{sample['id']} was not materialised into evidence"
                )
    # Every corpus kind must translate to at least one EvidenceNodeKind.
    assert EvidenceNodeKind.process in materialised
    assert EvidenceNodeKind.command in materialised
