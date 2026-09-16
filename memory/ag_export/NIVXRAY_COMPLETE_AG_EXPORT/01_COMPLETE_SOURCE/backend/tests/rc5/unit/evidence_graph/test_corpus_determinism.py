"""Phase 11.2 · Determinism CI gate for the Evidence Graph.

Runs the entire Golden Corpus **3× in a row** and asserts the emitted
Evidence Graph is **byte-identical** in its **canonical form** across
all runs. Determinism is a permanent quality gate — any regression here
is a `main` blocker.

CI wiring
---------
These tests are marked `slow` — the default `pytest` invocation (which
uses `-m "not slow"` from `pytest.ini`) SKIPS them so PR CI stays under
the wall-time budget. A nightly job runs `pytest -m "slow or not slow"`
to keep the determinism gate honest.

Note on canonical form
----------------------
`EvidenceGraph.to_canonical_json()` strips `source_node_ids` (which trace
back to random `ExecNode.id` UUIDs generated fresh each pipeline run).
The entity structure — node kinds, keys, attrs, edge topology — MUST
be identical across runs; only the raw provenance links change.

Guarantees
----------
* Same input → same node IDs (content-addressed).
* Same input → same edge IDs (content-addressed).
* Same input → same canonical JSON serialization.
* Integrity clean across all runs.
"""
from __future__ import annotations

from typing import List

import pytest

pytestmark = pytest.mark.slow

from engine.evidence_graph_builder import build_evidence_graph_sidecar
from engine.golden_corpus import GOLDEN_CORPUS
from engine.interpreters.cmd_interpreter import CmdInterpreter
from engine.interpreters.powershell_interpreter import PowerShellInterpreter
from engine.parsers.cmd_parser import CmdParser
from engine.parsers.powershell_parser import PowerShellParser


def _run_corpus_once() -> List[str]:
    """Execute the full corpus once. Returns one canonical JSON blob per
    sample, in stable corpus order."""
    outputs: List[str] = []
    for sample in GOLDEN_CORPUS:
        if sample["language"] == "powershell":
            parser, interp = PowerShellParser(), PowerShellInterpreter()
        else:
            parser, interp = CmdParser(), CmdInterpreter()
        exec_graph = interp.interpret(parser.parse(sample["input"]))
        graph, _ = build_evidence_graph_sidecar(exec_graph, force=True)
        assert graph is not None
        outputs.append(graph.to_canonical_json())
    return outputs


def test_corpus_is_byte_identical_across_three_runs():
    run1 = _run_corpus_once()
    run2 = _run_corpus_once()
    run3 = _run_corpus_once()
    assert len(run1) == len(GOLDEN_CORPUS)
    for i, (a, b, c) in enumerate(zip(run1, run2, run3)):
        sid = GOLDEN_CORPUS[i]["id"]
        assert a == b, f"non-determinism at {sid} between run1 and run2"
        assert b == c, f"non-determinism at {sid} between run2 and run3"


def test_content_addressed_ids_stable_across_runs():
    """Node/edge IDs are content-addressed → stable across runs
    (provenance UUIDs vary, IDs must not)."""
    def _snapshot():
        ids = []
        for sample in GOLDEN_CORPUS:
            if sample["language"] == "powershell":
                parser, interp = PowerShellParser(), PowerShellInterpreter()
            else:
                parser, interp = CmdParser(), CmdInterpreter()
            exec_graph = interp.interpret(parser.parse(sample["input"]))
            graph, _ = build_evidence_graph_sidecar(exec_graph, force=True)
            assert graph is not None
            ids.append((
                tuple(sorted(n.id for n in graph.nodes)),
                tuple(sorted(e.id for e in graph.edges)),
            ))
        return ids
    a, b = _snapshot(), _snapshot()
    assert a == b


def test_no_hard_errors_across_three_runs():
    for _ in range(3):
        for sample in GOLDEN_CORPUS:
            if sample["language"] == "powershell":
                parser, interp = PowerShellParser(), PowerShellInterpreter()
            else:
                parser, interp = CmdParser(), CmdInterpreter()
            exec_graph = interp.interpret(parser.parse(sample["input"]))
            graph, _ = build_evidence_graph_sidecar(exec_graph, force=True)
            assert graph is not None
            assert not graph.has_hard_errors(), (
                f"{sample['id']}: {graph.validate_integrity()}"
            )
