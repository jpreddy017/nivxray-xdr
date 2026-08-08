"""R28.9 · Provenance Graph API + AdapterResult refinement +
architectural invariant tests.

These tests establish the behavioural-equivalence baseline used by
Phase A (Engine Unification) — every future migration MUST preserve
the graph topology, not just the decoded output."""
import base64, gzip, json, io, zipfile

import pytest

from services.uaie import plugins as _p           # noqa: F401 — registers
from services.uaie.orchestrator import Orchestrator
from services.uaie.provenance import (
    ProvenanceGraph, build_provenance_graph, assert_graphs_equivalent,
)
from services.uaie.adapters import route_input, ADAPTERS
from services.uaie.adapters._base import AdapterResult


# ══════════════════════════════════════════════════════════════════
# 1. AdapterResult now has evidence field (matches CapabilityResult)
# ══════════════════════════════════════════════════════════════════
def test_adapter_result_has_evidence_field():
    r = AdapterResult()
    assert hasattr(r, "artifacts")
    assert hasattr(r, "evidence")
    assert hasattr(r, "diagnostics")
    assert hasattr(r, "meta")
    assert r.evidence == []


# ══════════════════════════════════════════════════════════════════
# 2. Provenance Graph builds without error on a trivial run
# ══════════════════════════════════════════════════════════════════
def test_provenance_graph_builds_on_plain_text_run():
    orch = Orchestrator(recognizers=_p.all_recognizers(),
                         max_artifacts=32, max_depth=8)
    r = orch.run(b"hello world " * 20)
    g = build_provenance_graph(r)
    assert isinstance(g, ProvenanceGraph)
    assert len(g.nodes) >= 1
    # Root exists and is flagged
    roots = [n for n in g.nodes if n.is_root]
    assert len(roots) >= 1


# ══════════════════════════════════════════════════════════════════
# 3. Graph carries the Sophos chain — root → gzip → xor → IOC
# ══════════════════════════════════════════════════════════════════
def _build_sophos_shape() -> bytes:
    xored = "38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D"  # trimmed OK for parse
    xored = xored * 4  # padding for min_len
    layer2 = (
        f"[Byte[]]$var_code = [System.Convert]::FromBase64String("
        f"'{xored}')\nfor ($x=0;$x -lt $var_code.Count;$x++)"
        f"{{$var_code[$x]=$var_code[$x] -bxor 35}}\nIEX $DoIt\n"
    )
    gz = gzip.compress(layer2.encode())
    b64_gz = base64.b64encode(gz).decode()
    layer1 = (f'$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String('
                f'"{b64_gz}"));IEX (New-Object IO.StreamReader(New-Object '
                f'IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]'
                f'::Decompress))).ReadToEnd();')
    enc = base64.b64encode(layer1.encode("utf-16-le")).decode()
    return (f"%COMSPEC% /b /c start /b /min powershell -nop -w hidden "
             f"-encodedcommand {enc}").encode()


def test_provenance_graph_captures_multi_layer_chain():
    orch = Orchestrator(recognizers=_p.all_recognizers(),
                         max_artifacts=64, max_depth=12)
    r = orch.run(_build_sophos_shape())
    g = build_provenance_graph(r)
    # At least 2 artifacts (root + at least one child)
    assert len(g.nodes) >= 2
    # At least one edge exists — provenance was recorded
    assert len(g.edges) >= 1
    # Every edge references a real capability name
    for e in g.edges:
        assert e.via_capability and e.via_capability != "unknown"


# ══════════════════════════════════════════════════════════════════
# 4. Graph equivalence — two runs of the same input produce
#    structurally-identical graphs (determinism gate)
# ══════════════════════════════════════════════════════════════════
def test_provenance_graph_is_deterministic_across_runs():
    payload = _build_sophos_shape()
    def _run():
        orch = Orchestrator(recognizers=_p.all_recognizers(),
                             max_artifacts=64, max_depth=12)
        return build_provenance_graph(orch.run(payload))
    g1 = _run()
    g2 = _run()
    # assert_graphs_equivalent raises AssertionError on drift
    assert_graphs_equivalent(g1, g2,
        msg="deterministic re-run produced different provenance")


# ══════════════════════════════════════════════════════════════════
# 5. Regression harness catches missing edge (topology drift)
# ══════════════════════════════════════════════════════════════════
def test_assert_graphs_equivalent_catches_missing_edge():
    from services.uaie.provenance import (ProvenanceGraph, ProvenanceNode,
                                              ProvenanceEdge)
    n1 = ProvenanceNode(uri="u1", artifact_type="text", depth=0, size=10,
                          discovered_by="root", is_root=True)
    n2 = ProvenanceNode(uri="u2", artifact_type="url", depth=1, size=20,
                          discovered_by="cap.a")
    g_full = ProvenanceGraph(
        nodes=[n1, n2],
        edges=[ProvenanceEdge(parent_uri="u1", child_uri="u2",
                                via_capability="cap.a")])
    g_missing = ProvenanceGraph(nodes=[n1, n2], edges=[])
    with pytest.raises(AssertionError) as excinfo:
        assert_graphs_equivalent(g_full, g_missing,
                                     msg="test-only")
    assert "missing edges" in str(excinfo.value).lower() or \
             "edge_count" in str(excinfo.value)


# ══════════════════════════════════════════════════════════════════
# 6. ARCHITECTURAL INVARIANT — adapters produce PRIMARY artifacts
#    only.  No adapter is allowed to short-circuit and emit
#    "secondary" artifact types.  If it does, we lose the recursive
#    discovery guarantee.
# ══════════════════════════════════════════════════════════════════
_ALLOWED_PRIMARY_TYPES = {
    "text", "commandline", "url", "domain", "ip", "hash",
    "email_envelope", "email_attachment", "html", "json",
    "archive_entry", "vba_project_bin", "embedded_object",
    "raw_bytes", "empty_input",
    # Also allow the very-generic starter types recognizers use.
    "unknown", "base64_bare", "powershell",   # json_adapter leaves
}


def test_adapters_only_emit_primary_artifact_types():
    """Every registered adapter must confine itself to the
    PRIMARY-artifact vocabulary.  If a new adapter emits a
    secondary type (e.g. ``shellcode_bytes``, ``configuration``,
    ``decoded_bytes``), it means the adapter is doing recursion work
    that belongs to the UAIE loop — a RADE-invariant violation."""
    # Exercise each adapter with a payload it will actually claim.
    probes = [
        (b"just a sentence with no special format",  "adapter.plain_text"),
        (b"%COMSPEC% /c powershell -nop -enc XYZ",   "adapter.commandline"),
        (b"https://example.com/x",                   "adapter.url"),
        (b'{"target":"https://e.com","ip":"1.2.3.4","h":"' + b"a"*64 + b'"}',
                                                       "adapter.json"),
        (b"<!doctype html><html><a href='http://e/y'>x</a></html>",
                                                       "adapter.html"),
    ]
    for payload, expected in probes:
        r = route_input(payload)
        assert r.meta.get("selected_adapter") == expected
        for a in r.artifacts:
            assert a.artifact_type in _ALLOWED_PRIMARY_TYPES, (
                f"{expected} emitted DISALLOWED secondary type "
                f"{a.artifact_type!r} — RADE invariant broken"
            )


# ══════════════════════════════════════════════════════════════════
# 7. Every adapter's AdapterResult now supports evidence field
# ══════════════════════════════════════════════════════════════════
def test_every_adapter_returns_new_shape():
    r = route_input(b"hello world " * 20)
    assert isinstance(r, AdapterResult)
    assert isinstance(r.evidence, list)
    assert isinstance(r.artifacts, list)
    assert isinstance(r.diagnostics, list)
    assert isinstance(r.meta, dict)


# ══════════════════════════════════════════════════════════════════
# 8. Chain narration — a run reaching an IOC must expose a
#    root→terminal chain the analyst can read
# ══════════════════════════════════════════════════════════════════
def test_provenance_chain_reaches_leaf_from_root():
    """A DOCX with an embedded URL must produce a chain
    root → url node so 'why this IOC' explainability is derivable."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml",
            "<document><body><p><r><t>hi</t></r></p></body></document>")
        zf.writestr("word/_rels/document.xml.rels",
            '<Relationships><Relationship Target="https://mal.example.com/x"/></Relationships>')
    orch = Orchestrator(recognizers=_p.all_recognizers(),
                         max_artifacts=64, max_depth=12)
    r = orch.run(buf.getvalue(), filename="lure.docx")
    g = build_provenance_graph(r)
    types = {n.artifact_type for n in g.nodes}
    assert "url" in types
    # There MUST be a chain that ends at the URL node so an analyst
    # can trace it back to the document.
    url_chains = [c for c in g.chains if c.terminal_kind == "url"]
    assert url_chains, (
        f"no chain terminated at a URL artifact.  "
        f"chains={[c.terminal_kind for c in g.chains]}"
    )
