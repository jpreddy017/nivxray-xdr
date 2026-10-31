"""Unit tests — Phase 4 · P1 · CEM + Recursive Child Artifact Pipeline.

Master architecture reference: `/app/memory/ARCHITECTURE.md` §4, §5, §6.
"""
from __future__ import annotations

from services.cem import emit_cem, CEM_VERSION
from services.recursive_child_pipeline import (
    process as rcp_process,
    flatten_for_correlation,
    MAX_DEPTH,
    MAX_CHILDREN,
)


def _case(**overrides):
    base = {
        "_id": "case-1",
        "id":  "case-1",
        "user_email": "t@t",
        "input": "powershell -c ...",
        "input_preview": "powershell -c ...",
        "output": "final canonical",
        "iedde": {
            "binary_artifact": {
                "kind": "PE",
                "subtype": "Executable",
                "routed_analysis": {
                    "artifact_type": "pe",
                    "capability_available": True,
                    "hashes": {"sha256": "a" * 64, "sha1": "b" * 40, "md5": "c" * 32},
                    "size": 4096,
                    "analysis": {
                        "findings": [
                            {"severity": "high",   "code": "packed",
                             "title": "UPX-like entropy", "detail": ""},
                            {"severity": "medium", "code": "no_pdb",
                             "title": "stripped", "detail": ""},
                        ],
                    },
                },
            },
        },
        "iedde_terminal_state": "binary_artifact_recovered",
        "canonical_confidence": 100,
        "canonical_confidence_reason": "recovered",
        "chain": ["b64d", "unhex", "utf8"],
        "iocs": {
            "urls":    ["http://evil.example/x"],
            "ips":     ["1.2.3.4"],
            "domains": ["evil.example"],
            "sha256":  ["a" * 64],
        },
        "mitre": [
            {"id": "T1059", "technique": "Command and Scripting Interpreter",
             "tactic": "Execution", "evidence": "powershell.exe"},
            {"id": "T1105", "technique": "Ingress Tool Transfer",
             "tactic": "Command and Control"},
        ],
        "verdict":      {"verdict": "Malicious", "interpreter": "powershell"},
        "verdict_card": {"risk_score": 85},
    }
    base.update(overrides)
    return base


# =====================================================================
# CEM emission
# =====================================================================
def test_cem_returns_full_schema_for_recorded_case():
    c = _case()
    cem = emit_cem(c)
    assert cem["cem_version"] == CEM_VERSION
    assert cem["artifact_id"] == "case-1"
    assert cem["convergence"]["reached"] is True
    assert cem["convergence"]["terminal_state"] == "binary_artifact_recovered"
    # canonical artifacts = canonical_text + binary_artifact
    kinds = [a["kind"] for a in cem["canonical_artifacts"]]
    assert "canonical_text" in kinds
    assert "binary_artifact" in kinds
    # Every event carries provenance
    assert cem["events"] and all("provenance" in ev for ev in cem["events"])
    # Analyzer findings surface as events
    assert any(ev.get("code") == "packed" for ev in cem["events"])
    # Indicators are normalised
    assert any(i["kind"] == "url" for i in cem["indicators"])
    assert any(i["kind"] == "sha256" for i in cem["indicators"])
    # MITRE preserves technique ids and tactics
    assert any(m["id"] == "T1059" for m in cem["mitre"])
    # Verdict summary populated
    assert cem["verdict"]["verdict"] == "Malicious"
    assert cem["verdict"]["risk_score"] == 85


def test_cem_convergence_false_when_terminal_state_is_stability_gate():
    c = _case(iedde_terminal_state="stability_gate")
    cem = emit_cem(c)
    assert cem["convergence"]["reached"] is False


def test_cem_handles_empty_case_gracefully():
    cem = emit_cem({})
    assert cem["cem_version"] == CEM_VERSION
    assert cem["convergence"]["reached"] is False
    assert cem["canonical_artifacts"] == []
    # A single bootstrap rte.convergence event is emitted even when the case
    # is empty, so downstream consumers always have a timeline anchor.
    assert len(cem["events"]) == 1
    assert cem["events"][0]["kind"] == "rte.convergence"
    assert cem["indicators"] == []
    assert cem["mitre"] == []


def test_cem_input_provenance_defaults_to_workspace_input():
    c = _case(input="powershell -c echo hi")
    cem = emit_cem(c)
    assert cem["input_provenance"] == "workspace_input"


def test_cem_input_provenance_detects_file_upload_from_pe_magic():
    c = _case(input="MZ\x00\x00binary bytes")
    cem = emit_cem(c)
    assert cem["input_provenance"] == "file_upload"


def test_cem_is_deterministic_same_input_same_output():
    c = _case()
    a = emit_cem(c)
    b = emit_cem(c)
    # Same schema, same values — deterministic.
    assert a == b


# =====================================================================
# Recursive Child Artifact Pipeline
# =====================================================================
def test_rcp_returns_empty_for_non_dict_input():
    assert rcp_process(None) == []
    assert rcp_process("not-a-dict") == []
    assert rcp_process({}) == []


def test_rcp_returns_empty_when_no_children_declared():
    routed = {"artifact_type": "pe", "analysis": {"findings": []}}
    assert rcp_process(routed) == []


def test_rcp_processes_office_macros_as_powershell_children():
    routed = {
        "artifact_type": "office",
        "analysis": {"macros": ["powershell.exe -EncodedCommand ZQBjAGgAbwA="]},
    }
    result = rcp_process(routed, depth=0)
    assert result, "expected at least one recursive child"
    child = result[0]
    assert child["type"] == "powershell"
    assert child["depth"] == 1
    assert child["provenance"] == "recursive_child_pipeline"
    # RTE ran on the snippet
    assert child["rte"] is not None
    assert child["rte"].get("terminal_state") in (
        "canonical", "stability_gate", "binary_artifact_recovered",
    )
    # Hash of canonical output is captured
    assert child.get("hash") is not None


def test_rcp_respects_max_depth():
    # Feed a payload that would recurse forever — bound must halt at MAX_DEPTH
    routed = {
        "artifact_type": "office",
        "analysis": {"macros": ["nested payload " * 10]},
    }
    budget = {"remaining": MAX_CHILDREN}
    r = rcp_process(routed, depth=MAX_DEPTH, budget=budget)
    assert r == []


def test_rcp_respects_budget():
    routed = {
        "artifact_type": "office",
        "analysis": {"macros": ["a" * 20] * 20},
    }
    budget = {"remaining": 2}
    result = rcp_process(routed, depth=0, budget=budget)
    assert len(result) <= 2
    assert budget["remaining"] == 0


def test_flatten_for_correlation_preserves_all_nodes():
    routed = {
        "artifact_type": "office",
        "analysis": {
            "macros": ["powershell.exe -Command echo one"],
            "embedded_files": [{"name": "child.docx"}],
        },
    }
    result = rcp_process(routed, depth=0)
    flat = flatten_for_correlation(result)
    assert len(flat) >= len(result)
    for f in flat:
        assert "type" in f and "depth" in f


def test_cem_child_artifacts_reads_from_recursive_children():
    c = _case()
    c["iedde"]["recursive_children"] = [
        {"type": "powershell", "label": "IEX...", "snippet": "IEX", "depth": 1,
         "hash": {"sha256": "d" * 64}, "provenance": "recursive_child_pipeline"},
    ]
    cem = emit_cem(c)
    assert cem["child_artifacts"]
    assert cem["child_artifacts"][0]["type"] == "powershell"
    assert cem["child_artifacts"][0]["depth"] == 1
