"""Unit tests for the Verdict Engine v3.

Runs under pytest OR standalone via `python test_verdict_v3.py`.
"""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # /app/backend

from v2.verdict import score


def test_benign_notepad():
    v = score({"lane": "process", "label": "notepad.exe", "cmdline": "notepad.exe README.md",
               "entity": {"iid": "ent_process_1"}, "parent": {"iid": "explorer.exe"},
               "mitre": []})
    assert v.score == 0, v
    assert v.band == "benign"


def test_named_binary_neutral_powershell():
    """powershell.exe alone with no MITRE → score 0, NEVER malicious by name."""
    v = score({"lane": "process", "label": "powershell.exe",
               "cmdline": "powershell.exe -Version",
               "entity": {"iid": "ent_ps"}, "parent": {"iid": "explorer.exe"},
               "mitre": []})
    assert v.score == 0, f"expected 0, got {v.score} · {v.explanation}"
    assert v.band == "benign"


def test_named_binary_neutral_cmd_wbadmin_help():
    """wbadmin.exe /? — no backup destruction verb → not malicious."""
    v = score({"lane": "process", "label": "wbadmin.exe",
               "cmdline": "wbadmin.exe /?",
               "entity": {"iid": "ent_wb"}, "parent": {"iid": "cmd.exe"},
               "mitre": []})
    assert v.score == 0, v.explanation


def test_corroboration_cap_alone():
    """Even a critical MITRE + LSASS mention still only reaches `low` because
    only two related families (execution + credential) fire — no independent
    corroboration. Cannot escalate to `malicious` alone."""
    v = score({"lane": "process", "label": "unknown.exe",
               "cmdline": "unknown.exe --target lsass",
               "entity": {"iid": "ent_x"}, "parent": {"iid": "cmd.exe"},
               "mitre": ["T1003"]})
    assert v.score <= 70, f"expected ≤ 70 (single-cluster ceiling), got {v.score} · {v.explanation}"
    assert v.band != "critical"


def test_ransomware_chain_scores_critical():
    """Office → PS → wbadmin → vssadmin → mass writes → ransom note = critical."""
    v = score({
        "lane": "process", "label": "wbadmin.exe",
        "cmdline": "powershell.exe -EncodedCommand ABCDEFGHIJKL0123456789+/AAAA==; wbadmin delete catalog -quiet; vssadmin delete shadows /all",
        "entity": {"iid": "ent_wb"}, "parent": {"iid": "powershell.exe"},
        "mitre": ["T1490", "T1027"],
        "rule_id": "R.impact.wbadmin.catalog_delete",
    }, ctx={"file_writes_60s": 47, "entropy_jump": 0.85})
    assert v.band in ("malicious", "critical"), v.explanation
    assert v.score >= 71


def test_expected_parent_decays():
    v = score({"lane": "process", "label": "svchost.exe",
               "cmdline": "svchost.exe -k netsvcs",
               "entity": {"iid": "ent_svc"}, "parent": {"iid": "services.exe"},
               "mitre": []})
    assert v.score == 0, v.explanation
    signals = {b["signal"] for b in v.breakdown}
    assert "EXPECTED_PARENT_CHILD" in signals
    assert "NO_MITRE_TAGS" in signals


def test_suspicious_parent_office_shell():
    v = score({"lane": "process", "label": "powershell.exe",
               "cmdline": "powershell.exe -Command Get-Process",
               "entity": {"iid": "ent_ps2"}, "parent": {"iid": "winword.exe"},
               "mitre": []})
    assert v.score > 0, v.explanation
    signals = {b["signal"] for b in v.breakdown}
    assert "SUSPICIOUS_PARENT" in signals


def test_family_cap_persistence():
    """Multiple persistence signals — final family contribution ≤ FAMILY_CAPS[persistence]."""
    v = score({
        "lane": "registry", "label": "reg add",
        "action": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Backdoor",
        "target": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Backdoor",
        "entity": {"iid": "ent_reg"}, "parent": {"iid": "cmd.exe"},
        "mitre": ["T1547"],
        "cmdline": "schtasks /create /tn EvilTask /tr evil.exe",
    })
    persist_sum = sum(b["effective_weight"] for b in v.breakdown if b["family"] == "persistence")
    assert persist_sum <= 30, f"family cap violated: {persist_sum}"


def test_determinism_over_iterations():
    evt = {"lane": "process", "label": "wbadmin.exe",
           "cmdline": "wbadmin delete catalog -quiet",
           "entity": {"iid": "ent_wb"}, "parent": {"iid": "cmd.exe"},
           "mitre": ["T1490"], "rule_id": "R.impact.wbadmin"}
    first = score(evt)
    for _ in range(500):
        v = score(evt)
        assert v.score == first.score
        assert v.band == first.band


if __name__ == "__main__":
    fns = [f for name, f in list(globals().items()) if name.startswith("test_")]
    ok, fail = 0, 0
    for fn in fns:
        try:
            fn()
            print(f"  ✓ {fn.__name__}")
            ok += 1
        except AssertionError as e:
            print(f"  ✗ {fn.__name__} · {e}")
            fail += 1
    print(f"\n{ok}/{ok+fail} passed")
    sys.exit(0 if fail == 0 else 1)
