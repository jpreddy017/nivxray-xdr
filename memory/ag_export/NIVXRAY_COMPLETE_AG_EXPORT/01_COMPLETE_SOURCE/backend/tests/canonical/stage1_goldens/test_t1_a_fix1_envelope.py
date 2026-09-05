"""T1-A · Fix 1 ``acquisition_failed`` envelope golden.

Freezes the exact ``report_extraction`` shape emitted by
``services.die.investigation_results.render()`` when URL acquisition
returns ``ok=False``.  Any Stage-1 change that alters the on-wire
Fix 1 envelope MUST be caught by this test.
"""
from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from tests.canonical.stage1_goldens._harness import compare_or_capture


def _install_failed_acquisition(monkeypatch):
    from services.die import investigation_results as ir

    def _fake_classify(src):
        return {
            "ida_class": "threat_report_url",
            "url_intent": {"acquirable": True, "kind": "threat_report"},
            "artifacts": [{"type": "url", "canonical": src, "value": src,
                            "source": "test"}],
        }

    class _FailedAcq:
        def __init__(self, url):
            self.ok = False
            self.url = url
            self.article_text = ""
            self.structured_blocks = []

        def to_dict(self):
            return {
                "ok": False,
                "url": self.url,
                "status_code": 403,
                "error_code": "http_error",
                "engine": "trafilatura",
                "error_detail": "HTTP 403",
                "fetched_bytes": 0,
                "article_chars": 0,
                "anti_bot": False,
                "fallback_tried": False,
            }

    monkeypatch.setattr(ir, "_ida_classify", _fake_classify, raising=True)
    monkeypatch.setattr(ir, "_ida_acquire",  lambda u: _FailedAcq(u),
                         raising=True)


def test_t1_a_fix1_envelope_golden(monkeypatch):
    _install_failed_acquisition(monkeypatch)
    from services.die.investigation_results import render
    result = render("https://blocked.example.gov/advisory/403")
    obj = result.get("object") or {}
    report_extraction = obj.get("report_extraction") or {}

    # The Fix 1 envelope is the single contract this test protects.
    assert report_extraction.get("source") == "acquisition_failed", (
        "Fix 1 envelope regressed — 'source' key is not 'acquisition_failed'."
    )

    compare_or_capture("t1_a_fix1_envelope", report_extraction)
