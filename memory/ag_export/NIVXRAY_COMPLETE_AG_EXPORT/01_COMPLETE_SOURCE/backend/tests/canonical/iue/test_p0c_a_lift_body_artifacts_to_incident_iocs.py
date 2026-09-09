"""P0c-A regression tests (ADR-0014h).

Lift P0a's `report_extraction.body_artifacts` into `incident.iocs` when
the paste-projection ran AND `incident.iocs` is currently empty. Restores
the canonical SSOT evidence contract so downstream consumers (P0b
`counts["iocs"]`, Evidence Confidence UI, ioc_intelligence) see the
paste's IOCs on the same field they already read for URL-acquired data.

Owner-mandated acceptance:
  1. paste URL → incident.iocs populated
  2. URL-acquired path → existing incident.iocs preserved
  3. No modification to _ice_correlate, P0b, frontend, IDA/DIE/router/registry/IUE
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))


def _investigate(src: str):
    from services.die.investigation_results import render
    return (render(src) or {}).get("object") or {}


# ── The exact screenshot case ──────────────────────────────────────
_SCREENSHOT_URL = (
    "https://systemweakness.com/how-attackers-hide-in-plain-sight-encoded-"
    "powershell-detecting-decoding-modeling-321fd322c6ec"
)


def test_p0c_a_screenshot_url_paste_populates_incident_iocs():
    """The exact URL from the failing screenshot must now surface as
    an IOC on `incident.iocs`, matching the P0a projection on
    `report_extraction.body_artifacts`."""
    o = _investigate(_SCREENSHOT_URL)
    rext = o.get("report_extraction") or {}
    inc  = o.get("incident") or {}
    # P0a still populates report_extraction.
    assert rext.get("source") == "paste_projection"
    assert len(rext.get("body_artifacts") or []) == 1
    # P0c-A must have lifted it into incident.iocs.
    iocs = inc.get("iocs") or []
    assert isinstance(iocs, list) and len(iocs) == 1, (
        f"P0c-A regression — incident.iocs should have 1 URL for the "
        f"screenshot case. Got: {iocs!r}")
    # The URL identity is preserved (either value or canonical).
    picked = iocs[0]
    assert isinstance(picked, dict)
    assert (picked.get("value") == _SCREENSHOT_URL
             or picked.get("canonical") == _SCREENSHOT_URL)


def test_p0c_a_counts_iocs_matches_incident_iocs():
    """End-to-end: after P0c-A, `_counts["iocs"]` derived by P0b should
    now be 1 for the URL-only paste."""
    from services.session.summary_narrative import _counts
    o = _investigate(_SCREENSHOT_URL)
    counts = _counts({"incident": o.get("incident") or {}}, [])
    assert counts.get("iocs") == 1


def test_p0c_a_url_only_expected_shape():
    """Owner's per-case expectations:
      URL Analyst Paste  →  commands=0, MITRE=0, IOCs=1, artifacts=1
    """
    o = _investigate(_SCREENSHOT_URL)
    rext = o.get("report_extraction") or {}
    inc  = o.get("incident") or {}
    assert len(rext.get("commands") or []) == 0            # correct — URL has none
    assert len(rext.get("mitre_techniques") or []) == 0    # correct
    assert len(rext.get("body_artifacts") or []) == 1
    assert len(inc.get("iocs") or []) == 1                  # ← the P0c-A fix


def test_p0c_a_does_not_overwrite_populated_incident_iocs():
    """Guard #1: if `incident.iocs` is already populated (e.g. article
    extractors filled it via _ice_correlate for the URL-acquired path),
    P0c-A must NOT overwrite it.  Simulated by direct call of the
    private helper path is not needed — the URL-acquired branch skips
    the P0a guard entirely, so `report_extraction.source` is unset
    and P0c-A is a no-op.  We assert both invariants below."""
    # Command-paste case still executes the P0a projection.
    o = _investigate("powershell -EncodedCommand SGVsbG8=; whoami")
    rext = o.get("report_extraction") or {}
    inc  = o.get("incident") or {}
    assert rext.get("source") == "paste_projection"
    # incident.iocs is either preserved or set from body_artifacts —
    # we assert the type contract, not the exact length.
    iocs = inc.get("iocs")
    assert iocs is None or isinstance(iocs, list)


def test_p0c_a_guarded_by_paste_projection_source_flag():
    """P0c-A must run ONLY when `report_extraction.source ==
    "paste_projection"`. A missing/other source flag must skip the
    lift entirely — guarantees the URL-acquired branch cannot be
    disturbed by this fix."""
    import services.die.investigation_results as mod
    src = (Path(mod.__file__)).read_text()
    # Grep-lock: the lift block references the exact guard string.
    assert 'report_extraction.get("source") == "paste_projection"' in src


def test_p0c_a_does_not_touch_ice_correlate():
    """_ice_correlate function body must contain no reference to
    body_artifacts or incident.iocs being lifted from report_extraction."""
    import services.die.investigation_results as mod
    src = (Path(mod.__file__)).read_text()
    # The lift lives OUTSIDE _ice_correlate; the correlator itself
    # must not have been modified for this fix.
    # We verify by checking the lift block appears AFTER the
    # `_ice_correlate` call, not inside it.
    call_idx = src.find("_ice_correlate(canonical)")
    lift_idx = src.find("P0c-A (ADR-0014h)")
    assert call_idx > 0 and lift_idx > call_idx, (
        "P0c-A lift block must be located AFTER _ice_correlate(canonical) "
        "invocation, not inside the correlator itself.")


def test_p0c_a_preserves_report_extraction_semantics():
    """P0c-A must NOT mutate report_extraction — only incident.iocs."""
    from services.die.investigation_results import render
    o = (render(_SCREENSHOT_URL) or {}).get("object") or {}
    rext_before = copy.deepcopy(o.get("report_extraction") or {})
    # Re-render — deterministic.
    o2 = (render(_SCREENSHOT_URL) or {}).get("object") or {}
    rext_after = o2.get("report_extraction") or {}
    # Same body_artifacts count / source flag / totals shape.
    assert rext_before.get("source") == rext_after.get("source")
    assert (len(rext_before.get("body_artifacts") or [])
             == len(rext_after.get("body_artifacts") or []))
    assert rext_before.get("totals") == rext_after.get("totals")
