"""Universal Family Recognizer + Skip-Reason Taxonomy · CI Gate.

Proves:
  1. `family.universal_recognizer` runs on every textual artifact type
     and emits family evidence with MITRE + tactic + `commonly_observed_in`.
  2. The Orchestrator emits STRUCTURED `skip_reason=<code>` entries so
     analysts can pinpoint why a specific capability didn't fire —
     no more log-diving.

Run:  cd /app/backend && python -m pytest tests/test_family_universal_and_skip_reasons.py -v
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, "/app/backend")
os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "test_database")

from services.uaie.orchestrator import Orchestrator
from services.uaie              import plugins as _plugins_pkg
from services.uaie.ledger       import (SKIP_NO_RECOGNIZER_MATCH,
                                          SKIP_MISSING_EVIDENCE_PREREQ,
                                          SKIP_CAPABILITY_ERROR)
from services.uaie.ssot_projector import _capability_coverage


# ─────────────────────────────────────────────────────────────────────
# T1 · The plugin is registered with the correct legacy wrapping.
# ─────────────────────────────────────────────────────────────────────
def test_family_universal_plugin_registered():
    plugins = {p["name"]: p for p in _plugins_pkg.all_plugins()}
    p = plugins.get("family.universal_recognizer")
    assert p, "family.universal_recognizer plugin missing"
    assert p["wraps_legacy"] == (
        "services.die.preprocessor.family_recognizer.recognize_families"
    )


# ─────────────────────────────────────────────────────────────────────
# T2 · Shadow-copy deletion is caught on a PowerShell artifact.
# ─────────────────────────────────────────────────────────────────────
def test_shadow_copy_deletion_family_matched_on_powershell():
    payload = (
        b"powershell.exe -NoProfile -Command "
        b"\"Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }\""
    )
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(payload, root_type="powershell")

    fam_evs = [ev for ev in result.evidence
                 if ev.kind == "family"
                 and ev.source_capability == "family.universal_recognizer"]
    assert fam_evs, (
        f"family.universal_recognizer did not emit for a Shadow-Copy "
        f"Deletion payload.  Evidence kinds: "
        f"{sorted({e.kind for e in result.evidence})}"
    )
    ids = {ev.meta.get("family_id") for ev in fam_evs}
    assert "shadow-copy-deletion" in ids, f"expected shadow-copy-deletion, got {ids}"
    # MITRE + tactic must ride along
    ev = next(ev for ev in fam_evs
               if ev.meta.get("family_id") == "shadow-copy-deletion")
    assert "T1490" in ev.mitre_techniques
    assert ev.kill_chain and "Impact" in ev.kill_chain


# ─────────────────────────────────────────────────────────────────────
# T3 · CMD-family payload — reg-add persistence.
# ─────────────────────────────────────────────────────────────────────
def test_registry_modification_family_matched_on_cmd():
    payload = (
        b"reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
        b"/v Updater /t REG_SZ /d C:\\Users\\Public\\payload.exe /f"
    )
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(payload, root_type="cmd")

    fam_evs = [ev for ev in result.evidence
                 if ev.kind == "family"
                 and ev.source_capability == "family.universal_recognizer"]
    assert fam_evs, "family.universal_recognizer failed on cmd reg-add"
    ids = {ev.meta.get("family_id") for ev in fam_evs}
    assert "registry-modification" in ids, f"expected registry-modification; got {ids}"


# ─────────────────────────────────────────────────────────────────────
# T4 · Family Recognizer NEVER emits noise on benign text.
# ─────────────────────────────────────────────────────────────────────
def test_family_recognizer_silent_on_benign_text():
    payload = b"Hello world.  This is a benign string with no tradecraft."
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(payload, root_type="text")

    fam_evs = [ev for ev in result.evidence
                 if ev.source_capability == "family.universal_recognizer"]
    assert not fam_evs, (
        f"family.universal_recognizer must not emit on benign text.  "
        f"Emitted: {[(ev.kind, ev.value) for ev in fam_evs]}"
    )


# ─────────────────────────────────────────────────────────────────────
# T5 · Structured skip-reason: no recognizer match on unknown blob.
# ─────────────────────────────────────────────────────────────────────
def test_skip_reason_no_recognizer_match_emitted():
    # 8-byte payload of a type nobody recognizes, root_type='unknown'.
    payload = b"\x00\x01\x02\x03\x04"
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(payload, root_type="unknown")

    reasons = [e.output_summary for e in result.ledger
                 if e.action == "schedule_skip"
                 and e.output_summary.startswith("skip_reason=")]
    assert any(SKIP_NO_RECOGNIZER_MATCH in r for r in reasons), (
        f"expected structured skip_reason={SKIP_NO_RECOGNIZER_MATCH!r} "
        f"in the ledger; found reasons={reasons!r}"
    )


# ─────────────────────────────────────────────────────────────────────
# T6 · capability_coverage surfaces skip_reasons per capability.
# ─────────────────────────────────────────────────────────────────────
def test_capability_coverage_exposes_skip_reasons():
    payload = b"Hello world benign string"
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(payload, root_type="text")

    all_names = [p["name"] for p in _plugins_pkg.all_plugins()]
    cov = _capability_coverage(result, all_names)
    assert "skip_reasons" in cov, "capability_coverage missing skip_reasons map"
    # Every entry in skip_reasons must be a known reason code.
    for cap_name, code in cov["skip_reasons"].items():
        assert code in {
            SKIP_NO_RECOGNIZER_MATCH,
            SKIP_MISSING_EVIDENCE_PREREQ,
            SKIP_CAPABILITY_ERROR,
            "artifact_type_mismatch", "depth_cap", "artifacts_cap",
            "already_seen", "unknown",
        }, f"unknown skip_reason code {code!r} for {cap_name!r}"


# ─────────────────────────────────────────────────────────────────────
# T7 · Family recognizer is deterministic (R28 purity).
# ─────────────────────────────────────────────────────────────────────
def test_family_recognizer_is_deterministic():
    payload = (b"powershell.exe -ExecutionPolicy Bypass -Command "
                b"\"vssadmin delete shadows /all /quiet\"")
    r1 = Orchestrator(recognizers=_plugins_pkg.all_recognizers()).run(
        payload, root_type="powershell")
    r2 = Orchestrator(recognizers=_plugins_pkg.all_recognizers()).run(
        payload, root_type="powershell")
    fam1 = sorted((ev.value, ev.meta.get("family_id"))
                   for ev in r1.evidence
                   if ev.source_capability == "family.universal_recognizer")
    fam2 = sorted((ev.value, ev.meta.get("family_id"))
                   for ev in r2.evidence
                   if ev.source_capability == "family.universal_recognizer")
    assert fam1 == fam2
    assert fam1, "family recognizer should have fired for vssadmin+bypass combo"
