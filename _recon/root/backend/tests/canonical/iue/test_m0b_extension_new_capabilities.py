"""M0b-extension · Report Generator + Artifact Intelligence registrations (ADR-0014d).

Locks the two new class-A capabilities identified by the pre-M0f
architecture reassessment.  Passive registration only — nothing in
production consumes these via the registry today.

The reassessment classified 9 unmapped legacy stages:
  A (independent) — Report Generator, Artifact Intelligence   ← THIS EXTENSION
  B (bundled)     — DKP, Attack Intent, Attack Story, Preprocessor,
                    Chain Analyzer, Investigation Confidence
  C (legacy)      — CRE (Command Reconstruction)               ← LOCKED
  D (uncertain)   — (none)

The 6 B-classified stages MUST NOT be registered — they already execute
inside `die.command.v1` or `report.narrative.v1`, and registering them
would cause duplicate execution.  This test locks their absence.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from services.registry import (   # noqa: E402
    ADAPTER_REGISTRY,
    ANALYZER_REGISTRY,
    health_check,
)
from services.registry.iue_projection import (   # noqa: E402
    _LEGACY_ENGINE_TO_ENTRY_ID,
    plan_to_execution_steps,
)
from services.die.input_understanding import understand   # noqa: E402


# ── Report Generator ────────────────────────────────────────────────────
def test_report_narrative_registered_and_resolvable():
    entry = ANALYZER_REGISTRY.get("report.narrative.v1")
    assert entry.implementation_path == "services.die.narrative:generate_report"
    assert entry.kind == "analyzer"
    assert entry.live_today is True
    assert entry.accepts_formats == frozenset({"die_envelope"})
    report = health_check()
    assert report["report.narrative.v1"]["importable"] is True


def test_report_narrative_impl_is_callable():
    from services.die.narrative import generate_report
    assert callable(generate_report)


# ── Artifact Intelligence ───────────────────────────────────────────────
def test_artifact_intel_registered_and_resolvable():
    entry = ANALYZER_REGISTRY.get("artifact.intel.v1")
    assert entry.implementation_path == "services.artifact_intelligence:dispatch"
    assert entry.kind == "analyzer"
    assert entry.live_today is True
    assert entry.accepts_formats == frozenset({"bytes"})
    report = health_check()
    assert report["artifact.intel.v1"]["importable"] is True


def test_artifact_intel_impl_is_callable():
    from services.artifact_intelligence import dispatch
    assert callable(dispatch)


# ── Class-B stages MUST NOT be registered ───────────────────────────────
_BUNDLED_STAGE_FORBIDDEN_IDS = {
    # Any id containing these tokens would indicate a mistaken B → A
    # registration.  We assert none exist in either registry.
    "dkp.",
    "attack_intent",
    "attack.intent",
    "die.attack_story",
    "preprocessor.",
    "chain_analyzer",
    "chain.analyzer",
    "investigation_confidence",
    "investigation.confidence",
    "cre.",   # CRE is class-C (label only, no impl)
}


def test_no_bundled_or_legacy_capability_was_registered():
    all_ids = set(ADAPTER_REGISTRY.ids()) | set(ANALYZER_REGISTRY.ids())
    for token in _BUNDLED_STAGE_FORBIDDEN_IDS:
        matches = [i for i in all_ids if token in i]
        assert not matches, (
            f"M0b-extension MUST NOT register class-B/C stages. "
            f"Token {token!r} matched: {matches}. "
            f"Registering these would cause duplicate execution (B) "
            f"or reference a non-existent implementation (C).")


# ── Mapping table sanity ────────────────────────────────────────────────
def test_mapping_table_has_exactly_6_entries():
    """M0b-extension grows the mapping from 4 → 6.  Any further growth
    requires an explicit authorised migration."""
    assert len(_LEGACY_ENGINE_TO_ENTRY_ID) == 6
    assert _LEGACY_ENGINE_TO_ENTRY_ID["Report Generator"]      == "report.narrative.v1"
    assert _LEGACY_ENGINE_TO_ENTRY_ID["Artifact Intelligence"] == "artifact.intel.v1"


# ── SystemWeakness governance witness (must NOT fix URL) ────────────────
def test_systemweakness_projection_gains_report_but_not_url_acquire():
    u = understand("https://systemweakness.com/some-report", execute=False)
    proj = plan_to_execution_steps(u)
    got = [s.entry_id for s in proj.steps]
    # After M0b-extension the projection has 2 steps, not 1.
    assert got == ["ioc_enrichment.v1", "report.narrative.v1"], (
        f"SystemWeakness projection drifted from expected M0b-extension "
        f"shape.  Got: {got}")
    # CRITICAL: url.acquire.v1 MUST STILL BE ABSENT.  Adding it would
    # mean the M0b-extension accidentally started fixing the SystemWeakness
    # URL problem — that is IUE-side migration territory (M0h/M1/M4), LOCKED.
    assert "url.acquire.v1" not in got, (
        "M0b-extension MUST NOT introduce url.acquire.v1 into the "
        "SystemWeakness projection.  URL Acquisition remains in "
        "engines_skipped by design.")
    # Report Generator is now mapped, so unmapped_engines is empty here.
    assert proj.unmapped_engines == []


# ── M0a envelope hashes STILL byte-identical ─────────────────────────────
_M0A_EXPECTED = {
    "bare_url_medium_style": "febd68f13aab444b8018ee91dd0d97e0bd04b407d565aedffd9fef6038f93a00",
    "powershell_naked":      "92b9c1cf9c6ac52c6600fa6b3d12660a2a6641d89f3cc765d2cd350e6d1af56b",
    "plain_english_short":   "35aa379db9d4b99e5587825657092843d4ae775553ad5b0ebdbd528a29dd329b",
    "hex_ratio_long":        "7061f38454cd08a06cb092d6827779f30500d87abd57114caf31ebd4e1b97aad",
}
_M0A_CORPUS = {
    "bare_url_medium_style": "https://systemweakness.com/some-report",
    "powershell_naked":      "powershell.exe -EncodedCommand SGVsbG8=",
    "plain_english_short":   "the quick brown fox jumps over the lazy dog",
    "hex_ratio_long":        "4d5a" + "90" * 260,
}


@pytest.mark.parametrize("name", sorted(_M0A_CORPUS.keys()))
def test_m0a_iue_hashes_still_byte_identical(name):
    u = understand(_M0A_CORPUS[name], execute=False)
    got = hashlib.sha256(
        json.dumps(asdict(u), default=str, sort_keys=True).encode()).hexdigest()
    assert got == _M0A_EXPECTED[name], (
        f"M0b-extension changed the IUE envelope for {name!r} — "
        f"expected {_M0A_EXPECTED[name]}, got {got}. "
        "Passive registration must NEVER touch IUE behaviour.")


# ── Zero-producer proof for the two new capabilities ────────────────────
def test_new_capabilities_have_zero_new_router_wiring():
    """M0b-extension is PASSIVE.  Nothing outside the registry package
    and outside tests may import the new capabilities via the registry
    dispatch path.  (The IMPLEMENTATIONS themselves — generate_report,
    dispatch — are still callable directly from their own routes; that
    predates M0b-extension and is intentional.)

    We grep for `entry_id="report.narrative.v1"` / `entry_id="artifact.intel.v1"`
    outside the registry package to prove no shadow dispatch table was
    seeded.
    """
    targets = [_BACKEND / p for p in
                ("routers", "services", "canonical", "server.py",
                 "operations.py", "analysis_core.py", "evidence_extractor.py")]
    r = subprocess.run(
        ["grep", "-rln", "--include=*.py", "-E",
         r"entry_id\s*=\s*[\"'](report\.narrative\.v1|artifact\.intel\.v1)[\"']",
         *[str(p) for p in targets if p.exists()]],
        capture_output=True, text=True,
    )
    hits = [ln for ln in r.stdout.splitlines() if ln
            and "/services/registry/" not in ln
            and "/tests/" not in ln
            and "/__pycache__/" not in ln]
    assert not hits, (
        "M0b-extension MUST leave the two new entry_ids referenced ONLY "
        "from services/registry/.  Shadow dispatch found in:\n"
        + "\n".join(hits))


# ── Health check still fully green ──────────────────────────────────────
def test_health_check_has_zero_broken_entries():
    report = health_check()
    broken = {k: v for k, v in report.items() if not v["importable"]}
    assert not broken, (
        "Registry health-check broken entries under M0b-extension:\n"
        + json.dumps(broken, indent=2))
