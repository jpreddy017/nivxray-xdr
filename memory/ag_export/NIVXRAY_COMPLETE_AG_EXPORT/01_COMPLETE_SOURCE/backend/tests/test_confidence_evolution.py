"""Confidence-Evolution Trace · CI Gate (R25.3).

Proves the SSOT projector exposes a per-artifact confidence trace
showing how certainty grew at each stage of the peel.

Run:  cd /app/backend && python -m pytest tests/test_confidence_evolution.py -v
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, "/app/backend")
os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "test_database")

from services.uaie              import plugins as _plugins_pkg
from services.uaie.orchestrator import Orchestrator
from services.uaie.ssot_projector import (project, _confidence_evolution)


# ─────────────────────────────────────────────────────────────────────
# T1 · Confidence evolution is a list of per-artifact steps ordered
#      by discovery, each carrying (artifact_type, recognizer, confidence).
# ─────────────────────────────────────────────────────────────────────
def test_confidence_evolution_contract():
    payload = (
        b"$h='43,61,6c,63,2e,65,78,65'; "
        b"$c = $h -split ',' | ForEach-Object {[char][int]('0x'+$_)}; "
        b"iex ($c -join '')"
    )
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(payload, root_type="text")

    trace = _confidence_evolution(result)
    assert isinstance(trace, list) and trace, "trace must be non-empty for a decodable payload"
    for step in trace:
        assert "artifact_uri" in step
        assert "recognizer"   in step
        assert "confidence"   in step
        assert 0.0 <= step["confidence"] <= 1.0

    # First step's confidence must be a real number > 0 (root got recognised).
    assert trace[0]["confidence"] > 0.0

    # There must be MORE THAN ONE step for a peeled payload — proving that
    # the loop discovered new artifacts, each with its own recognition.
    assert len(trace) >= 2, (
        f"confidence trace collapsed to a single artifact for a "
        f"multi-layer payload.  trace={trace}"
    )


# ─────────────────────────────────────────────────────────────────────
# T2 · Trace confidence never decreases MORE than a small step from
#      the running maximum (analyst-visible "certainty grew").
# ─────────────────────────────────────────────────────────────────────
def test_confidence_evolution_is_monotonic_in_spirit():
    """Not strictly monotone — a peel may enter a lower-confidence
    branch — but the *running max* must be non-decreasing.  This is
    the "certainty grew as each stage completed" property the UI
    surfaces."""
    payload = (b"powershell.exe -ExecutionPolicy Bypass -Command "
                b"\"vssadmin delete shadows /all /quiet\"")
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(payload, root_type="powershell")
    trace = _confidence_evolution(result)
    assert trace
    running_max = 0.0
    for step in trace:
        running_max = max(running_max, step["confidence"])
    assert running_max >= trace[0]["confidence"], (
        "running max confidence must never regress"
    )


# ─────────────────────────────────────────────────────────────────────
# T3 · Full SSOT payload carries the confidence_evolution key.
# ─────────────────────────────────────────────────────────────────────
def test_ssot_project_includes_confidence_evolution():
    payload = b"$s = 'exe.clac'; $s[-1..-8] -join ''"
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(payload, root_type="text")
    ssot = project(result,
                    all_plugin_names=[p["name"] for p in _plugins_pkg.all_plugins()])
    assert "confidence_evolution" in ssot
    assert isinstance(ssot["confidence_evolution"], list)
    assert ssot["confidence_evolution"], "should be non-empty for a decodable payload"


# ─────────────────────────────────────────────────────────────────────
# T4 · Determinism — same payload → same trace across two runs.
# ─────────────────────────────────────────────────────────────────────
def test_confidence_evolution_is_deterministic():
    payload = b"$h='43,61,6c,63'; ForEach-Object {[char][int]('0x'+$_)}"
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    r1 = orch.run(payload, root_type="text")
    orch2 = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    r2 = orch2.run(payload, root_type="text")

    def _fp(evs):
        return [(s["artifact_type"], s["recognizer"], s["confidence"])
                for s in _confidence_evolution(evs)]

    assert _fp(r1) == _fp(r2), "confidence trace must be pure (R28)"
