"""User-Reported Cases · No-OUTPUT-EQUALS-INPUT Regression Gate (P4 · frozen).

Every case dropped into ``tests/uaie_baseline/11_user_reported/NNN_slug/``
becomes a permanent CI gate against the historical "OUTPUT = INPUT"
class of regression that has already recurred 5+ times in this project.

Contract enforced on every commit:

    1. `input.txt` exists and is non-empty.
    2. The UAIE pipeline PRODUCES a strictly-different terminal
       payload for that input (``output_text != input_text``).
    3. The evidence set for the case is NOT empty.
    4. Determinism — 5 identical runs.

Placeholder cases (``000_placeholder`` etc.) whose ``metadata.json``
declares ``artifact_type == "placeholder"`` are excluded so the gate
only enforces on real user-reported production payloads.

Drop a new case as:
    tests/uaie_baseline/11_user_reported/NNN_slug/
        input.txt          — the raw production payload
        metadata.json      — {"origin": "prod-YYYY-MM-DD", ...}
        (expected.json + slo.json optional; harness fills them)

Run:  cd /app/backend && python -m pytest tests/test_notdecoded_regression.py -v
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, "/app/backend")
os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "test_database")


_ROOT = Path("/app/backend/tests/uaie_baseline/11_user_reported")


def _real_user_cases():
    """Return every directory under 11_user_reported/ whose metadata
    marks it as a real user-reported payload (not a placeholder)."""
    cases = []
    if not _ROOT.exists():
        return cases
    for d in sorted(_ROOT.iterdir()):
        if not d.is_dir():
            continue
        meta = d / "metadata.json"
        if not meta.exists():
            continue
        try:
            m = json.loads(meta.read_text())
        except Exception:
            continue
        if m.get("artifact_type") == "placeholder":
            continue
        if not (d / "input.txt").exists():
            continue
        cases.append(d)
    return cases


_CASES = _real_user_cases()


@pytest.mark.skipif(not _CASES,
                    reason="No real user-reported cases under "
                              "tests/uaie_baseline/11_user_reported/ yet — "
                              "drop production JSON in NNN_slug/ to arm the gate.")
@pytest.mark.parametrize("case", _CASES,
                          ids=[c.name for c in _CASES])
class TestNotdecodedRegressionGate:
    """P4 · Permanent CI gate against the OUTPUT=INPUT regression class."""

    def _run(self, case: Path):
        from services.uaie              import plugins as _p
        from services.uaie.orchestrator import Orchestrator
        from services.uaie.ssot_projector import project

        raw = (case / "input.txt").read_bytes()
        orch = Orchestrator(recognizers=_p.all_recognizers())
        result = orch.run(raw, root_type="unknown")
        ssot = project(result, all_plugin_names=[p["name"] for p in _p.all_plugins()])
        return result, ssot

    # ── Gate 1 · Non-empty input ────────────────────────────────────
    def test_input_is_non_empty(self, case: Path):
        raw = (case / "input.txt").read_bytes()
        assert len(raw) > 0, f"[{case.name}] input.txt is empty"

    # ── Gate 2 · OUTPUT != INPUT ────────────────────────────────────
    # The core anti-regression contract.  If the pipeline can't peel
    # any layer off a user-reported payload the CI must fail.
    def test_output_is_strictly_different_from_input(self, case: Path):
        _, ssot = self._run(case)
        raw_in = (case / "input.txt").read_text(encoding="utf-8", errors="replace")
        out    = ssot.get("root_output") or ssot.get("output") or ""
        # Additional signal: verdict card may carry the terminal output.
        vc = ssot.get("verdict_card") or {}
        if not out and isinstance(vc, dict):
            out = str(vc.get("output_text") or "")
        assert out and out != raw_in, (
            f"[{case.name}] OUTPUT=INPUT regression — the UAIE loop "
            f"produced identical output for a user-reported payload.  "
            f"This is the historical Notdecoded class of bug and MUST "
            f"NEVER be merged.  "
            f"in_len={len(raw_in)} out_len={len(out)} "
            f"equal_prefix={out[:40]!r}"
        )

    # ── Gate 3 · Evidence must not be empty ─────────────────────────
    def test_at_least_one_evidence_emitted(self, case: Path):
        result, _ = self._run(case)
        assert result.evidence, (
            f"[{case.name}] no evidence emitted — a user-reported "
            f"payload must yield ≥ 1 evidence entry."
        )

    # ── Gate 4 · Determinism ────────────────────────────────────────
    def test_five_runs_are_deterministic(self, case: Path):
        raw = (case / "input.txt").read_bytes()
        from services.uaie              import plugins as _p
        from services.uaie.orchestrator import Orchestrator
        sigs = []
        for _ in range(5):
            r = Orchestrator(recognizers=_p.all_recognizers()).run(
                raw, root_type="unknown")
            sigs.append(sorted((e.kind, str(e.value)[:200],
                                  e.source_capability,
                                  tuple(e.mitre_techniques))
                                 for e in r.evidence))
        assert all(s == sigs[0] for s in sigs), (
            f"[{case.name}] non-deterministic UAIE run — R28 purity broken"
        )
