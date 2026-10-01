"""
UAIE Phase 0 · Compatibility + Determinism CI Gates (Rule R26)

Three gates enforce the migration contract on every commit:

    1. Behaviour compatibility — each case in `tests/uaie_baseline/`
       must produce the same expected.json every run.
    2. Determinism             — every case must produce byte-identical
       output over 5 consecutive runs (Rule R26 amendment gate #1).
    3. Plugin independence     — reserved.  Disabling any single plugin
       leaves the rest of the engine running (Rule R26 amendment gate
       #2).  Activated when Phase 4 plugin scaffolding lands.

Any regression on these gates blocks the PR.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.uaie_baseline_capture import (
    _strip_volatile, build_expected, iter_cases,
)


CASES = list(iter_cases())


@pytest.mark.skipif(not CASES, reason="No cases under tests/uaie_baseline/")
@pytest.mark.parametrize("case", CASES,
                          ids=[str(c.relative_to(c.parents[1])) for c in CASES])
class TestUAIEBaselineCompatibility:
    """Rule R26 · Compatibility gate — expected.json is the golden contract."""

    def test_current_matches_expected(self, case: Path):
        expected_path = case / "expected.json"
        assert expected_path.exists(), (
            f"[{case.name}] expected.json missing — run "
            f"`python -m tests.uaie_baseline_capture --write` first."
        )
        expected = _strip_volatile(json.loads(expected_path.read_text()))
        current = _strip_volatile(
            build_expected((case / "input.txt").read_text(encoding="utf-8"))
        )
        for layer in ("evidence", "behavior", "graph", "verdict", "explainability"):
            assert current.get(layer) == expected.get(layer), (
                f"[{case.name}] R26 L·{layer} regression\n"
                f"expected: {expected.get(layer)}\n"
                f"current:  {current.get(layer)}"
            )


@pytest.mark.skipif(not CASES, reason="No cases under tests/uaie_baseline/")
@pytest.mark.parametrize("case", CASES,
                          ids=[str(c.relative_to(c.parents[1])) for c in CASES])
class TestUAIEDeterminismGate:
    """R26 amendment gate #1 — same input → byte-identical output ×5."""

    def test_five_runs_are_identical(self, case: Path):
        text = (case / "input.txt").read_text(encoding="utf-8")
        first = _strip_volatile(build_expected(text))
        for i in range(4):
            other = _strip_volatile(build_expected(text))
            assert other == first, (
                f"[{case.name}] non-deterministic on run {i + 2}"
            )
