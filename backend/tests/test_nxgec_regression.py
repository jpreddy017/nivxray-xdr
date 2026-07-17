"""NXGEC Gold Corpus · deterministic regression suite.

Loads /app/backend/tests/fixtures/nxgec.jsonl and asserts a baseline
pass-rate. New archetype work is expected to only INCREASE this number.
"""
from __future__ import annotations

import json
import os
import pytest

from analysis_core import deterministic_best_decode
from operations import extract_iocs, mitre_map

try:
    from lolbas import scan_lolbas as _scan_lolbas
except Exception:  # noqa: BLE001
    _scan_lolbas = lambda t: []


FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "nxgec.jsonl")

# Baseline: any archetype work should only INCREASE this. If it drops, fail.
_MIN_PASS_RATE = 95.0    # % — Feb-2026 baseline (100% now; guardrail at 95%)


def _load():
    if not os.path.exists(FIXTURE):
        pytest.skip("nxgec fixture missing — run tests.fixtures.import_nxgec")
    with open(FIXTURE, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _mitre_covers(expected: set, got: set) -> bool:
    """T1059 in expected covers T1059.001 in got, and vice versa."""
    for e in expected:
        if e in got:
            continue
        base = e.split(".")[0]
        if any(g == e or g.startswith(base + ".") or g == base for g in got):
            continue
        return False
    return True


@pytest.fixture(scope="module")
def cases():
    return _load()


def test_fixture_present_and_populated(cases):
    assert len(cases) >= 50, f"expected ≥50 NXGEC cases, got {len(cases)}"
    volumes = {c.get("volume") for c in cases}
    assert volumes >= set(range(1, 11)), f"expected volumes 1..10, got {volumes}"


def test_baseline_mitre_coverage(cases):
    """% of NXGEC cases where our MITRE T-IDs cover the expected set."""
    covered = 0
    total_with_expected = 0
    for c in cases:
        exp = set(c.get("expected_mitre_ids") or [])
        if not exp:
            continue
        total_with_expected += 1
        scan = f"{c['input']}\n{deterministic_best_decode(c['input']).get('output', '')}"
        got = {m.get("id", "") for m in mitre_map(scan) if m.get("id")}
        if _mitre_covers(exp, got):
            covered += 1
    rate = covered * 100 / max(1, total_with_expected)
    print(f"\nNXGEC MITRE coverage: {covered}/{total_with_expected} = {rate:.1f}%")
    assert rate >= _MIN_PASS_RATE, (
        f"MITRE coverage regression: {rate:.1f}% < baseline {_MIN_PASS_RATE}%"
    )


def test_every_case_returns_output_without_crashing(cases):
    """No matter the input, deterministic_best_decode must not throw."""
    for c in cases:
        r = deterministic_best_decode(c["input"])
        assert isinstance(r, dict), f"case {c['id']} returned {type(r)}"
        assert "output" in r, f"case {c['id']} missing output key"


@pytest.mark.parametrize("volume", list(range(1, 11)))
def test_every_volume_has_at_least_one_pass(cases, volume):
    """Sanity: at least ONE case in every volume should pass MITRE match."""
    vol_cases = [c for c in cases if c.get("volume") == volume]
    if not vol_cases:
        pytest.skip(f"no cases in volume {volume}")
    at_least_one = False
    for c in vol_cases:
        exp = set(c.get("expected_mitre_ids") or [])
        if not exp:
            at_least_one = True
            break
        scan = f"{c['input']}\n{deterministic_best_decode(c['input']).get('output', '')}"
        got = {m.get("id", "") for m in mitre_map(scan) if m.get("id")}
        if _mitre_covers(exp, got):
            at_least_one = True
            break
    assert at_least_one, f"volume {volume}: zero cases passed — full regression!"
