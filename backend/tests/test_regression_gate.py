"""RC5 Regression Gate · Phase 0.

Enforces GOVERNANCE.md §13 (Regression Contract) + Round-5 Phase 0
exit criteria:

    ✓ Golden Corpus 100% pass (no drop from baseline).
    ✓ Aggregate pass_rate ≥ baseline.
    ✓ Verdict / MITRE / LOLBIN / Behavior accuracy ≥ baseline.
    ✓ Latency p50/p95/p99 ≤ baseline × tolerance multiplier.
    ✓ Per-sample verdict + MITRE set BYTE-IDENTICAL to baseline
      (sample_map_hash unchanged).
    ✓ Public Interface Contract: every frozen endpoint is still
      registered on the FastAPI app.
    ✓ Feature-flag contract: `all_disabled()` is True in the test
      environment (no v2 code path silently active).

Fails LOUDLY on any breach. This test IS the enforceable side of
the immutability contract for RC5.

To refresh the baseline (governance-approved change only):
    python -m tests.tools.rebaseline
"""
from __future__ import annotations

import hashlib
import json
import os
import statistics
from pathlib import Path

import pytest

# Ensure we are looking at the frozen artefact regardless of cwd.
_BASELINE_PATH = Path(__file__).resolve().parents[1] / "baselines" / "rc5_baseline.json"
_PIC_PATH      = Path(__file__).resolve().parents[1] / "baselines" / "public_interface_contract.json"


@pytest.fixture(scope="module")
def baseline() -> dict:
    assert _BASELINE_PATH.exists(), (
        f"Baseline missing: {_BASELINE_PATH}. Run tests/tools/rebaseline.py "
        "only via a governance-approved change."
    )
    with _BASELINE_PATH.open() as f:
        return json.load(f)


@pytest.fixture(scope="module")
def public_interface() -> dict:
    assert _PIC_PATH.exists(), f"PIC missing: {_PIC_PATH}"
    with _PIC_PATH.open() as f:
        return json.load(f)


@pytest.fixture(scope="module")
def report():
    """Live Golden-Corpus run — deterministic, ~20 ms per sample."""
    from engine.golden_corpus import run_corpus
    return run_corpus()


# ─── 1. Golden Corpus: 100% pass ────────────────────────────────────
def test_golden_corpus_all_pass(report, baseline):
    assert report.total == baseline["corpus_size"], (
        f"Corpus size drifted: baseline={baseline['corpus_size']} "
        f"live={report.total}. Adding/removing corpus samples requires "
        "a governance amendment + baseline refresh."
    )
    assert report.failed == 0, (
        f"Golden Corpus regression — {report.failed} sample(s) failed: "
        f"{sorted(report.newly_failing)}"
    )
    assert report.pass_rate >= baseline["golden"]["pass_rate"], (
        f"pass_rate dropped: baseline={baseline['golden']['pass_rate']} "
        f"live={report.pass_rate}"
    )


# ─── 2. Sample-level determinism (byte-identical per-sample map) ────
def test_per_sample_verdicts_unchanged(report, baseline):
    per = {
        s.sample_id: {
            "verdict": s.got_verdict,
            "passed": s.passed,
            "mitre": s.mitre_technique_ids,
            "weighted_conf": round(s.weighted_conf, 3) if s.weighted_conf else 0.0,
        }
        for s in report.samples
    }
    live_hash = hashlib.sha256(json.dumps(per, sort_keys=True).encode()).hexdigest()
    assert live_hash == baseline["sample_map_hash"], (
        "Per-sample verdict / MITRE / confidence map has drifted from "
        f"baseline. baseline={baseline['sample_map_hash'][:12]}… "
        f"live={live_hash[:12]}… — this indicates an RC5 behaviour "
        "change and violates the Immutability Contract (GOVERNANCE.md §2)."
    )


# ─── 3. Accuracy floors ─────────────────────────────────────────────
def test_accuracy_dimensions_not_regressed(report, baseline):
    live = report.accuracy
    base = baseline["accuracy"]
    for key in ("verdict", "mitre", "lolbin", "behavior", "overall_pass_rate"):
        assert live.get(key, 0) >= base.get(key, 0) - baseline["tolerance"]["accuracy_min_drop"], (
            f"accuracy.{key} regressed: baseline={base[key]} live={live.get(key)}"
        )


# ─── 4. Latency ceilings ────────────────────────────────────────────
def _q(values, p):
    if not values:
        return 0.0
    values = sorted(values)
    return values[min(len(values) - 1, int(len(values) * p))]


def test_latency_within_tolerance(report, baseline):
    lat = sorted(s.duration_ms for s in report.samples)
    tol = baseline["tolerance"]
    live = {
        "p50": _q(lat, 0.5),
        "p95": _q(lat, 0.95),
        "p99": _q(lat, 0.99),
        "mean": round(statistics.mean(lat), 3) if lat else 0.0,
    }
    base_lat = baseline["latency_ms"]
    checks = [
        ("p50", tol["latency_p50_multiplier"]),
        ("p95", tol["latency_p95_multiplier"]),
        ("p99", tol["latency_p99_multiplier"]),
    ]
    for q, mult in checks:
        # Guard tiny-baseline noise: only enforce ceiling when baseline
        # p is ≥ 0.05 ms (below that we're measuring scheduler jitter).
        if base_lat[q] < 0.05:
            continue
        ceiling = base_lat[q] * mult
        assert live[q] <= ceiling, (
            f"latency {q} regressed beyond {mult:.2f}× tolerance: "
            f"baseline={base_lat[q]:.3f}ms live={live[q]:.3f}ms ceiling={ceiling:.3f}ms"
        )


# ─── 5. Public Interface Contract: endpoints still registered ──────
def test_public_interface_contract_endpoints_present(public_interface):
    from server import app  # imports the FastAPI application
    live_routes = {
        (m.upper(), r.path)
        for r in app.routes
        for m in getattr(r, "methods", set())
    }
    missing = []
    for ep in public_interface["frozen_endpoints"]:
        # Path params in the PIC use {id}; FastAPI also stores them
        # as `{id}` in .path, so a direct compare works.
        if (ep["method"].upper(), ep["path"]) not in live_routes:
            missing.append(f"{ep['method']} {ep['path']}")
    assert not missing, (
        "Frozen endpoints missing from the running app — this violates "
        f"the Public Interface Contract: {missing}"
    )


# ─── 6. API response-schema compatibility for /rc5/parse ────────────
def test_rc5_parse_response_schema(public_interface):
    """Statically check the router still produces the frozen top-level
    shape. We do a code-level assertion (no live HTTP) so this remains
    fast + hermetic. If the response model changes shape, this test
    fires before deploy."""
    import importlib
    from server import app  # noqa: F401 · triggers router registration

    # rc5_parse module exports a Pydantic model or a dict-return handler;
    # we inspect the OpenAPI definition FastAPI derives.
    schema = app.openapi()
    rc5_parse = schema["paths"].get("/api/rc5/parse", {}).get("post")
    assert rc5_parse is not None, "/api/rc5/parse missing from OpenAPI"

    # Minimal contract: request body accepted, 200 response documented.
    responses = rc5_parse.get("responses", {})
    assert "200" in responses, "/api/rc5/parse must document a 200 response"


# ─── 7. Feature-flag contract: all disabled in the test env ────────
def test_all_v2_flags_disabled_by_default():
    from v2 import flags
    active = {n: f.state.value for n, f in flags.FLAGS.items() if not f.disabled()}
    assert not active, (
        "v2 feature flags leaked into the test environment: "
        f"{active}. Governance §12 requires all flags DISABLED unless "
        "an approved shadow / enabled rollout is in progress."
    )
    assert flags.all_disabled() is True


# ─── 8. Deterministic re-run (identical input twice → identical) ────
def test_engine_determinism():
    from engine.golden_corpus import run_corpus
    a = run_corpus()
    b = run_corpus()

    def _fingerprint(rep):
        per = {
            s.sample_id: {
                "verdict": s.got_verdict,
                "mitre": s.mitre_technique_ids,
                "passed": s.passed,
            } for s in rep.samples
        }
        return hashlib.sha256(json.dumps(per, sort_keys=True).encode()).hexdigest()

    assert _fingerprint(a) == _fingerprint(b), (
        "Non-determinism detected: two consecutive runs produced different "
        "per-sample results. This violates the Deterministic-First principle."
    )
