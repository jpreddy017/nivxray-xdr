"""Phase 4 Wave 1 · Observation infrastructure tests.

Locks:
  * `observation_store.record_observation` shapes the record correctly
    and never raises on garbage input.
  * `_to_record` produces the queryable schema owner needs.
  * The aggregator router endpoint is wired.
  * Latency is captured on every shadow invocation.
  * Persistence never blocks the primary verdict.
"""
from __future__ import annotations

import asyncio
import ast
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from v2.verdict.observation_store import _to_record, record_observation


# ══════════════════════════════════════════════════════════════════
# 1. Record shape
# ══════════════════════════════════════════════════════════════════
def test_to_record_flattens_full_shadow_payload():
    shadow = {
        "shadow_engine": "canonical-v2-verdict-1.0",
        "existing_verdict":  {"label": "Malicious", "confidence_pct": 73},
        "verdict_canonical": {"label": "Undetermined", "confidence_pct": 4},
        "input_completeness": {
            "buckets_populated": {
                "incident_metadata":  False, "asset_context":     False,
                "process_activity":   True,  "file_activity":     False,
                "network_activity":   False, "registry_activity": False,
                "authentication":     False, "threat_intel":      False,
                "historical":         False,
            },
            "populated_count":  1,
            "buckets_total":    9,
            "completeness_pct": 11,
            "coverage_class":   "minimal",
        },
        "divergence": {"class": "INPUT-CONTRACT-UNRESOLVED",
                             "explanation": "..."},
    }
    rec = _to_record("run-abc-001", shadow, latency_ms=12.75)
    assert rec["run_id"] == "run-abc-001"
    assert rec["shadow_engine"].startswith("canonical-v2-verdict")
    assert rec["existing_label"] == "Malicious"
    assert rec["existing_conf_pct"] == 73
    assert rec["canonical_label"] == "Undetermined"
    assert rec["canonical_conf_pct"] == 4
    assert rec["completeness_pct"] == 11
    assert rec["coverage_class"] == "minimal"
    assert rec["divergence_class"] == "INPUT-CONTRACT-UNRESOLVED"
    assert rec["shadow_latency_ms"] == 12.75
    assert "process_activity" not in rec["missing_buckets"]
    assert "file_activity" in rec["missing_buckets"]
    assert len(rec["missing_buckets"]) == 8


def test_to_record_handles_error_shadow():
    shadow = {"shadow_error": "SomeError: boom", "shadow_latency_ms": 3.1}
    rec = _to_record("run-err", shadow, latency_ms=3.1)
    assert rec["error"] == "SomeError: boom"
    assert rec["existing_label"] == ""
    assert rec["canonical_label"] == ""
    assert rec["completeness_pct"] == 0


def test_to_record_swallows_malformed_shadow():
    # Not a dict at all
    rec = _to_record("run-x", None, latency_ms=1.0)  # type: ignore[arg-type]
    assert rec["run_id"] == "run-x"


# ══════════════════════════════════════════════════════════════════
# 2. record_observation — fire-and-forget, never raises
# ══════════════════════════════════════════════════════════════════
def test_record_observation_no_op_on_none_shadow():
    # Must not raise, must not schedule anything
    record_observation("run-none", None, 0.0)


def test_record_observation_schedules_task_when_loop_running():
    async def _drive():
        with patch("v2.verdict.observation_store._persist_async",
                        new=AsyncMock()) as mock_persist:
            record_observation("run-loop",
                                     {"existing_verdict": {"label": "X"},
                                      "input_completeness": {"completeness_pct": 50}},
                                     latency_ms=1.5)
            # Give the event loop a tick to run the scheduled task
            await asyncio.sleep(0)
            assert mock_persist.await_count >= 1
    asyncio.run(_drive())


def test_record_observation_never_raises_on_persist_failure():
    async def _drive():
        with patch("v2.verdict.observation_store._persist_async",
                        new=AsyncMock(side_effect=RuntimeError("db down"))):
            # Must not raise despite persist failure
            record_observation("run-fail",
                                     {"existing_verdict": {"label": "X"}},
                                     latency_ms=1.5)
            await asyncio.sleep(0)
    asyncio.run(_drive())


# ══════════════════════════════════════════════════════════════════
# 3. Latency captured on the shadow payload
# ══════════════════════════════════════════════════════════════════
def test_shadow_includes_latency_ms():
    from v2.verdict.shadow import compute_shadow
    from nivxforge.investigation.graph import EvidenceGraph
    cio = MagicMock()
    cio.metadata = {"input_text_normalised": "hello"}
    cio.evidence_graph = EvidenceGraph()
    cio.verdict = {"label": "Undetermined", "confidence_pct": 0}
    r = compute_shadow(cio)
    assert r is not None
    assert "shadow_latency_ms" in r
    assert isinstance(r["shadow_latency_ms"], float)
    assert r["shadow_latency_ms"] >= 0.0


def test_shadow_latency_on_error_path():
    from v2.verdict.shadow import compute_shadow
    class _Garbage:  pass
    r = compute_shadow(_Garbage())
    assert r is not None
    # Either normal payload with latency, or error record with latency
    assert "shadow_latency_ms" in r


# ══════════════════════════════════════════════════════════════════
# 4. Router wiring — auto_investigate imports observation_store
# ══════════════════════════════════════════════════════════════════
def test_auto_investigate_imports_record_observation():
    p = Path("/app/backend/routers/auto_investigate.py")
    tree = ast.parse(p.read_text())
    imported = False
    called = False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module == "v2.verdict.observation_store":
                if any(n.name in ("record_observation",) for n in node.names):
                    imported = True
        if isinstance(node, ast.Call):
            fn = node.func
            name = (fn.attr if isinstance(fn, ast.Attribute)
                        else (fn.id if isinstance(fn, ast.Name) else ""))
            if name in ("record_observation", "_record_obs"):
                called = True
    assert imported, "auto_investigate.py must import record_observation"
    assert called,   "auto_investigate.py must invoke record_observation"


def test_observation_router_registered_in_server():
    src = Path("/app/backend/server.py").read_text()
    assert "from routers.observation import router as observation_router" in src
    assert "api.include_router(observation_router)" in src


# ══════════════════════════════════════════════════════════════════
# 5. Aggregator helper functions
# ══════════════════════════════════════════════════════════════════
def test_completeness_class_counts_deterministic_order():
    from routers.observation import _completeness_class_counts
    obs = [
        {"coverage_class": "minimal"},
        {"coverage_class": "sparse"},
        {"coverage_class": "sparse"},
        {"coverage_class": "moderate"},
        {"coverage_class": "rich"},
        {"coverage_class": "rich"},
        {"coverage_class": "rich"},
    ]
    out = _completeness_class_counts(obs)
    assert list(out.keys()) == ["minimal", "sparse", "moderate", "rich"]
    assert out == {"minimal": 1, "sparse": 2, "moderate": 1, "rich": 3}


def test_agreement_rate_by_class_computes_correctly():
    from routers.observation import _agreement_rate_by_class
    obs = [
        {"coverage_class": "rich",     "divergence_class": "AGREE"},
        {"coverage_class": "rich",     "divergence_class": "AGREE"},
        {"coverage_class": "rich",     "divergence_class": "POTENTIAL-FALSE-NEGATIVE"},
        {"coverage_class": "moderate", "divergence_class": "AGREE"},
    ]
    r = _agreement_rate_by_class(obs)
    assert r["rich"]["cases"] == 3
    assert r["rich"]["agree"] == 2
    assert r["rich"]["agree_pct"] == round(2/3*100, 2)
    assert r["rich"]["divergence"]["POTENTIAL-FALSE-NEGATIVE"] == 1
    assert r["moderate"]["cases"] == 1
    assert r["sparse"]["cases"] == 0


def test_missing_bucket_frequency_computes_correctly():
    from routers.observation import _missing_bucket_frequency
    obs = [
        {"missing_buckets": ["file_activity", "network_activity", "threat_intel"]},
        {"missing_buckets": ["file_activity", "threat_intel"]},
        {"missing_buckets": ["file_activity"]},
    ]
    r = _missing_bucket_frequency(obs)
    assert r["n_observations"] == 3
    assert r["buckets"]["file_activity"]["missing_count"] == 3
    assert r["buckets"]["file_activity"]["missing_pct"] == 100.0
    assert r["buckets"]["threat_intel"]["missing_count"] == 2
    assert "file_activity" in r["top_missing"]


def test_upstream_hint_flags_chronically_missing_buckets():
    from routers.observation import _upstream_ingestion_hint
    freq = {"buckets": {
        "process_activity": {"missing_pct": 5.0},
        "file_activity":    {"missing_pct": 92.0},
        "threat_intel":     {"missing_pct": 71.0},
        "authentication":   {"missing_pct": 40.0},
    }}
    r = _upstream_ingestion_hint(freq)
    names = {s["bucket"] for s in r["upstream_ingestion_suspects"]}
    assert "file_activity" in names
    assert "threat_intel"  in names
    assert "process_activity" not in names
    assert "authentication"   not in names
    # Sorted by missing_pct desc
    pcts = [s["missing_pct"] for s in r["upstream_ingestion_suspects"]]
    assert pcts == sorted(pcts, reverse=True)


def test_latency_stats_percentiles():
    from routers.observation import _latency_stats
    obs = [{"shadow_latency_ms": v} for v in
                (5.0, 10.0, 20.0, 40.0, 80.0, 160.0, 320.0, 640.0, 1280.0, 2560.0)]
    r = _latency_stats(obs)
    assert r["n"] == 10
    assert r["p50_ms"] <= r["p95_ms"] <= r["p99_ms"] <= r["max_ms"]


def test_extract_potential_cases_only_mod_and_rich():
    from routers.observation import _extract_potential_cases
    obs = [
        {"divergence_class": "POTENTIAL-FALSE-POSITIVE",
         "coverage_class": "minimal",
         "run_id": "r1", "existing_label": "U", "canonical_label": "M",
         "existing_conf_pct": 0, "canonical_conf_pct": 90, "completeness_pct": 15,
         "missing_buckets": []},
        {"divergence_class": "POTENTIAL-FALSE-POSITIVE",
         "coverage_class": "rich",
         "run_id": "r2", "existing_label": "U", "canonical_label": "M",
         "existing_conf_pct": 0, "canonical_conf_pct": 92, "completeness_pct": 78,
         "missing_buckets": []},
    ]
    r = _extract_potential_cases(obs, "POTENTIAL-FALSE-POSITIVE")
    assert len(r) == 1
    assert r[0]["run_id"] == "r2"


# ══════════════════════════════════════════════════════════════════
# 6. Zero legacy-engine imports in the observation infrastructure
# ══════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("path", [
    "/app/backend/v2/verdict/observation_store.py",
    "/app/backend/routers/observation.py",
])
def test_observation_infra_has_no_legacy_engine_imports(path):
    tree = ast.parse(Path(path).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            assert "nivxforge.investigation.verdict_engine" not in mod
            assert "engine.detectors.verdict_v2" not in mod
            assert "v2.semantic.ps_verdict" not in mod
