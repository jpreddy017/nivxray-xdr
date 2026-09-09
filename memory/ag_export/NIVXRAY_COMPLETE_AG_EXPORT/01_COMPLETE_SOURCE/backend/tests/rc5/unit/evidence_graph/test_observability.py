"""Phase 11.0 · Evidence Graph observability — unit tests."""
from __future__ import annotations

import pytest

from engine.evidence_graph_config import EvidenceGraphMetrics
from engine.evidence_graph_observability import (
    aggregate, record, reset, set_window_size,
)


def _mk(build_ms: float, peak_kb: float, nodes: int = 3, edges: int = 2,
        integrity: int = 0) -> EvidenceGraphMetrics:
    return EvidenceGraphMetrics(
        node_count=nodes,
        edge_count=edges,
        build_ms=build_ms,
        peak_memory_kb=peak_kb,
        integrity_errors=integrity,
        exec_graph_schema_version=1,
        evidence_graph_schema_version=1,
    )


@pytest.fixture(autouse=True)
def _clear():
    reset()
    yield
    reset()


def test_empty_snapshot():
    s = aggregate()
    assert s.sample_count == 0
    assert s.error_count == 0
    assert s.total_seen == 0
    assert s.success_rate == 1.0
    assert s.build_ms_p50 == 0.0


def test_records_and_aggregates():
    for i, ms in enumerate([1.0, 2.0, 3.0, 4.0, 5.0]):
        record(_mk(ms, 100.0 + i))
    s = aggregate()
    assert s.sample_count == 5
    assert s.error_count == 0
    assert s.total_seen == 5
    assert s.success_rate == 1.0
    assert s.build_ms_max == 5.0
    assert s.build_ms_p50 == 3.0
    assert s.build_ms_p95 == 5.0


def test_error_reduces_success_rate():
    for _ in range(3):
        record(_mk(1.0, 10.0))
    record(None, error=True)
    s = aggregate()
    assert s.sample_count == 3
    assert s.error_count == 1
    assert s.total_seen == 4
    assert s.success_rate == 0.75


def test_window_bounds_the_deque():
    set_window_size(3)
    for ms in [1.0, 2.0, 3.0, 4.0, 5.0]:
        record(_mk(ms, 1.0))
    s = aggregate()
    assert s.sample_count == 3
    # Only the last 3 samples retained → build_ms_max = 5, p50 = 4
    assert s.build_ms_max == 5.0
    assert s.build_ms_p50 == 4.0
    set_window_size(500)


def test_integrity_errors_summed():
    record(_mk(1.0, 1.0, integrity=2))
    record(_mk(1.0, 1.0, integrity=3))
    s = aggregate()
    assert s.integrity_error_total == 5


def test_thread_safe_smoke():
    import threading
    def _writer():
        for _ in range(200):
            record(_mk(1.0, 1.0))
    threads = [threading.Thread(target=_writer) for _ in range(4)]
    for t in threads: t.start()
    for t in threads: t.join()
    s = aggregate()
    assert s.total_seen == 800
    assert s.sample_count in (500, 800)  # depending on window vs total
