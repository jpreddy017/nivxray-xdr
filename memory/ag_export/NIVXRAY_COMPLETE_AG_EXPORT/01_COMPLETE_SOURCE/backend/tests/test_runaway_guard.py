"""Runaway loop guard — regression tests.

The Feb-2026 Cloudflare 524 incident post-mortem required a hard cap on
per-decode input size. These tests lock:

  1. Normal payloads (< 8 MB) run unchanged.
  2. Payloads larger than the cap short-circuit in < 500 ms with a clean
     `budget` terminal state — no fingerprint compute, no plugin dispatch.
  3. The stopped_reason carries an operator-actionable message.
"""
from __future__ import annotations

import time
import pytest

from engine import Orchestrator, AnalysisContext, Budget


def test_small_payload_runs_normally() -> None:
    ctx = AnalysisContext(budget=Budget())
    t0 = time.time()
    result = Orchestrator(ctx).run("SQBFAFgAKAA=")   # base64 UTF-16LE "IEX("
    elapsed = int((time.time() - t0) * 1000)
    assert result.terminal in ("complete", "english", "family-identified")
    assert elapsed < 2000


def test_runaway_guard_short_circuits_10mb_payload() -> None:
    """A 10 MB payload must NOT tie up the request thread with fingerprinting
    or plugin dispatch. Guard fires immediately, returns `budget` terminal.
    """
    big = "A" * (10 * 1024 * 1024)
    ctx = AnalysisContext(budget=Budget(wall_time_ms=8000))
    t0 = time.time()
    result = Orchestrator(ctx).run(big)
    elapsed = int((time.time() - t0) * 1000)
    assert elapsed < 500, f"guard should abort in <500ms, took {elapsed}ms"
    assert result.terminal == "budget"
    assert "runaway" in result.stopped_reason.lower() or \
           "cap" in result.stopped_reason.lower()
    # No plugins should have been dispatched
    assert result.plugin_report.layers_run == 0


def test_runaway_guard_preserves_first_2kb_of_payload_for_analyst_context() -> None:
    """When the guard fires, keep a short preview so the analyst can still
    see WHAT was submitted (first 2 KB) rather than a completely empty
    output block."""
    big = "prefix-that-should-survive-" + ("A" * (10 * 1024 * 1024))
    ctx = AnalysisContext(budget=Budget())
    result = Orchestrator(ctx).run(big)
    assert result.output.startswith("prefix-that-should-survive-")
    assert "bytes suppressed by runaway guard" in result.output


def test_moderate_payload_under_cap_is_not_guarded() -> None:
    """A 4 KB payload — well under the per-decode cap — should NOT trip
    the pre-fingerprint runaway guard.
    """
    mid = "AAAA" * (4 * 1024 // 4)
    assert len(mid) == 4 * 1024
    ctx = AnalysisContext(budget=Budget(max_depth=3, wall_time_ms=2_000))
    result = Orchestrator(ctx).run(mid)
    assert "per-decode input cap" not in (result.stopped_reason or "")
