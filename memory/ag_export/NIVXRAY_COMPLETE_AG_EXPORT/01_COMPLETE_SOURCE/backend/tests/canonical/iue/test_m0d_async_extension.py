"""M0d-async-extension · Router awaits async callables (ADR-0014f).

Owner-mandated coverage (M0d-async authorisation, 2026-02-15):
  1. Sync callable remains byte-identical.
  2. Async callable is actually awaited.
  3. Coroutine object is NEVER returned as SUCCESS.
  4. Async result is captured in StepOutcome.result.
  5. Async exception → EXECUTION_FAILED.
  6. Async dependency ordering remains deterministic.
  7. Existing 20/20 equivalence results remain unchanged.
  8. M0a SHA-256 baselines remain unchanged.
  9. SystemWeakness remains unchanged.

Constraint: NO nested event loops.  Router uses `asyncio.run()` when
no loop is running, else runs the awaitable in a fresh thread with its
own loop.  The router itself remains synchronous.  Callables themselves
are NOT modified.
"""
from __future__ import annotations

import asyncio
import inspect
import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

# Register a test-scope async callable in the registry so the router
# can dispatch it via a stable entry_id.  We patch the registry only
# for these tests (via monkeypatch); production registry is untouched.
from services.registry import ADAPTER_REGISTRY, ANALYZER_REGISTRY, RegistryEntry  # noqa: E402
from services.registry.router import (   # noqa: E402
    ExecutionStep,
    StepStatus,
    execute_plan,
    _resolve_awaitable,
)


# ── Test-scope async fixtures ────────────────────────────────────────
async def _async_double(*, x: int) -> int:
    await asyncio.sleep(0)   # ensure it's a real coroutine
    return x * 2


async def _async_boom(**_kwargs) -> int:
    await asyncio.sleep(0)
    raise ValueError("intentional async failure")


async def _async_dict_producer(**_kwargs) -> dict:
    await asyncio.sleep(0)
    return {"kind": "async_dict", "value": 42}


@pytest.fixture
def _isolated_registry():
    """Snapshot and restore ANALYZER_REGISTRY._entries around a test.
    Prevents test-scope injections from leaking into other tests."""
    snapshot = dict(ANALYZER_REGISTRY._entries)
    yield
    ANALYZER_REGISTRY._entries.clear()
    ANALYZER_REGISTRY._entries.update(snapshot)


def _register_test_capability(entry_id: str, fn) -> None:
    """Inject a test-only registry entry pointing at `fn` in this module.
    Requires the caller to use the `_isolated_registry` fixture so the
    injection is torn down at test end."""
    this_mod = __name__
    entry = RegistryEntry(
        entry_id=entry_id, kind="analyzer", version="1",
        implementation_path=f"{this_mod}:{fn.__name__}",
        accepts_formats=frozenset({"test"}),
        role="test-only async capability",
        live_today=False,
    )
    ANALYZER_REGISTRY._entries[entry.entry_id] = entry


# ── Axis 1 · sync remains byte-identical ─────────────────────────────
def test_sync_callable_returns_verbatim_result():
    outcomes = execute_plan([
        ExecutionStep(step_id="s0", entry_id="text.passthrough.v1",
                       inputs={"object": "hello"}),
    ])
    assert outcomes[0].status == StepStatus.SUCCESS
    assert outcomes[0].result == "hello"
    assert type(outcomes[0].result) is str   # never a coroutine


# ── Axis 2/3/4 · async callable is awaited, returns real result ─────
def test_async_callable_is_awaited(_isolated_registry):
    _register_test_capability("test.async_double.v1", _async_double)
    outcomes = execute_plan([
        ExecutionStep(step_id="s0", entry_id="test.async_double.v1",
                       inputs={"x": 21}),
    ])
    assert outcomes[0].status == StepStatus.SUCCESS
    # Real awaited result — not a coroutine object.
    assert outcomes[0].result == 42
    assert not inspect.iscoroutine(outcomes[0].result)


def test_async_result_is_captured_in_step_outcome(_isolated_registry):
    _register_test_capability("test.async_dict.v1", _async_dict_producer)
    outcomes = execute_plan([
        ExecutionStep(step_id="s0", entry_id="test.async_dict.v1"),
    ])
    assert outcomes[0].result == {"kind": "async_dict", "value": 42}


def test_coroutine_object_never_captured_as_success(_isolated_registry):
    """Regression witness — the exact bug the equivalence harness surfaced."""
    _register_test_capability("test.async_double.v1", _async_double)
    outcomes = execute_plan([
        ExecutionStep(step_id="s0", entry_id="test.async_double.v1",
                       inputs={"x": 3}),
    ])
    assert not inspect.iscoroutine(outcomes[0].result)
    assert not inspect.isawaitable(outcomes[0].result)
    assert isinstance(outcomes[0].result, int)


# ── Axis 5 · async exception → EXECUTION_FAILED ─────────────────────
def test_async_exception_becomes_execution_failed(_isolated_registry):
    _register_test_capability("test.async_boom.v1", _async_boom)
    outcomes = execute_plan([
        ExecutionStep(step_id="s0", entry_id="test.async_boom.v1"),
    ])
    assert outcomes[0].status == StepStatus.EXECUTION_FAILED
    assert "intentional async failure" in outcomes[0].error
    assert outcomes[0].error_type == "ValueError"


# ── Axis 6 · async dependency ordering deterministic ────────────────
def test_async_dependency_ordering_deterministic(_isolated_registry):
    _register_test_capability("test.async_double.v1", _async_double)
    plan = [
        ExecutionStep(step_id="a", entry_id="test.async_double.v1",
                       inputs={"x": 1}),
        ExecutionStep(step_id="b", entry_id="test.async_double.v1",
                       inputs={"x": 2}, depends_on=frozenset({"a"})),
        ExecutionStep(step_id="c", entry_id="test.async_double.v1",
                       inputs={"x": 3}, depends_on=frozenset({"b"})),
    ]
    r1 = execute_plan(plan)
    r2 = execute_plan(plan)
    assert [o.result for o in r1] == [2, 4, 6]
    assert [o.result for o in r2] == [2, 4, 6]
    assert [o.step_id for o in r1] == ["a", "b", "c"]


# ── Axis 7 · nested-event-loop safety ────────────────────────────────
def test_router_works_inside_running_event_loop(_isolated_registry):
    """No nested asyncio.run() — must succeed even when called from
    inside an already-running event loop."""
    _register_test_capability("test.async_double.v1", _async_double)

    async def _driver():
        # This block is running inside asyncio.run's event loop.
        outcomes = execute_plan([
            ExecutionStep(step_id="s0", entry_id="test.async_double.v1",
                           inputs={"x": 5}),
        ])
        return outcomes[0].result

    result = asyncio.run(_driver())
    assert result == 10


# ── Axis 8 · resolve_awaitable helper behaviour ─────────────────────
def test_resolve_awaitable_returns_non_awaitable_verbatim():
    assert _resolve_awaitable(42) == 42
    assert _resolve_awaitable({"a": 1}) == {"a": 1}
    assert _resolve_awaitable("hello") == "hello"


def test_resolve_awaitable_awaits_coroutines():
    async def _c():
        return 7
    assert _resolve_awaitable(_c()) == 7


# ── Axis 9 · SystemWeakness / M0a guardrails ─────────────────────────
def test_m0a_hashes_still_byte_identical_after_async_extension():
    import hashlib, json
    from dataclasses import asdict
    from services.die.input_understanding import understand
    expected = {
        "bare_url_medium_style": "febd68f13aab444b8018ee91dd0d97e0bd04b407d565aedffd9fef6038f93a00",
        "powershell_naked":      "92b9c1cf9c6ac52c6600fa6b3d12660a2a6641d89f3cc765d2cd350e6d1af56b",
        "plain_english_short":   "35aa379db9d4b99e5587825657092843d4ae775553ad5b0ebdbd528a29dd329b",
        "hex_ratio_long":        "7061f38454cd08a06cb092d6827779f30500d87abd57114caf31ebd4e1b97aad",
    }
    corpus = {
        "bare_url_medium_style": "https://systemweakness.com/some-report",
        "powershell_naked":      "powershell.exe -EncodedCommand SGVsbG8=",
        "plain_english_short":   "the quick brown fox jumps over the lazy dog",
        "hex_ratio_long":        "4d5a" + "90" * 260,
    }
    for name, text in corpus.items():
        u = understand(text, execute=False)
        h = hashlib.sha256(
            json.dumps(asdict(u), default=str, sort_keys=True).encode()).hexdigest()
        assert h == expected[name]


def test_systemweakness_projection_unchanged_after_async_extension():
    from services.die.input_understanding import understand
    from services.registry.iue_projection import plan_to_execution_steps
    u = understand("https://systemweakness.com/some-report", execute=False)
    proj = plan_to_execution_steps(u)
    ids = [s.entry_id for s in proj.steps]
    assert "url.acquire.v1" not in ids
    # Post-M0b-extension expected shape.
    assert ids == ["ioc_enrichment.v1", "report.narrative.v1"]


# ── Axis 10 · real ioc_enrichment.v1 now returns an actual dict ─────
def test_real_ioc_enrichment_no_longer_returns_coroutine():
    outcomes = execute_plan([
        ExecutionStep(step_id="s0", entry_id="ioc_enrichment.v1",
                       inputs={"iocs": {"url": ["http://a.test/x"]}, "keys": {}}),
    ])
    r = outcomes[0].result
    assert outcomes[0].status == StepStatus.SUCCESS
    assert not inspect.iscoroutine(r)
    assert not inspect.isawaitable(r)
    # analysis_core.enrich_iocs returns a dict.
    assert isinstance(r, dict)
