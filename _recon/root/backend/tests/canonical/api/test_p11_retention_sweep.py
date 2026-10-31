"""P1.1 · Automated retention-sweeper background job.

Tests only the *scheduler* invariants — FileStore.sweep_expired unit
behaviour (pin protection, TTL cutoff, GridFS chunk cleanup) is
covered by `test_p1_server_side_files.py`.

Locks:
* start_retention_sweeper is idempotent (double-start returns same task)
* NIVX_FILES_SWEEP_ENABLED=0 disables the loop
* Sweep failures are logged and swallowed — subsequent ticks still run
* stop_retention_sweeper cancels the task cleanly
* Interval is env-controlled and floored at 60 s (guards against tight loops)
"""
from __future__ import annotations
import asyncio
import importlib
import os

import pytest

pytestmark = pytest.mark.asyncio


def _fresh_module():
    from services.files import retention_sweeper as m
    # Reset module-scope singleton so tests are independent.
    m._task = None
    return m


async def _get_real_db():
    from deps import init_database, db as proxy
    init_database()
    return object.__getattribute__(proxy, "_real")


async def test_disabled_env_returns_none():
    m = _fresh_module()
    os.environ["NIVX_FILES_SWEEP_ENABLED"] = "0"
    try:
        db = await _get_real_db()
        task = m.start_retention_sweeper(db)
        assert task is None
    finally:
        os.environ.pop("NIVX_FILES_SWEEP_ENABLED", None)


async def test_start_is_idempotent():
    m = _fresh_module()
    db = await _get_real_db()
    os.environ["NIVX_FILES_SWEEP_INTERVAL_S"] = "3600"
    try:
        t1 = m.start_retention_sweeper(db)
        t2 = m.start_retention_sweeper(db)
        assert t1 is t2, "second start must reuse existing task"
        assert not t1.done()
    finally:
        await m.stop_retention_sweeper()


async def test_stop_cancels_cleanly():
    m = _fresh_module()
    db = await _get_real_db()
    os.environ["NIVX_FILES_SWEEP_INTERVAL_S"] = "3600"
    t = m.start_retention_sweeper(db)
    assert t is not None
    await m.stop_retention_sweeper()
    assert t.done() or t.cancelled()


async def test_interval_floor_60s():
    m = _fresh_module()
    os.environ["NIVX_FILES_SWEEP_INTERVAL_S"] = "1"
    assert m._interval_seconds() == 60


async def test_interval_default_and_parse_error():
    m = _fresh_module()
    os.environ.pop("NIVX_FILES_SWEEP_INTERVAL_S", None)
    assert m._interval_seconds() == 86400
    os.environ["NIVX_FILES_SWEEP_INTERVAL_S"] = "not-a-number"
    try:
        assert m._interval_seconds() == 86400
    finally:
        os.environ.pop("NIVX_FILES_SWEEP_INTERVAL_S", None)


async def test_sweep_failure_does_not_crash_loop():
    """A raised sweep exception must be caught; the loop continues."""
    m = _fresh_module()

    class ExplodingStore:
        def __init__(self):
            self.calls = 0
        async def sweep_expired(self):
            self.calls += 1
            if self.calls <= 2:
                raise RuntimeError("simulated sweep failure")
            return {"deleted": 0, "errors": 0}

    store = ExplodingStore()
    # Run the private loop directly with a super-short interval by patching.
    orig_sleep = asyncio.sleep
    counter = {"n": 0}

    async def fast_sleep(_):
        counter["n"] += 1
        if counter["n"] > 3:
            raise asyncio.CancelledError()
        await orig_sleep(0)

    original_asyncio_sleep = m.asyncio.sleep
    m.asyncio.sleep = fast_sleep  # type: ignore[assignment]
    try:
        with pytest.raises(asyncio.CancelledError):
            await m._sweep_loop(store)
    finally:
        m.asyncio.sleep = original_asyncio_sleep  # type: ignore[assignment]

    assert store.calls >= 2, "loop must survive multiple sweep failures"


async def test_sweep_loop_runs_real_sweep():
    """End-to-end: the loop invokes FileStore.sweep_expired at least once."""
    m = _fresh_module()

    class CountingStore:
        def __init__(self):
            self.n = 0
        async def sweep_expired(self):
            self.n += 1
            return {"deleted": 0, "errors": 0}

    store = CountingStore()
    orig_sleep = m.asyncio.sleep
    ticks = {"n": 0}

    async def one_tick(_):
        ticks["n"] += 1
        if ticks["n"] >= 2:
            raise asyncio.CancelledError()
        await orig_sleep(0)

    m.asyncio.sleep = one_tick  # type: ignore[assignment]
    try:
        with pytest.raises(asyncio.CancelledError):
            await m._sweep_loop(store)
    finally:
        m.asyncio.sleep = orig_sleep  # type: ignore[assignment]

    assert store.n >= 1
