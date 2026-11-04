"""Authored-rule cache must bound reads even for an empty successful store."""
from unittest.mock import Mock
import pytest
import deps
from detection_content import rule_store_binding as rsb

@pytest.fixture
def cache_env(monkeypatch):
    clock = [1000.0]
    coll = Mock()
    coll.find.return_value = []
    monkeypatch.setattr(deps, "sync_collection", lambda name: coll)
    monkeypatch.setattr(rsb, "_cache", {"at": 0.0, "bindings": None})
    monkeypatch.setattr(rsb.time, "time", lambda: clock[0])
    monkeypatch.setattr(rsb, "_Binding", lambda doc: doc)
    return coll, clock

def test_empty_store_is_cached_across_1000_events(cache_env):
    coll, _ = cache_env
    for _ in range(1000):
        assert rsb.load_bindings() == []
    assert coll.find.call_count == 1

def test_expiration_loads_newly_added_rules(cache_env):
    coll, clock = cache_env
    assert rsb.load_bindings() == []
    coll.find.return_value = [{"rule": "new"}]
    clock[0] += rsb._CACHE_TTL_SECONDS - 1
    assert rsb.load_bindings() == []
    clock[0] += 1
    assert rsb.load_bindings() == [{"rule": "new"}]
    assert coll.find.call_count == 2

def test_force_refresh_bypasses_empty_cache(cache_env):
    coll, _ = cache_env
    rsb.load_bindings()
    coll.find.return_value = [{"rule": "new"}]
    assert rsb.load_bindings(force=True) == [{"rule": "new"}]
    assert coll.find.call_count == 2

def test_initial_read_failure_is_not_cached_as_empty(cache_env):
    coll, _ = cache_env
    coll.find.side_effect = RuntimeError("read unavailable")
    with pytest.raises(RuntimeError):
        rsb.load_bindings()
    assert rsb._cache == {"at": 0.0, "bindings": None}
    coll.find.side_effect = None
    assert rsb.load_bindings() == []
    assert coll.find.call_count == 2

def test_expired_failure_does_not_refresh_ttl_or_serve_stale(cache_env):
    coll, clock = cache_env
    coll.find.return_value = [{"rule": "old"}]
    rsb.load_bindings()
    old = dict(rsb._cache)
    clock[0] += rsb._CACHE_TTL_SECONDS
    coll.find.side_effect = RuntimeError("read unavailable")
    for _ in range(2):
        with pytest.raises(RuntimeError):
            rsb.load_bindings()
    assert rsb._cache == old
    assert coll.find.call_count == 3

def test_partial_cursor_failure_does_not_publish_partial_rules(cache_env):
    coll, _ = cache_env
    def broken_cursor():
        yield {"rule": "partial"}
        raise RuntimeError("cursor failed")
    coll.find.return_value = broken_cursor()
    with pytest.raises(RuntimeError):
        rsb.load_bindings()
    assert rsb._cache["bindings"] is None

def test_populated_cache_reuses_successful_snapshot(cache_env):
    coll, _ = cache_env
    coll.find.return_value = [{"rule": "one"}]
    first = rsb.load_bindings()
    assert rsb.load_bindings() is first
    assert coll.find.call_count == 1
