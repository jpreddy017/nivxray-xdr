"""
Round 28 · Adapter Framework Proof.

Locked owner criteria:

    VendorAdapter
       │
   ┌───┴───┐
   ↓       ↓
Cortex   demo_edr
   │       │
   └───┬───┘
       ↓
  Same wizard · vault · executor · capability model · response
  console · evidence model.

  Zero vendor-specific changes above the adapter boundary.
"""
from __future__ import annotations

import asyncio
import pytest

from detection_content.xdr_vendor_registry import (
    get_vendor_class, list_production_vendors, list_all_vendors,
)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_registry_holds_cortex_and_stub():
    prod = list_production_vendors()
    keys = {v["vendor_key"] for v in prod}
    assert "cortex"   in keys
    # Guardrail: stub must NOT appear in the production catalogue.
    assert "demo_edr" not in keys

    all_v = list_all_vendors(include_internal=True)
    all_keys = {v["vendor_key"] for v in all_v}
    assert {"cortex", "demo_edr"}.issubset(all_keys)


def test_metadata_shape_is_uniform():
    # Every registered vendor must expose the same metadata shape so
    # the wizard can render any of them without vendor-specific code.
    required = {"vendor_key", "display_name", "lifecycle",
                    "credential_schema", "capability_ids"}
    for meta in list_all_vendors(include_internal=True):
        missing = required - meta.keys()
        assert not missing, f"{meta.get('vendor_key')}: {missing}"
        for field in meta["credential_schema"]:
            assert {"key", "label", "kind"}.issubset(field.keys())
        assert meta["lifecycle"] in {"PRODUCTION", "INTERNAL_TEST_ONLY"}


def test_stub_is_honestly_useless():
    cls = get_vendor_class("demo_edr")
    adapter = cls(credentials={"base_url": "http://demo.local",
                                        "api_key": "x"})
    connect = _run(adapter.connect())
    assert connect["ok"] is False
    assert connect["reason"] == "NO_LIVE_TENANT"
    caps = _run(adapter.capabilities())
    assert all(c["state"] == "NOT_SUPPORTED" for c in caps)
    exec_res = _run(adapter.execute_action(
        "ENDPOINT_ISOLATE", {"target": {"kind": "host", "value": "x"}}))
    assert exec_res["ok"] is False
    assert exec_res["vendor_action_id"] is None


def test_cortex_facade_still_returns_normalized_envelope():
    cls = get_vendor_class("cortex")
    # No connector wired → legacy adapter returns ok=False with a
    # "credentials not configured" detail; the facade must map that
    # to reason=NO_LIVE_TENANT (honest state, not fabricated).
    adapter = cls(credentials={})
    connect = _run(adapter.connect())
    assert connect["ok"] is False
    assert connect["reason"] in {"NO_LIVE_TENANT", "VENDOR_ERROR"}
    # The facade must not leak vendor-specific keys.
    assert set(connect.keys()) <= {"ok", "reason", "detail", "vendor_reference"}


def test_uniform_flow_above_adapter_boundary():
    """The whole point of Round 28: iterate over EVERY registered
    vendor and drive its adapter through the same 4 methods with
    the same shape of arguments.  Any vendor that breaks this loop
    has leaked vendor-specific requirements above the adapter."""
    for meta in list_all_vendors(include_internal=True):
        cls = get_vendor_class(meta["vendor_key"])
        # 1. constructable with a generic credential blob
        adapter = cls(credentials={"base_url": "http://x",
                                            "api_key": "y",
                                            "api_key_id": "1"})
        # 2. connect() returns normalized envelope
        r = _run(adapter.connect())
        assert isinstance(r, dict) and "ok" in r and "reason" in r
        # 3. capabilities() returns list of {action_id, capability_id, state}
        caps = _run(adapter.capabilities())
        assert isinstance(caps, list)
        for c in caps:
            assert {"action_id", "state"}.issubset(c.keys())
            assert c["state"] in {"AVAILABLE", "UNAVAILABLE",
                                          "FAILED", "NOT_SUPPORTED"}
        # 4. ingest_incidents(cursor=None) returns {events, next_cursor}
        ing = _run(adapter.ingest_incidents(since_cursor=None))
        assert "events" in ing and "next_cursor" in ing
        # 5. execute_action returns normalized envelope
        e = _run(adapter.execute_action(
            "ENDPOINT_ISOLATE", {"target": {"kind": "host", "value": "x"}}))
        assert isinstance(e, dict) and "ok" in e
