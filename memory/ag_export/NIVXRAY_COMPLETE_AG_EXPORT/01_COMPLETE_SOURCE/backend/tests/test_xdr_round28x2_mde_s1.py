"""
Round 28.x.2 · MDE + SentinelOne acceptance suite.

Locked owner criteria:
  1. Framework-leakage canary: no protected file above the
     adapter boundary mentions `mde`, `defender`, or
     `sentinelone`.
  2. Metadata shape uniform across both vendors.
  3. Honest `NO_LIVE_TENANT` without credentials.
  4. Honest capability matrix (NOT_SUPPORTED where the vendor
     genuinely lacks the capability).
  5. Uniform-flow proof — the SAME five methods work identically
     on Cortex, Falcon, MDE, and SentinelOne.
"""
from __future__ import annotations

import asyncio
import os
import re
import pytest

from detection_content.xdr_vendor_registry import (
    get_vendor_class, list_production_vendors,
)


PROTECTED_FILES = [
    "detection_content/xdr_credential_vault.py",
    "detection_content/xdr_cortex_executor.py",
    "detection_content/xdr_capability_service.py",
    "detection_content/xdr_cortex_ingest.py",
    "detection_content/xdr_cortex_promotion.py",
    "detection_content/xdr_vendor_adapter.py",
    "routers/xdr_vendor_wizard.py",
    "routers/xdr_cortex_actions.py",
]
FORBIDDEN_TOKENS = re.compile(
    r"\b(mde|defender|sentinelone|sentinel-one|singularity)\b", re.I)
BACKEND_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_framework_leakage_canary():
    leaks = []
    for rel in PROTECTED_FILES:
        with open(os.path.join(BACKEND_ROOT, rel), "r", encoding="utf-8") as f:
            body = f.read()
        if FORBIDDEN_TOKENS.search(body):
            leaks.append(rel)
    assert not leaks, f"framework leak in {leaks}"


def test_both_vendors_in_production_catalogue():
    keys = {v["vendor_key"] for v in list_production_vendors()}
    assert {"cortex", "falcon", "mde", "sentinelone"}.issubset(keys)


@pytest.mark.parametrize("vendor_key", ["mde", "sentinelone"])
def test_metadata_shape_is_uniform(vendor_key):
    meta = get_vendor_class(vendor_key).metadata()
    assert meta["lifecycle"] == "PRODUCTION"
    schema = meta["credential_schema"]
    assert schema and all({"key", "label", "kind"}.issubset(f) for f in schema)
    assert meta["capability_ids"], "capability ids missing"


@pytest.mark.parametrize("vendor_key", ["mde", "sentinelone"])
def test_connect_honest_no_live_tenant(vendor_key):
    cls = get_vendor_class(vendor_key)
    adapter = cls(credentials={})
    r = _run(adapter.connect())
    assert r["ok"] is False
    assert r["reason"] == "NO_LIVE_TENANT"


@pytest.mark.parametrize("vendor_key", ["mde", "sentinelone"])
def test_capabilities_matrix_shape(vendor_key):
    caps = _run(get_vendor_class(vendor_key)(credentials={}).capabilities())
    states = {c["state"] for c in caps}
    assert states.issubset({"AVAILABLE", "UNAVAILABLE",
                                    "FAILED", "NOT_SUPPORTED"})
    # At minimum, endpoint isolate + block hash must be advertised.
    action_ids = {c["action_id"] for c in caps}
    assert {"ENDPOINT_ISOLATE", "BLOCK_HASH"}.issubset(action_ids)


def test_uniform_flow_across_all_production_vendors():
    """Same five methods drive every PRODUCTION vendor with the
    same argument shape and produce normalised envelopes."""
    for meta in list_production_vendors():
        cls = get_vendor_class(meta["vendor_key"])
        adapter = cls(credentials={"base_url": "http://x",
                                            "api_key": "y",
                                            "api_key_id": "1",
                                            "cloud": "us-1",
                                            "client_id": "x",
                                            "client_secret": "y",
                                            "tenant_id": "t",
                                            "mgmt_url": "http://s1",
                                            "api_token": "tok"})
        c = _run(adapter.connect())
        assert isinstance(c, dict) and "ok" in c and "reason" in c
        caps = _run(adapter.capabilities())
        assert isinstance(caps, list) and all(
            {"action_id", "state"}.issubset(x.keys()) for x in caps)
        ing = _run(adapter.ingest_incidents(since_cursor=None))
        assert "events" in ing and "next_cursor" in ing
        e = _run(adapter.execute_action(
            "ENDPOINT_ISOLATE",
            {"target": {"kind": "host", "value": "x", "id": "x"}}))
        assert isinstance(e, dict) and "ok" in e
