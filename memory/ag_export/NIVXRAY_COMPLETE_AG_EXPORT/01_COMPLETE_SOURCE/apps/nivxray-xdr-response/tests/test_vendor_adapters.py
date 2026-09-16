"""Multi-vendor adapter contract tests.

Owner-locked invariants:
  · No fabricated success — a stub returning ``ok=True`` must include
    ``simulation_only: true`` in its result so the UI never claims a
    real vendor call happened.
  · Credentials come only from environment.  ``is_configured()`` must
    return False when the env vars are absent — never from source code.
  · Every declared capability must resolve to a ``_do_<capability>``
    method or a ``capability_not_implemented`` error.
"""
import os
import pytest
from framework.vendor_adapters import (
    VendorAdapterRegistry, CrowdStrikeAdapter, DefenderAdapter,
    SentinelOneAdapter, CiscoSEPAdapter,
    STATUS_AVAILABLE, STATUS_NOT_CONNECTED, STATUS_NOT_IMPLEMENTED,
)


def test_default_registry_has_four_vendors():
    r = VendorAdapterRegistry.default()
    ids = {a.vendor_id for a in r.all()}
    assert ids == {"crowdstrike", "defender", "sentinelone", "cisco_sep"}


def test_every_adapter_declares_at_least_isolate_endpoint():
    r = VendorAdapterRegistry.default()
    for a in r.all():
        assert "isolate_endpoint" in a.capabilities, \
            f"{a.vendor_id} missing isolate_endpoint capability"


def test_phase1_stubs_report_simulation_only_status():
    for A in (CrowdStrikeAdapter, DefenderAdapter,
                 SentinelOneAdapter, CiscoSEPAdapter):
        st = A().status()
        assert st["status"] == STATUS_AVAILABLE
        assert st.get("simulation_only") is True


@pytest.mark.asyncio
async def test_stub_isolate_endpoint_never_claims_real_call():
    for A in (CrowdStrikeAdapter, DefenderAdapter,
                 SentinelOneAdapter, CiscoSEPAdapter):
        res = await A().execute("isolate_endpoint",
                                       {"host_id": "H1"}, ctx={})
        assert res.ok is True
        assert res.result["simulation_only"] is True
        assert res.reversal_id                          # every isolate is reversible
        assert res.latency_ms is not None


@pytest.mark.asyncio
async def test_missing_parameter_fails_deterministically():
    a = CrowdStrikeAdapter()
    res = await a.execute("isolate_endpoint", {}, ctx={})
    assert res.ok is False
    assert "missing_parameter" in res.error


@pytest.mark.asyncio
async def test_unimplemented_capability_returns_error_not_success():
    a = DefenderAdapter()
    # DefenderAdapter doesn't declare kill_process; guarantee that
    # asking for it fails honestly instead of silently returning ok.
    res = await a.execute("kill_process",
                                    {"host_id": "H", "pid": 1}, ctx={})
    assert res.ok is False
    assert "capability_not_implemented" in res.error


def test_status_by_capability_lists_each_vendor():
    r = VendorAdapterRegistry.default()
    m = r.status_by_capability()
    assert "isolate_endpoint" in m
    assert set(m["isolate_endpoint"].keys()) == {
        "crowdstrike", "defender", "sentinelone", "cisco_sep"}


def test_configuration_requires_secrets_never_source(monkeypatch):
    # In an empty environment none of the adapters are configured;
    # they must NOT report AVAILABLE with real_vendor_call=True.
    for k in list(os.environ.keys()):
        if k.startswith("NIVX_"):
            monkeypatch.delenv(k, raising=False)
    for A in (CrowdStrikeAdapter, DefenderAdapter,
                 SentinelOneAdapter, CiscoSEPAdapter):
        a = A()
        assert a.is_configured() is False
        # In Phase 1 the adapter is a stub so the honest status is
        # AVAILABLE + simulation_only — Phase C flips real_vendor_call
        # and MUST then require env-provided secrets.
        a.real_vendor_call = True
        st = a.status()
        assert st["status"] == STATUS_NOT_CONNECTED
        assert "credentials" in st["reason"]


@pytest.mark.asyncio
async def test_reversal_only_when_declared():
    a = CrowdStrikeAdapter()
    # Isolate declares an inverse.
    res = await a.reverse("isolate_endpoint", "cs-isol-abc", ctx={})
    assert res.ok is True
    # Kill_process has no inverse — must surface honestly.
    res2 = await a.reverse("kill_process", "cs-kill-abc", ctx={})
    assert res2.ok is False
    assert "reversal_not_supported" in res2.error
