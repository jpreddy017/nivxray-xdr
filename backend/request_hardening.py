"""Production-grade middleware — request tracing, hard timeouts, payload caps.

Every request gets:
  * X-Request-ID (generated if missing) → returned in response + logged
  * Duration timing (elapsed_ms) → logged with request ID for incident triage
  * Hard timeout via asyncio.wait_for — prevents Cloudflare 524s on long LLM calls
  * Body size cap enforcement (raises 413 for oversized inputs)

Timeouts are per-path — LLM endpoints get 85s (5s safety margin below Cloudflare's
100s cutoff), everything else 30s.
"""
from __future__ import annotations
import asyncio
import logging
import time
import uuid
from typing import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

log = logging.getLogger("nivxray.middleware")

# Per-path timeout overrides. LLM endpoints run longer; everything else is fast.
_LLM_PATHS = (
    "/api/ai/",
    "/api/decode/chain/narrative",
    "/api/analyze",         # /analyze may invoke ai_describe_and_verdict
    "/api/decode/smart",    # magic_decoder can be slow on huge inputs
    "/api/moe/analyze",     # MoE panel: 3 parallel Claude reviewers + synth
    "/api/threat-model/enrich",   # threat-model deterministic + MoE enrichment
    "/api/cases/",           # SAVE-with-reinvestigate + /cases/{id}/reinvestigate
    "/api/v2/auto-investigate",     # deterministic per-command budget already inside
    "/api/v2/report-writer/",       # invokes auto-investigate internally
)
_DEFAULT_TIMEOUT_S = 30
_LLM_TIMEOUT_S     = 120
# Frontend cap is 500 KB — enforce here too as a hard safety net.
_MAX_BODY_BYTES    = 512 * 1024
# Endpoints that legitimately accept large real-world incident text
# (multi-megabyte PowerShell EncodedCommand payloads, EVTX chunks, etc.).
# They have their OWN per-command guardrails, so we raise the middleware
# ceiling for these paths only.
_LARGE_BODY_PATHS  = (
    "/api/upload",                  # universal file upload (image/pdf/docx/eml/zip)
    "/api/documents/upload",        # explicit document upload
    "/api/v2/auto-investigate",
    "/api/v2/report-writer/",
    "/api/v2/ingestion/",
)
_MAX_LARGE_BODY_BYTES = 50 * 1024 * 1024   # 50 MB


def _timeout_for(path: str) -> float:
    return _LLM_TIMEOUT_S if any(path.startswith(p) for p in _LLM_PATHS) else _DEFAULT_TIMEOUT_S


class RequestHardeningMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # ── X-Request-ID: use incoming or generate ─────────────────────
        rid = request.headers.get("x-request-id") or f"nvx-{uuid.uuid4().hex[:12]}"

        # ── Body size cap (streaming-safe; skips non-body methods) ─────
        # Only inspect Content-Length; DO NOT `await request.body()` here
        # (that would break FastAPI's downstream body reading).
        cl = request.headers.get("content-length")
        path = request.url.path
        large_ok = any(path.startswith(p) for p in _LARGE_BODY_PATHS)
        cap = _MAX_LARGE_BODY_BYTES if large_ok else _MAX_BODY_BYTES
        if cl and cl.isdigit() and int(cl) > cap:
            log.warning(f"[{rid}] 413 payload_too_large path={path} cl={cl} cap={cap}")
            return JSONResponse(
                status_code=413,
                content={
                    "detail": f"Payload too large — max {cap//1024}KB. "
                              f"Split into stages via /decode/chain, or reduce input.",
                    "request_id": rid,
                    "content_length": int(cl),
                    "limit": cap,
                },
                headers={"X-Request-ID": rid},
            )

        # ── Hard timeout wrapping ──────────────────────────────────────
        started = time.perf_counter()
        timeout = _timeout_for(request.url.path)
        try:
            response = await asyncio.wait_for(call_next(request), timeout=timeout)
        except asyncio.TimeoutError:
            elapsed = int((time.perf_counter() - started) * 1000)
            log.error(f"[{rid}] 504 server_timeout path={request.url.path} timeout_ms={timeout*1000} elapsed_ms={elapsed}")
            return JSONResponse(
                status_code=504,
                content={
                    "detail": (
                        f"Server timeout after {timeout}s. "
                        f"For AI narratives on chains with many stages, try fewer stages "
                        f"or use TROUBLESHOOT (offline, no LLM)."
                    ),
                    "request_id": rid,
                    "timeout_seconds": timeout,
                    "path": request.url.path,
                },
                headers={"X-Request-ID": rid},
            )
        except Exception as e:
            elapsed = int((time.perf_counter() - started) * 1000)
            log.exception(f"[{rid}] 500 unhandled path={request.url.path} elapsed_ms={elapsed}")
            return JSONResponse(
                status_code=500,
                content={"detail": str(e)[:400], "request_id": rid},
                headers={"X-Request-ID": rid},
            )

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        response.headers["X-Request-ID"] = rid
        response.headers["X-Elapsed-Ms"] = str(elapsed_ms)
        if elapsed_ms > 5000:  # log slow requests for triage
            log.warning(f"[{rid}] slow path={request.url.path} elapsed_ms={elapsed_ms} status={response.status_code}")
        else:
            log.info(f"[{rid}] path={request.url.path} elapsed_ms={elapsed_ms} status={response.status_code}")
        return response
