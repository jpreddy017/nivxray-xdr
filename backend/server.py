"""NivXRay — FastAPI backend (main app + wiring).

Refactored Feb-2026: previously a monolithic 2,700-line file. Endpoints are
now split into cohesive routers under `/app/backend/routers/`:
  - auth.py         · /api/auth/*
  - ops.py          · /api/operations, /api/recipe, /api/upload,
                       /api/decode/{smart|magic}, /api/analyze/{command|shellcode}
  - analyze.py      · /api/analyze (sync/stream/async), feedback, playbook votes
  - ai.py           · /api/ai/{auto-decode|auto-investigate|troubleshoot}
  - reports.py      · /api/share, /api/report
  - admin.py        · /api/admin/* (OSINT keys, Model Studio, Samples, LOLBAS, Users)
  - threat_intel.py · /api/threat-intel/*

Shared modules:
  - schemas.py        · Pydantic request/response types
  - deps.py           · DB, auth, LLM, settings helpers
  - analysis_core.py  · deterministic_best_decode, ai_describe_and_verdict, TI hits
  - report_renderers.py · TXT/HTML/DOCX/PDF/CSV renderers (pure)
"""
from __future__ import annotations
import asyncio
import logging
import os

from fastapi import FastAPI, APIRouter
from starlette.middleware.cors import CORSMiddleware

# Register operation registries eagerly (needed for /operations and decoders)
from operations import OPERATIONS  # noqa: F401
import ops_extended  # noqa: F401  — registers +42 operations
from smart_decoder import smart_decode
from magic_decoder import magic_decode
from lolbas import load_from_db as lolbas_load, maybe_refresh as lolbas_maybe_refresh
import models_studio as ms
import sample_library as sl

from deps import client, db, seed_admin
from routers.auth import router as auth_router
from routers.ops import router as ops_router
from routers.analyze import router as analyze_router
from routers.ai import router as ai_router
from routers.reports import router as reports_router
from routers.admin import router as admin_router
from routers.threat_intel import router as threat_intel_router, _ensure_iocs_indexes

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("nivxray")

app = FastAPI(title="NivXRay API")
api = APIRouter(prefix="/api")

# Wire routers under /api
api.include_router(auth_router)
api.include_router(ops_router)
api.include_router(analyze_router)
api.include_router(ai_router)
api.include_router(reports_router)
api.include_router(admin_router)
api.include_router(threat_intel_router)

app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


async def _nightly_benchmark_loop():
    """Runs the full sample-library benchmark every 24h in the background."""
    await asyncio.sleep(300)
    while True:
        try:
            r = await sl.benchmark_all(db, smart_decode, magic_decode)
            log.info("nightly benchmark: %d samples · %d passed (%.1f%%)",
                     r.get("total", 0), r.get("passed", 0), r.get("pass_pct", 0.0))
        except Exception as e:
            log.warning("nightly benchmark failed: %s", e)
        await asyncio.sleep(24 * 60 * 60)


@app.on_event("startup")
async def _startup():
    await seed_admin(log)
    await _ensure_iocs_indexes()
    # LOLBAS: load persisted cache, then trigger a background refresh if stale (>7d)
    await lolbas_load(db)
    asyncio.create_task(lolbas_maybe_refresh(db))
    # Model Studio: indexes + seed built-in personas/providers/examples
    await ms.ensure_indexes(db)
    await ms.seed_builtins(db)
    await ms.ensure_vote_indexes(db)
    # Sample Library: indexes + seed built-in samples + start nightly benchmark
    await sl.ensure_indexes(db)
    await sl.seed_builtins(db)
    asyncio.create_task(_nightly_benchmark_loop())


@app.on_event("shutdown")
async def _shutdown():
    client.close()
