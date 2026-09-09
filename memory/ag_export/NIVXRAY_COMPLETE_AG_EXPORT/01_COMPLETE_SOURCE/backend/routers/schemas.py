"""ADR-0014 · Public CIO Schema router.

Serves the JSON Schema for the Canonical Investigation Object. This is
the sanctioned public contract for backend / frontend / CI / SDK /
external SIEM-SOAR integrators.

Endpoints (unauthenticated · public read-only):

    GET /api/schemas/v1/cio.schema.json      → v1 schema (stable)
    GET /api/schemas/latest/cio.schema.json  → alias for the newest stable version

Compatibility policy (ADR-0014-Slice-D + ADR-0020):
    patch  (1.0.x)  documentation-only / non-breaking clarifications
    minor  (1.x.0)  backward-compatible additions (new optional fields)
    major  (2.0.0)  breaking structural changes → new /v2/ path
"""
from __future__ import annotations

import json
from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse


router = APIRouter(prefix="/schemas", tags=["schemas"])

_SCHEMA_DIR = Path(__file__).resolve().parent.parent / "nivxforge" / "schemas"
_LATEST_VERSION = "v1"


def _load(version: str) -> dict:
    fpath = _SCHEMA_DIR / f"cio.schema.{version}.json"
    if not fpath.exists():
        raise HTTPException(status_code=404,
                            detail=f"CIO schema {version} not found")
    try:
        return json.loads(fpath.read_text())
    except json.JSONDecodeError as exc:  # pragma: no cover
        raise HTTPException(status_code=500,
                            detail=f"schema decode error: {exc}") from exc


def _response(schema: dict) -> JSONResponse:
    return JSONResponse(content=schema, headers={
        "Cache-Control": "public, max-age=3600",
        "X-Schema-Contract": "https://nivxray.nivxforge.com/docs/cio-compatibility-policy",
    })


@router.get("/v1/cio.schema.json")
async def get_cio_schema_v1() -> JSONResponse:
    return _response(_load("v1"))


@router.get("/latest/cio.schema.json")
async def get_cio_schema_latest() -> JSONResponse:
    return _response(_load(_LATEST_VERSION))
