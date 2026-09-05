"""v2/routers/artifacts.py · Artifact Store HTTP API (R2).

Endpoints:
    POST   /api/v2/artifacts                              → create_or_update
    GET    /api/v2/artifacts/{artifact_iid}               → fetch by IID
    GET    /api/v2/artifacts/by-sha/{sha256}              → fetch by SHA
    GET    /api/v2/cases/{case_id}/artifacts              → list by case
    POST   /api/v2/artifacts/{artifact_iid}/custody       → append custody event
    POST   /api/v2/artifacts/{artifact_iid}/link/case     → attach a case_id
    POST   /api/v2/artifacts/{artifact_iid}/link/entity   → attach an entity iid
    POST   /api/v2/artifacts/{artifact_iid}/link/observation → attach observation iid

All routes admin-gated + ARTIFACT_STORE flag-gated. Zero RC5 imports.
"""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Body, Depends, HTTPException, Query

from deps import require_admin, db as _db
from v2.flags import get as get_flag
from v2.artifact_store import (
    create_or_update, get_by_iid, get_by_sha, list_by_case,
    append_custody, link_case, link_entity, link_observation,
)

router = APIRouter(prefix="/v2", tags=["v2-artifacts"])


def _guard() -> None:
    if not get_flag("ARTIFACT_STORE").observable():
        raise HTTPException(status_code=503,
                            detail="artifact store disabled — set NIVX_FLAG_ARTIFACT_STORE=shadow")


# ─── Create / upsert ─────────────────────────────────────────────────
@router.post("/artifacts")
async def create_artifact(
    payload: dict[str, Any] = Body(...),
    _: dict = Depends(require_admin),
) -> dict[str, Any]:
    _guard()
    kind = payload.get("kind")
    value = payload.get("value", "")
    if not kind:
        raise HTTPException(status_code=422, detail="`kind` is required")
    if not value and not payload.get("sha256"):
        raise HTTPException(status_code=422,
                            detail="either `value` or `sha256` must be provided")
    actor = payload.get("actor") or "admin"
    art = await create_or_update(
        _db,
        kind=kind,
        value=value,
        sha256=payload.get("sha256"),
        mime_type=payload.get("mime_type", "text/plain"),
        size=payload.get("size"),
        acquisition_time=payload.get("acquisition_time", ""),
        source=payload.get("source", "manual"),
        provenance=payload.get("provenance") or {},
        case_id=payload.get("case_id"),
        entity_iid=payload.get("entity_iid"),
        observation_iid=payload.get("observation_iid"),
        actor=actor,
    )
    return {"ok": True, "artifact": art.model_dump()}


# ─── Fetch ───────────────────────────────────────────────────────────
@router.get("/artifacts/{artifact_iid}")
async def read_artifact(artifact_iid: str, _: dict = Depends(require_admin)) -> dict[str, Any]:
    _guard()
    art = await get_by_iid(_db, artifact_iid)
    if not art:
        raise HTTPException(status_code=404, detail=f"artifact {artifact_iid} not found")
    return {"ok": True, "artifact": art.model_dump()}


@router.get("/artifacts/by-sha/{sha256}")
async def read_artifact_by_sha(
    sha256: str, kind: str | None = Query(None),
    _: dict = Depends(require_admin),
) -> dict[str, Any]:
    _guard()
    art = await get_by_sha(_db, sha256, kind=kind)
    if not art:
        raise HTTPException(status_code=404, detail=f"no artifact with sha256 {sha256}")
    return {"ok": True, "artifact": art.model_dump()}


@router.get("/cases/{case_id}/artifacts")
async def list_case_artifacts(
    case_id: str,
    kind: str | None = Query(None),
    limit: int = Query(500, ge=1, le=5000),
    _: dict = Depends(require_admin),
) -> dict[str, Any]:
    _guard()
    arts = await list_by_case(_db, case_id, kind=kind, limit=limit)
    return {
        "ok": True, "case_id": case_id, "count": len(arts),
        "artifacts": [a.model_dump() for a in arts],
    }


# ─── Custody + links ─────────────────────────────────────────────────
@router.post("/artifacts/{artifact_iid}/custody")
async def add_custody(
    artifact_iid: str,
    payload: dict[str, Any] = Body(...),
    admin: dict = Depends(require_admin),
) -> dict[str, Any]:
    _guard()
    action = payload.get("action")
    if action not in ("acquired","ingested","linked","reviewed",
                      "annotated","exported","sealed"):
        raise HTTPException(status_code=422, detail=f"invalid custody action: {action}")
    detail = payload.get("detail", "")
    actor = payload.get("actor") or admin.get("email") or "admin"
    art = await append_custody(_db, artifact_iid=artifact_iid,
                               actor=actor, action=action, detail=detail)
    if not art:
        raise HTTPException(status_code=404, detail=f"artifact {artifact_iid} not found")
    return {"ok": True, "artifact": art.model_dump()}


@router.post("/artifacts/{artifact_iid}/link/case")
async def link_to_case(
    artifact_iid: str,
    payload: dict[str, Any] = Body(...),
    admin: dict = Depends(require_admin),
) -> dict[str, Any]:
    _guard()
    case_id = payload.get("case_id")
    if not case_id:
        raise HTTPException(status_code=422, detail="`case_id` is required")
    art = await link_case(_db, artifact_iid, case_id,
                          actor=payload.get("actor") or admin.get("email") or "admin")
    if not art:
        raise HTTPException(status_code=404, detail=f"artifact {artifact_iid} not found")
    return {"ok": True, "artifact": art.model_dump()}


@router.post("/artifacts/{artifact_iid}/link/entity")
async def link_to_entity(
    artifact_iid: str,
    payload: dict[str, Any] = Body(...),
    admin: dict = Depends(require_admin),
) -> dict[str, Any]:
    _guard()
    entity_iid = payload.get("entity_iid")
    if not entity_iid:
        raise HTTPException(status_code=422, detail="`entity_iid` is required")
    art = await link_entity(_db, artifact_iid, entity_iid,
                            actor=payload.get("actor") or admin.get("email") or "admin")
    if not art:
        raise HTTPException(status_code=404, detail=f"artifact {artifact_iid} not found")
    return {"ok": True, "artifact": art.model_dump()}


@router.post("/artifacts/{artifact_iid}/link/observation")
async def link_to_observation(
    artifact_iid: str,
    payload: dict[str, Any] = Body(...),
    admin: dict = Depends(require_admin),
) -> dict[str, Any]:
    _guard()
    observation_iid = payload.get("observation_iid")
    if not observation_iid:
        raise HTTPException(status_code=422, detail="`observation_iid` is required")
    art = await link_observation(_db, artifact_iid, observation_iid,
                                 actor=payload.get("actor") or admin.get("email") or "admin")
    if not art:
        raise HTTPException(status_code=404, detail=f"artifact {artifact_iid} not found")
    return {"ok": True, "artifact": art.model_dump()}
