"""P1 Server-Side File Mode · /api/files/* router.

Auth-gated. Never exposes internal storage paths. Server-side upload
cap enforced during streaming ingest (see ``FileStore.put``).
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Response
from fastapi.responses import StreamingResponse

from deps import get_current_user
from deps import db as _default_db
from services.files.store import FileStore, FileStoreError
from services.files.input_router import route_for


router = APIRouter()


def _store():
    # deps.db is a proxy — unwrap to the real MotorDatabase for GridFS.
    real_db = object.__getattribute__(_default_db, "_real")
    if real_db is None:
        # Force bind if init_database hasn't been called yet.
        from deps import init_database
        init_database()
        real_db = object.__getattribute__(_default_db, "_real")
    return FileStore(real_db)


@router.post("/files")
async def upload_file(
    file: UploadFile = File(...),
    user=Depends(get_current_user),
):
    """Streaming upload → GridFS → race-safe SHA-256 dedup.

    Response:
        { file_id, sha256, size, mime, filename, uploaded_at,
          tenant_id, pinned_cases, analysis_status }
    """
    store = _store()
    await store.ensure_indexes()
    try:
        rec = await store.put(file, uploaded_by=user.get("email", ""))
    except FileStoreError as e:
        code = 413 if e.reason == "upload_too_large" else 422
        raise HTTPException(status_code=code, detail=e.to_dict())
    return rec.public()


@router.get("/files/{file_id}/metadata")
async def file_metadata(file_id: str, user=Depends(get_current_user)):
    store = _store()
    try:
        rec = await store.metadata(file_id)
    except FileStoreError as e:
        raise HTTPException(status_code=404, detail=e.to_dict())
    return rec.public()


@router.get("/files/{file_id}")
async def file_download(file_id: str, user=Depends(get_current_user)):
    """Streaming download — no internal path exposure."""
    store = _store()
    try:
        rec = await store.metadata(file_id)
        stream = await store.open_read(file_id)
    except FileStoreError as e:
        raise HTTPException(status_code=404, detail=e.to_dict())

    async def gen():
        while True:
            chunk = await stream.readchunk()
            if not chunk:
                break
            yield chunk

    headers = {
        "Content-Disposition": f'attachment; filename="{rec.filename}"',
        "X-Content-SHA256":    rec.sha256,
        "X-Content-Size":      str(rec.size),
    }
    return StreamingResponse(gen(), media_type=rec.mime, headers=headers)


@router.delete("/files/{file_id}")
async def file_delete(file_id: str, user=Depends(get_current_user)):
    # Owner-scope: for now, any authenticated user can delete their own
    # file. Admin can delete any. (Multi-tenant scope arrives with P5.)
    store = _store()
    rec = await store.metadata(file_id)
    if rec.uploaded_by != user.get("email") and user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="not_owner")
    ok = await store.delete(file_id)
    return {"deleted": ok, "file_id": file_id}


@router.post("/files/{file_id}/pin")
async def file_pin(file_id: str, case_id: str, user=Depends(get_current_user)):
    store = _store()
    await store.pin(file_id, case_id)
    return {"pinned": True, "file_id": file_id, "case_id": case_id}


@router.post("/files/{file_id}/unpin")
async def file_unpin(file_id: str, case_id: str, user=Depends(get_current_user)):
    store = _store()
    await store.unpin(file_id, case_id)
    return {"pinned": False, "file_id": file_id, "case_id": case_id}


@router.post("/files/{file_id}/analyze")
async def file_analyze(file_id: str, user=Depends(get_current_user)):
    """Dispatch this file to the appropriate existing analyzer.

    This endpoint intentionally routes to LIVE analyzers only — it does
    NOT promote v2 IKG / Verdict-v3 / Case Engine. Unsupported inputs
    return a deterministic ``UNSUPPORTED_INPUT`` result rather than a
    mysterious failure.
    """
    store = _store()
    try:
        rec = await store.metadata(file_id)
        stream = await store.open_read(file_id)
    except FileStoreError as e:
        raise HTTPException(status_code=404, detail=e.to_dict())

    # Peek first 4 KB for magic-based routing without holding whole file
    peek = await stream.read(4096)
    route = route_for(peek, rec.mime, rec.filename)

    if route == "unsupported":
        return {
            "file_id": file_id,
            "route": route,
            "result": "UNSUPPORTED_INPUT",
            "reason": "no_recognised_content_shape",
            "metadata": rec.public(),
        }

    # For LIVE analyzers we return the dispatch decision + the metadata
    # the analyzer needs to consume the file. The analyzer call itself
    # remains the existing DIE / analyze / ops surface — the Input
    # Router does not duplicate their behaviour.
    return {
        "file_id": file_id,
        "route": route,
        "result": "DISPATCHED",
        "next_endpoint": _dispatch_endpoint(route),
        "metadata": rec.public(),
    }


def _dispatch_endpoint(route: str) -> str:
    """Human-readable pointer to the existing analyzer for each route."""
    return {
        "text":    "/api/die/analyze",
        "archive": "/api/upload",        # already applies P0 archive guard
        "office":  "/api/upload",
        "pdf":     "/api/upload",
        "pe":      "/api/analyze/shellcode",
        "image":   "/api/upload",
        "email":   "/api/upload",
        "csv":     "/api/die/investigation-results",
    }.get(route, "/api/upload")
