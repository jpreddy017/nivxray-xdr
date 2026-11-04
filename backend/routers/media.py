"""File & media storage · /api/media/*

Auth-gated, tenant-scoped media library backed by Emergent object storage.
MongoDB (``media_assets``) is the source of truth; storage has no delete API
so removal is a soft delete. Supports direct multipart upload and chunked
upload for large files (proxy body limits).
"""
from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Optional

import jwt
from fastapi import (APIRouter, Depends, File, Header, HTTPException, Query,
                     Request, Response, UploadFile)
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from deps import JWT_SECRET, db, get_current_user
from services.media.object_store import (MediaStorageError, get_object,
                                         object_path, put_object, storage_ready)

try:  # deps exposes the algorithm; fall back to the project default.
    from deps import JWT_ALG
except ImportError:  # pragma: no cover
    JWT_ALG = "HS256"

router = APIRouter()

MAX_UPLOAD_BYTES = int(os.environ.get("NIVX_MEDIA_MAX_UPLOAD_BYTES", str(50 * 1024 * 1024)))
STAGING_ROOT = os.environ.get("NIVX_MEDIA_STAGING_DIR") or os.path.join(tempfile.gettempdir(), "nivx_media_chunks")
STREAM_CHUNK = 1024 * 1024

MIME_TYPES = {
    "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
    "gif": "image/gif", "webp": "image/webp", "svg": "image/svg+xml",
    "pdf": "application/pdf", "json": "application/json",
    "csv": "text/csv", "txt": "text/plain", "md": "text/markdown",
    "mp4": "video/mp4", "webm": "video/webm", "mp3": "audio/mpeg",
    "wav": "audio/wav", "zip": "application/zip",
}
ALLOWED_EXTS = set(MIME_TYPES)


def _tenant_of(user: dict) -> str:
    return str(user.get("tenant_id") or "default")


def _ext_of(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else "bin"


def _validate(filename: str, size: Optional[int]) -> str:
    ext = _ext_of(filename or "")
    if ext not in ALLOWED_EXTS:
        raise HTTPException(status_code=415, detail={
            "reason": "unsupported_media_type",
            "detail": f".{ext} is not accepted",
            "allowed": sorted(ALLOWED_EXTS),
        })
    if size is not None and size > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail={
            "reason": "upload_too_large", "max_bytes": MAX_UPLOAD_BYTES,
        })
    return ext


def _public(doc: dict) -> dict:
    return {
        "id": doc["id"],
        "filename": doc["original_filename"],
        "content_type": doc["content_type"],
        "size": doc["size"],
        "sha256": doc.get("sha256"),
        "uploaded_by": doc.get("uploaded_by"),
        "created_at": doc.get("created_at"),
        "url": f"/api/media/{doc['id']}/content",
    }


async def _persist(*, asset_id: str, path: str, filename: str, content_type: str,
                   size: int, sha256: str, user: dict) -> dict:
    doc = {
        "id": asset_id,
        "storage_path": path,
        "original_filename": filename,
        "content_type": content_type,
        "size": size,
        "sha256": sha256,
        "tenant_id": _tenant_of(user),
        "uploaded_by": user.get("email", ""),
        "is_deleted": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.media_assets.insert_one(dict(doc))
    return doc


# ─── Upload (direct) ─────────────────────────────────────────────────
@router.post("/media")
async def upload_media(file: UploadFile = File(...), user=Depends(get_current_user)):
    ext = _validate(file.filename or "", None)
    asset_id = str(uuid.uuid4())

    digest = hashlib.sha256()
    buf = bytearray()
    while True:
        chunk = await file.read(STREAM_CHUNK)
        if not chunk:
            break
        buf.extend(chunk)
        digest.update(chunk)
        if len(buf) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail={
                "reason": "upload_too_large", "max_bytes": MAX_UPLOAD_BYTES})

    content_type = file.content_type or MIME_TYPES.get(ext, "application/octet-stream")
    path = object_path(_tenant_of(user), asset_id, ext)
    try:
        result = await run_in_threadpool(put_object, path, bytes(buf), content_type)
    except MediaStorageError as e:
        raise HTTPException(status_code=e.status, detail=e.to_dict())

    doc = await _persist(asset_id=asset_id, path=result["path"],
                         filename=file.filename or f"{asset_id}.{ext}",
                         content_type=content_type,
                         size=result.get("size", len(buf)),
                         sha256=digest.hexdigest(), user=user)
    return _public(doc)


# ─── Upload (chunked, for large files) ───────────────────────────────
class ChunkedInit(BaseModel):
    filename: str
    content_type: Optional[str] = None
    total_size: int = Field(..., ge=0)


def _staging_dir(upload_id: str) -> str:
    return os.path.join(STAGING_ROOT, upload_id)


@router.post("/media/chunked/init")
async def chunked_init(body: ChunkedInit, user=Depends(get_current_user)):
    ext = _validate(body.filename, body.total_size)
    upload_id = str(uuid.uuid4())
    os.makedirs(_staging_dir(upload_id), exist_ok=True)
    await db.media_uploads.insert_one({
        "upload_id": upload_id,
        "filename": body.filename,
        "ext": ext,
        "content_type": body.content_type or MIME_TYPES.get(ext, "application/octet-stream"),
        "total_size": body.total_size,
        "received": 0,
        "tenant_id": _tenant_of(user),
        "uploaded_by": user.get("email", ""),
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return {"upload_id": upload_id, "chunk_size": 4 * 1024 * 1024,
            "max_bytes": MAX_UPLOAD_BYTES}


async def _owned_session(upload_id: str, user: dict) -> dict:
    sess = await db.media_uploads.find_one(
        {"upload_id": upload_id, "uploaded_by": user.get("email", "")}, {"_id": 0})
    if not sess:
        raise HTTPException(status_code=404, detail={"reason": "upload_session_not_found"})
    return sess


@router.put("/media/chunked/{upload_id}")
async def chunked_put(upload_id: str, request: Request,
                      index: int = Query(..., ge=0), user=Depends(get_current_user)):
    sess = await _owned_session(upload_id, user)
    body = await request.body()
    if sess["received"] + len(body) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail={
            "reason": "upload_too_large", "max_bytes": MAX_UPLOAD_BYTES})
    part = os.path.join(_staging_dir(upload_id), f"{index:06d}.part")
    with open(part, "wb") as fh:
        fh.write(body)
    await db.media_uploads.update_one({"upload_id": upload_id},
                                     {"$set": {"received": sess["received"] + len(body)}})
    return {"upload_id": upload_id, "index": index, "bytes": len(body)}


@router.post("/media/chunked/{upload_id}/complete")
async def chunked_complete(upload_id: str, user=Depends(get_current_user)):
    sess = await _owned_session(upload_id, user)
    folder = _staging_dir(upload_id)
    parts = sorted(os.listdir(folder)) if os.path.isdir(folder) else []
    if not parts:
        raise HTTPException(status_code=422, detail={"reason": "no_chunks_received"})

    digest = hashlib.sha256()
    buf = bytearray()
    for name in parts:
        with open(os.path.join(folder, name), "rb") as fh:
            data = fh.read()
        buf.extend(data)
        digest.update(data)

    asset_id = str(uuid.uuid4())
    path = object_path(sess["tenant_id"], asset_id, sess["ext"])
    try:
        result = await run_in_threadpool(put_object, path, bytes(buf), sess["content_type"])
    except MediaStorageError as e:
        raise HTTPException(status_code=e.status, detail=e.to_dict())

    doc = await _persist(asset_id=asset_id, path=result["path"], filename=sess["filename"],
                         content_type=sess["content_type"],
                         size=result.get("size", len(buf)),
                         sha256=digest.hexdigest(), user=user)
    shutil.rmtree(folder, ignore_errors=True)
    await db.media_uploads.delete_one({"upload_id": upload_id})
    return _public(doc)


@router.delete("/media/chunked/{upload_id}")
async def chunked_abort(upload_id: str, user=Depends(get_current_user)):
    await _owned_session(upload_id, user)
    shutil.rmtree(_staging_dir(upload_id), ignore_errors=True)
    await db.media_uploads.delete_one({"upload_id": upload_id})
    return {"upload_id": upload_id, "aborted": True}


# ─── Library ─────────────────────────────────────────────────────────
@router.get("/media")
async def list_media(limit: int = Query(100, ge=1, le=500), skip: int = Query(0, ge=0),
                     user=Depends(get_current_user)):
    q = {"tenant_id": _tenant_of(user), "is_deleted": False}
    total = await db.media_assets.count_documents(q)
    cursor = db.media_assets.find(q, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit)
    return {"total": total, "items": [_public(d) async for d in cursor]}


@router.get("/media/health")
async def media_health(user=Depends(get_current_user)):
    ready = await run_in_threadpool(storage_ready)
    return {"storage": "ready" if ready else "unavailable",
            "max_upload_bytes": MAX_UPLOAD_BYTES,
            "allowed_extensions": sorted(ALLOWED_EXTS)}


async def _user_from_header_or_query(authorization: Optional[str], auth: Optional[str]) -> dict:
    """`<img src>` cannot send headers — accept ?auth=<jwt> as an alternative."""
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]
    elif auth:
        token = auth
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        email = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG]).get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = await db.users.find_one({"email": email}, {"_id": 0, "password": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


@router.get("/media/{asset_id}")
async def media_metadata(asset_id: str, user=Depends(get_current_user)):
    doc = await db.media_assets.find_one(
        {"id": asset_id, "tenant_id": _tenant_of(user), "is_deleted": False}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail={"reason": "asset_not_found"})
    return _public(doc)


@router.get("/media/{asset_id}/content")
async def media_content(asset_id: str, authorization: Optional[str] = Header(None),
                        auth: Optional[str] = Query(None),
                        download: bool = Query(False)):
    user = await _user_from_header_or_query(authorization, auth)
    doc = await db.media_assets.find_one(
        {"id": asset_id, "tenant_id": _tenant_of(user), "is_deleted": False}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail={"reason": "asset_not_found"})
    try:
        data, content_type = await run_in_threadpool(get_object, doc["storage_path"])
    except MediaStorageError as e:
        raise HTTPException(status_code=e.status, detail=e.to_dict())
    headers = {"Cache-Control": "private, max-age=300"}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{doc["original_filename"]}"'
    return Response(content=data, media_type=doc.get("content_type") or content_type,
                    headers=headers)


@router.delete("/media/{asset_id}")
async def delete_media(asset_id: str, user=Depends(get_current_user)):
    res = await db.media_assets.update_one(
        {"id": asset_id, "tenant_id": _tenant_of(user), "is_deleted": False},
        {"$set": {"is_deleted": True,
                  "deleted_at": datetime.now(timezone.utc).isoformat(),
                  "deleted_by": user.get("email", "")}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail={"reason": "asset_not_found"})
    return {"id": asset_id, "deleted": True}
