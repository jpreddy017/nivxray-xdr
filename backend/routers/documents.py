"""Documents / Case Vault router (Feb 2026).

In-app file storage so analysts can upload artefacts of any supported type
directly from the browser when the chat-side upload is unavailable.

Storage: MongoDB GridFS (`documents` bucket) — no extra infra.
Auth: user-scoped, admin can list all via `?all=true`.

Endpoints:
    POST  /api/documents/upload               multipart file(s) upload
    GET   /api/documents                        list current user's uploads
    GET   /api/documents/{id}                   metadata for one doc
    GET   /api/documents/{id}/download          raw bytes stream
    GET   /api/documents/{id}/preview           safe text preview (best-effort)
    DELETE /api/documents/{id}
    POST  /api/documents/{id}/ingest-fixture    for JSON — feed into ir_export_to_fixture
    POST  /api/documents/{id}/re-investigate    for text/JSON — pipe through /decode/smart
"""
from __future__ import annotations

import io
import json
import mimetypes
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from bson import ObjectId
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, Body
from fastapi.responses import StreamingResponse
from motor.motor_asyncio import AsyncIOMotorGridFSBucket
from pydantic import BaseModel

from deps import db, client, DB_NAME, get_current_user

router = APIRouter()

# ── Configuration ────────────────────────────────────────────────────────────
BUCKET_NAME = "documents"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MB per file
ALLOWED_EXTENSIONS = {
    "pdf", "doc", "docx", "csv", "xls", "xlsx",
    "json", "jsonl", "txt", "log", "eml", "msg",
    "html", "htm", "xml", "md", "yml", "yaml",
    "ps1", "bat", "sh", "py", "js", "vbs",
}
PREVIEWABLE_TEXT_EXTS = {
    "json", "jsonl", "txt", "log", "eml", "html", "htm", "xml",
    "md", "yml", "yaml", "csv", "ps1", "bat", "sh", "py", "js", "vbs",
}


def _bucket() -> AsyncIOMotorGridFSBucket:
    return AsyncIOMotorGridFSBucket(client[DB_NAME], bucket_name=BUCKET_NAME)


def _oid(v: Any) -> Optional[ObjectId]:
    try:
        return ObjectId(str(v))
    except Exception:
        return None


def _ext(filename: str) -> str:
    if not filename or "." not in filename:
        return ""
    return filename.rsplit(".", 1)[-1].lower()


def _serialize(f) -> Dict[str, Any]:
    """Normalise a GridFSFile object into a JSON-safe dict."""
    meta = f.metadata or {}
    return {
        "id":            str(f._id),
        "filename":      f.filename,
        "length":        f.length,
        "upload_date":   f.upload_date.isoformat() if isinstance(f.upload_date, datetime) else None,
        "content_type":  meta.get("content_type") or mimetypes.guess_type(f.filename)[0] or "application/octet-stream",
        "ext":           _ext(f.filename or ""),
        "user_email":    meta.get("user_email"),
        "notes":         meta.get("notes") or "",
        "tags":          meta.get("tags") or [],
        "ingested":      bool(meta.get("ingested_as_fixture")),
        "reinvestigated":bool(meta.get("reinvestigated")),
        "reinvestigate_history_id": meta.get("reinvestigate_history_id"),
        "sha256":        meta.get("sha256"),
    }


# ═════════════════════════════════════════════════════════════════════════════
# UPLOAD
# ═════════════════════════════════════════════════════════════════════════════
@router.post("/documents/upload")
async def upload_document(
    file: UploadFile = File(...),
    user=Depends(get_current_user),
):
    """Upload a single file. Returns metadata for the stored document."""
    filename = (file.filename or "unnamed").strip()
    ext = _ext(filename)
    if ext and ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=415, detail=f"Unsupported file extension: .{ext}")

    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds {MAX_UPLOAD_BYTES // (1024*1024)} MB limit",
        )

    import hashlib
    sha = hashlib.sha256(data).hexdigest()

    bucket = _bucket()
    file_id = await bucket.upload_from_stream(
        filename,
        io.BytesIO(data),
        metadata={
            "user_email":    user["email"],
            "content_type":  file.content_type or mimetypes.guess_type(filename)[0]
                             or "application/octet-stream",
            "sha256":        sha,
            "uploaded_at":   datetime.now(timezone.utc).isoformat(),
            "tags":          [],
            "notes":         "",
        },
    )
    stored = await bucket.find({"_id": file_id}).to_list(1)
    return _serialize(stored[0])


# ═════════════════════════════════════════════════════════════════════════════
# LIST
# ═════════════════════════════════════════════════════════════════════════════
@router.get("/documents")
async def list_documents(
    q: str = "",
    ext: str = "",
    all: bool = False,
    limit: int = 100,
    skip: int = 0,
    user=Depends(get_current_user),
):
    """Paginated list of uploaded documents (own by default; admin can pass ?all=true)."""
    bucket = _bucket()
    query: Dict[str, Any] = {}
    is_admin = (user or {}).get("role") == "admin"
    if not (all and is_admin):
        query["metadata.user_email"] = user["email"]
    if q:
        query["filename"] = {"$regex": q, "$options": "i"}
    if ext:
        # match against extension in filename (case-insensitive)
        query["filename"] = {"$regex": rf"\.{ext.strip('.').lower()}$", "$options": "i"}

    total = await db[f"{BUCKET_NAME}.files"].count_documents(query)
    cursor = bucket.find(query).sort("uploadDate", -1).skip(max(0, skip)).limit(max(1, min(500, limit)))
    items: List[Dict[str, Any]] = []
    async for f in cursor:
        items.append(_serialize(f))
    return {"total": total, "items": items, "limit": limit, "skip": skip}


@router.get("/documents/{doc_id}")
async def get_document(doc_id: str, user=Depends(get_current_user)):
    oid = _oid(doc_id)
    if not oid:
        raise HTTPException(status_code=400, detail="invalid id")
    bucket = _bucket()
    async for f in bucket.find({"_id": oid}):
        meta = f.metadata or {}
        if meta.get("user_email") != user["email"] and user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="forbidden")
        return _serialize(f)
    raise HTTPException(status_code=404, detail="not found")


# ═════════════════════════════════════════════════════════════════════════════
# DOWNLOAD
# ═════════════════════════════════════════════════════════════════════════════
@router.get("/documents/{doc_id}/download")
async def download_document(doc_id: str, user=Depends(get_current_user)):
    oid = _oid(doc_id)
    if not oid:
        raise HTTPException(status_code=400, detail="invalid id")
    bucket = _bucket()
    # Verify ownership
    f_meta = None
    async for f in bucket.find({"_id": oid}):
        f_meta = f
        break
    if not f_meta:
        raise HTTPException(status_code=404, detail="not found")
    meta = f_meta.metadata or {}
    if meta.get("user_email") != user["email"] and user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="forbidden")

    stream = await bucket.open_download_stream(oid)
    data = await stream.read()

    ctype = meta.get("content_type") or "application/octet-stream"
    filename = f_meta.filename or "download"
    return StreamingResponse(
        io.BytesIO(data),
        media_type=ctype,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/documents/{doc_id}/preview")
async def preview_document(doc_id: str, max_chars: int = 20000, user=Depends(get_current_user)):
    """Best-effort text preview. For binary formats returns a placeholder."""
    oid = _oid(doc_id)
    if not oid:
        raise HTTPException(status_code=400, detail="invalid id")
    bucket = _bucket()
    f_meta = None
    async for f in bucket.find({"_id": oid}):
        f_meta = f
        break
    if not f_meta:
        raise HTTPException(status_code=404, detail="not found")
    meta = f_meta.metadata or {}
    if meta.get("user_email") != user["email"] and user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="forbidden")

    ext = _ext(f_meta.filename or "")
    stream = await bucket.open_download_stream(oid)
    data = await stream.read()

    if ext in PREVIEWABLE_TEXT_EXTS:
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = data.decode("latin-1", errors="replace")
        return {"kind": "text", "ext": ext, "content": text[:max_chars],
                "truncated": len(text) > max_chars, "length": len(text)}

    if ext == "pdf":
        try:
            from pdfminer.high_level import extract_text
            with io.BytesIO(data) as buf:
                text = extract_text(buf) or ""
            return {"kind": "text", "ext": ext, "content": text[:max_chars],
                    "truncated": len(text) > max_chars, "length": len(text)}
        except Exception:
            pass

    if ext in ("docx",):
        try:
            from docx import Document
            with io.BytesIO(data) as buf:
                doc = Document(buf)
                text = "\n".join(p.text for p in doc.paragraphs)
            return {"kind": "text", "ext": ext, "content": text[:max_chars],
                    "truncated": len(text) > max_chars, "length": len(text)}
        except Exception:
            pass

    if ext in ("xlsx",):
        try:
            from openpyxl import load_workbook
            with io.BytesIO(data) as buf:
                wb = load_workbook(buf, read_only=True, data_only=True)
                rows: List[str] = []
                for sh in wb.sheetnames[:5]:
                    ws = wb[sh]
                    rows.append(f"── Sheet: {sh} ──")
                    for r in ws.iter_rows(values_only=True, max_row=200):
                        rows.append("\t".join("" if v is None else str(v) for v in r))
            text = "\n".join(rows)
            return {"kind": "text", "ext": ext, "content": text[:max_chars],
                    "truncated": len(text) > max_chars, "length": len(text)}
        except Exception:
            pass

    return {
        "kind": "binary",
        "ext": ext,
        "content": f"Binary file ({f_meta.length} bytes). Download to view.",
        "length": f_meta.length,
    }


# ═════════════════════════════════════════════════════════════════════════════
# DELETE
# ═════════════════════════════════════════════════════════════════════════════
@router.delete("/documents/{doc_id}")
async def delete_document(doc_id: str, user=Depends(get_current_user)):
    oid = _oid(doc_id)
    if not oid:
        raise HTTPException(status_code=400, detail="invalid id")
    bucket = _bucket()
    async for f in bucket.find({"_id": oid}):
        meta = f.metadata or {}
        if meta.get("user_email") != user["email"] and user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="forbidden")
        await bucket.delete(oid)
        return {"deleted": True, "id": doc_id}
    raise HTTPException(status_code=404, detail="not found")


# ═════════════════════════════════════════════════════════════════════════════
# INGEST AS FIXTURE (JSON only)
# ═════════════════════════════════════════════════════════════════════════════
@router.post("/documents/{doc_id}/ingest-fixture")
async def ingest_as_fixture(doc_id: str, user=Depends(get_current_user)):
    """Feed an uploaded IR-export JSON through tools/ir_export_to_fixture.py.

    On success stores the fixture path in the file metadata and returns the
    fixture body so the frontend can preview + open it in Workspace.
    """
    oid = _oid(doc_id)
    if not oid:
        raise HTTPException(status_code=400, detail="invalid id")
    bucket = _bucket()
    f_meta = None
    async for f in bucket.find({"_id": oid}):
        f_meta = f
        break
    if not f_meta:
        raise HTTPException(status_code=404, detail="not found")
    meta = f_meta.metadata or {}
    if meta.get("user_email") != user["email"] and user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="forbidden")

    ext = _ext(f_meta.filename or "")
    if ext not in ("json", "jsonl"):
        raise HTTPException(status_code=400, detail="Only JSON/JSONL can be ingested as fixtures")

    stream = await bucket.open_download_stream(oid)
    data = await stream.read()
    text = data.decode("utf-8", errors="replace")

    try:
        # Write to a tmp file and invoke the converter via subprocess so we
        # reuse the exact CLI validation & schema logic without duplicating it.
        import tempfile, subprocess, sys, os
        with tempfile.NamedTemporaryFile("w", suffix=f".{ext}", delete=False, encoding="utf-8") as tf:
            tf.write(text)
            tmp_path = tf.name
        try:
            proc = subprocess.run(
                [sys.executable, "/app/backend/tools/ir_export_to_fixture.py", tmp_path,
                 "--out-dir", "/app/backend/tests/fixtures/plugin_regression"],
                capture_output=True, text=True, timeout=60,
            )
            ok = proc.returncode == 0
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
    except FileNotFoundError:
        raise HTTPException(status_code=501, detail="ir_export_to_fixture.py not installed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ingest failed: {e}")

    if ok:
        await db[f"{BUCKET_NAME}.files"].update_one(
            {"_id": oid},
            {"$set": {"metadata.ingested_as_fixture": True,
                      "metadata.ingest_stdout": (proc.stdout or "")[:4000],
                      "metadata.ingest_ts": datetime.now(timezone.utc).isoformat()}},
        )
    return {
        "ok": ok,
        "stdout": (proc.stdout or "")[:4000],
        "stderr": (proc.stderr or "")[:2000],
        "returncode": proc.returncode,
    }


# ═════════════════════════════════════════════════════════════════════════════
# RE-INVESTIGATE (text / JSON payloads → /decode/smart)
# ═════════════════════════════════════════════════════════════════════════════
class ReinvestigateOpts(BaseModel):
    input_field: Optional[str] = None   # for JSON: extract from this key
    max_chars: int = 100000


@router.post("/documents/{doc_id}/re-investigate")
async def reinvestigate_document(
    doc_id: str,
    body: Optional[Dict[str, Any]] = Body(default=None),
    user=Depends(get_current_user),
):
    """Extract the text payload from an uploaded file and pipe it through
    the deterministic decoder pipeline (/decode/smart).

    For JSON, if `input_field` is provided it will be used as the input
    string; otherwise the whole JSON body is used as the input.
    """
    oid = _oid(doc_id)
    if not oid:
        raise HTTPException(status_code=400, detail="invalid id")
    bucket = _bucket()
    f_meta = None
    async for f in bucket.find({"_id": oid}):
        f_meta = f
        break
    if not f_meta:
        raise HTTPException(status_code=404, detail="not found")
    meta = f_meta.metadata or {}
    if meta.get("user_email") != user["email"] and user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="forbidden")

    body = body or {}
    input_field = body.get("input_field")
    max_chars = int(body.get("max_chars") or 100_000)

    stream = await bucket.open_download_stream(oid)
    data = await stream.read()

    ext = _ext(f_meta.filename or "")
    # Extract text depending on the format
    text: Optional[str] = None
    if ext in PREVIEWABLE_TEXT_EXTS:
        text = data.decode("utf-8", errors="replace")
    elif ext == "pdf":
        try:
            from pdfminer.high_level import extract_text as _pdf_extract
            with io.BytesIO(data) as buf:
                text = _pdf_extract(buf) or ""
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"PDF extract failed: {e}")
    elif ext == "docx":
        try:
            from docx import Document
            with io.BytesIO(data) as buf:
                text = "\n".join(p.text for p in Document(buf).paragraphs)
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"DOCX extract failed: {e}")
    elif ext == "xlsx":
        try:
            from openpyxl import load_workbook
            with io.BytesIO(data) as buf:
                wb = load_workbook(buf, read_only=True, data_only=True)
                rows: List[str] = []
                for sh in wb.sheetnames[:5]:
                    ws = wb[sh]
                    for r in ws.iter_rows(values_only=True, max_row=500):
                        rows.append("\t".join("" if v is None else str(v) for v in r))
            text = "\n".join(rows)
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"XLSX extract failed: {e}")
    else:
        raise HTTPException(
            status_code=415,
            detail=f".{ext} is not supported for re-investigate; download and paste manually",
        )

    if not text or not text.strip():
        raise HTTPException(status_code=422, detail="No extractable text in file")

    # JSON with a specific input_field
    if ext in ("json", "jsonl") and input_field:
        try:
            j = json.loads(text)
            if isinstance(j, dict) and input_field in j:
                text = str(j[input_field] or "")
            elif isinstance(j, list) and j and isinstance(j[0], dict) and input_field in j[0]:
                # take first record
                text = str(j[0][input_field] or "")
        except Exception:
            pass  # fall through with raw text

    text = text[:max_chars]

    # Import and call decode/smart under-the-hood (re-use handler, skip HTTP)
    try:
        from routers.ops import decode_smart, DecodeIn
        result = await decode_smart(DecodeIn(input=text), user=user)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"decode/smart failed: {e}")

    # Try to grab the recorded history id (record_investigation runs
    # fire-and-forget inside decode_smart; look it up by sha256 of the input).
    import hashlib
    ihash = hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()
    hist = await db.investigations.find_one(
        {"user_email": user["email"], "input_hash": ihash},
        sort=[("ts", -1)],
    )
    history_id = str(hist["_id"]) if hist else None

    await db[f"{BUCKET_NAME}.files"].update_one(
        {"_id": oid},
        {"$set": {
            "metadata.reinvestigated": True,
            "metadata.reinvestigate_history_id": history_id,
            "metadata.reinvestigate_ts": datetime.now(timezone.utc).isoformat(),
        }},
    )

    verdict_card = None
    if isinstance(result, dict):
        verdict_card = result.get("verdict_card")
    elif hasattr(result, "verdict_card"):
        verdict_card = getattr(result, "verdict_card", None)

    # Result may be a DecodeResult pydantic object OR a dict — normalise.
    def _g(k, default=None):
        if isinstance(result, dict):
            return result.get(k, default)
        return getattr(result, k, default)

    return {
        "ok": True,
        "history_id": history_id,
        "engine": _g("engine"),
        "confidence": _g("confidence"),
        "chain": [s.get("op") if isinstance(s, dict) else s for s in (_g("steps") or [])] or [t.get("op") for t in (_g("layer_trace") or [])],
        "output_preview": (_g("output") or "")[:2000],
        "verdict_card": verdict_card,
        "iocs": _g("iocs") or {},
        "mitre": _g("mitre") or [],
        "lolbas": _g("lolbas") or [],
        "reached_shellcode": bool(_g("reached_shellcode")),
    }
