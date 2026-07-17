"""Workspace Case Library — persist named investigations for later reload.

Feb 2026 · analyst can hit 💾 SAVE CASE in workspace to store the current
decoded state (input/output/engine/chain/verdict/IOCs) with a friendly name.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import uuid
import os

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from pymongo import MongoClient

from deps import get_current_user

router = APIRouter()

_client = MongoClient(os.environ.get("MONGO_URL"))
_db     = _client[os.environ.get("DB_NAME")]
_col    = _db.workspace_cases


class SaveCaseIn(BaseModel):
    name:        str
    input:       str
    output:      str
    engine:      Optional[str] = None
    confidence:  Optional[float] = None
    chain_ids:   List[str] = Field(default_factory=list)
    # Feb 2026: verdict may be either a bare string ("Suspicious") OR a dict
    # ({verdict, confidence, summary, family, ...}) depending on which panel
    # emitted the save. Accept Any to prevent 422s from the strict-str schema.
    verdict:     Optional[Any] = None
    iocs:        Dict[str, Any] = Field(default_factory=dict)


@router.post("/cases/save")
async def save_case(body: SaveCaseIn, user=Depends(get_current_user)):
    user_email = getattr(user, "email", None) or (user.get("email") if isinstance(user, dict) else None)
    name = body.name.strip()[:200]
    now  = datetime.now(timezone.utc).isoformat()

    # Feb 2026 · UPSERT by (user_email, name) — a subsequent SAVE with the
    # same name updates the existing record instead of creating a duplicate.
    # This matches the analyst's mental model: "SAVE" on a case they've
    # already named should just persist their latest edits.
    existing = _col.find_one({"user_email": user_email, "name": name})
    doc_body = {
        "user_email":  user_email,
        "name":        name,
        "input":       body.input,
        "output":      body.output,
        "engine":      body.engine,
        "confidence":  body.confidence,
        "chain_ids":   body.chain_ids,
        "verdict":     body.verdict,
        "iocs":        body.iocs,
        "input_len":   len(body.input),
        "output_len":  len(body.output),
        "updated_at":  now,
    }

    if existing:
        _col.update_one(
            {"_id": existing["_id"]},
            {"$set": doc_body},
        )
        doc = {**existing, **doc_body}
        updated = True
    else:
        doc = {
            "id":         str(uuid.uuid4()),
            "created_at": now,
            **doc_body,
        }
        _col.insert_one(doc)
        updated = False

    # ─── Golden Vault auto-capture (only on first save per case-id) ──────
    # Idempotent by fixture 'id' — the update path reuses the original id,
    # so re-saves don't create duplicate fixture rows.
    try:
        _append_to_golden_vault(doc)
    except Exception:
        pass
    return {
        "id":         doc["id"],
        "name":       doc["name"],
        "created_at": doc["created_at"],
        "updated":    updated,
    }


def _append_to_golden_vault(doc: Dict[str, Any]) -> None:
    """Append a SAVE CASE snapshot to /app/backend/tests/fixtures/user_golden_vault.jsonl.
    Idempotent by fixture 'id'. Skips snapshots that contain CJK gibberish
    (those are broken outputs and shouldn't be locked in as truth)."""
    import json as _json
    out = doc.get("output") or ""
    if any((0x4E00 <= ord(c) <= 0x9FFF) or (0x3040 <= ord(c) <= 0x30FF)
           or (0x3400 <= ord(c) <= 0x4DBF) or (0xAC00 <= ord(c) <= 0xD7AF)
           for c in out):
        return  # don't lock in broken output
    head = out.split("━━")[0].strip() if "━━" in out else out
    sig  = "".join(c for c in head if 32 <= ord(c) < 127 or c in "\n\r\t")[:200]
    fx = {
        "name":                doc.get("name") or "unnamed",
        "source":              "workspace_case",
        "id":                  doc["id"],
        "created_at":          doc["created_at"],
        "input":               doc["input"],
        "expected_engine":     doc.get("engine"),
        "expected_conf":       doc.get("confidence"),
        "expected_signature":  sig,
    }
    vault = "/app/backend/tests/fixtures/user_golden_vault.jsonl"
    # Read existing IDs for idempotency
    existing_ids = set()
    if os.path.exists(vault):
        with open(vault, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    existing_ids.add(_json.loads(line).get("id"))
                except Exception:
                    pass
    if fx["id"] in existing_ids:
        return
    os.makedirs(os.path.dirname(vault), exist_ok=True)
    with open(vault, "a", encoding="utf-8") as f:
        f.write(_json.dumps(fx, ensure_ascii=False) + "\n")


@router.get("/cases")
async def list_cases(limit: int = 50, user=Depends(get_current_user)):
    """List saved cases (newest first) — metadata only."""
    user_email = getattr(user, "email", None) or (user.get("email") if isinstance(user, dict) else None)
    q = {"user_email": user_email} if user_email else {}
    cur = _col.find(q, {
        "_id": 0, "id": 1, "created_at": 1, "name": 1, "engine": 1,
        "confidence": 1, "verdict": 1, "input_len": 1, "output_len": 1,
    }).sort("created_at", -1).limit(min(int(limit), 200))
    return {"cases": list(cur)}


@router.get("/cases/{case_id}")
async def get_case(case_id: str, user=Depends(get_current_user)):
    doc = _col.find_one({"id": case_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="case not found")
    return doc


@router.delete("/cases/{case_id}")
async def delete_case(case_id: str, user=Depends(get_current_user)):
    r = _col.delete_one({"id": case_id})
    return {"deleted": r.deleted_count}
