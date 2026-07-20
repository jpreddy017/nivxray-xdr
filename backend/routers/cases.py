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

    # Feb 2026 · If the frontend saved BEFORE the decode ran (output echoes
    # the input, chain empty, no engine) — synthesise a fresh investigation
    # so the persisted case has proper output/verdict/iocs. Without this the
    # analyst's Case Library entry is useless ("no proper output" bug).
    body_out = body.output or ""
    needs_reinvestigate = (
        not body_out.strip()
        or body_out.strip() == (body.input or "").strip()
        or not (body.chain_ids or [])
        or (body.engine in (None, "-", ""))
    )
    fresh: Dict[str, Any] = {}
    if body.input and needs_reinvestigate:
        try:
            from routers.ops import decode_smart
            from schemas import AutoIn as _DecodeIn
            result = await decode_smart(_DecodeIn(input=body.input), user=user)
            def _g(k, default=None):
                if isinstance(result, dict):
                    return result.get(k, default)
                return getattr(result, k, default)
            vc = _g("verdict_card") or {}
            layer_trace = _g("layer_trace") or []
            fresh = {
                "output":       _g("output") or body_out,
                "engine":       _g("engine") or body.engine or "-",
                "confidence":   _g("confidence") if _g("confidence") is not None else body.confidence,
                "chain_ids":    [t.get("op") if isinstance(t, dict) else t for t in layer_trace]
                                 or (body.chain_ids or []),
                "verdict":      vc.get("verdict") or vc.get("label") or body.verdict,
                "verdict_card": vc,
                "iocs":         _g("iocs") or body.iocs or {},
                "mitre":        _g("mitre") or [],
                "lolbas":       _g("lolbas") or [],
                "reached_shellcode": bool(_g("reached_shellcode")),
                "reinvestigated_at": now,
            }
        except Exception:
            # Fall back to whatever the client sent — never fail the save.
            fresh = {}

    # Feb 2026 · UPSERT by (user_email, name) — a subsequent SAVE with the
    # same name updates the existing record instead of creating a duplicate.
    # This matches the analyst's mental model: "SAVE" on a case they've
    # already named should just persist their latest edits.
    existing = _col.find_one({"user_email": user_email, "name": name})
    doc_body = {
        "user_email":  user_email,
        "name":        name,
        "input":       body.input,
        "output":      fresh.get("output", body.output),
        "engine":      fresh.get("engine", body.engine),
        "confidence":  fresh.get("confidence", body.confidence),
        "chain_ids":   fresh.get("chain_ids", body.chain_ids),
        "verdict":     fresh.get("verdict", body.verdict),
        "iocs":        fresh.get("iocs", body.iocs),
        "input_len":   len(body.input),
        "output_len":  len(fresh.get("output", body.output) or ""),
        "updated_at":  now,
    }
    if fresh:
        # Only stash the extra fields if we actually re-ran the pipeline.
        doc_body["verdict_card"] = fresh.get("verdict_card")
        doc_body["mitre"]        = fresh.get("mitre")
        doc_body["lolbas"]       = fresh.get("lolbas")
        doc_body["reached_shellcode"] = fresh.get("reached_shellcode")
        doc_body["reinvestigated_at"] = fresh.get("reinvestigated_at")

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
    # ─── Tag History row with the friendly case name (Feb 2026) ──────────
    # The History Drawer previously showed only the raw input_preview. Now
    # rows carry `case_name` so the analyst can find "Immediate1" instantly.
    try:
        from routers.history import tag_history_with_case
        await tag_history_with_case(
            user_email or "", body.input or "", doc["name"], doc.get("id"),
        )
    except Exception:
        pass
    return {
        "id":         doc["id"],
        "name":       doc["name"],
        "created_at": doc["created_at"],
        "updated":    updated,
        "reinvestigated": bool(fresh),
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


# ═════════════════════════════════════════════════════════════════════════════
# SIGMA EXPORT — deterministic YAML rule for SIEM ingestion
# ═════════════════════════════════════════════════════════════════════════════
@router.get("/cases/{case_id}/sigma")
async def export_case_as_sigma(case_id: str, format: str = "yaml",
                                user=Depends(get_current_user)):
    """Auto-generate a Sigma detection rule from a saved case.
    format=yaml (default) returns text/yaml body; format=json returns the dict."""
    from fastapi.responses import Response
    from sigma_export import build_sigma_rule, rule_to_yaml
    doc = _col.find_one({"id": case_id})
    if not doc:
        raise HTTPException(status_code=404, detail="case not found")
    rule = build_sigma_rule(
        case_name=doc.get("name") or "case",
        case_id=doc.get("id"),
        verdict=doc.get("verdict_card") or (
            {"verdict": doc.get("verdict")} if isinstance(doc.get("verdict"), str) else (doc.get("verdict") or {})
        ),
        input_text=doc.get("input") or "",
        output_text=doc.get("output") or "",
        chain=doc.get("chain_ids") or [],
        iocs=doc.get("iocs") or {},
        mitre=doc.get("mitre") or [],
        lolbas=doc.get("lolbas") or [],
        author=(user.get("email") if isinstance(user, dict) else getattr(user, "email", None)) or "NivXRay",
    )
    if format == "json":
        return {"rule": rule}
    yaml_text = rule_to_yaml(rule)
    fname = f"{rule['id']}.yml"
    return Response(
        content=yaml_text,
        media_type="application/x-yaml",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ═════════════════════════════════════════════════════════════════════════════
# RE-INVESTIGATE — re-run /decode/smart on a saved case's input and persist
# the fresh output/verdict/iocs/mitre/chain to the case doc. Fixes the classic
# "OUTPUT=INPUT" saved-before-decode state.
# ═════════════════════════════════════════════════════════════════════════════
@router.post("/cases/{case_id}/reinvestigate")
async def reinvestigate_case(case_id: str, user=Depends(get_current_user)):
    """Re-run the deterministic decoding pipeline on this case's input and
    overwrite output / engine / confidence / verdict / iocs / chain_ids with
    the fresh result. Returns the updated case document."""
    doc = _col.find_one({"id": case_id})
    if not doc:
        raise HTTPException(status_code=404, detail="case not found")

    from routers.ops import decode_smart
    from schemas import AutoIn as _DecodeIn
    try:
        result = await decode_smart(_DecodeIn(input=doc.get("input") or ""), user=user)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"decode/smart failed: {e}")

    def _g(k, default=None):
        if isinstance(result, dict):
            return result.get(k, default)
        return getattr(result, k, default)

    # Extract structured fields from the fresh run
    fresh_output = _g("output") or ""
    fresh_engine = _g("engine")
    fresh_conf   = _g("confidence")
    iocs         = _g("iocs") or {}
    mitre        = _g("mitre") or []
    lolbas       = _g("lolbas") or []
    verdict_card = _g("verdict_card") or {}
    layer_trace  = _g("layer_trace") or []
    reached_sc   = bool(_g("reached_shellcode"))

    chain_ops = [t.get("op") if isinstance(t, dict) else t for t in layer_trace]
    verdict_str = verdict_card.get("verdict") or verdict_card.get("label")

    now = datetime.now(timezone.utc).isoformat()
    update = {
        "output":       fresh_output,
        "output_len":   len(fresh_output),
        "engine":       fresh_engine or "-",
        "confidence":   fresh_conf,
        "chain_ids":    chain_ops,
        "verdict":      verdict_str,
        "verdict_card": verdict_card,
        "iocs":         iocs,
        "mitre":        mitre,
        "lolbas":       lolbas,
        "reached_shellcode": reached_sc,
        "reinvestigated_at": now,
        "updated_at":   now,
    }
    _col.update_one({"id": case_id}, {"$set": update})
    # Feb 2026 — tag the history row created by decode_smart with the case name
    try:
        from routers.history import tag_history_with_case
        user_email = getattr(user, "email", None) or (user.get("email") if isinstance(user, dict) else None)
        await tag_history_with_case(
            user_email or "", doc.get("input") or "", doc.get("name") or "", doc.get("id"),
        )
    except Exception:
        pass
    doc = _col.find_one({"id": case_id}, {"_id": 0})
    return {"ok": True, "case": doc}


@router.post("/cases/reinvestigate-broken")
async def reinvestigate_broken(user=Depends(get_current_user)):
    """Batch: re-run the decoder on every case where output==input or the
    chain is empty (i.e. the case was saved before AUTO-INVESTIGATE ran)."""
    user_email = getattr(user, "email", None) or (
        user.get("email") if isinstance(user, dict) else None
    )
    q: Dict[str, Any] = {}
    if user_email:
        q["user_email"] = user_email
    docs = list(_col.find(q, {"id": 1, "input": 1, "output": 1, "chain_ids": 1, "name": 1, "_id": 0}))
    from routers.ops import decode_smart
    from schemas import AutoIn as _DecodeIn
    fixed: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    failed: List[Dict[str, Any]] = []
    for d in docs:
        inp = d.get("input") or ""
        out = d.get("output") or ""
        chain = d.get("chain_ids") or []
        # Broken = output equals input (echo bug) OR chain is empty
        if not inp:
            skipped.append({"id": d.get("id"), "name": d.get("name"), "reason": "empty input"})
            continue
        if out.strip() and out.strip() != inp.strip() and chain:
            skipped.append({"id": d.get("id"), "name": d.get("name"), "reason": "already investigated"})
            continue
        try:
            result = await decode_smart(_DecodeIn(input=inp), user=user)

            def _g(k, default=None):
                if isinstance(result, dict):
                    return result.get(k, default)
                return getattr(result, k, default)

            vc = _g("verdict_card") or {}
            layer_trace = _g("layer_trace") or []
            update = {
                "output":       _g("output") or "",
                "output_len":   len(_g("output") or ""),
                "engine":       _g("engine") or "-",
                "confidence":   _g("confidence"),
                "chain_ids":    [t.get("op") if isinstance(t, dict) else t for t in layer_trace],
                "verdict":      vc.get("verdict") or vc.get("label"),
                "verdict_card": vc,
                "iocs":         _g("iocs") or {},
                "mitre":        _g("mitre") or [],
                "lolbas":       _g("lolbas") or [],
                "reached_shellcode": bool(_g("reached_shellcode")),
                "reinvestigated_at": datetime.now(timezone.utc).isoformat(),
                "updated_at":   datetime.now(timezone.utc).isoformat(),
            }
            _col.update_one({"id": d["id"]}, {"$set": update})
            # Tag the history row so History Drawer shows the friendly name
            try:
                from routers.history import tag_history_with_case
                user_email_now = getattr(user, "email", None) or (
                    user.get("email") if isinstance(user, dict) else None
                )
                await tag_history_with_case(
                    user_email_now or "", inp, d.get("name") or "", d.get("id"),
                )
            except Exception:
                pass
            fixed.append({
                "id":      d.get("id"),
                "name":    d.get("name"),
                "verdict": update["verdict"],
                "engine":  update["engine"],
                "chain_len": len(update["chain_ids"]),
                "output_len": update["output_len"],
            })
        except Exception as e:  # noqa: BLE001
            failed.append({"id": d.get("id"), "name": d.get("name"), "error": str(e)[:200]})
    return {
        "total": len(docs),
        "fixed": fixed,
        "skipped": skipped,
        "failed": failed,
    }
