"""Admin router — OSINT keys, Model Studio, Sample Library, Users, LOLBAS."""
from __future__ import annotations
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException

from schemas import (
    SettingsUpdateIn, ModelIn, ModelPatchIn, ModelTestIn,
    SampleIn, SamplePatchIn, SampleBulkIn,
)
from deps import db, require_admin, load_osint_keys, mask
from operations import OPERATIONS, run_operation
from smart_decoder import smart_decode
from magic_decoder import magic_decode
from osint import OSINT_SERVICES
from lolbas import (
    get_status as lolbas_status,
    refresh_from_source as lolbas_refresh,
)
import models_studio as ms
import sample_library as sl

router = APIRouter()


# ============================================================================
# OSINT settings
# ============================================================================
@router.get("/admin/osint/services")
async def get_osint_services(user=Depends(require_admin)):
    keys = await load_osint_keys()
    return [
        {**s, "configured": bool(keys.get(s["id"])), "masked_key": mask(keys.get(s["id"], ""))}
        for s in OSINT_SERVICES
    ]


@router.put("/admin/osint/settings")
async def update_osint_settings(body: SettingsUpdateIn, user=Depends(require_admin)):
    existing = await load_osint_keys()
    merged = {**existing}
    for svc_id, key in body.keys.items():
        if svc_id not in [s["id"] for s in OSINT_SERVICES]:
            continue
        if key == "":
            merged.pop(svc_id, None)
        else:
            merged[svc_id] = key.strip()
    await db.settings.update_one(
        {"_id": "osint_keys"},
        {"$set": {"keys": merged, "updated_by": user["email"],
                  "updated_at": datetime.now(timezone.utc).isoformat()}},
        upsert=True,
    )
    return {"ok": True, "configured_services": [k for k, v in merged.items() if v]}


@router.post("/admin/osint/test/{service_id}")
async def test_osint(service_id: str, user=Depends(require_admin)):
    keys = await load_osint_keys()
    key = keys.get(service_id)
    if not key:
        raise HTTPException(status_code=400, detail=f"No API key configured for {service_id}")
    async with httpx.AsyncClient(timeout=8.0, headers={"User-Agent": "NivXRay/1.0"}) as c:
        try:
            if service_id == "virustotal":
                r = await c.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                                headers={"x-apikey": key})
            elif service_id == "abuseipdb":
                r = await c.get("https://api.abuseipdb.com/api/v2/check",
                                headers={"Key": key, "Accept": "application/json"},
                                params={"ipAddress": "8.8.8.8", "maxAgeInDays": 30})
            elif service_id == "shodan":
                r = await c.get("https://api.shodan.io/api-info", params={"key": key})
            elif service_id == "greynoise":
                r = await c.get("https://api.greynoise.io/v3/community/8.8.8.8",
                                headers={"key": key})
            elif service_id == "urlscan":
                r = await c.get("https://urlscan.io/user/quotas/", headers={"API-Key": key})
            elif service_id == "otx":
                r = await c.get("https://otx.alienvault.com/api/v1/user/me",
                                headers={"X-OTX-API-KEY": key})
            elif service_id == "ipinfo":
                r = await c.get("https://ipinfo.io/8.8.8.8", params={"token": key})
            elif service_id == "hybrid_analysis":
                r = await c.get("https://www.hybrid-analysis.com/api/v2/key/current",
                                headers={"api-key": key, "user-agent": "Falcon Sandbox"})
            else:
                raise HTTPException(status_code=400, detail="Unknown service")
            return {"ok": r.status_code < 400, "status_code": r.status_code,
                    "body_snippet": r.text[:200]}
        except HTTPException:
            raise
        except Exception as e:
            return {"ok": False, "error": str(e)}


# ============================================================================
# Users + stats
# ============================================================================
@router.get("/admin/users")
async def list_users(user=Depends(require_admin)):
    return await db.users.find({}, {"_id": 0, "password": 0}).to_list(50)


@router.get("/admin/stats")
async def admin_stats(user=Depends(require_admin)):
    total_shares = await db.shares.count_documents({})
    total_users = await db.users.count_documents({})
    total_iocs = await db.iocs.count_documents({})
    keys = await load_osint_keys()
    return {
        "total_shares": total_shares,
        "total_users": total_users,
        "total_iocs": total_iocs,
        "configured_osint_services": len([v for v in keys.values() if v]),
        "total_operations": len(OPERATIONS),
        "lolbas": lolbas_status(),
    }


# ============================================================================
# Model Studio
# ============================================================================
@router.get("/admin/models")
async def list_admin_models(kind: Optional[str] = None, user=Depends(require_admin)):
    if kind and kind not in ms.MODEL_KINDS:
        raise HTTPException(status_code=400, detail=f"invalid kind: {kind}")
    return await ms.list_models(db, kind=kind)


@router.get("/admin/models/catalog")
async def model_catalog(user=Depends(require_admin)):
    return {
        "kinds": list(ms.MODEL_KINDS),
        "operations": sorted(OPERATIONS.keys()),
        "providers": [
            {"provider": "anthropic", "model": "claude-sonnet-4-5-20250929", "label": "Claude Sonnet 4.5"},
            {"provider": "openai", "model": "gpt-5.2", "label": "GPT-5.2"},
            {"provider": "google", "model": "gemini-3-pro", "label": "Gemini 3 Pro"},
        ],
    }


@router.post("/admin/models")
async def create_admin_model(body: ModelIn, user=Depends(require_admin)):
    try:
        return await ms.create_model(
            db, kind=body.kind, name=body.name, config=body.config or {},
            created_by=user.get("email"), enabled=body.enabled,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/admin/models/{model_id}")
async def update_admin_model(model_id: str, body: ModelPatchIn, user=Depends(require_admin)):
    try:
        patch = {k: v for k, v in body.model_dump().items() if v is not None}
        updated = await ms.update_model(db, model_id, patch)
        if not updated:
            raise HTTPException(status_code=404, detail="model not found")
        return updated
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/admin/models/{model_id}")
async def delete_admin_model(model_id: str, user=Depends(require_admin)):
    try:
        ok = await ms.delete_model(db, model_id)
        if not ok:
            raise HTTPException(status_code=404, detail="model not found")
        return {"deleted": True}
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))


@router.post("/admin/models/{model_id}/test")
async def test_admin_model(model_id: str, body: ModelTestIn, user=Depends(require_admin)):
    """Test a model against a sample input."""
    m = await ms.get_model(db, model_id)
    if not m:
        raise HTTPException(status_code=404, detail="model not found")
    kind = m["kind"]
    cfg = m.get("config") or {}
    sample = body.sample or ""
    if kind == "detection_rule":
        hits = ms.scan_custom_rules(sample, [{
            "binary_regex": cfg.get("binary_regex", ""),
            "argv": cfg.get("argv_regex"),
            "purposes": cfg.get("purposes") or ["Custom"],
            "mitre": cfg.get("mitre") or [],
            "desc": cfg.get("description") or m["name"],
            "url": "", "source": f"custom:{m['id']}",
            "name": m["name"], "severity": cfg.get("severity", "medium"),
            "model_id": m["id"],
        }])
        return {"kind": kind, "matched": bool(hits), "hits": hits}
    if kind == "decode_recipe":
        try:
            matched = bool(re.search(cfg.get("match_regex", ""), sample, re.IGNORECASE | re.DOTALL))
        except re.error as e:
            raise HTTPException(status_code=400, detail=f"invalid match_regex: {e}")
        steps_out: List[Dict[str, Any]] = []
        output = sample
        if matched:
            for step in (cfg.get("ops") or []):
                op = step.get("op")
                if op not in OPERATIONS:
                    steps_out.append({"op": op, "error": "unknown op"})
                    break
                try:
                    output = run_operation(op, output, step.get("args") or {})
                    steps_out.append({"op": op, "output_preview": (output or "")[:300]})
                except Exception as e:
                    steps_out.append({"op": op, "error": str(e)})
                    break
        return {"kind": kind, "matched": matched, "steps": steps_out, "output": output}
    if kind == "ai_persona":
        return {"kind": kind,
                "system_prompt_preview": (cfg.get("system_prompt") or "")[:800],
                "sample_would_be_sent_as": (sample or "(no sample provided)")[:400]}
    if kind == "ai_provider":
        return {"kind": kind, "provider": cfg.get("provider"), "model": cfg.get("model"),
                "note": "Provider connectivity is verified at Auto-Investigate time via the Emergent Universal LLM Key."}
    if kind == "playbook":
        return {"kind": kind,
                "applies_to": cfg.get("applies_to") or ["ai"],
                "body_preview": (cfg.get("body") or "")[:800],
                "note": "This playbook is auto-appended to every AI investigation. Trigger AUTO-INVESTIGATE on a sample to see the effect."}
    if kind == "training_note":
        return {"kind": kind,
                "body_preview": (cfg.get("body") or "")[:800],
                "note": "This training note is ALWAYS PREPENDED to every AI investigation system prompt (ranked above playbooks). Analyst 👍/👎 votes adjust its ordering for future prompts."}
    raise HTTPException(status_code=400, detail=f"unknown kind: {kind}")


# ============================================================================
# Malware Sample Library
# ============================================================================
@router.get("/admin/samples")
async def list_samples_endpoint(category: Optional[str] = None, user=Depends(require_admin)):
    return await sl.list_samples(db, category=category)


@router.get("/admin/samples/dashboard")
async def samples_dashboard(user=Depends(require_admin)):
    return await sl.dashboard_snapshot(db)


@router.get("/admin/samples/{sid}")
async def get_sample_endpoint(sid: str, user=Depends(require_admin)):
    s = await sl.get_sample(db, sid)
    if not s:
        raise HTTPException(status_code=404, detail="sample not found")
    return s


@router.post("/admin/samples")
async def create_sample_endpoint(body: SampleIn, user=Depends(require_admin)):
    try:
        return await sl.create_sample(db, body.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/admin/samples/bulk")
async def bulk_create_samples(body: SampleBulkIn, user=Depends(require_admin)):
    created, failed = [], []
    for s in body.samples:
        try:
            created.append(await sl.create_sample(db, s.model_dump()))
        except Exception as e:
            failed.append({"name": s.name, "error": str(e)})
    return {"created": len(created), "failed": len(failed), "items": created, "errors": failed}


@router.put("/admin/samples/{sid}")
async def update_sample_endpoint(sid: str, body: SamplePatchIn, user=Depends(require_admin)):
    patch = {k: v for k, v in body.model_dump().items() if v is not None}
    updated = await sl.update_sample(db, sid, patch)
    if not updated:
        raise HTTPException(status_code=404, detail="sample not found")
    return updated


@router.delete("/admin/samples/{sid}")
async def delete_sample_endpoint(sid: str, user=Depends(require_admin)):
    try:
        ok = await sl.delete_sample(db, sid)
        if not ok:
            raise HTTPException(status_code=404, detail="sample not found")
        return {"deleted": True}
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))


@router.post("/admin/samples/{sid}/benchmark")
async def benchmark_one_endpoint(sid: str, user=Depends(require_admin)):
    try:
        return await sl.benchmark_one(db, sid, smart_decode, magic_decode)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/admin/samples/benchmark/all")
async def benchmark_all_endpoint(user=Depends(require_admin)):
    return await sl.benchmark_all(db, smart_decode, magic_decode)


# ============================================================================
# LOLBAS catalog admin
# ============================================================================
@router.get("/admin/lolbas/status")
async def get_lolbas_status(user=Depends(require_admin)):
    return lolbas_status()


@router.post("/admin/lolbas/sync")
async def sync_lolbas_catalog(user=Depends(require_admin)):
    """Force-refresh the LOLBAS catalog from lolbas-project.github.io."""
    return await lolbas_refresh(db)



# ============================================================================
# LLM Telemetry (observability only — no architectural change)
# ============================================================================
@router.get("/admin/llm-telemetry")
async def get_llm_telemetry(user=Depends(require_admin)):
    """Snapshot of in-process LLM call counters.

    Use this to spot event-loop starvation (in_flight climbs but
    completed_total stalls) or runaway loops (started_total rises while the
    UI is idle).
    """
    from utils.llm_telemetry import snapshot
    out = snapshot()
    try:
        from llm_decoder import l3_rate_snapshot
        out["l3_rate_limiter"] = l3_rate_snapshot()
    except Exception:
        pass
    return out


@router.get("/admin/resource-protection")
async def get_resource_protection(user=Depends(require_admin)):
    """Snapshot of the Resource Protection Policy every adapter enforces.

    Values are read at process start from :mod:`services.resource_protection`
    and may be overridden via ``NIVX_RPP_<KIND>_<SETTING>`` env vars.
    """
    from services.resource_protection import snapshot
    return snapshot()


@router.post("/admin/behaviors/preview")
async def preview_behaviors(body: dict, user=Depends(require_admin)):
    """Deterministic behavior extraction preview.

    Body: ``{"text": "<raw PowerShell / command / decoded output>"}``.

    Returns the folded text, MITRE techniques, kill-chain lanes, and
    de-duplicated behavior nodes exactly as the Reasoning Engine will
    consume them.  Purely deterministic — no LLM.
    """
    from services.normalization.powershell_folding import fold
    from services.reasoning.behavior_extractor import (
        extract_behaviors, correlate_behaviors,
        to_lane_map, to_mitre_techniques,
    )
    text = (body or {}).get("text") or ""
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        lines = [text]
    folded = [fold(line) for line in lines]
    per_line = [
        extract_behaviors(line, location_prefix=f"line.{i+1}")
        for i, line in enumerate(lines)
    ]
    merged = correlate_behaviors(per_line)
    return {
        "input_lines":  len(lines),
        "folded":       [f.text for f in folded],
        "transformations": [f.transformations for f in folded],
        "behaviors":    [
            {
                "id":               b.id,
                "title":            b.title,
                "kill_chain":       b.kill_chain,
                "mitre_techniques": b.mitre_techniques,
                "mitre_tactic":     b.mitre_tactic,
                "confidence":       b.confidence,
                "description":      b.description,
                "evidence":         [
                    {"text": e.text, "location": e.location}
                    for e in b.evidence
                ],
            }
            for b in merged
        ],
        "lanes":  {
            phase: [b.id for b in bs]
            for phase, bs in to_lane_map(merged).items()
        },
        "mitre":  to_mitre_techniques(merged),
    }
