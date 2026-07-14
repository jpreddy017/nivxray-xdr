"""AI router — /api/ai/auto-decode, /api/ai/auto-investigate, /api/ai/troubleshoot."""
from __future__ import annotations
import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException

from schemas import AutoIn, TroubleshootIn, RecipeStep, RunRecipeIn, AnalyzeIn
from deps import get_current_user, llm_json
from operations import OPERATIONS
from magic_decoder import magic_decode
from analysis_core import (
    deterministic_best_decode, extract_iocs_from_text,
)
from routers.ops import run_recipe
from routers.analyze import analyze as run_analyze

router = APIRouter()

_OP_IDS = sorted(OPERATIONS.keys())


@router.post("/ai/auto-decode")
async def ai_auto_decode(body: AutoIn, user=Depends(get_current_user)):
    """AI Decode with strict anti-hallucination guardrails for SOC use."""
    system = (
        "You are an expert malware analyst using a CyberChef-like tool. "
        "Given an obfuscated / encoded payload, produce a JSON recipe of operations that will fully decode it.\n"
        f"AVAILABLE OPERATION IDS: {_OP_IDS}\n"
        "Return STRICT JSON only with keys: reasoning (short string), steps (array of {op, args}).\n"
        "For XOR ops YOU MUST include the key in args, e.g. {\"op\":\"xor\",\"args\":{\"key\":\"0x23\"}}. "
        "For gzip/zlib/base64 chained forms, list each step separately. "
        "Only use ids from AVAILABLE OPERATION IDS. Max 8 steps."
    )
    prompt = f"PAYLOAD:\n{body.input[:4000]}\n\nReturn only JSON."
    try:
        plan = await llm_json("autodecode-" + str(datetime.now(timezone.utc).timestamp()), system, prompt)
    except HTTPException:
        plan = {"reasoning": "AI unavailable — falling back to deterministic decoder.", "steps": []}

    ai_steps: List[RecipeStep] = []
    for s in (plan.get("steps") or [])[:8]:
        if s.get("op") in OPERATIONS:
            ai_steps.append(RecipeStep(op=s["op"], args=s.get("args") or {}))

    async def _run_ai_plan() -> Dict[str, Any]:
        if not ai_steps:
            return {"engine": "ai", "output": "", "recipe": [], "errors": ["no valid steps proposed"]}
        r = await run_recipe(RunRecipeIn(input=body.input, steps=ai_steps), user=user)
        return {
            "engine": "ai", "output": r.output or "",
            "recipe": [s.model_dump() for s in ai_steps],
            "steps_output": r.steps_output,
            "detected_type": r.detected_type,
            "errors": r.errors,
        }

    def _run_magic() -> Dict[str, Any]:
        m = magic_decode(body.input, max_depth=6, max_branches=5, top_n=3)
        top = (m.get("top_results") or [{}])[0]
        return {
            "engine": "magic", "output": top.get("output", ""),
            "recipe": [{"op": c["op"], "args": c.get("args") or {}}
                       for c in (top.get("chain") or [])],
            "steps_output": top.get("chain") or [],
            "detected_type": m.get("detected_type"),
            "errors": [],
            "is_shellcode": top.get("is_shellcode", False),
            "score": (top.get("score_breakdown") or {}).get("score", 0.0),
        }

    ai_task = asyncio.create_task(_run_ai_plan())
    magic_result = _run_magic()
    ai_result = await ai_task

    def _quality_score(res: Dict[str, Any]) -> Dict[str, Any]:
        out = res.get("output") or ""
        if not out:
            return {"score": 0.0, "printable_ratio": 0.0, "shellcode": False,
                    "iocs_found": 0, "reasons": ["empty output"]}
        printable = sum(1 for c in out if 32 <= ord(c) < 127 or ord(c) in (9, 10, 13))
        pr = printable / max(1, len(out))
        reasons: List[str] = []
        score = pr * 0.4

        try:
            from shellcode_analyzer import starts_with_known_prologue
            raw = out.encode("latin-1") if all(ord(c) < 256 for c in out) \
                                        else out.encode("utf-8", errors="replace")
            is_sc = starts_with_known_prologue(raw)
            if is_sc:
                score += 0.35
                reasons.append("known shellcode prologue detected (+0.35)")
        except Exception:
            is_sc = False

        try:
            iocs = extract_iocs_from_text(out)
            n_iocs = sum(len(v) if isinstance(v, list) else 0 for v in iocs.values())
            if n_iocs:
                score += min(0.20, 0.05 * n_iocs)
                reasons.append(f"{n_iocs} IOC(s) recovered")
        except Exception:
            n_iocs = 0

        markers = ("IEX", "Invoke-Expression", "DownloadString", "New-Object",
                   "FromBase64String", "http://", "https://", "MZ", "PE", "ELF",
                   "cmd.exe", "powershell", "$env:")
        matched_markers = [m for m in markers if m in out]
        if matched_markers:
            score += min(0.15, 0.05 * len(matched_markers))
            reasons.append(f"script markers: {matched_markers[:3]}")

        if pr >= 0.90 and not is_sc:
            score += 0.10
            reasons.append("clean printable (+0.10)")

        return {
            "score": round(min(1.0, score), 3),
            "printable_ratio": round(pr, 3),
            "shellcode": is_sc,
            "iocs_found": n_iocs,
            "reasons": reasons,
        }

    ai_q = _quality_score(ai_result)
    mg_q = _quality_score(magic_result)

    QUALITY_FLOOR = 0.35

    if ai_q["shellcode"] and not mg_q["shellcode"]:
        winner, wq, loser, lq = ai_result, ai_q, magic_result, mg_q
    elif mg_q["shellcode"] and not ai_q["shellcode"]:
        winner, wq, loser, lq = magic_result, mg_q, ai_result, ai_q
    elif ai_q["score"] >= mg_q["score"]:
        winner, wq, loser, lq = ai_result, ai_q, magic_result, mg_q
    else:
        winner, wq, loser, lq = magic_result, mg_q, ai_result, ai_q

    stopped_gracefully = wq["score"] < QUALITY_FLOOR

    return {
        "reasoning": plan.get("reasoning", ""),
        "recipe": winner["recipe"],
        "output": winner["output"] if not stopped_gracefully else "",
        "steps_output": winner.get("steps_output") or [],
        "detected_type": winner.get("detected_type"),
        "errors": winner.get("errors") or [],
        "winner_engine": winner["engine"],
        "confidence": int(round(wq["score"] * 100)),
        "quality_reasons": wq["reasons"],
        "stopped_gracefully": stopped_gracefully,
        "graceful_message": (
            "No further deterministic decoding possible. "
            f"Best attempt via '{winner['engine']}' engine scored {int(round(wq['score']*100))}/100 "
            f"(readability {int(wq['printable_ratio']*100)}%, "
            f"shellcode={wq['shellcode']}, IOCs={wq['iocs_found']}). "
            "The payload may already be plaintext, use a key/format not yet supported, "
            "or be intentionally corrupted."
        ) if stopped_gracefully else "",
        "alternate": {
            "engine": loser["engine"],
            "confidence": int(round(lq["score"] * 100)),
            "recipe": loser.get("recipe") or [],
        },
    }


@router.post("/ai/auto-investigate")
async def ai_auto_investigate(body: AutoIn, user=Depends(get_current_user)):
    """Auto Decode + full Analyze (OSINT + AI describe + AI verdict).

    Strategy:
      1. Run BOTH deterministic engines (smart + magic) and pick the winner
         using shellcode terminal state → score → chain length.
      2. If neither deterministic engine produced usable steps, fall back to
         AI-planned decode.
      3. Run OSINT enrichment and AI describe/verdict against the decoded output.
    """
    det = deterministic_best_decode(body.input)
    if det["steps"]:
        steps = [RecipeStep(op=x["op"], args=x.get("args", {})) for x in det["steps"]]
        reasoning = (
            f"Deterministic {det['engine']} decoder chained: "
            + " → ".join(s.op for s in steps)
            + ("  [reached-shellcode-terminal-state]" if det.get("reached_shellcode") else "")
        )
    else:
        dec = await ai_auto_decode(body, user=user)
        steps = [RecipeStep(op=s["op"], args=s.get("args", {})) for s in dec["recipe"]]
        reasoning = dec.get("reasoning", "")

    exec_result = await run_recipe(RunRecipeIn(input=body.input, steps=steps), user=user)
    decoded_output = exec_result.output

    analysis = await run_analyze(AnalyzeIn(
        input=body.input, output=decoded_output,
        use_ai_verdict=True, describe=True, enrich_osint=True,
    ), user=user)

    result = {
        "reasoning": reasoning,
        "recipe": [s.model_dump() for s in steps],
        "output": decoded_output,
        "steps_output": exec_result.steps_output,
        "detected_type": exec_result.detected_type,
        "errors": exec_result.errors,
        "analysis": analysis,
        "engine": det.get("engine"),
        "reached_shellcode": det.get("reached_shellcode", False),
    }
    # Auto-record the full-fat investigation into user's history
    try:
        from routers.history import record_investigation
        conf = int(round(min(1.0, (det.get("score") or 0.0)) * 100))
        await record_investigation(
            user["email"],
            input=body.input, output=decoded_output,
            chain=[s.op for s in steps],
            trace=[{"op": s.op, "args": s.args or {}} for s in steps],
            engine=det.get("engine"), confidence=conf,
            reached_shellcode=det.get("reached_shellcode", False),
            iocs=(analysis or {}).get("iocs") or {},
            mitre=(analysis or {}).get("mitre") or [],
            verdict=(analysis or {}).get("ai_verdict"),
        )
    except Exception:
        pass
    return result


@router.post("/ai/troubleshoot")
async def ai_troubleshoot(body: TroubleshootIn, user=Depends(get_current_user)):
    system = (
        "You are a DFIR analyst helping troubleshoot a stuck decoding recipe. "
        "Given the input, the recipe applied, and any error, explain what went wrong (1-3 sentences) "
        "and propose a fixed recipe.\n"
        f"AVAILABLE OPERATION IDS: {_OP_IDS}\n"
        "Return STRICT JSON: {diagnosis: string, suggested_steps: [{op, args}]}. Max 8 steps."
    )
    prompt = (
        f"INPUT:\n{body.input[:3000]}\n\n"
        f"CURRENT RECIPE: {json.dumps([s.model_dump() for s in body.steps])}\n\n"
        f"ERROR: {body.error or 'no error - output looks wrong'}\n\nReturn only JSON."
    )
    result = await llm_json("troubleshoot-" + str(datetime.now(timezone.utc).timestamp()), system, prompt)
    fixed = [{"op": s["op"], "args": s.get("args") or {}}
             for s in (result.get("suggested_steps") or [])[:8] if s.get("op") in OPERATIONS]
    return {"diagnosis": result.get("diagnosis", ""), "suggested_steps": fixed}
