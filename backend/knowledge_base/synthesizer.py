"""LLM-driven KB entry synthesis (with anti-hallucination).

Given a bucket of past investigations sharing the same fingerprint, we ask
Claude to produce ONLY three things:
    1. Short title      (≤ 60 chars)
    2. 1-2 sentence summary
    3. 3–6 numbered triage playbook steps

Each string MUST cite an evidence substring drawn from either an input_preview,
output_preview, or verdict.summary of one of the source investigations. Any
step whose citation cannot be verified is dropped by `_verify_citations`.

If the LLM is unavailable or violates every rule, we fall back to a
deterministic template that never invents anything.
"""
from __future__ import annotations
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from fastapi import HTTPException
from deps import llm_json

log = logging.getLogger("nivxray")

_SYSTEM_PROMPT = """You are the NivXRay Knowledge Base Synthesizer.

You will receive a BUCKET of past investigations that share the same MITRE
+ verdict fingerprint. Your job is to distil them into a reusable KB entry.

STRICT RULES
1. Every text field you output MUST be defensible from the provided
   investigations. Do NOT invent IPs, URLs, filenames, tools, or claims.
2. Every playbook step MUST cite (via `evidence`) a substring taken verbatim
   from one of the investigation inputs, outputs, or verdict summaries.
3. If you cannot cite evidence for a step, do not emit that step.
4. Do NOT add MITRE IDs that are not already present in the bucket.

OUTPUT — strict JSON (no markdown, no commentary):
{
  "title": "≤ 60 char human title",
  "summary": "1-2 sentences describing this archetype",
  "severity": "info|low|medium|high|critical",
  "playbook_steps": [
    {"step": "short numbered triage action", "evidence": "<substring cited>"},
    ...
  ],
  "hunt_queries": ["short Sigma/YARA/KQL idea", ...],
  "evidence_refs": ["<substring>", ...]
}
"""


def _bucket_to_prompt(bucket: List[Dict[str, Any]], max_items: int = 6) -> str:
    lines = []
    for i, inv in enumerate(bucket[:max_items], 1):
        lines.append(f"--- INVESTIGATION {i} ---")
        lines.append(f"engine: {inv.get('engine') or 'unknown'}")
        lines.append(f"verdict: {(inv.get('verdict') or {}).get('verdict','unknown')}")
        lines.append(f"MITRE ids: {[m.get('id') for m in (inv.get('mitre') or [])[:4]]}")
        lines.append(f"input_preview:\n{(inv.get('input_preview') or '')[:400]}")
        lines.append(f"output_preview:\n{(inv.get('output_preview') or '')[:400]}")
        v_summary = (inv.get("verdict") or {}).get("summary", "")
        if v_summary:
            lines.append(f"verdict.summary: {v_summary[:200]}")
        iocs = inv.get("iocs") or {}
        if any(iocs.values()):
            lines.append(f"iocs: {json.dumps({k: v[:3] for k, v in iocs.items() if v})}")
    return "\n".join(lines)


def _corpus(bucket: List[Dict[str, Any]]) -> str:
    """The union of all searchable text from the bucket — used for citation checks."""
    pieces = []
    for inv in bucket:
        pieces.append(inv.get("input_preview") or "")
        pieces.append(inv.get("output_preview") or "")
        pieces.append((inv.get("verdict") or {}).get("summary", "") or "")
    return "\n".join(pieces).lower()


def _verify_citations(data: Dict[str, Any], corpus: str) -> Tuple[Dict[str, Any], List[str]]:
    """Drop playbook_steps whose evidence citation isn't in the corpus."""
    warnings: List[str] = []
    kept_steps = []
    for s in data.get("playbook_steps") or []:
        if not isinstance(s, dict):
            continue
        step = (s.get("step") or "").strip()
        ev = (s.get("evidence") or "").strip().lower()
        if not step:
            continue
        if not ev:
            warnings.append(f"dropped playbook step (no evidence): {step[:60]}")
            continue
        if ev not in corpus:
            warnings.append(f"dropped playbook step (uncited evidence): {step[:60]}")
            continue
        kept_steps.append(step)
    data["playbook_steps"] = kept_steps

    # Same rule for evidence_refs — must appear in corpus
    kept_refs = [r for r in (data.get("evidence_refs") or [])
                 if isinstance(r, str) and r.lower() in corpus]
    if len(kept_refs) < len(data.get("evidence_refs") or []):
        warnings.append("some evidence_refs pruned as uncited")
    data["evidence_refs"] = kept_refs
    return data, warnings


def _deterministic_fallback(bucket: List[Dict[str, Any]]) -> Dict[str, Any]:
    """A safe, honest KB entry when the LLM is unavailable or fully hallucinated."""
    engines = sorted({(inv.get("engine") or "unknown") for inv in bucket})
    verdicts = sorted({(inv.get("verdict") or {}).get("verdict", "unknown") for inv in bucket})
    mitres = sorted({m.get("id") for inv in bucket for m in (inv.get("mitre") or []) if m.get("id")})
    title = f"{verdicts[0]} · {(mitres[:2] or ['unclassified'])[0]}"
    summary = (f"Archetype derived from {len(bucket)} investigation(s) using engine(s) "
               f"{', '.join(engines)}. MITRE: {', '.join(mitres[:5]) or 'none'}. "
               "Playbook synthesis unavailable — deterministic fallback.")
    return {
        "title": title[:60],
        "summary": summary,
        "severity": "medium",
        "playbook_steps": [],
        "hunt_queries": [],
        "evidence_refs": [],
    }


async def synthesize(bucket: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], List[str]]:
    """Return (synth_data, warnings). Never raises."""
    if not bucket:
        return _deterministic_fallback([]), ["empty bucket"]

    user_prompt = _bucket_to_prompt(bucket)
    session_id = f"kb-{datetime.now(timezone.utc).timestamp()}"
    try:
        data = await llm_json(session_id, _SYSTEM_PROMPT, user_prompt, retries=1)
    except HTTPException as e:
        log.warning("KB synth: LLM unavailable — using deterministic fallback (%s)", e.detail)
        return _deterministic_fallback(bucket), [f"LLM upstream unavailable ({e.detail})"]
    except Exception as e:
        log.warning("KB synth: LLM failed — %s", e)
        return _deterministic_fallback(bucket), [f"LLM error: {e}"]

    if not isinstance(data, dict):
        return _deterministic_fallback(bucket), ["LLM returned non-dict"]

    corpus = _corpus(bucket)
    data, warns = _verify_citations(data, corpus)

    # If validator stripped everything, fall back but keep title/summary/severity
    if not data.get("playbook_steps") and not data.get("hunt_queries"):
        fb = _deterministic_fallback(bucket)
        # keep LLM's title/summary if provided and non-empty
        for k in ("title", "summary", "severity"):
            v = data.get(k)
            if isinstance(v, str) and v.strip():
                fb[k] = v.strip()
        warns.append("playbook empty after validation — deterministic fields used")
        return fb, warns

    # Normalise fields
    return {
        "title":         (data.get("title") or "").strip()[:60] or _deterministic_fallback(bucket)["title"],
        "summary":       (data.get("summary") or "").strip() or _deterministic_fallback(bucket)["summary"],
        "severity":      (data.get("severity") or "medium").strip().lower(),
        "playbook_steps": data.get("playbook_steps") or [],
        "hunt_queries":   [q for q in (data.get("hunt_queries") or []) if isinstance(q, str)][:6],
        "evidence_refs":  data.get("evidence_refs") or [],
    }, warns
