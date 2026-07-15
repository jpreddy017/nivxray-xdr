"""Documentation router — /api/docs/*.

Endpoints
    GET  /api/docs/stats
    GET  /api/docs/features                     list all features
    GET  /api/docs/features/{id}                one feature
    GET  /api/docs/workflows                    list all workflows
    GET  /api/docs/workflows/{id}               one workflow
    GET  /api/docs/guide?audience=user|admin|developer|all
                                                auto-generated Markdown guide
    GET  /api/docs/export/pdf?audience=...      auto-generated PDF User Guide
    GET  /api/docs/search?q=...
    POST /api/docs/explain                      AI "explain this page" helper
"""
from __future__ import annotations
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

from deps import get_current_user
from docs import (
    list_features, get_feature, list_workflows, get_workflow,
    search, generate_guide, guide_stats,
)
from docs.pdf_generator import create_user_guide


router = APIRouter()


class ExplainIn(BaseModel):
    page: str = Field(..., description="Page id, e.g. 'candidate_explorer' or 'encoded_powershell'")
    context: Optional[str] = Field(None, description="Optional extra context")
    question: Optional[str] = Field(None, description="Optional follow-up question")
    session_id: Optional[str] = Field(None, description="Reuse an existing chat session for multi-turn follow-ups")


def _resolve_page(page_id: str) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Return (doc, kind) — kind is 'feature' | 'workflow' | None."""
    feat = get_feature(page_id)
    if feat:
        return feat, "feature"
    wf = get_workflow(page_id)
    if wf:
        return wf, "workflow"
    return None, None


def _build_context_block(doc: Dict[str, Any], kind: str) -> str:
    """Compact YAML-derived per-page context for the LLM."""
    if kind == "workflow":
        lines = [
            f"WORKFLOW: {doc.get('title')} (id={doc.get('id')})",
            f"Purpose: {doc.get('purpose', '')}",
            "Steps:",
        ]
        for i, s in enumerate(doc.get("steps") or [], 1):
            lines.append(f"  {i}. {s.get('title', '')}")
            if s.get("action"):
                lines.append(f"     action: {s['action']}")
            if s.get("expected"):
                lines.append(f"     expected: {s['expected']}")
        rel = doc.get("related_features") or []
        if rel:
            lines.append(f"Related features: {', '.join(rel)}")
        return "\n".join(lines)

    lines = [
        f"FEATURE: {doc.get('title')} (id={doc.get('id')})",
        f"Category: {doc.get('category', '?')}  ·  Audience: {doc.get('audience', 'user')}",
        f"Purpose: {doc.get('purpose', '')}",
    ]
    for label, key in (("When to use", "when_to_use"),
                       ("Supported formats", "supported_formats"),
                       ("Confidence rules", "confidence_rules"),
                       ("Common errors", "common_errors"),
                       ("Tips", "tips")):
        vals = doc.get(key) or []
        if vals:
            lines.append(f"{label}:")
            lines.extend(f"  - {v}" for v in vals)
    exs = doc.get("examples") or []
    if exs:
        lines.append("Examples:")
        for ex in exs:
            lines.append(f"  input='{ex.get('input', '')}'  →  output='{ex.get('output', '')}'")
            if ex.get("notes"):
                lines.append(f"    note: {ex['notes']}")
    rel = doc.get("related") or []
    if rel:
        # Enrich with related feature titles so the LLM can compare/contrast.
        enriched = []
        for rid in rel:
            r = get_feature(rid)
            enriched.append(f"{rid} ({r.get('title')})" if r else rid)
        lines.append(f"Related features: {', '.join(enriched)}")
    return "\n".join(lines)


def _suggested_questions(doc: Optional[Dict[str, Any]], kind: Optional[str]) -> List[str]:
    """Return 3 smart follow-up questions grounded in the page's YAML."""
    if not doc:
        return [
            "What can NivXRay do?",
            "How do I decode a suspicious PowerShell blob?",
            "Where do I start as a new analyst?",
        ]
    if kind == "workflow":
        title = doc.get("title", "this workflow")
        rel = doc.get("related_features") or []
        qs = [
            f"What's the fastest shortcut to complete '{title}'?",
            "Which step trips up new analysts most often?",
        ]
        if rel:
            qs.append(f"How does this workflow use `{rel[0]}`?")
        else:
            qs.append("What does a successful run look like?")
        return qs
    # feature
    title = doc.get("title", "this feature")
    rel = doc.get("related") or []
    qs = [f"What's a common mistake when using {title}?"]
    if rel:
        qs.append(f"How is {title} different from `{rel[0]}`?")
    else:
        qs.append(f"When should I NOT use {title}?")
    if doc.get("examples"):
        qs.append("Walk me through one of the examples step-by-step.")
    else:
        qs.append("Show me a realistic input this would apply to.")
    return qs[:3]


@router.post("/docs/explain", tags=["docs"])
async def explain_this_page(body: ExplainIn, user=Depends(get_current_user)):
    """AI contextual help — describe a page + how to use it.

    Phase-2 enhancements:
    - Auto-loads the full feature/workflow YAML (per-page context) into the prompt
    - Enriches related features with their titles for compare/contrast questions
    - Multi-turn: pass back `session_id` from a previous turn to ask follow-ups
    - Returns 3 grounded `suggested_questions` derived from the page's YAML
    - Static fallback still returns a useful markdown summary when no key
    """
    doc, kind = _resolve_page(body.page)

    # Static-registry summary (works with or without LLM).
    static_summary = None
    if doc and kind == "feature":
        static_summary = (
            f"**{doc.get('title')}** — {doc.get('purpose', '')}\n\n"
            + ("**When to use**\n" + "\n".join(f"- {w}" for w in (doc.get("when_to_use") or [])) + "\n\n"
               if doc.get("when_to_use") else "")
            + ("**Tips**\n" + "\n".join(f"- {t}" for t in (doc.get("tips") or []))
               if doc.get("tips") else "")
        ).strip()
    elif doc and kind == "workflow":
        steps_md = "\n".join(
            f"{i}. **{s.get('title', '')}** — {s.get('action', '')}"
            for i, s in enumerate(doc.get("steps") or [], 1)
        )
        static_summary = (
            f"**{doc.get('title')}** — {doc.get('purpose', '')}\n\n{steps_md}"
        ).strip()

    suggested = _suggested_questions(doc, kind)

    key = os.environ.get("EMERGENT_LLM_KEY", "")
    if not key:
        return {
            "provider": "static-registry",
            "session_id": body.session_id or f"static-{body.page}",
            "explanation": static_summary or (
                "No LLM key configured and no matching feature/workflow for "
                f"`{body.page}`. Try `GET /api/docs/search?q={body.page}`."
            ),
            "suggested_questions": suggested,
        }

    try:
        from emergentintegrations.llm.chat import LlmChat, UserMessage
        system = (
            "You are NivXRay's in-app help — a senior SOC analyst pair-programmer.\n"
            "Answer as concise GitHub-flavoured Markdown. Be specific to the page's YAML "
            "content that's provided. When the analyst asks a follow-up, reuse the earlier "
            "context — do NOT re-summarise unless asked.\n"
            "Default format when no follow-up question is provided:\n"
            "  • **What it does** — one sentence\n"
            "  • **When to use** — 2-3 bullets grounded in the YAML\n"
            "  • **Pitfall** — one common mistake\n"
            "  • **Related** — one sentence pointing at a related feature (if given)\n"
            "Keep total length ≤ 200 words unless the analyst asks for depth."
        )
        parts = [f"Page id: `{body.page}`"]
        if doc and kind:
            parts.append(f"Per-page context (from YAML):\n```\n{_build_context_block(doc, kind)}\n```")
        else:
            parts.append("No matching feature/workflow found. Answer generally about NivXRay.")
        if body.context:
            parts.append(f"Extra context from the UI:\n{body.context}")
        if body.question:
            parts.append(f"Analyst question: {body.question}")
        else:
            parts.append("Analyst has not asked a question yet — produce the default summary.")
        prompt = "\n\n".join(parts)

        session_id = body.session_id or f"explain-{body.page}-{user.get('email', 'anon') if isinstance(user, dict) else 'anon'}"
        chat = (
            LlmChat(api_key=key, session_id=session_id, system_message=system)
            .with_model("anthropic", "claude-sonnet-4-5-20250929")
            .with_params(max_tokens=450)
        )
        reply = await chat.send_message(UserMessage(text=prompt))
        return {
            "provider": "emergent-claude",
            "session_id": session_id,
            "explanation": (reply or "").strip() or static_summary or "",
            "suggested_questions": suggested,
        }
    except Exception as e:
        return {
            "provider": "static-registry",
            "session_id": body.session_id or f"static-{body.page}",
            "explanation": static_summary or f"LLM error: {e}",
            "suggested_questions": suggested,
        }


@router.get("/docs/stats", tags=["docs"])
async def stats(user=Depends(get_current_user)):
    return guide_stats()


@router.get("/docs/features", tags=["docs"])
async def features_all(audience: Optional[str] = None,
                         user=Depends(get_current_user)):
    return {"features": list_features(audience=audience)}


@router.get("/docs/features/{feature_id}", tags=["docs"])
async def feature_one(feature_id: str, user=Depends(get_current_user)):
    doc = get_feature(feature_id)
    if not doc:
        raise HTTPException(404, f"feature '{feature_id}' not found")
    return doc


@router.get("/docs/workflows", tags=["docs"])
async def workflows_all(user=Depends(get_current_user)):
    return {"workflows": list_workflows()}


@router.get("/docs/workflows/{workflow_id}", tags=["docs"])
async def workflow_one(workflow_id: str, user=Depends(get_current_user)):
    doc = get_workflow(workflow_id)
    if not doc:
        raise HTTPException(404, f"workflow '{workflow_id}' not found")
    return doc


@router.get("/docs/guide", tags=["docs"])
async def guide(
    audience: str = Query("user", pattern="^(user|admin|developer|all)$"),
    user=Depends(get_current_user),
):
    return {"audience": audience, "markdown": generate_guide(audience=audience)}


@router.get("/docs/export/pdf", tags=["docs"])
async def export_pdf(
    audience: str = Query("user", pattern="^(user|admin|developer|all)$"),
    user=Depends(get_current_user),
):
    """Return an auto-generated PDF user guide for the given audience."""
    pdf_bytes = create_user_guide(audience=audience)
    filename = f"nivxray-{audience}-guide.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/docs/search", tags=["docs"])
async def search_endpoint(q: str = "", user=Depends(get_current_user)):
    return search(q)
