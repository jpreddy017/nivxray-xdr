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
from typing import Any, Dict, Optional

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
    page: str = Field(..., description="Page id, e.g. 'workspace', 'admin/regression'")
    context: Optional[str] = Field(None, description="Optional extra context")
    question: Optional[str] = None


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


@router.post("/docs/explain", tags=["docs"])
async def explain_this_page(body: ExplainIn, user=Depends(get_current_user)):
    """AI contextual help — describe a page + how to use it.

    Uses Claude via Emergent LLM key when configured. Falls back to a
    static feature-registry-driven explanation when the key is missing.
    """
    # Try to find a matching feature or workflow by id / title fragment.
    feat = get_feature(body.page)
    static_summary = None
    if feat:
        static_summary = (
            f"**{feat.get('title')}** — {feat.get('purpose', '')}\n\n"
            f"When to use:\n" + "\n".join(f"- {w}" for w in (feat.get("when_to_use") or []))
        )

    key = os.environ.get("EMERGENT_LLM_KEY", "")
    if not key:
        return {
            "provider": "static-registry",
            "explanation": static_summary or (
                "No LLM key configured and no matching feature found for "
                f"`{body.page}`. Use `GET /api/docs/search?q={body.page}` to browse."
            ),
        }

    try:
        from emergentintegrations.llm.chat import LlmChat, UserMessage
        system = (
            "You are NivXRay's in-app help. Explain in 3-4 short bullet points: "
            "(1) what this page does, (2) when an analyst should use it, "
            "(3) one common mistake to avoid. Reply as concise Markdown only."
        )
        prompt_parts = [f"Page: {body.page}"]
        if static_summary:
            prompt_parts.append(f"Feature-registry summary:\n{static_summary}")
        if body.context:
            prompt_parts.append(f"Extra context:\n{body.context}")
        if body.question:
            prompt_parts.append(f"User's question: {body.question}")
        prompt = "\n\n".join(prompt_parts)

        chat = (
            LlmChat(api_key=key, session_id=f"explain-{body.page}",
                    system_message=system)
            .with_model("anthropic", "claude-sonnet-4-5-20250929")
            .with_params(max_tokens=350)
        )
        reply = await chat.send_message(UserMessage(text=prompt))
        return {"provider": "emergent-claude",
                "explanation": (reply or "").strip() or static_summary or ""}
    except Exception as e:
        return {"provider": "static-registry",
                "explanation": static_summary or f"LLM error: {e}"}
