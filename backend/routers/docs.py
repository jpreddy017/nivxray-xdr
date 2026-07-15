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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel, Field

from deps import db, get_current_user
from docs import (
    list_features, get_feature, list_workflows, get_workflow,
    search, generate_guide, guide_stats,
)
from docs.automation import (
    coverage_report, scaffold_yaml, suggest_fix, walk_routes,
)
from docs.exporters import generate_docx, generate_html
from docs.pdf_generator import create_user_guide
from docs.rag_index import retrieve as rag_retrieve, index_stats as rag_stats, invalidate as rag_invalidate


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

    Phase-3 (RAG) enhancements:
    - BM25 retrieval over the full docs corpus finds cross-feature snippets
      relevant to either the current page (default) or the analyst's question
    - Retrieved snippets are injected into the LLM prompt as authoritative
      context (top-3, current page excluded)
    - Response includes a `related_pages` list [{id, kind, title, score}] so
      the UI can render clickable chips to jump to those pages
    """
    doc, kind = _resolve_page(body.page)

    # ---- RAG retrieval (cross-feature) ------------------------------
    rag_query = body.question or ""
    if doc and not rag_query:
        # Use the page's own YAML as the retrieval query when the analyst
        # hasn't typed one — surfaces the most related sibling docs.
        rag_query = " ".join(filter(None, [
            doc.get("title", ""),
            doc.get("purpose", ""),
            " ".join(doc.get("when_to_use") or []),
            " ".join(doc.get("related") or doc.get("related_features") or []),
        ]))
    rag_hits = rag_retrieve(rag_query, k=3, exclude_ids=[body.page] if doc else None)
    related_pages = [
        {"id": h["id"], "kind": h["kind"], "title": h["title"], "score": h["score"]}
        for h in rag_hits
    ]

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
        # Append related-pages hint to the static summary so it's still useful.
        tail = ""
        if related_pages:
            tail = "\n\n**Related pages** — " + ", ".join(
                f"`{r['id']}`" for r in related_pages)
        return {
            "provider": "static-registry",
            "session_id": body.session_id or f"static-{body.page}",
            "explanation": (static_summary or (
                "No LLM key configured and no matching feature/workflow for "
                f"`{body.page}`. Try `GET /api/docs/search?q={body.page}`."
            )) + tail,
            "suggested_questions": suggested,
            "related_pages": related_pages,
        }

    try:
        from emergentintegrations.llm.chat import LlmChat, UserMessage
        system = (
            "You are NivXRay's in-app help — a senior SOC analyst pair-programmer.\n"
            "Answer as concise GitHub-flavoured Markdown. Ground every claim in the YAML "
            "content provided; if the RAG snippets contradict the current page, PREFER the "
            "current page's YAML and note the discrepancy briefly. When the analyst asks a "
            "follow-up, reuse the earlier context — do NOT re-summarise unless asked.\n"
            "Default format when no follow-up question is provided:\n"
            "  • **What it does** — one sentence\n"
            "  • **When to use** — 2-3 bullets grounded in the YAML\n"
            "  • **Pitfall** — one common mistake\n"
            "  • **Related** — one sentence pointing at the strongest related feature from RAG\n"
            "Keep total length ≤ 250 words unless the analyst asks for depth."
        )
        parts = [f"Page id: `{body.page}`"]
        if doc and kind:
            parts.append(f"Per-page context (from YAML):\n```\n{_build_context_block(doc, kind)}\n```")
        else:
            parts.append("No matching feature/workflow found. Answer generally about NivXRay.")
        if rag_hits:
            rag_block = "\n".join(
                f"- **{h['title']}** ({h['kind']}, id=`{h['id']}`, score={h['score']}): {h['snippet']}"
                for h in rag_hits
            )
            parts.append(
                "Cross-feature RAG results (top-3, current page excluded — cite by id when relevant):\n"
                + rag_block
            )
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
            .with_params(max_tokens=500)
        )
        reply = await chat.send_message(UserMessage(text=prompt))
        return {
            "provider": "emergent-claude",
            "session_id": session_id,
            "explanation": (reply or "").strip() or static_summary or "",
            "suggested_questions": suggested,
            "related_pages": related_pages,
        }
    except Exception as e:
        tail = ""
        if related_pages:
            tail = "\n\n**Related pages** — " + ", ".join(
                f"`{r['id']}`" for r in related_pages)
        return {
            "provider": "static-registry",
            "session_id": body.session_id or f"static-{body.page}",
            "explanation": (static_summary or f"LLM error: {e}") + tail,
            "suggested_questions": suggested,
            "related_pages": related_pages,
        }


@router.get("/docs/related", tags=["docs"])
async def related_pages(
    q: str = Query("", description="free-text query"),
    page: Optional[str] = Query(None, description="current page id to exclude"),
    k: int = Query(3, ge=1, le=10),
    user=Depends(get_current_user),
):
    """BM25 retrieval over the docs corpus.

    - Pass `q` alone for pure keyword search across features+workflows.
    - Pass `page` to auto-generate the query from that page's YAML AND
      exclude it from the results (cross-feature retrieval).
    """
    query = q
    exclude: List[str] = []
    if page:
        exclude.append(page)
        if not query:
            doc, kind = _resolve_page(page)
            if doc:
                query = " ".join(filter(None, [
                    doc.get("title", ""),
                    doc.get("purpose", ""),
                    " ".join(doc.get("when_to_use") or []),
                    " ".join(doc.get("related") or doc.get("related_features") or []),
                ]))
    hits = rag_retrieve(query or "", k=k, exclude_ids=exclude or None)
    return {"query": query, "hits": hits}


@router.get("/docs/rag/stats", tags=["docs"])
async def rag_index_stats(user=Depends(get_current_user)):
    return rag_stats()


@router.post("/docs/rag/reindex", tags=["docs"])
async def rag_reindex(user=Depends(get_current_user)):
    """Invalidate the in-memory BM25 index; next retrieval rebuilds it."""
    rag_invalidate()
    return {"status": "invalidated", "stats": rag_stats()}


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


@router.get("/docs/export/html", tags=["docs"])
async def export_html(
    audience: str = Query("user", pattern="^(user|admin|developer|all)$"),
    inline: bool = Query(False, description="Render inline instead of attachment"),
    user=Depends(get_current_user),
):
    """Return an auto-generated standalone HTML user guide."""
    html = generate_html(audience=audience)
    filename = f"nivxray-{audience}-guide.html"
    headers = {}
    if not inline:
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return HTMLResponse(content=html, headers=headers)


@router.get("/docs/export/docx", tags=["docs"])
async def export_docx(
    audience: str = Query("user", pattern="^(user|admin|developer|all)$"),
    user=Depends(get_current_user),
):
    """Return an auto-generated DOCX user guide."""
    data = generate_docx(audience=audience)
    filename = f"nivxray-{audience}-guide.docx"
    return Response(
        content=data,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/docs/search", tags=["docs"])
async def search_endpoint(q: str = "", user=Depends(get_current_user)):
    return search(q)


# ============================================================================
# Explain feedback loop — 👍/👎 on assistant replies → learning_events
# ============================================================================
class ExplainFeedbackIn(BaseModel):
    page: str = Field(..., description="Page id the reply was about")
    session_id: str = Field(..., description="Chat session id from /docs/explain")
    message_index: int = Field(0, ge=0, description="Position of the reply in the thread")
    vote: str = Field(..., pattern="^(up|down|none)$")
    provider: Optional[str] = Field(None, description="emergent-claude | static-registry")
    question: Optional[str] = Field(None, description="Analyst question this reply answered")
    reply_snippet: Optional[str] = Field(None, description="First ~500 chars of the reply")
    comment: Optional[str] = Field(None, description="Optional freeform comment")


@router.post("/docs/explain/feedback", tags=["docs"])
async def submit_explain_feedback(body: ExplainFeedbackIn,
                                    user=Depends(get_current_user)):
    """Persist an analyst 👍/👎 on an Explain assistant reply.

    Records into the shared `learning_events` collection with a
    distinctive `event_type: "docs_explain_feedback"` so the fine-tuning
    exporter (which filters on `corrected_output`) safely skips these
    events, and the feedback stats endpoint can aggregate them.
    """
    analyst = user.get("email") if isinstance(user, dict) else str(user)
    doc = {
        "event_type": "docs_explain_feedback",
        "page": body.page,
        "session_id": body.session_id,
        "message_index": body.message_index,
        "vote": body.vote,
        "provider": body.provider,
        "question": (body.question or "")[:500],
        "reply_snippet": (body.reply_snippet or "")[:500],
        "comment": (body.comment or "")[:500],
        "analyst_id": analyst,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    if body.vote == "none":
        # Retract any prior vote from this analyst for this reply.
        result = await db["learning_events"].delete_many({
            "event_type": "docs_explain_feedback",
            "session_id": body.session_id,
            "message_index": body.message_index,
            "analyst_id": analyst,
        })
        return {"status": "retracted", "deleted": result.deleted_count}
    # Upsert: any prior vote from this analyst on this exact reply is
    # replaced (toggle up↔down is a single logical event).
    await db["learning_events"].delete_many({
        "event_type": "docs_explain_feedback",
        "session_id": body.session_id,
        "message_index": body.message_index,
        "analyst_id": analyst,
    })
    res = await db["learning_events"].insert_one(doc)
    return {"status": "recorded", "id": str(res.inserted_id)}


@router.get("/docs/explain/feedback/stats", tags=["docs"])
async def explain_feedback_stats(user=Depends(get_current_user)):
    """Aggregate 👍/👎 counts by page and by provider."""
    pipeline_page = [
        {"$match": {"event_type": "docs_explain_feedback"}},
        {"$group": {
            "_id": {"page": "$page", "vote": "$vote"},
            "count": {"$sum": 1},
        }},
    ]
    per_page: Dict[str, Dict[str, int]] = {}
    async for row in db["learning_events"].aggregate(pipeline_page):
        pg = row["_id"]["page"]
        vt = row["_id"]["vote"]
        per_page.setdefault(pg, {"up": 0, "down": 0})[vt] = row["count"]

    per_provider: Dict[str, Dict[str, int]] = {}
    pipeline_provider = [
        {"$match": {"event_type": "docs_explain_feedback",
                    "provider": {"$ne": None}}},
        {"$group": {
            "_id": {"provider": "$provider", "vote": "$vote"},
            "count": {"$sum": 1},
        }},
    ]
    async for row in db["learning_events"].aggregate(pipeline_provider):
        pv = row["_id"]["provider"]
        vt = row["_id"]["vote"]
        per_provider.setdefault(pv, {"up": 0, "down": 0})[vt] = row["count"]

    totals = {"up": 0, "down": 0}
    for v in per_page.values():
        totals["up"] += v.get("up", 0)
        totals["down"] += v.get("down", 0)
    # Rank pages by net-negative score (down − up) DESC — actionable
    # "which docs pages need the most attention".
    weakest = sorted(
        (
            {
                "page": pg,
                "up": pv.get("up", 0),
                "down": pv.get("down", 0),
                "net_negative": pv.get("down", 0) - pv.get("up", 0),
            }
            for pg, pv in per_page.items()
        ),
        key=lambda x: (-x["net_negative"], -x["down"]),
    )
    return {
        "totals": totals,
        "per_page": per_page,
        "per_provider": per_provider,
        "weakest_pages": weakest[:10],
    }


@router.get("/docs/explain/feedback/recent", tags=["docs"])
async def explain_feedback_recent(
    vote: Optional[str] = Query(None, pattern="^(up|down)$"),
    page: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=200),
    user=Depends(get_current_user),
):
    """Return recent Explain feedback events for the admin panel drill-down."""
    q: Dict[str, Any] = {"event_type": "docs_explain_feedback"}
    if vote:
        q["vote"] = vote
    if page:
        q["page"] = page
    cur = db["learning_events"].find(q).sort("created_at", -1).limit(limit)
    out: List[Dict[str, Any]] = []
    async for d in cur:
        out.append({
            "id": str(d.get("_id")),
            "page": d.get("page"),
            "vote": d.get("vote"),
            "provider": d.get("provider"),
            "analyst_id": d.get("analyst_id"),
            "question": d.get("question"),
            "reply_snippet": d.get("reply_snippet"),
            "comment": d.get("comment"),
            "created_at": d.get("created_at"),
            "session_id": d.get("session_id"),
        })
    return {"events": out}


# ============================================================================
# Workflow screenshots (captured by scripts/capture_docs_screenshots.py)
# ============================================================================
_SCREENSHOTS_DIR = Path(__file__).parent.parent / "docs" / "screenshots"
_ASSETS_DIR = Path(__file__).parent.parent / "docs" / "assets"


@router.get("/docs/assets/{filename}", tags=["docs"])
async def get_docs_asset(filename: str, user=Depends(get_current_user)):
    """Serve a static docs asset (SVG diagrams, PNGs bundled with the docs)."""
    if "/" in filename or ".." in filename:
        raise HTTPException(400, "invalid filename")
    path = _ASSETS_DIR / filename
    if not path.exists() or not path.is_file():
        raise HTTPException(404, "asset not found")
    if filename.endswith(".svg"):
        media = "image/svg+xml"
    elif filename.endswith(".png"):
        media = "image/png"
    elif filename.endswith(".gif"):
        media = "image/gif"
    else:
        media = "application/octet-stream"
    return FileResponse(path, media_type=media)


@router.get("/docs/screenshots/{workflow_id}", tags=["docs"])
async def list_workflow_screenshots(workflow_id: str,
                                      user=Depends(get_current_user)):
    """List captured screenshots for a workflow (order-preserving)."""
    d = _SCREENSHOTS_DIR / workflow_id
    if not d.exists():
        return {"workflow_id": workflow_id, "screenshots": []}
    files = sorted(d.glob("step_*.png")) + sorted(d.glob("step_*.gif"))
    return {
        "workflow_id": workflow_id,
        "screenshots": [
            {"step": i + 1, "filename": f.name,
             "url": f"/api/docs/screenshots/{workflow_id}/{f.name}"}
            for i, f in enumerate(files)
        ],
    }


@router.get("/docs/screenshots/{workflow_id}/{filename}", tags=["docs"])
async def get_workflow_screenshot(workflow_id: str, filename: str,
                                    user=Depends(get_current_user)):
    """Serve a single screenshot/gif captured for a workflow step."""
    if "/" in filename or ".." in filename:
        raise HTTPException(400, "invalid filename")
    path = _SCREENSHOTS_DIR / workflow_id / filename
    if not path.exists() or not path.is_file():
        raise HTTPException(404, "screenshot not found")
    media = "image/png" if filename.endswith(".png") else "image/gif"
    return FileResponse(path, media_type=media)

# ============================================================================
# Documentation Automation — coverage · scaffold · suggest-fix (Phase 6)
# ============================================================================
class ScaffoldIn(BaseModel):
    route_path: str = Field(..., description="Route path, e.g. /api/decode/candidates")
    method: str = Field("GET", pattern="^(GET|POST|PUT|PATCH|DELETE)$")


class SuggestFixIn(BaseModel):
    page: str = Field(..., description="Feature or workflow id to revise")
    limit: int = Field(20, ge=1, le=100,
                        description="How many recent 👎 events to consider")


@router.get("/docs/automation/coverage", tags=["docs"])
async def automation_coverage(request: Request,
                                user=Depends(get_current_user)):
    """List every /api/* route with a covered/uncovered YAML flag.

    See `docs.automation.coverage_report` for the matching heuristic
    (explicit `tags` → path-token windows → feature ids).
    """
    return coverage_report(request.app)


@router.post("/docs/automation/scaffold", tags=["docs"])
async def automation_scaffold(body: ScaffoldIn, request: Request,
                                user=Depends(get_current_user)):
    """AI-draft a starter feature YAML for an undocumented route."""
    # Look the route up on the live app so we get the real docstring.
    hit = None
    for r in walk_routes(request.app):
        if r["path"] == body.route_path and r["method"] == body.method.upper():
            hit = r
            break
    if not hit:
        raise HTTPException(
            404,
            f"route not found: {body.method.upper()} {body.route_path}",
        )
    return await scaffold_yaml(hit)


@router.post("/docs/automation/suggest-fix", tags=["docs"])
async def automation_suggest_fix(body: SuggestFixIn,
                                    user=Depends(get_current_user)):
    """Draft a revised YAML for a docs page based on its recent 👎 feedback."""
    # Pull the most recent 👎 events for this page.
    cur = db["learning_events"].find({
        "event_type": "docs_explain_feedback",
        "page": body.page,
        "vote": "down",
    }).sort("created_at", -1).limit(body.limit)
    events: List[Dict[str, Any]] = []
    async for d in cur:
        events.append({
            "question": d.get("question"),
            "reply_snippet": d.get("reply_snippet"),
            "comment": d.get("comment"),
            "created_at": d.get("created_at"),
        })

    result = await suggest_fix(body.page, events)
    if result.get("error"):
        raise HTTPException(404, result["error"])
    return {**result, "negative_event_count": len(events)}

