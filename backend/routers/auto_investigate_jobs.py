"""Worker + WebSocket router for AUTO INVESTIGATE background jobs.

Endpoints (mounted under /api/v2/auto-investigate):
  POST /jobs                 → create + start job → { job_id, ws_path }
  GET  /jobs/{id}            → snapshot (queued / running / complete / failed)
  WS   /jobs/{id}/ws?token=  → live event stream (progress / command / result)

The WebSocket authenticates via `?token=<jwt>` query param because
browsers cannot set the Authorization header on `new WebSocket(...)`.
The token is the same JWT used everywhere else in the app.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.websockets import WebSocketState

from deps import get_current_user
from fastapi.security import HTTPAuthorizationCredentials
from services.analysis_scope import resolve_analysis_owner

from v2.jobs import pubsub, store
from v2.jobs.pipeline import run_investigation_with_progress, MAX_INCIDENT_BYTES

log = logging.getLogger("nivx.routers.auto_investigate_jobs")

router = APIRouter(prefix="/v2/auto-investigate", tags=["auto-investigate-jobs"])


# ── Request models ─────────────────────────────────────────────────
class JobIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_text: str = Field(..., min_length=1, max_length=MAX_INCIDENT_BYTES, description="Raw pasted incident text")
    focus: str | None = Field(None,
                              description="Optional analyst focus keyword")


    @field_validator("incident_text")
    @classmethod
    def bounded_incident(cls, value):
        if len(value.encode("utf-8", errors="strict")) > MAX_INCIDENT_BYTES:
            raise ValueError("Incident exceeds existing byte limit")
        return value


# ── Worker ────────────────────────────────────────────────────────
async def _run_worker(job_id: str, incident_text: str, focus: str | None, tenant_id: str) -> None:
    """Background worker. Publishes progress events to pubsub AND
    persists progress + statuses in Mongo so late joiners can catch up."""
    async def on_progress(event: dict) -> None:
        # 1. broadcast live to WS subscribers
        await pubsub.publish(job_id, event)
        # 2. persist progress-only events so a page refresh can resume
        try:
            if event.get("type") == "progress":
                await store.set_progress(job_id,
                                         stage=event.get("stage", ""),
                                         percent=int(event.get("percent", 0)),
                                         message=event.get("message", ""))
            elif event.get("type") == "command":
                await store.append_command_status(job_id, {
                    "index":   event.get("index"),
                    "binary":  event.get("binary"),
                    "bytes":   event.get("bytes"),
                    "seconds": event.get("seconds"),
                    "status":  event.get("status"),
                    "message": event.get("message"),
                })
        except Exception as e:  # noqa: BLE001
            log.warning("persist progress failed job=%s: %s", job_id, e)

    try:
        result = await run_investigation_with_progress(
            incident_text, focus=focus, on_progress=on_progress, job_id=job_id, tenant_id=tenant_id,
        )
        await store.mark_complete(job_id, result)
        await pubsub.publish(job_id, {"type": "result", "result": result})
        await pubsub.publish(job_id, {"type": "done", "status": "complete"})
    except Exception as e:  # noqa: BLE001
        log.exception("auto-investigate job=%s failed", job_id)
        await store.mark_failed(job_id, str(e))
        await pubsub.publish(job_id, {"type": "done", "status": "failed",
                                      "error": str(e)[:400]})
    finally:
        # Allow late joiners a short window, then flush the ring buffer.
        await asyncio.sleep(5)
        pubsub.close_job(job_id)


# ── HTTP endpoints ────────────────────────────────────────────────
@router.post("/jobs")
async def create_job(body: JobIn, request: Request, user=Depends(get_current_user)):
    if os.environ.get("AUTO_INVESTIGATE_V1", "on").lower() in ("off", "0", "false"):
        raise HTTPException(status_code=503, detail="AUTO_INVESTIGATE_V1 disabled")
    if not body.incident_text or not body.incident_text.strip():
        raise HTTPException(status_code=400, detail="incident_text must be non-empty")
    owner = resolve_analysis_owner(request, user)
    job = await store.create_job(
        incident_text=body.incident_text,
        focus=body.focus,
        user_email=owner.principal_email,
        tenant_id=owner.tenant_id,
    )
    job_id = job["job_id"]
    # Spawn the worker but do NOT await it — the HTTP request returns
    # immediately so the browser is never held open.
    asyncio.create_task(_run_worker(job_id, body.incident_text, body.focus, owner.tenant_id))
    return {
        "ok": True,
        "job_id": job_id,
        "status": job["status"],
        "ws_path": f"/api/v2/auto-investigate/jobs/{job_id}/ws",
        "poll_path": f"/api/v2/auto-investigate/jobs/{job_id}",
    }


@router.get("/jobs/{job_id}")
async def get_job(job_id: str, request: Request, user=Depends(get_current_user)):
    owner = resolve_analysis_owner(request, user)
    doc = await store.get_job(job_id, tenant_id=owner.tenant_id, user_email=owner.principal_email)
    if not doc:
        raise HTTPException(status_code=404, detail="job not found")
    # Never leak the raw incident text back to the caller — it's already
    # inside `result.raw_incident` on completion.
    return {
        "ok": True,
        "job_id": doc["job_id"],
        "status": doc["status"],
        "progress": doc.get("progress", {}),
        "decode_statuses": doc.get("decode_statuses", []),
        "result": doc.get("result"),
        "error": doc.get("error"),
        "created_at": doc.get("created_at"),
        "updated_at": doc.get("updated_at"),
    }


# ── WebSocket ─────────────────────────────────────────────────────
async def _authorize_ws(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    try:
        return await get_current_user(HTTPAuthorizationCredentials(scheme="Bearer", credentials=token))
    except HTTPException as exc:
        if exc.status_code >= 500:
            raise
        return None
    except Exception as exc:
        raise HTTPException(503, detail="ANALYSIS_AUTHORITY_UNAVAILABLE") from exc


@router.websocket("/jobs/{job_id}/ws")
async def job_stream_ws(websocket: WebSocket, job_id: str):
    token = websocket.query_params.get("token")
    try:
        identity = await _authorize_ws(token)
    except HTTPException:
        await websocket.close(code=4503)
        return
    if identity is None:
        # 4401 = custom "unauthorized" close code
        await websocket.close(code=4401)
        return

    try:
        owner = resolve_analysis_owner(websocket, identity)
        doc = await store.get_job(job_id, tenant_id=owner.tenant_id, user_email=owner.principal_email)
    except HTTPException as exc:
        await websocket.close(code=4503 if exc.status_code == 503 else 4403)
        return
    if not doc:
        await websocket.close(code=4404)
        return

    async def send_owned(event):
        # Long-lived streams must not outlive token or stored tenant grants.
        try:
            fresh = await _authorize_ws(token)
            code = 4401 if fresh is None else None
        except HTTPException:
            fresh, code = None, 4503
        if fresh is not None:
            try:
                if resolve_analysis_owner(websocket, fresh) != owner:
                    code = 4403
            except HTTPException as exc:
                code = 4503 if exc.status_code == 503 else 4403
        if code is not None:
            await websocket.close(code=code)
            raise WebSocketDisconnect(code=code)
        await websocket.send_json(event)

    await websocket.accept()
    q = await pubsub.subscribe(job_id)

    # If pubsub has NO history for this job (i.e. it already closed after
    # the 5s post-completion window), replay the persisted result + done
    # from Mongo and disconnect.
    if doc.get("status") in ("complete", "failed") and q.empty():
        try:
            # Replay persisted progress steps so the UI still gets the
            # full timeline for a completed job.
            for step in doc.get("progress", {}).get("steps", []):
                await send_owned({
                    "type": "progress",
                    "stage": step.get("stage", ""),
                    "percent": step.get("percent", 0),
                    "message": step.get("message", ""),
                })
            for st in doc.get("decode_statuses", []):
                await send_owned({"type": "command", **st})
            if doc.get("result") is not None:
                await send_owned({"type": "result", "result": doc["result"]})
            await send_owned({"type": "done", "status": doc["status"]})
        finally:
            await pubsub.unsubscribe(job_id, q)
            if websocket.client_state == WebSocketState.CONNECTED and websocket.application_state == WebSocketState.CONNECTED:
                await websocket.close(code=1000)
            return

    try:
        # Drain the queue (may already contain replayed history) until
        # we see a `done` event or the client disconnects.
        while True:
            event = await q.get()
            if websocket.client_state != WebSocketState.CONNECTED:
                break
            await send_owned(event)
            if event.get("type") == "done":
                break
    except WebSocketDisconnect:
        pass
    except Exception as e:  # noqa: BLE001
        log.warning("ws stream error job=%s: %s", job_id, e)
    finally:
        await pubsub.unsubscribe(job_id, q)
        if websocket.client_state == WebSocketState.CONNECTED and websocket.application_state == WebSocketState.CONNECTED:
            try:
                await websocket.close(code=1000)
            except Exception:
                pass
