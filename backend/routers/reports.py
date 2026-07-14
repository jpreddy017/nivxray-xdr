"""Reports router — /api/share, /api/share/{token}, /api/report, /api/report/{fmt}, /api/report/stix."""
from __future__ import annotations
import base64
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from schemas import ShareIn, AnalyzeIn
from deps import db, get_current_user
from analysis_core import analysis_context, deterministic_best_decode
from operations import extract_iocs, mitre_map
from stix_export import build_investigation_bundle
from report_renderers import (
    download,
    render_csv_report, render_docx_report, render_pdf_from_html,
    render_text_report, render_html_report,
)
from schemas import AutoIn

router = APIRouter()


@router.post("/share")
async def create_share(body: ShareIn, user=Depends(get_current_user)):
    payload = json.dumps({"input": body.input,
                          "steps": [s.model_dump() for s in body.steps]}).encode("utf-8")
    token = base64.urlsafe_b64encode(payload).decode("utf-8").rstrip("=")
    await db.shares.insert_one({
        "token": token, "input_len": len(body.input),
        "steps": [s.model_dump() for s in body.steps],
        "created_by": user["email"],
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return {"token": token}


@router.get("/share/{token}")
async def get_share(token: str):
    padded = token + "=" * (-len(token) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=404, detail="Invalid share token")


@router.post("/report")
async def build_report(body: AnalyzeIn, user=Depends(get_current_user)):
    """JSON with both text + html body (for backward compat / preview)."""
    ctx = await analysis_context(body, user)
    ts = ctx["ts"]
    txt = render_text_report(user, ts, body, ctx["risk"], ctx["mitre"], ctx["yara"],
                             ctx["lolbas"], ctx["iocs"], ctx["ti_hits"], ctx["osint"],
                             ctx["description"], ctx["verdict"])
    html = render_html_report(user, ts, body, ctx["risk"], ctx["mitre"], ctx["yara"],
                              ctx["lolbas"], ctx["iocs"], ctx["ti_hits"], ctx["osint"],
                              ctx["description"], ctx["verdict"])
    return {
        "report": txt, "html": html,
        "filename": f"nivxray_report_{int(datetime.now().timestamp())}.txt",
        "filename_html": f"nivxray_report_{int(datetime.now().timestamp())}.html",
    }


@router.post("/report/stix")
async def build_stix_report(body: AutoIn, user=Depends(get_current_user)):
    """Return a STIX 2.1 bundle for the given payload.

    Runs the deterministic best-of decoder, extracts IOCs + MITRE, then wraps
    everything in indicators / attack-patterns / note / report objects tied
    together with a single top-level bundle. Ready to import into MISP,
    OpenCTI, ThreatConnect, Anomali, or any other STIX 2.1-aware platform.
    """
    det = deterministic_best_decode(body.input)
    decoded = det.get("output") or ""
    text = (decoded or "") + "\n" + body.input
    iocs = extract_iocs(text)
    mitre = mitre_map(text)
    confidence = int(round(min(1.0, det.get("score", 0.0)) * 100))
    trace = [{"op": s["op"], "args": s.get("args") or {}} for s in det.get("steps") or []]

    bundle = build_investigation_bundle(
        analyst_email=user.get("email") or "unknown@nivxray",
        input_preview=body.input, output_preview=decoded,
        engine=det.get("engine"),
        confidence=confidence,
        trace=trace, iocs=iocs, mitre=mitre, verdict=None,
    )
    return bundle


@router.post("/report/stix/download")
async def download_stix_report(body: AutoIn, user=Depends(get_current_user)):
    """Same as /report/stix but returns as downloadable JSON attachment."""
    bundle = await build_stix_report(body, user=user)
    payload = json.dumps(bundle, indent=2).encode("utf-8")
    stem = f"nivxray_stix_{int(datetime.now().timestamp())}"
    return download(payload, f"{stem}.json", "application/vnd.oasis.stix+json")


# ============================================================================
# Generic report renderers — must be AFTER the literal /report/stix routes
# above so FastAPI doesn't shadow them via the {fmt} path parameter.
# ============================================================================
@router.post("/report/{fmt}")
async def build_report_fmt(fmt: str, body: AnalyzeIn, user=Depends(get_current_user)):
    """Download report as txt / html / csv / docx / pdf."""
    fmt = fmt.lower()
    if fmt not in ("txt", "html", "csv", "docx", "pdf"):
        raise HTTPException(status_code=400, detail="format must be one of txt|html|csv|docx|pdf")
    ctx = await analysis_context(body, user)
    stem = f"nivxray_report_{int(datetime.now().timestamp())}"
    ts = ctx["ts"]

    if fmt == "txt":
        payload = render_text_report(user, ts, body, ctx["risk"], ctx["mitre"], ctx["yara"],
                                     ctx["lolbas"], ctx["iocs"], ctx["ti_hits"], ctx["osint"],
                                     ctx["description"], ctx["verdict"]).encode("utf-8")
        return download(payload, f"{stem}.txt", "text/plain; charset=utf-8")

    if fmt == "html":
        payload = render_html_report(user, ts, body, ctx["risk"], ctx["mitre"], ctx["yara"],
                                     ctx["lolbas"], ctx["iocs"], ctx["ti_hits"], ctx["osint"],
                                     ctx["description"], ctx["verdict"]).encode("utf-8")
        return download(payload, f"{stem}.html", "text/html; charset=utf-8")

    if fmt == "csv":
        payload = render_csv_report(user, ts, body, ctx).encode("utf-8")
        return download(payload, f"{stem}.csv", "text/csv; charset=utf-8")

    if fmt == "docx":
        payload = render_docx_report(user, ts, body, ctx)
        return download(payload, f"{stem}.docx",
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document")

    if fmt == "pdf":
        html_body = render_html_report(user, ts, body, ctx["risk"], ctx["mitre"], ctx["yara"],
                                       ctx["lolbas"], ctx["iocs"], ctx["ti_hits"], ctx["osint"],
                                       ctx["description"], ctx["verdict"])
        payload = render_pdf_from_html(html_body)
        return download(payload, f"{stem}.pdf", "application/pdf")


# ============================================================================
# STIX 2.1 bundle export — decoded investigation ready for TIP ingestion
# ============================================================================
