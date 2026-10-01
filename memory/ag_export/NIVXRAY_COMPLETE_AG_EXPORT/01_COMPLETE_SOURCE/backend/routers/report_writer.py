"""Report Writer API — Phase 6 endpoint.

POST /api/v2/report-writer/generate
  { incident_text: str, profile?: "executive"|"customer"|"soc_analyst"|"technical",
    customer?: str }

Convenience: runs the AUTO INVESTIGATE orchestrator to build the
investigation model, then hands off to the deterministic Report Writer.
The two engines remain fully decoupled — the writer can also be invoked
directly with a pre-built investigation payload via /generate/from-model.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from deps import get_current_user
from v2.report_writer import build_report, render_markdown

# Reuse the orchestrator that ships in routers/auto_investigate.py so we
# don't duplicate command/entity detection logic.
from routers.auto_investigate import (
    _detect_commands, _detect_commands_with_fallback, _extract_entities, _classify, _worst_verdict,
    _flatten_mitre, _merge_iocs, _severity, _findings as _cmd_findings,
    _executive_summary as _cmd_exec_summary, _recommendations,
    _investigation_quality, _osint_lookup, _run_single_command,
    MAX_CMD_BYTES, MAX_CMD_SECONDS, MAX_CMDS_PER_INCIDENT,
    MAX_INCIDENT_BYTES,
)
from engine import AnalysisContext, Orchestrator
from engine.config import new_budget
import logging

log = logging.getLogger("nivx.report_writer")

router = APIRouter(prefix="/v2/report-writer", tags=["report-writer"])


class GenerateIn(BaseModel):
    incident_text: str = Field(..., description="Raw pasted incident text")
    profile: str        = Field("soc_analyst",
                                description="executive · customer · soc_analyst · technical")
    customer: str | None = Field(None, description="Customer name for the report header")


class GenerateFromModelIn(BaseModel):
    investigation: dict = Field(..., description="Pre-computed AUTO INVESTIGATE payload")
    profile: str        = Field("soc_analyst")
    customer: str | None = Field(None)


def _run_investigation(raw: str) -> dict:
    """Sync wrapper — retained for backwards compatibility."""
    import asyncio
    return asyncio.run(_run_investigation_async(raw))


async def _run_investigation_async(raw: str) -> dict:
    """Guarded orchestrator loop shared with the auto-investigate router.
    One oversized command cannot stall the pipeline; every command has
    its own decode budget."""
    incident_bytes = len(raw.encode("utf-8", errors="ignore"))
    incident_truncated = False
    if incident_bytes > MAX_INCIDENT_BYTES:
        raw = raw.encode("utf-8", errors="ignore")[:MAX_INCIDENT_BYTES].decode("utf-8", errors="ignore")
        incident_truncated = True
    commands = _detect_commands_with_fallback(raw)
    if len(commands) > MAX_CMDS_PER_INCIDENT:
        commands_dropped = len(commands) - MAX_CMDS_PER_INCIDENT
        commands = commands[:MAX_CMDS_PER_INCIDENT]
    else:
        commands_dropped = 0
    entities = _extract_entities(raw)
    reports, decode_statuses = [], []
    for cmd in commands:
        report, status = _run_single_command(cmd)
        decode_statuses.append(status)
        if report is not None:
            reports.append(report)
    verdict = _worst_verdict(reports) if reports else "unknown"
    classification = _classify(reports) if reports else (
        "Suspicious (no decodable commands)" if entities.get("ips") or entities.get("domains")
        else "Benign / Informational")
    mitre = _flatten_mitre(reports)
    iocs = _merge_iocs(reports, entities)
    severity = _severity(verdict)
    findings = _cmd_findings(reports, commands)
    summary = _cmd_exec_summary(raw, commands, verdict, classification, iocs, mitre)
    recs = _recommendations(verdict, mitre, iocs)
    osint = await _osint_lookup(entities, iocs)
    quality = _investigation_quality(raw, commands, entities, reports, mitre, iocs)
    if osint.get("summary", {}).get("matches") is not None:
        quality.setdefault("coverage", {})["threat_intel_matches"] = osint["summary"]["matches"]
    n_failed = sum(1 for s in decode_statuses if s.get("status") != "complete")
    quality.setdefault("command_analysis", {})["failed_decodes"] = n_failed
    quality["command_analysis"]["commands_decoded"] = len(reports)
    quality["command_analysis"]["decode_ratio"]    = f"{len(reports)}/{len(commands)}" if commands else "0/0"
    decided = sum(1 for r in reports if (getattr(r.findings, "verdict", None) or "unknown") != "unknown") if reports else 0
    confidence = int(round(100 * decided / max(1, len(reports)))) if reports else 0
    return {
        "ok": True,
        "raw_incident": raw,
        "detected": {"commands": commands, "entities": entities},
        "decode_pipeline": {
            "statuses": decode_statuses,
            "budgets": {"max_command_bytes": MAX_CMD_BYTES,
                        "max_command_seconds": MAX_CMD_SECONDS,
                        "max_commands_per_incident": MAX_CMDS_PER_INCIDENT,
                        "max_incident_bytes": MAX_INCIDENT_BYTES},
            "guardrails_triggered": {
                "incident_truncated": incident_truncated,
                "commands_dropped":   commands_dropped,
                "timeouts":     sum(1 for s in decode_statuses if s.get("status") == "timeout"),
                "size_exceeded": sum(1 for s in decode_statuses if s.get("status") == "size_exceeded"),
                "errors":       sum(1 for s in decode_statuses if s.get("status") == "error"),
            },
        },
        "final_incident_summary": {
            "executive_summary": summary,
            "classification": classification,
            "severity": severity,
            "confidence": {"score": confidence,
                           "reason": f"{decided}/{len(reports)} decoded commands reached a deterministic verdict"
                                     if reports else "no decodable commands present"},
            "verdict": verdict,
            "findings": findings,
            "mitre_attack": mitre,
            "iocs": iocs,
            "recommendations": recs,
            "evidence_counts": {
                "commands": len(commands),
                "processes": len({c["binary"] for c in commands}),
                "ips": len(entities.get("ips", [])),
                "domains": len(entities.get("domains", [])),
                "urls": len(entities.get("urls", [])),
                "hashes": (len(entities.get("sha256", []))
                           + len(entities.get("sha1", []))
                           + len(entities.get("md5", []))),
                "files": len(entities.get("files", [])),
                "registry": len(entities.get("registry", [])),
                "users": len(entities.get("users", [])),
            },
            "ioc_reputation": osint,
            "investigation_quality": quality,
        },
    }


@router.post("/generate")
async def generate(body: GenerateIn, user=Depends(get_current_user)):
    if not body.incident_text or not body.incident_text.strip():
        raise HTTPException(400, "incident_text must be non-empty")
    if body.profile not in ("executive", "customer", "soc_analyst", "technical"):
        raise HTTPException(400, f"unknown profile '{body.profile}'")
    inv = await _run_investigation_async(body.incident_text)
    report = build_report(inv, profile=body.profile, customer=body.customer)
    return {"ok": True, "report": report, "investigation": inv}


@router.post("/generate/from-model")
async def generate_from_model(body: GenerateFromModelIn, user=Depends(get_current_user)):
    if not body.investigation:
        raise HTTPException(400, "investigation payload must be non-empty")
    report = build_report(body.investigation, profile=body.profile, customer=body.customer)
    return {"ok": True, "report": report}


@router.post("/generate/markdown")
async def generate_markdown(body: GenerateIn, user=Depends(get_current_user)):
    inv = await _run_investigation_async(body.incident_text)
    report = build_report(inv, profile=body.profile, customer=body.customer)
    md = render_markdown(report)
    return Response(content=md, media_type="text/markdown")
