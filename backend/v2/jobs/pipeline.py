"""Progress-emitting AUTO INVESTIGATE pipeline for background jobs.

Wraps the same deterministic helpers used by the synchronous
`POST /api/v2/auto-investigate` — imported from `routers/auto_investigate`
— but yields per-stage and per-command progress events so a WebSocket
subscriber can render live progress bars.

Contract: exactly the same FinalIncidentSummary payload as the sync
endpoint. Zero behaviour drift; the ONLY addition is the `on_progress`
callback + the Decoded Artifact Store (P0.2) cache in front of every
per-command decode.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable

from engine.models import AnalystReport

from routers.auto_investigate import (
    _detect_commands, _detect_commands_with_fallback, _extract_entities, _classify, _worst_verdict,
    _flatten_mitre, _merge_iocs, _severity, _findings as _cmd_findings,
    _executive_summary as _cmd_exec_summary, _recommendations,
    _investigation_quality, _osint_lookup, _run_single_command,
    MAX_CMD_BYTES, MAX_CMD_SECONDS, MAX_CMDS_PER_INCIDENT,
    MAX_INCIDENT_BYTES,
)
from v2.decoded_artifacts import (
    get_artifact as _artifact_get,
    upsert_artifact as _artifact_upsert,
    sha256_of as _sha256_of,
)

log = logging.getLogger("nivx.jobs.pipeline")

ProgressCB = Callable[[dict], Awaitable[None]]


async def _emit(cb: ProgressCB | None, event: dict) -> None:
    if cb is None:
        return
    try:
        await cb(event)
    except Exception as e:  # noqa: BLE001
        log.warning("progress callback failed: %s", e)


async def _decode_with_cache(cmd: dict, job_id: str | None):
    """Try the Decoded Artifact Store first. On hit, reconstruct the
    AnalystReport from the cached dict and skip the decoder entirely.
    On miss, run the deterministic decoder and persist the result.
    Returns `(report_or_None, status_dict, cache_hit: bool)`."""
    cmdline = cmd.get("command_line") or ""
    sha = _sha256_of(cmdline)
    cached = await _artifact_get(sha)
    if cached and cached.get("report"):
        try:
            report = AnalystReport(**cached["report"])
        except Exception as e:  # noqa: BLE001
            log.warning("cache reconstruct failed sha=%s: %s", sha, e)
            report = None
        if report is not None:
            # Bump provenance so hit_count reflects reality.
            await _artifact_upsert(
                command_binary=cmd.get("binary") or "",
                command_line=cmdline,
                report_dict=cached["report"],
                job_id=job_id,
            )
            status = {
                "binary": cmd.get("binary"),
                "bytes":  len(cmdline.encode("utf-8", errors="ignore")),
                "seconds": 0.0,
                "status": "cache_hit",
                "sha256": sha,
                "message": ("Decoded artifact reused from cache — identical "
                            "command decoded previously."),
            }
            return report, status, True
    # Cache miss — run the deterministic decoder.
    report, status = await asyncio.to_thread(_run_single_command, cmd)
    status["sha256"] = sha
    if report is not None:
        try:
            await _artifact_upsert(
                command_binary=cmd.get("binary") or "",
                command_line=cmdline,
                report_dict=report.model_dump(),
                job_id=job_id,
            )
        except Exception as e:  # noqa: BLE001
            log.warning("artifact upsert failed sha=%s: %s", sha, e)
    return report, status, False


def _project_decode_chain(cmd: dict, report, status: dict, cache_hit: bool, idx: int) -> dict:
    """Project a per-command AnalystReport into a UI-friendly recursive
    decode chain. Used by the frontend Decode Tree component."""
    layers: list[dict] = []
    if report is not None:
        for step in (getattr(report, "trace", None) or []):
            # step is a Pydantic TraceStep — normalise to a plain dict
            s = step.model_dump() if hasattr(step, "model_dump") else dict(step)
            layers.append({
                "layer":      s.get("layer"),
                "decoder":    s.get("decoder"),
                "confidence": round(float(s.get("confidence") or 0.0), 3),
                "why":        (s.get("why") or "")[:200],
                "in_len":     s.get("in_len"),
                "out_len":    s.get("out_len"),
                "exec_ms":    s.get("exec_ms"),
                "preview":    (s.get("preview") or "")[:200],
                "sub_iocs":   {k: v[:12] for k, v in (s.get("sub_iocs") or {}).items() if v},
            })
    findings = getattr(report, "findings", None)
    return {
        "index":         idx,
        "binary":        cmd.get("binary"),
        "command_line":  (cmd.get("command_line") or "")[:400],
        "sha256":        status.get("sha256"),
        "status":        status.get("status"),
        "cache_hit":     cache_hit,
        "elapsed_ms":    int((status.get("seconds") or 0.0) * 1000) if status.get("status") != "cache_hit"
                          else int(getattr(report, "elapsed_ms", 0) or 0) if report else 0,
        "layers":        layers,
        "layer_count":   len(layers),
        "terminal":      getattr(report, "terminal", None) if report else None,
        "verdict":       (getattr(findings, "verdict", None) if findings else None) or "unknown",
        "risk_score":    int(getattr(findings, "risk_score", 0) or 0) if findings else 0,
        "mitre_ids":     sorted({(m.id if hasattr(m, "id") else m.get("id"))
                                 for m in (getattr(findings, "mitre_techniques", None) or [])
                                 if (m.id if hasattr(m, "id") else m.get("id"))}) if findings else [],
    }


def _recursive_stats(chains: list[dict]) -> dict:
    """Aggregate decoder-layer statistics across every command."""
    from collections import Counter
    total_layers = sum(c["layer_count"] for c in chains)
    decoder_hist: Counter = Counter()
    exec_ms = 0
    max_depth = 0
    for c in chains:
        for L in c["layers"]:
            if L.get("decoder"):
                decoder_hist[L["decoder"]] += 1
            exec_ms += int(L.get("exec_ms") or 0)
            max_depth = max(max_depth, int(L.get("layer") or 0))
    return {
        "commands_analysed":  len(chains),
        "total_layers":       total_layers,
        "avg_layers":         round(total_layers / max(1, len(chains)), 2),
        "max_depth":          max_depth,
        "total_layer_ms":     exec_ms,
        "cache_hit_count":    sum(1 for c in chains if c["cache_hit"]),
        "top_decoders":       [{"decoder": d, "count": n}
                               for d, n in decoder_hist.most_common(8)],
        "success_rate":       round(
                                100 * sum(1 for c in chains
                                          if c["status"] in ("complete", "cache_hit"))
                                / max(1, len(chains)), 1),
    }


async def run_investigation_with_progress(
    raw: str,
    focus: str | None = None,
    on_progress: ProgressCB | None = None,
    job_id: str | None = None,
) -> dict:
    """Run the deterministic investigation pipeline, emitting events at
    every meaningful boundary. Returns the FinalIncidentSummary payload
    (identical shape to the sync endpoint)."""
    # ── Stage 1 · Parse & extract ────────────────────────────────
    await _emit(on_progress, {"type": "progress", "stage": "parsing",
                              "percent": 5,
                              "message": "Parsing incident and extracting entities…"})
    incident_bytes = len(raw.encode("utf-8", errors="ignore"))
    incident_truncated = False
    if incident_bytes > MAX_INCIDENT_BYTES:
        raw = raw.encode("utf-8", errors="ignore")[:MAX_INCIDENT_BYTES]\
                 .decode("utf-8", errors="ignore")
        incident_truncated = True
        await _emit(on_progress, {"type": "progress", "stage": "parsing",
                                  "percent": 8,
                                  "message": (f"Incident payload truncated to "
                                              f"{MAX_INCIDENT_BYTES//(1024*1024)} MB")})
    commands = _detect_commands_with_fallback(raw)
    entities = _extract_entities(raw)
    commands_dropped = 0
    if len(commands) > MAX_CMDS_PER_INCIDENT:
        commands_dropped = len(commands) - MAX_CMDS_PER_INCIDENT
        commands = commands[:MAX_CMDS_PER_INCIDENT]
    total_ioc = sum(len(v) for v in entities.values() if isinstance(v, list))
    await _emit(on_progress, {
        "type": "parse_result",
        "commands_detected": len(commands),
        "entities": {k: len(v) for k, v in entities.items() if isinstance(v, list)},
        "iocs_total": total_ioc,
        "incident_bytes": incident_bytes,
        "incident_truncated": incident_truncated,
        "commands_dropped": commands_dropped,
    })
    await _emit(on_progress, {"type": "progress", "stage": "parsing",
                              "percent": 15,
                              "message": (f"Extracted {len(commands)} command(s) "
                                          f"and {total_ioc} IOC candidate(s)")})

    # ── Stage 2 · Decode every command in isolation (cache-first) ─
    reports: list = []
    decode_statuses: list[dict] = []
    decode_chains: list[dict] = []
    cache_hits = 0
    total = max(1, len(commands))
    for idx, cmd in enumerate(commands):
        pct = 15 + int(round(60 * (idx / total)))
        await _emit(on_progress, {
            "type": "progress", "stage": "decoding", "percent": pct,
            "message": (f"Decoding command {idx + 1}/{len(commands)}: "
                        f"{cmd.get('binary')}"),
        })
        report, status, was_hit = await _decode_with_cache(cmd, job_id)
        decode_statuses.append(status)
        if was_hit:
            cache_hits += 1
        if report is not None:
            reports.append(report)
        chain = _project_decode_chain(cmd, report, status, was_hit, idx)
        decode_chains.append(chain)
        await _emit(on_progress, {
            "type": "command",
            "index": idx,
            "binary": cmd.get("binary"),
            "bytes": status.get("bytes"),
            "seconds": status.get("seconds"),
            "status": status.get("status"),
            "sha256": status.get("sha256"),
            "cache_hit": was_hit,
            "layer_count": chain["layer_count"],
            "verdict": chain["verdict"],
            "message": status.get("message"),
        })
        # Stream the full decode chain as a separate event so the UI can
        # populate its Decode Tree in real time.
        await _emit(on_progress, {"type": "decode_chain", **chain})
    await _emit(on_progress, {"type": "progress", "stage": "decoding",
                              "percent": 75,
                              "message": (f"{len(reports)}/{len(commands)} "
                                          f"commands fully decoded"
                                          f" · {cache_hits} cache-hit(s)")})

    # ── Stage 3 · Aggregate ──────────────────────────────────────
    await _emit(on_progress, {"type": "progress", "stage": "aggregating",
                              "percent": 80,
                              "message": "Aggregating verdicts and MITRE mapping…"})
    verdict = _worst_verdict(reports) if reports else "unknown"
    classification = _classify(reports) if reports else (
        "Suspicious (no decodable commands)"
        if entities.get("ips") or entities.get("domains") else "Benign / Informational")
    mitre = _flatten_mitre(reports)
    iocs = _merge_iocs(reports, entities)
    severity = _severity(verdict)
    findings = _cmd_findings(reports, commands)
    summary = _cmd_exec_summary(raw, commands, verdict, classification, iocs, mitre)
    recs = _recommendations(verdict, mitre, iocs)

    # ── Stage 4 · OSINT enrichment ───────────────────────────────
    await _emit(on_progress, {"type": "progress", "stage": "osint",
                              "percent": 88,
                              "message": "Validating IOCs against local threat-intel corpus…"})
    osint = await _osint_lookup(entities, iocs)
    await _emit(on_progress, {
        "type": "osint_result",
        "matches": osint.get("summary", {}).get("matches", 0),
        "total_lookups": osint.get("summary", {}).get("total_lookups", 0),
        "sources": osint.get("sources", {}),
    })

    # ── Stage 5 · Quality dashboard ──────────────────────────────
    await _emit(on_progress, {"type": "progress", "stage": "reporting",
                              "percent": 94,
                              "message": "Composing Final Incident Summary…"})
    quality = _investigation_quality(raw, commands, entities, reports, mitre, iocs)
    if osint.get("summary", {}).get("matches") is not None:
        quality.setdefault("coverage", {})["threat_intel_matches"] = osint["summary"]["matches"]
    n_failed = sum(
        1 for s in decode_statuses
        if s.get("status") not in ("complete", "cache_hit")
    )
    quality.setdefault("command_analysis", {})["failed_decodes"] = n_failed
    quality["command_analysis"]["commands_decoded"] = len(reports)
    quality["command_analysis"]["cache_hits"] = cache_hits
    quality["command_analysis"]["decode_ratio"] = (
        f"{len(reports)}/{len(commands)}" if commands else "0/0")
    if reports:
        decided = sum(
            1 for r in reports
            if (getattr(r.findings, "verdict", None) or "unknown") != "unknown"
        )
        confidence = int(round(100 * decided / max(1, len(reports))))
    else:
        decided = 0
        confidence = 0

    result = {
        "ok": True,
        "raw_incident": raw,
        "focus": focus,
        "detected": {"commands": commands, "entities": entities},
        "decode_pipeline": {
            "statuses": decode_statuses,
            "chains":   decode_chains,
            "recursive_stats": _recursive_stats(decode_chains),
            "budgets": {
                "max_command_bytes": MAX_CMD_BYTES,
                "max_command_seconds": MAX_CMD_SECONDS,
                "max_commands_per_incident": MAX_CMDS_PER_INCIDENT,
                "max_incident_bytes": MAX_INCIDENT_BYTES,
            },
            "guardrails_triggered": {
                "incident_truncated": incident_truncated,
                "commands_dropped": commands_dropped,
                "timeouts": sum(1 for s in decode_statuses if s.get("status") == "timeout"),
                "size_exceeded": sum(1 for s in decode_statuses if s.get("status") == "size_exceeded"),
                "errors": sum(1 for s in decode_statuses if s.get("status") == "error"),
                "cache_hits": cache_hits,
            },
        },
        "final_incident_summary": {
            "executive_summary": summary,
            "classification": classification,
            "severity": severity,
            "confidence": {
                "score": confidence,
                "reason": (f"{decided}/{len(reports)} decoded commands reached a "
                           f"deterministic verdict") if reports
                else "no decodable commands present — verdict driven by IOCs",
            },
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
        "engine": {
            "orchestrator_reports": len(reports),
            "version": "auto-investigate-v1-async",
            "cache_hits": cache_hits,
        },
    }
    await _emit(on_progress, {"type": "progress", "stage": "done",
                              "percent": 100,
                              "message": "Investigation complete."})
    return result
