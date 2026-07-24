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
from v2.enrichment.strings_extractor import enrich_report as _enrich_report
from v2.semantic.ps_semantic import analyze as _ps_semantic_analyze
from v2.mdr.incident_parser import (
    parse_events as _mdr_parse_events,
    build_timeline as _mdr_build_timeline,
    compose_executive_summary as _mdr_exec_summary,
    derive_recommendations as _mdr_recommendations,
    escalation_decision as _mdr_escalation,
)
from v2.mdr.reference_urls import classify_all as _mdr_classify_urls

# Optional bridge to the Workspace's larger decoder registry — enables
# PowerShell binary-split, string-concat, char-array, ps-encodedcommand
# multi-layer patterns that the RC5 Orchestrator's smart-detection alone
# doesn't catch. Wraps `wrapper_archetypes.try_archetypes()` inside a
# `try/except` so a missing module never breaks the pipeline.
try:
    from wrapper_archetypes import try_archetypes as _try_archetypes  # type: ignore
except Exception:  # pragma: no cover
    _try_archetypes = None  # type: ignore

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
    Returns `(report_or_None, status_dict, cache_hit: bool, archetype_layers)`.

    `archetype_layers` is a list of extra layer dicts recovered from the
    Workspace's `wrapper_archetypes` registry BEFORE we hand off to the
    RC5 Orchestrator — this bridges the ~200-op Workspace decoders into
    Auto Investigate (e.g. PS binary-split, string-concat, char-array,
    ps-encodedcommand multi-layer) which the RC5 registry alone misses.
    """
    cmdline = cmd.get("command_line") or ""
    sha = _sha256_of(cmdline)
    # Feb-2026 · Pipeline version tag. Bump this whenever a decoder /
    # archetype change should invalidate previously cached artifacts.
    PIPELINE_VERSION = "v5-mdr-investigator"
    cached = await _artifact_get(sha)
    # Cache-invalidation guard. Any artifact cached BEFORE the archetype
    # bridge shipped has `layers == 0` for inputs the archetypes can now
    # decode. Force a fresh run whenever a cached report either
    # (a) predates the current pipeline version or (b) recovered zero
    # layers — the deterministic engine has probably been upgraded since
    # then and deserves another shot.
    if cached and cached.get("report"):
        _rep = cached["report"] or {}
        _layers = len(_rep.get("trace") or [])
        _cached_version = cached.get("pipeline_version") or ""
        if _layers == 0 or _cached_version != PIPELINE_VERSION:
            log.info("cache invalidated sha=%s layers=%s ver=%s → re-running",
                     sha, _layers, _cached_version)
            # DELETE the stale doc so the upcoming upsert writes a fresh
            # report — the default upsert path only bumps provenance
            # when a doc already exists.
            try:
                from deps import db as _db
                await _db["v2_decoded_payloads"].delete_one({"_id": sha})
            except Exception as e:  # noqa: BLE001
                log.warning("stale cache delete failed sha=%s: %s", sha, e)
            cached = None
    if cached and cached.get("report"):
        try:
            report = AnalystReport(**cached["report"])
        except Exception as e:  # noqa: BLE001
            log.warning("cache reconstruct failed sha=%s: %s", sha, e)
            report = None
        if report is not None:
            await _artifact_upsert(
                command_binary=cmd.get("binary") or "",
                command_line=cmdline,
                report_dict=cached["report"],
                job_id=job_id,
                pipeline_version=PIPELINE_VERSION,
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
            # Cached artefacts already include archetype layers baked into
            # the AnalystReport.trace — no extra ones to inject.
            return report, status, True, []

    # ── Cache miss ───────────────────────────────────────────────
    # 1) Pre-decode using the Workspace's `wrapper_archetypes` — this
    #    catches PS binary-split, string-concat, char-array, ps-encoded-
    #    command multi-layer and other patterns the RC5 Orchestrator's
    #    smart-detection doesn't include. If a chain fires, its OUTPUT
    #    becomes the input we hand to the Orchestrator so it can peel
    #    additional layers (base64 inside a decoded PS command, etc.).
    archetype_layers: list[dict] = []
    orchestrator_input = cmdline
    if _try_archetypes is not None:
        try:
            arch = await asyncio.to_thread(_try_archetypes, cmdline)
        except Exception as e:  # noqa: BLE001
            log.warning("archetype pre-decode failed: %s", e)
            arch = None
        if isinstance(arch, dict) and arch.get("output"):
            orchestrator_input = arch["output"]
            for i, step in enumerate(arch.get("steps") or []):
                archetype_layers.append({
                    "layer":      -1 * (len(arch["steps"]) - i),  # negative → renders BEFORE RC5 layers
                    "decoder":    step.get("op") or arch.get("archetype_id") or "archetype",
                    "confidence": 0.9,
                    "why":        arch.get("archetype_desc") or "Workspace archetype match",
                    "in_len":     len(cmdline.encode("utf-8", errors="ignore")),
                    "out_len":    len(orchestrator_input.encode("utf-8", errors="ignore")),
                    "exec_ms":    0,
                    "preview":    orchestrator_input[:200],
                    "sub_iocs":   {},
                    "source":     "wrapper_archetype",
                })

    # 2) Run the RC5 deterministic decoder on the (possibly pre-decoded) input.
    def _run_with_replacement():
        # Copy cmd but swap in the archetype-decoded line so RC5 sees it.
        cmd2 = dict(cmd)
        cmd2["command_line"] = orchestrator_input
        return _run_single_command(cmd2)
    report, status = await asyncio.to_thread(_run_with_replacement)
    status["sha256"] = sha
    if archetype_layers:
        status["archetype_id"] = archetype_layers[-1]["decoder"]
    if report is not None:
        try:
            report_dict = report.model_dump()
            # Bake archetype layers into the persisted report.trace so a
            # cache-hit next time still shows the full chain.
            if archetype_layers:
                existing_trace = report_dict.get("trace") or []
                report_dict["trace"] = archetype_layers + existing_trace
            await _artifact_upsert(
                command_binary=cmd.get("binary") or "",
                command_line=cmdline,
                report_dict=report_dict,
                job_id=job_id,
                pipeline_version=PIPELINE_VERSION,
            )
        except Exception as e:  # noqa: BLE001
            log.warning("artifact upsert failed sha=%s: %s", sha, e)
    return report, status, False, archetype_layers


def _project_decode_chain(cmd: dict, report, status: dict, cache_hit: bool, idx: int,
                          archetype_layers: list[dict] | None = None) -> dict:
    """Project a per-command AnalystReport into a UI-friendly recursive
    decode chain. Used by the frontend Decode Tree component.
    `archetype_layers` are Workspace-registry layers that fired BEFORE
    the RC5 Orchestrator; they render at the top of the tree."""
    layers: list[dict] = list(archetype_layers or [])
    trace_previews: list[str] = [L.get("preview", "") for L in layers]
    input_cmdline = (cmd.get("command_line") or "")
    if report is not None:
        for step in (getattr(report, "trace", None) or []):
            s = step.model_dump() if hasattr(step, "model_dump") else dict(step)
            preview = (s.get("preview") or "")
            trace_previews.append(preview)
            layers.append({
                "layer":      s.get("layer"),
                "decoder":    s.get("decoder"),
                "confidence": round(float(s.get("confidence") or 0.0), 3),
                "why":        (s.get("why") or "")[:200],
                "in_len":     s.get("in_len"),
                "out_len":    s.get("out_len"),
                "exec_ms":    s.get("exec_ms"),
                "preview":    preview[:200],
                "sub_iocs":   {k: v[:12] for k, v in (s.get("sub_iocs") or {}).items() if v},
            })
    findings = getattr(report, "findings", None)
    # ── PowerShell semantic decode (v3 · spec-compliant) ──────
    # Runs an AST-level pass on the recovered PowerShell to produce
    # evidence-weighted verdicts, loopback classification, MITRE from
    # observed behaviours only, and a proper decode tree tail.
    semantic: dict = {}
    try:
        sr = _ps_semantic_analyze(input_cmdline)
        if sr.detected:
            semantic = sr.to_dict()
            # Append synthetic layers to the tail of the chain so the UI
            # renders EncodedCommand → Base64 → UTF16LE → PowerShell AST
            # as a continuous story.
            _last_layer = max([l.get("layer") or 0 for l in layers] or [0])
            if semantic.get("recovered_script"):
                layers.append({
                    "layer":      _last_layer + 1,
                    "decoder":    "powershell-ast",
                    "confidence": semantic.get("confidence", 0) / 100.0,
                    "why":        (f"Recovered PowerShell parsed into "
                                   f"{len(semantic.get('ast') or [])}-step AST; "
                                   f"decode_outcome={semantic.get('decode_outcome')}"),
                    "in_len":     len(input_cmdline.encode("utf-8", errors="ignore")),
                    "out_len":    len(semantic["recovered_script"].encode("utf-8", errors="ignore")),
                    "exec_ms":    0,
                    "preview":    semantic["recovered_script"][:200],
                    "sub_iocs":   {"urls":  [a["value"] for a in semantic["artifacts"] if a["kind"]=="url"][:8],
                                   "ips":   [a["value"] for a in semantic["artifacts"] if a["kind"]=="ip"][:8]},
                    "source":     "ps_semantic",
                })
    except Exception as e:  # noqa: BLE001
        log.warning("ps semantic analyze failed idx=%s: %s", idx, e)
    # Only run string enrichment when the decoder actually peeled at
    # least one layer — otherwise we'd emit the raw input as a "string"
    # which pollutes the IOC Summary (see the user's report where the
    # entire PS command showed up as a STRINGS entry).
    enrichment: dict = {}
    input_cmdline = (cmd.get("command_line") or "")
    if report is not None and layers:
        try:
            report_output = getattr(report, "output", "") or ""
            # Skip enrichment if the "recovered" output is essentially the
            # same as the input (nothing was decoded — pure noise).
            if report_output and report_output.strip() != input_cmdline.strip():
                enrichment = _enrich_report(report_output, trace_previews)
        except Exception as e:  # noqa: BLE001
            log.warning("strings enrichment failed idx=%s: %s", idx, e)
            enrichment = {}
    # If the semantic pass produced a decisive verdict, prefer it over
    # the RC5 Orchestrator's coarse label — spec: verdict must be
    # evidence-weighted, not rule-triggered on "EncodedCommand exists".
    chain_verdict = (getattr(findings, "verdict", None) if findings else None) or "unknown"
    chain_risk    = int(getattr(findings, "risk_score", 0) or 0) if findings else 0
    chain_mitre   = sorted({(m.id if hasattr(m, "id") else m.get("id"))
                            for m in (getattr(findings, "mitre_techniques", None) or [])
                            if (m.id if hasattr(m, "id") else m.get("id"))}) if findings else []
    if semantic and semantic.get("verdict") and semantic["verdict"] != "unknown":
        chain_verdict = semantic["verdict"]
        chain_risk    = semantic.get("risk_score", chain_risk)
        # Union MITRE — semantic MITRE is behavior-driven and always trustworthy.
        chain_mitre = sorted(set(chain_mitre) | set(semantic.get("mitre_ids") or []))
    return {
        "index":         idx,
        "binary":        cmd.get("binary"),
        "command_line":  input_cmdline[:400],
        "sha256":        status.get("sha256"),
        "status":        status.get("status"),
        "cache_hit":     cache_hit,
        "elapsed_ms":    int((status.get("seconds") or 0.0) * 1000) if status.get("status") != "cache_hit"
                          else int(getattr(report, "elapsed_ms", 0) or 0) if report else 0,
        "layers":        layers,
        "layer_count":   len(layers),
        "archetype_id":  status.get("archetype_id"),
        "terminal":      getattr(report, "terminal", None) if report else None,
        "verdict":       chain_verdict,
        "risk_score":    chain_risk,
        "mitre_ids":     chain_mitre,
        "enrichment":    enrichment,
        "semantic":      semantic or None,
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
        report, status, was_hit, archetype_layers = await _decode_with_cache(cmd, job_id)
        decode_statuses.append(status)
        if was_hit:
            cache_hits += 1
        if report is not None:
            reports.append(report)
        chain = _project_decode_chain(cmd, report, status, was_hit, idx,
                                       archetype_layers=archetype_layers)
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

    # ── Strings & artefact aggregation across every chain ──────
    # Surfaces User-Agents, extracted printable strings, and any URL /
    # path / registry / cmdlet artefacts that appear inside recovered
    # payloads but weren't already captured as first-class IOCs.
    all_strings: list[str] = []
    all_user_agents: list[str] = []
    for _ch in decode_chains:
        enr = _ch.get("enrichment") or {}
        for s in enr.get("strings") or []:
            if s not in all_strings:
                all_strings.append(s)
        for ua in (enr.get("artefacts", {}) or {}).get("user_agents") or []:
            if ua not in all_user_agents:
                all_user_agents.append(ua)
        # Fold newly-surfaced network artefacts back into the top-level IOCs
        # so the UI's IOC Summary card is complete without duplicating.
        for u in (enr.get("artefacts", {}) or {}).get("urls") or []:
            if u not in iocs.setdefault("urls", []):
                iocs["urls"].append(u)
        for h in (enr.get("artefacts", {}) or {}).get("hostnames") or []:
            if h not in iocs.setdefault("domains", []):
                iocs["domains"].append(h)
        for ip in (enr.get("artefacts", {}) or {}).get("ipv4") or []:
            if ip not in iocs.setdefault("ips", []):
                iocs["ips"].append(ip)
        for fp in (enr.get("artefacts", {}) or {}).get("file_paths") or []:
            if fp not in iocs.setdefault("files", []):
                iocs["files"].append(fp)
        for rk in (enr.get("artefacts", {}) or {}).get("registry") or []:
            if rk not in iocs.setdefault("registry", []):
                iocs["registry"].append(rk)
    if all_user_agents:
        iocs["user_agents"] = all_user_agents
    if all_strings:
        # Cap to keep the report lean; the full list stays per-chain.
        iocs["strings"] = all_strings[:80]
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

    # ── AUTO INVESTIGATE v2 · MDR reasoning layer ─────────────
    # Turns the raw incident text into structured events, a chronological
    # timeline, evidence-driven recommendations and an escalation
    # decision — replacing the old "count IOCs" behaviour with the
    # investigation output an MDR analyst would produce.
    try:
        mdr_events = _mdr_parse_events(raw)
    except Exception as e:  # noqa: BLE001
        log.warning("MDR parse_events failed: %s", e)
        mdr_events = []
    mdr_timeline = _mdr_build_timeline(mdr_events) if mdr_events else []
    # URL classification — separates attacker infra from reference /
    # vendor URLs so recommendations never propose blocking cisco.com.
    _ti_hits: set[str] = set()
    for k in ("ips", "domains", "urls"):
        for it in (osint.get("hits") or {}).get(k, []) or []:
            if isinstance(it, dict) and it.get("value"):
                _ti_hits.add(it["value"])
            elif isinstance(it, str):
                _ti_hits.add(it)
    url_buckets = _mdr_classify_urls(iocs.get("urls") or [], raw, _ti_hits)
    mdr_escal   = _mdr_escalation(mdr_events, url_buckets)
    mdr_recs    = _mdr_recommendations(mdr_events, url_buckets)
    mdr_summary = _mdr_exec_summary(mdr_events, verdict,
                                    mdr_escal["decision"] == "escalate")

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
        "mdr_investigation": {
            "executive_summary": mdr_summary,
            "events":            [e.to_dict() for e in mdr_events],
            "timeline":          mdr_timeline,
            "url_classification": url_buckets,
            "recommendations":   mdr_recs,
            "escalation":        mdr_escal,
            "hosts":             sorted({e.hostname for e in mdr_events if e.hostname}),
            "users":             sorted({e.user for e in mdr_events if e.user}),
            "sources":           sorted({e.source for e in mdr_events if e.source}),
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
