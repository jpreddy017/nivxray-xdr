"""Orchestrator — recursive plugin-driven decode + intelligence loop.

Production hardening (Feb 2026)
-------------------------------
* Loop detection — payload SHA-1 short-hash memo prevents same-content from
  being decoded twice. Same plugin cannot fire twice on identical bytes.
* Memory ceiling — per-step and cumulative output size caps.
* Wall-time + depth + branch caps (via Budget).
* Plugin execution report — records EVERY plugin invocation with its outcome
  (accepted / skipped / detect_zero / decode_error / no_improvement / loop).
* Explainable confidence — every point contributing to risk_score is stored
  in ConfidenceBreakdown with its source and evidence.
* Terminal states — english, family-identified, budget, no-candidate, complete.

Vision alignment
----------------
The orchestrator ONLY routes. AI cannot influence decoding, verdicts, or
Findings — it may enrich the executive_summary post-hoc via a separate,
opt-in step outside this loop.
"""
from __future__ import annotations

import hashlib
import logging
import time
from typing import List, Optional, Set

from .fingerprint_util import compute as fingerprint_compute
from .models import (
    AnalysisContext,
    AnalystReport,
    ConfidenceBreakdown,
    Findings,
    Fingerprint,
    IOCBundle,
    InvestigationRecommendation,
    PluginExecutionEntry,
    PluginExecutionReport,
    RiskContribution,
    TraceStep,
)
from .registry import DecoderRegistry

log = logging.getLogger("nivx.engine.orchestrator")

# Terminal / scoring constants — kept in one place for tunability.
_TERMINAL_ENGLISH = 0.7
_TERMINAL_FAMILY_CONFIDENCE = 0.8
_IMPROVEMENT_EPS = 0.02

# Safety limits (env-tunable in Budget; defaults here are hard fallbacks).
_MAX_OUTPUT_BYTES = 4 * 1024 * 1024        # 4 MB per intermediate output
_MAX_CUMULATIVE_BYTES = 32 * 1024 * 1024   # 32 MB across all layers

_SEVERITY_WEIGHTS = {"info": 2, "low": 5, "medium": 15, "high": 35, "critical": 60}


def _short_hash(text: str) -> str:
    return hashlib.sha1(text.encode("latin-1", errors="replace")).hexdigest()[:16]


def _score(fp: Fingerprint) -> float:
    return (fp.english_density * 0.6
            + fp.printable_ratio * 0.3
            + max(0.0, (5.0 - fp.entropy)) * 0.02)


def _merge_iocs(bundle: IOCBundle, add: dict) -> None:
    for k, v in (add or {}).items():
        if not isinstance(v, list):
            continue
        target = getattr(bundle, k, None)
        if target is None:
            continue
        for item in v:
            if item and item not in target:
                target.append(item)


def _aggregate_findings(trace: List[TraceStep]) -> Findings:
    findings = Findings()
    seen_mitre = set()
    seen_family = {}
    for step in trace:
        _merge_iocs(findings.iocs, step.sub_iocs)
        for hint in step.mitre_hints:
            key = (hint.id, hint.source)
            if key not in seen_mitre:
                findings.mitre_techniques.append(hint)
                seen_mitre.add(key)
        for fh in step.family_hints:
            prev = seen_family.get(fh.family)
            if prev is None or fh.confidence > prev.confidence:
                seen_family[fh.family] = fh
        for hit in step.lolbas_hits:
            findings.lolbas.append(hit)
        for tc in step.tradecraft:
            findings.tradecraft.append(tc)
    if seen_family:
        ranked = sorted(seen_family.values(), key=lambda h: -h.confidence)
        top = ranked[0]
        findings.family.family = top.family
        findings.family.confidence = top.confidence
        findings.family.evidence = [top.evidence] if top.evidence else []
        findings.family.alternatives = ranked[1:]
    return findings


def _compute_confidence_breakdown(findings: Findings) -> ConfidenceBreakdown:
    """Explainable risk_score — one RiskContribution per signal source."""
    contribs: List[RiskContribution] = []
    total = 0

    # Family match — the strongest deterministic signal
    if findings.family.confidence >= 0.8:
        pts = 55
        contribs.append(RiskContribution(
            source="family-match", points=pts,
            detail=f"High-confidence family: {findings.family.family} "
                   f"({findings.family.confidence * 100:.0f}%)",
        ))
        total += pts
    elif findings.family.confidence >= 0.7:
        pts = 35
        contribs.append(RiskContribution(
            source="family-match", points=pts,
            detail=f"Family: {findings.family.family} "
                   f"({findings.family.confidence * 100:.0f}%)",
        ))
        total += pts
    elif findings.family.confidence >= 0.5:
        pts = 15
        contribs.append(RiskContribution(
            source="family-match", points=pts,
            detail=f"Weak family match: {findings.family.family}",
        ))
        total += pts

    # MITRE techniques
    if findings.mitre_techniques:
        pts = 8 * len(findings.mitre_techniques)
        ids = ", ".join(sorted({h.id for h in findings.mitre_techniques}))
        contribs.append(RiskContribution(
            source="mitre", points=pts,
            detail=f"{len(findings.mitre_techniques)} MITRE technique(s): {ids}",
        ))
        total += pts

    # IOCs
    ioc_total = (len(findings.iocs.urls) + len(findings.iocs.ips)
                 + len(findings.iocs.domains))
    if ioc_total:
        pts = 4 * ioc_total
        contribs.append(RiskContribution(
            source="iocs", points=pts,
            detail=(f"{len(findings.iocs.ips)} IPs, {len(findings.iocs.urls)} URLs, "
                    f"{len(findings.iocs.domains)} domains extracted"),
        ))
        total += pts

    # LOLBAS
    if findings.lolbas:
        pts = 4 * len(findings.lolbas)
        bins = ", ".join(sorted({h.binary for h in findings.lolbas}))
        contribs.append(RiskContribution(
            source="lolbas", points=pts,
            detail=f"LOLBAS usage: {bins}",
        ))
        total += pts

    # Tradecraft flags — severity-weighted
    if findings.tradecraft:
        pts = sum(_SEVERITY_WEIGHTS.get(tc.severity, 5) for tc in findings.tradecraft)
        flags = ", ".join(f"{tc.flag}({tc.severity})" for tc in findings.tradecraft)
        contribs.append(RiskContribution(
            source="tradecraft", points=pts, detail=flags,
        ))
        total += pts

    total = min(100, total)
    if total >= 70:
        verdict = "malicious"
    elif total >= 40:
        verdict = "suspicious"
    elif total > 0:
        verdict = "needs_review"
    else:
        verdict = "unknown"
    return ConfidenceBreakdown(total=total, verdict=verdict, contributions=contribs)


def _executive_summary(trace: List[TraceStep], findings: Findings) -> str:
    if not trace and findings.risk_score == 0:
        return "No transforms applied; payload appears to be plaintext with no notable indicators."
    parts: List[str] = []
    if trace:
        chain = " → ".join(step.decoder for step in trace)
        parts.append(f"Deterministically decoded {len(trace)} layer(s): {chain}.")
    if findings.family.family and findings.family.family != "unknown":
        parts.append(f"Identified family: **{findings.family.family}** "
                     f"({findings.family.confidence * 100:.0f}% confidence).")
    if findings.mitre_techniques:
        ids = ", ".join(h.id for h in findings.mitre_techniques[:6])
        parts.append(f"MITRE ATT&CK: {ids}"
                     + ("…" if len(findings.mitre_techniques) > 6 else "") + ".")
    ioc_counts = [
        (n, len(getattr(findings.iocs, n)))
        for n in ("urls", "ips", "domains", "sha256", "sha1", "md5")
    ]
    ioc_bits = [f"{count} {name}" for name, count in ioc_counts if count]
    if ioc_bits:
        parts.append("IOCs: " + ", ".join(ioc_bits) + ".")
    if findings.lolbas:
        parts.append(f"LOLBAS usage: {', '.join(h.binary for h in findings.lolbas[:5])}.")
    parts.append(f"Verdict: **{findings.verdict}** (risk {findings.risk_score}/100).")
    return " ".join(parts)


def _default_recommendations(findings: Findings) -> List[InvestigationRecommendation]:
    recs: List[InvestigationRecommendation] = []
    if findings.iocs.ips:
        recs.append(InvestigationRecommendation(
            priority="high",
            action=f"Block and hunt for outbound connections to: {', '.join(findings.iocs.ips[:5])}",
            rationale="IP indicators extracted from decoded payload.",
            related_iocs=findings.iocs.ips[:5],
        ))
    if findings.iocs.domains:
        recs.append(InvestigationRecommendation(
            priority="high",
            action=f"Add DNS block / proxy denylist for: {', '.join(findings.iocs.domains[:5])}",
            rationale="Domain indicators extracted from decoded payload.",
            related_iocs=findings.iocs.domains[:5],
        ))
    if findings.family.confidence >= 0.7:
        recs.append(InvestigationRecommendation(
            priority="critical",
            action=f"Trigger IR playbook for {findings.family.family}",
            rationale=f"High-confidence family match ({findings.family.confidence * 100:.0f}%).",
        ))
    if not recs and findings.risk_score > 0:
        recs.append(InvestigationRecommendation(
            priority="medium",
            action="Review the decoded output and confirm the source system's context.",
            rationale="Non-zero risk indicators present but no direct IOCs to action.",
        ))
    return recs


class Orchestrator:
    """Run the deterministic recursive decode + intelligence pipeline."""

    def __init__(self, ctx: Optional[AnalysisContext] = None):
        self.ctx = ctx or AnalysisContext()

    def run(self, payload: str) -> AnalystReport:
        ctx = self.ctx
        started = time.monotonic_ns()

        current = payload or ""
        current_fp = fingerprint_compute(current)
        ctx.trace.add_fingerprint(current_fp)
        best_score = _score(current_fp)
        depth = 0
        terminal = "no-op"
        stopped_reason = ""

        # Production-hardening state
        seen_hashes: Set[str] = {_short_hash(current)}          # loop detection
        # Track (plugin_id, payload_hash) to prevent re-firing same plugin on same bytes
        plugin_payload_seen: Set[tuple] = set()
        cumulative_bytes = len(current)
        exec_report = PluginExecutionReport()

        def _log(**kw):
            exec_report.entries.append(PluginExecutionEntry(**kw))

        while True:
            # 1. Budget check
            reason = ctx.budget.exhausted(depth)
            if reason:
                terminal = "budget"
                stopped_reason = f"Budget exhausted ({reason})"
                break

            # 2. Terminal: already English
            if current_fp.english_density >= _TERMINAL_ENGLISH:
                terminal = "english"
                stopped_reason = (
                    f"english_density={current_fp.english_density:.2f} ≥ {_TERMINAL_ENGLISH}"
                )
                break

            # 3. Terminal: previous step identified a high-confidence family
            if ctx.trace.steps:
                last_step = ctx.trace.steps[-1]
                terminal_family = None
                for fh in last_step.family_hints:
                    if fh.confidence >= _TERMINAL_FAMILY_CONFIDENCE:
                        terminal_family = fh
                        break
                if terminal_family:
                    terminal = "family-identified"
                    stopped_reason = (
                        f"Family '{terminal_family.family}' identified with "
                        f"{terminal_family.confidence * 100:.0f}% confidence — "
                        "stopping recursion at terminal state."
                    )
                    break

            # 4. Candidate discovery
            cands = DecoderRegistry.candidates(
                current, current_fp, ctx, top_n=ctx.budget.max_branches
            )
            if not cands:
                # Record every plugin as "skipped: detect_zero"
                for dec in DecoderRegistry.all():
                    _log(plugin=dec.id, layer=depth, outcome="detect_zero",
                         detect_confidence=0.0, reason="detect() returned 0",
                         exec_ms=0)
                if depth == 0:
                    terminal = "no-candidate"
                    stopped_reason = (
                        f"No decoder claimed confidence ≥ 0.05 on the raw input "
                        f"({len(DecoderRegistry.all())} plugins considered)."
                    )
                else:
                    terminal = "complete"
                    stopped_reason = (
                        f"Decoded {depth} layer(s); no plugin claims further transform."
                    )
                break

            # 5. Try candidates
            accepted = None
            current_hash = _short_hash(current)
            for plugin, det in cands:
                # Loop-detection: same plugin can't run on same-content payload twice
                key = (plugin.id, current_hash)
                if key in plugin_payload_seen:
                    _log(plugin=plugin.id, layer=depth, outcome="skipped",
                         detect_confidence=det.confidence, detect_reason=det.why,
                         reason="loop-detection: same plugin already applied to identical bytes",
                         exec_ms=0)
                    continue

                step_start = time.monotonic_ns()
                try:
                    res = plugin.decode(current, det.args, ctx)
                except Exception as exc:
                    exec_ms = (time.monotonic_ns() - step_start) // 1_000_000
                    _log(plugin=plugin.id, layer=depth, outcome="decode_error",
                         detect_confidence=det.confidence, detect_reason=det.why,
                         reason=f"{type(exc).__name__}: {exc}", exec_ms=int(exec_ms))
                    log.warning("decode() raised in %s: %s", plugin.id, exc)
                    continue
                exec_ms = (time.monotonic_ns() - step_start) // 1_000_000

                # Memory safety: reject outputs above the per-step ceiling
                if len(res.output) > _MAX_OUTPUT_BYTES:
                    _log(plugin=plugin.id, layer=depth, outcome="skipped",
                         detect_confidence=det.confidence, detect_reason=det.why,
                         reason=f"output {len(res.output)}B exceeds per-step limit {_MAX_OUTPUT_BYTES}B",
                         exec_ms=int(exec_ms))
                    continue
                if cumulative_bytes + len(res.output) > _MAX_CUMULATIVE_BYTES:
                    _log(plugin=plugin.id, layer=depth, outcome="skipped",
                         detect_confidence=det.confidence, detect_reason=det.why,
                         reason=f"cumulative {cumulative_bytes + len(res.output)}B "
                                f"exceeds pipeline limit {_MAX_CUMULATIVE_BYTES}B",
                         exec_ms=int(exec_ms))
                    continue

                # Loop-detection on OUTPUT: if we've seen this exact payload already,
                # applying this plugin is guaranteed useless.
                out_hash = _short_hash(res.output)
                if out_hash in seen_hashes:
                    _log(plugin=plugin.id, layer=depth, outcome="skipped",
                         detect_confidence=det.confidence, detect_reason=det.why,
                         reason="loop-detection: output identical to a previously-seen state",
                         exec_ms=int(exec_ms))
                    plugin_payload_seen.add(key)
                    continue

                cand_fp = fingerprint_compute(res.output)
                cand_score = _score(cand_fp)

                emitted_signals = bool(
                    res.mitre_hints or res.family_hints
                    or res.lolbas_hits or res.tradecraft or res.iocs
                )
                score_improved = cand_score >= best_score + _IMPROVEMENT_EPS
                high_conf_transform = (
                    det.confidence >= 0.7 and res.output and res.output != current
                )
                soft_improvement = (
                    res.output != current and cand_score >= best_score * 0.75
                )
                improved = score_improved or high_conf_transform or soft_improvement

                if improved or emitted_signals:
                    step = TraceStep(
                        layer=depth,
                        decoder=plugin.id,
                        schema_version=plugin.schema_version,
                        confidence=det.confidence,
                        why=det.why,
                        in_len=len(current),
                        out_len=len(res.output),
                        exec_ms=int(exec_ms),
                        preview=res.output[:200],
                        args=det.args,
                        sub_iocs=res.iocs,
                        mitre_hints=res.mitre_hints,
                        family_hints=res.family_hints,
                        lolbas_hits=res.lolbas_hits,
                        tradecraft=res.tradecraft,
                    )
                    ctx.trace.add_step(step)
                    plugin_payload_seen.add(key)
                    _log(plugin=plugin.id, layer=depth, outcome="accepted",
                         detect_confidence=det.confidence, detect_reason=det.why,
                         reason=("score improved" if score_improved
                                 else ("high-confidence transform" if high_conf_transform
                                       else ("soft improvement" if soft_improvement
                                             else "signals emitted"))),
                         exec_ms=int(exec_ms), signals_emitted=emitted_signals)
                    if improved:
                        current = res.output
                        current_fp = cand_fp
                        ctx.trace.add_fingerprint(current_fp)
                        best_score = cand_score
                        seen_hashes.add(out_hash)
                        cumulative_bytes += len(res.output)
                    accepted = plugin.id
                    if improved:
                        break
                    # signals-only plugins don't advance the loop; try next candidate
                    continue

                _log(plugin=plugin.id, layer=depth, outcome="no_improvement",
                     detect_confidence=det.confidence, detect_reason=det.why,
                     reason=f"score {cand_score:.3f} vs best {best_score:.3f}",
                     exec_ms=int(exec_ms))

            if not accepted:
                if depth == 0:
                    terminal = "no-candidate"
                    tried_names = ", ".join(
                        f"{d.id}({dr.confidence:.2f})" for d, dr in cands
                    )
                    stopped_reason = (
                        f"No plugin produced a useful transform on the raw input. "
                        f"Considered: {tried_names}."
                    )
                else:
                    terminal = "complete"
                    tried_names = ", ".join(
                        f"{d.id}({dr.confidence:.2f})" for d, dr in cands
                    )
                    stopped_reason = (
                        f"Decoded {depth} layer(s); no further transform improved the score. "
                        f"Considered at final layer: {tried_names}. "
                        f"Final english_density={current_fp.english_density:.2f}, "
                        f"printable={current_fp.printable_ratio:.2f}."
                    )
                break

            depth += 1

        elapsed_ms = (time.monotonic_ns() - started) // 1_000_000

        # Aggregate intelligence and build explainable confidence
        findings = _aggregate_findings(list(ctx.trace.steps))
        breakdown = _compute_confidence_breakdown(findings)
        findings.risk_score = breakdown.total
        findings.verdict = breakdown.verdict

        summary = _executive_summary(list(ctx.trace.steps), findings)
        recommendations = _default_recommendations(findings)

        exec_report.layers_run = len(ctx.trace.steps)
        exec_report.total_time_ms = int(elapsed_ms)
        exec_report.budget_snapshot = {
            "max_depth": ctx.budget.max_depth,
            "max_branches": ctx.budget.max_branches,
            "wall_time_ms": ctx.budget.wall_time_ms,
            "elapsed_ms": ctx.budget.elapsed_ms(),
        }

        return AnalystReport(
            output=current,
            trace=list(ctx.trace.steps),
            fingerprint_history=list(ctx.trace.fingerprints),
            terminal=terminal,
            stopped_reason=stopped_reason,
            elapsed_ms=int(elapsed_ms),
            engine="orchestrator-v1",
            findings=findings,
            executive_summary=summary,
            investigation_steps=recommendations,
            confidence_breakdown=breakdown,
            plugin_report=exec_report,
        )
