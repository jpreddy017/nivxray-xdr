"""Orchestrator — recursive plugin-driven decode + intelligence loop.

Algorithm (Phase A, deterministic-only)
---------------------------------------
1. Compute L0 fingerprint of the current payload.
2. Ask DecoderRegistry for candidate plugins (ranked by confidence, cost).
3. Try each candidate up to `budget.max_branches` times per layer.
4. Score the output — if it improves on the current best, accept it and recurse.
5. Collect intelligence signals (mitre_hints, family_hints, lolbas_hits,
   tradecraft, iocs) from every step into the aggregated `Findings` object.
6. Terminate on:
      - english_density ≥ 0.7 (very likely plaintext)
      - budget exhausted (depth or wall-time)
      - no candidate improves the score

Vision alignment
----------------
The orchestrator ONLY routes. All capability — decoding AND intelligence — lives
in plugins. This makes NivXRay extensible from "commands" to "scripts" to
"malware families" without changes to the core loop.
"""
from __future__ import annotations

import logging
import time
from typing import List, Optional

from .fingerprint_util import compute as fingerprint_compute
from .models import (
    AnalysisContext,
    AnalystReport,
    Findings,
    Fingerprint,
    IOCBundle,
    InvestigationRecommendation,
    TraceStep,
)
from .registry import DecoderRegistry

log = logging.getLogger("nivx.engine.orchestrator")

_TERMINAL_ENGLISH = 0.7
_IMPROVEMENT_EPS = 0.02

# Weight table for verdict/risk aggregation (Phase A — keep simple, tune later)
_SEVERITY_WEIGHTS = {
    "info": 2, "low": 5, "medium": 15, "high": 35, "critical": 60,
}


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
    """Build the single-source-of-truth Findings object from every trace step."""
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

    # Family match — pick top confidence
    if seen_family:
        ranked = sorted(seen_family.values(), key=lambda h: -h.confidence)
        top = ranked[0]
        findings.family.family = top.family
        findings.family.confidence = top.confidence
        findings.family.evidence = [top.evidence] if top.evidence else []
        findings.family.alternatives = ranked[1:]

    # Risk score & verdict
    risk = 0
    for tc in findings.tradecraft:
        risk += _SEVERITY_WEIGHTS.get(tc.severity, 5)
    risk += 8 * len(findings.mitre_techniques)
    risk += 4 * len(findings.lolbas)
    risk += 20 if findings.family.confidence >= 0.7 else 0
    risk += 4 * (len(findings.iocs.urls) + len(findings.iocs.ips) + len(findings.iocs.domains))
    findings.risk_score = min(100, risk)

    if findings.risk_score >= 70:
        findings.verdict = "malicious"
    elif findings.risk_score >= 40:
        findings.verdict = "suspicious"
    elif findings.risk_score > 0:
        findings.verdict = "needs_review"
    else:
        findings.verdict = "unknown"

    return findings


def _executive_summary(trace: List[TraceStep], findings: Findings) -> str:
    """Deterministic prose summary — AI may enrich later if enabled."""
    if not trace and findings.risk_score == 0:
        return "No transforms applied; payload appears to be plaintext with no notable indicators."
    parts = []
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
    """Deterministic next-step suggestions based on findings."""
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

        while True:
            reason = ctx.budget.exhausted(depth)
            if reason:
                terminal = "budget"
                stopped_reason = f"Budget exhausted ({reason})"
                break

            if current_fp.english_density >= _TERMINAL_ENGLISH:
                terminal = "english"
                stopped_reason = (
                    f"english_density={current_fp.english_density:.2f} ≥ {_TERMINAL_ENGLISH}"
                )
                break

            cands = DecoderRegistry.candidates(
                current, current_fp, ctx, top_n=ctx.budget.max_branches
            )
            if not cands:
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

            accepted = None
            for plugin, det in cands:
                step_start = time.monotonic_ns()
                try:
                    res = plugin.decode(current, det.args, ctx)
                except Exception as exc:                       # pragma: no cover
                    log.warning("decode() raised in %s: %s", plugin.id, exc)
                    continue
                exec_ms = (time.monotonic_ns() - step_start) // 1_000_000
                cand_fp = fingerprint_compute(res.output)
                cand_score = _score(cand_fp)

                # Accept if score improves OR the plugin emitted intelligence signals
                emitted_signals = bool(
                    res.mitre_hints or res.family_hints
                    or res.lolbas_hits or res.tradecraft or res.iocs
                )
                improved = (
                    cand_score >= best_score + _IMPROVEMENT_EPS
                    or (res.output != current and cand_score >= best_score * 0.75)
                )
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
                    if improved:
                        current = res.output
                        current_fp = cand_fp
                        ctx.trace.add_fingerprint(current_fp)
                        best_score = cand_score
                    accepted = plugin.id
                    if improved:
                        break
                    # signals-only plugins don't advance the loop; try next candidate
                    continue

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

        # Aggregate intelligence from every layer
        findings = _aggregate_findings(list(ctx.trace.steps))
        summary = _executive_summary(list(ctx.trace.steps), findings)
        recommendations = _default_recommendations(findings)

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
        )
