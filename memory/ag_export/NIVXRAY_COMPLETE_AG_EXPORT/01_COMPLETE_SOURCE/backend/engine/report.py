"""Analyst Report generator — deterministic export of AnalystReport to
Markdown / JSON / plain text.

Every renderer must be pure and side-effect-free so reports are byte-stable
across runs (analysts often diff two reports).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .models import AnalystReport


def to_json(report: AnalystReport, *, indent: int = 2) -> str:
    return report.model_dump_json(indent=indent)


def to_markdown(report: AnalystReport, *, title: str = "NivXRay Analyst Report") -> str:
    """Deterministic Markdown export — no timestamps in report body to keep
    byte-stable across identical runs (analysts diff reports)."""
    findings = report.findings
    lines: list[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append("_Deterministic Malware Command Intelligence — powered by NivXRay_")
    lines.append("")

    # 1. Executive summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(report.executive_summary or "_(No summary generated.)_")
    lines.append("")

    # 2. Verdict / risk / confidence breakdown
    lines.append("## Verdict")
    lines.append("")
    lines.append(f"| Field | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| Verdict | **{findings.verdict}** |")
    lines.append(f"| Risk Score | **{findings.risk_score} / 100** |")
    lines.append(f"| Terminal State | `{report.terminal}` |")
    lines.append(f"| Stopping Reason | {report.stopped_reason or '_n/a_'} |")
    lines.append(f"| Elapsed | {report.elapsed_ms} ms |")
    lines.append(f"| Engine | `{report.engine}` |")
    lines.append("")

    # 2b. Explainable confidence
    if report.confidence_breakdown.contributions:
        lines.append("### Why This Score")
        lines.append("")
        lines.append("| Source | Points | Evidence |")
        lines.append("|---|---:|---|")
        for c in report.confidence_breakdown.contributions:
            lines.append(f"| `{c.source}` | +{c.points} | {c.detail} |")
        lines.append(f"| **Total (capped at 100)** | **{report.confidence_breakdown.total}** | |")
        lines.append("")

    # 3. Malware family
    if findings.family.family and findings.family.family != "unknown":
        lines.append("## Malware Family")
        lines.append("")
        lines.append(f"- **Family:** {findings.family.family}")
        lines.append(f"- **Confidence:** {findings.family.confidence * 100:.0f}%")
        if findings.family.evidence:
            lines.append(f"- **Evidence:**")
            for e in findings.family.evidence:
                lines.append(f"  - {e}")
        if findings.family.alternatives:
            lines.append(f"- **Alternatives considered:**")
            for a in findings.family.alternatives[:5]:
                lines.append(f"  - {a.family} ({a.confidence * 100:.0f}%)")
        lines.append("")

    # 4. Decode timeline
    lines.append("## Decode Timeline")
    lines.append("")
    if report.trace:
        lines.append("| # | Plugin | Confidence | In → Out | Time | Why |")
        lines.append("|---:|---|---:|---:|---:|---|")
        for i, s in enumerate(report.trace, 1):
            lines.append(
                f"| {i} | `{s.decoder}` | {s.confidence * 100:.0f}% | "
                f"{s.in_len} → {s.out_len} | {s.exec_ms} ms | {s.why} |"
            )
    else:
        lines.append("_No transforms were applied — payload appears to be plaintext._")
    lines.append("")

    # 5. IOC bundle
    ioc_sections = [
        ("URLs", findings.iocs.urls),
        ("IPs", findings.iocs.ips),
        ("Domains", findings.iocs.domains),
        ("Emails", findings.iocs.emails),
        ("MD5", findings.iocs.md5),
        ("SHA-1", findings.iocs.sha1),
        ("SHA-256", findings.iocs.sha256),
        ("Bitcoin Addresses", findings.iocs.bitcoin_addresses),
        ("File Paths", findings.iocs.file_paths),
    ]
    non_empty_iocs = [(k, v) for k, v in ioc_sections if v]
    if non_empty_iocs:
        lines.append("## Indicators of Compromise")
        lines.append("")
        for label, items in non_empty_iocs:
            lines.append(f"### {label}")
            for it in items[:50]:
                lines.append(f"- `{it}`")
            lines.append("")

    # 6. MITRE ATT&CK
    if findings.mitre_techniques:
        lines.append("## MITRE ATT&CK Mapping")
        lines.append("")
        lines.append("| Technique | Name | Tactic | Source | Evidence |")
        lines.append("|---|---|---|---|---|")
        for h in findings.mitre_techniques:
            lines.append(
                f"| `{h.id}` | {h.technique or '_n/a_'} | {h.tactic or '_n/a_'} | "
                f"{h.source} | {h.evidence} |"
            )
        lines.append("")

    # 7. LOLBAS
    if findings.lolbas:
        lines.append("## LOLBAS Detection")
        lines.append("")
        lines.append("| Binary | Technique | Evidence |")
        lines.append("|---|---|---|")
        for h in findings.lolbas:
            lines.append(f"| `{h.binary}` | `{h.technique_id or '_n/a_'}` | {h.evidence} |")
        lines.append("")

    # 8. Tradecraft
    if findings.tradecraft:
        lines.append("## Tradecraft Flags")
        lines.append("")
        lines.append("| Flag | Severity | Evidence |")
        lines.append("|---|---|---|")
        for t in findings.tradecraft:
            lines.append(f"| `{t.flag}` | **{t.severity}** | {t.evidence} |")
        lines.append("")

    # 9. Investigation recommendations
    if report.investigation_steps:
        lines.append("## Recommended Investigation Steps")
        lines.append("")
        for i, rec in enumerate(report.investigation_steps, 1):
            lines.append(f"{i}. **[{rec.priority.upper()}]** {rec.action}")
            if rec.rationale:
                lines.append(f"   _Rationale: {rec.rationale}_")
            if rec.related_iocs:
                lines.append(f"   _Related IOCs: {', '.join(rec.related_iocs[:5])}_")
        lines.append("")

    # 10. Plugin execution report
    if report.plugin_report.entries:
        lines.append("## Plugin Execution Report")
        lines.append("")
        lines.append(f"- Layers run: **{report.plugin_report.layers_run}**")
        lines.append(f"- Total time: **{report.plugin_report.total_time_ms} ms**")
        b = report.plugin_report.budget_snapshot
        lines.append(f"- Budget: depth ≤ {b.get('max_depth', '?')}, "
                     f"branches ≤ {b.get('max_branches', '?')}, "
                     f"wall-time ≤ {b.get('wall_time_ms', '?')} ms "
                     f"(used {b.get('elapsed_ms', '?')} ms).")
        lines.append("")
        lines.append("| Layer | Plugin | Outcome | Confidence | Reason | Time |")
        lines.append("|---:|---|---|---:|---|---:|")
        for e in report.plugin_report.entries:
            lines.append(
                f"| {e.layer} | `{e.plugin}` | {e.outcome} | "
                f"{e.detect_confidence * 100:.0f}% | {e.reason or e.detect_reason} | "
                f"{e.exec_ms} ms |"
            )
        lines.append("")

    # 11. Final decoded output preview (truncated)
    lines.append("## Final Decoded Output (Preview)")
    lines.append("")
    preview = report.output[:2000]
    if not preview:
        lines.append("_(empty)_")
    else:
        lines.append("```")
        lines.append(preview)
        if len(report.output) > 2000:
            lines.append(f"... [{len(report.output) - 2000} more chars truncated]")
        lines.append("```")
    lines.append("")

    lines.append("---")
    lines.append("_Report generated by NivXRay MCIP · deterministic · offline-first._")
    return "\n".join(lines)


def to_text(report: AnalystReport) -> str:
    """Plain-text export — same content as Markdown but without formatting."""
    md = to_markdown(report)
    # trivial reduction: drop markdown tokens
    return (md
            .replace("| ", "  ").replace(" |", "")
            .replace("**", "").replace("`", "")
            .replace("---|", "").replace("#### ", "").replace("### ", "")
            .replace("## ", "").replace("# ", ""))
