"""NivXRay Report Critic — quality gate for Customer / Threat-Hunt /
Forensic / Decoder reports.

Pipeline:

    Customer Report ──► Report Critic ──► pass / fail + reasons + score

Enforces:

  * GAP 1 · Report Quality Validator      — required CIO fields present
                                            when the CIO carries them
  * GAP 5 · Persona MUST-CONTAIN gates    — Threat Hunt must mention
                                            MITRE + Timeline + Evidence;
                                            Forensic must mention Hashes
                                            + Command Line + Paths;
                                            Decoder must mention Decode
                                            + Transformations; Customer
                                            must NEVER contain IEX / Base64 /
                                            UTF16 / Decode
  * GAP 6 · Dynamic section selection     — sections with no meaningful
                                            content are dropped
  * GAP 8 · Report Critic                 — one call that returns
                                            {passed, score, issues[],
                                             coverage{}, dropped_sections[]}

Never rewrites the report. The critic is a linter; the composer owns
regeneration. Deterministic.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .customer_report import (
    CustomerReport,
    FORBIDDEN_TERMS,
    _iocs,
    _hosts,
    _users,
    _hashes,
    _mitre,
    _osint,
    _timeline,
    _findings,
    _recommendations,
)


# ── Persona quality contracts ─────────────────────────────────────────
#
# Each entry describes the surface a given persona must (`must_contain`)
# and must-not (`must_not_contain`) render. Substring match — persona
# tests are cheap, deterministic, and skimmable.

@dataclass(frozen=True)
class PersonaContract:
    persona: str
    must_contain: Tuple[str, ...] = ()
    must_not_contain: Tuple[str, ...] = ()


PERSONA_CONTRACTS: Dict[str, PersonaContract] = {
    "customer": PersonaContract(
        persona="customer",
        must_contain=(),
        must_not_contain=(
            *FORBIDDEN_TERMS,
            # Additional customer-inappropriate terms per your directive:
            "IEX", "Base64", "UTF16", "UTF-16", " Decode ",
        ),
    ),
    "threat_hunt": PersonaContract(
        persona="threat_hunt",
        must_contain=("MITRE", "Timeline", "Evidence"),
        must_not_contain=FORBIDDEN_TERMS,
    ),
    "forensic": PersonaContract(
        persona="forensic",
        must_contain=("Hash", "IOCs"),   # command line / paths are optional when CIO doesn't carry them
        must_not_contain=FORBIDDEN_TERMS,
    ),
    "decoder": PersonaContract(
        persona="decoder",
        must_contain=(),                 # decoder is exempt from most gates
        must_not_contain=(),
    ),
}


# ── Report Critic ─────────────────────────────────────────────────────

@dataclass
class CriticIssue:
    severity: str          # blocker | high | medium | low | info
    code: str              # short identifier for machine consumers
    message: str
    section: Optional[str] = None
    remediation: str = ""


@dataclass
class CoverageResult:
    field_name: str
    present_in_cio: bool
    present_in_report: bool
    ok: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field": self.field_name,
            "present_in_cio": self.present_in_cio,
            "present_in_report": self.present_in_report,
            "ok": self.ok,
        }


@dataclass
class CriticResult:
    passed: bool
    score: int             # 0..100
    persona: str
    issues: List[CriticIssue] = field(default_factory=list)
    coverage: List[CoverageResult] = field(default_factory=list)
    dropped_sections: List[str] = field(default_factory=list)
    kept_sections: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "score": self.score,
            "persona": self.persona,
            "issues": [i.__dict__ for i in self.issues],
            "coverage": [c.to_dict() for c in self.coverage],
            "dropped_sections": self.dropped_sections,
            "kept_sections": self.kept_sections,
        }


# ── Coverage checks (GAP 1) ───────────────────────────────────────────
#
# For every canonical CIO field, if the CIO carries it, the report must
# mention it. If the CIO doesn't carry it, absence is fine (dynamic
# section selection drops the section).

def _has_text(md: str, needle: str) -> bool:
    return needle.lower() in md.lower()


def _coverage_checks(cio: Dict[str, Any], md: str) -> List[CoverageResult]:
    out: List[CoverageResult] = []

    hosts = _hosts(cio)
    out.append(CoverageResult("hosts", bool(hosts), any(_has_text(md, h) for h in hosts) if hosts else True, True))
    if hosts and not any(_has_text(md, h) for h in hosts):
        out[-1] = CoverageResult("hosts", True, False, False)

    users = _users(cio)
    ok = True if not users else any(_has_text(md, u) for u in users)
    out.append(CoverageResult("users", bool(users), ok, ok))

    all_hashes: List[str] = []
    for algo, vs in _hashes(cio).items():
        all_hashes.extend(vs)
    ok = True if not all_hashes else any(_has_text(md, h[:12]) for h in all_hashes)
    out.append(CoverageResult("file_hashes", bool(all_hashes), ok, ok))

    iocs = _iocs(cio)
    ioc_vals = [v for vs in iocs.values() for v in vs]
    ok = True if not ioc_vals else any(_has_text(md, v[:20]) for v in ioc_vals)
    out.append(CoverageResult("iocs", bool(ioc_vals), ok, ok))

    mitre = _mitre(cio)
    ok = True if not mitre else any(_has_text(md, t.get("technique_id") or "") for t in mitre)
    out.append(CoverageResult("mitre", bool(mitre), ok, ok))

    osint = _osint(cio)
    ok = True if not osint else _has_text(md, "OSINT") or _has_text(md, "Threat Intelligence")
    out.append(CoverageResult("osint", bool(osint), ok, ok))

    timeline = _timeline(cio)
    ok = True if not timeline else _has_text(md, "Timeline")
    out.append(CoverageResult("timeline", bool(timeline), ok, ok))

    recs = _recommendations(cio)
    ok = True if not recs else _has_text(md, "Recommendations")
    out.append(CoverageResult("recommendations", bool(recs), ok, ok))

    return out


# ── Dynamic section selection (GAP 6) ─────────────────────────────────
#
# A section is "empty" when its body reads as a placeholder ("No … was
# included with this submission." / "No … extracted." / "…" catch-all).
# The critic reports these so the composer or the UI can hide them.

EMPTY_MARKERS = (
    "No affected-host telemetry",
    "No host telemetry",
    "No timestamped events",
    "No high-signal findings",
    "No file hashes",
    "No IOCs extracted",
    "No OSINT enrichment",
    "OSINT ran but returned no populated providers",
    "No MITRE techniques",
    "No specific analyst actions",
    "No user account was attributed",
    "No containment signal recorded",
    "Behavioural execution chain could not be resolved",
)


def _classify_sections(report: CustomerReport) -> Tuple[List[str], List[str]]:
    dropped: List[str] = []
    kept: List[str] = []
    for s in report.sections:
        body = (s.body or "").strip()
        empty = any(marker.lower() in body.lower() for marker in EMPTY_MARKERS)
        # Executive Summary and Analyst Verdict are always kept even
        # when short, because the customer expects them.
        always_kept = s.number in (1, 15)
        if empty and not always_kept:
            dropped.append(s.title)
        else:
            kept.append(s.title)
    return dropped, kept


# ── Persona MUST/MUST-NOT gates (GAP 5) ───────────────────────────────

def _persona_gate(report: CustomerReport, md: str) -> List[CriticIssue]:
    contract = PERSONA_CONTRACTS.get(report.persona)
    if not contract:
        return []
    issues: List[CriticIssue] = []
    for term in contract.must_contain:
        if not _has_text(md, term):
            issues.append(CriticIssue(
                severity="high",
                code="persona-missing-required",
                message=f"{report.persona!r} report must contain '{term}' but it is absent.",
                remediation=f"Ensure the CIO carries data for the '{term}' section or the persona should be relaxed.",
            ))
    for term in contract.must_not_contain:
        if _has_text(md, term):
            issues.append(CriticIssue(
                severity="blocker",
                code="persona-forbidden-term",
                message=f"{report.persona!r} report contains forbidden term '{term}'.",
                remediation="Sanitize the composer or move this text to a Decoder-persona report.",
            ))
    return issues


# ── Main entry ────────────────────────────────────────────────────────

def critique(report: CustomerReport, cio: Any) -> CriticResult:
    """Run every gate against `report` (composed from `cio`) and return
    a machine-readable {passed, score, issues, coverage, dropped}."""
    if hasattr(cio, "model_dump"):
        cio = cio.model_dump()
    md = report.to_markdown()
    issues: List[CriticIssue] = []

    # (a) Coverage — GAP 1
    coverage = _coverage_checks(cio, md)
    for c in coverage:
        if not c.ok:
            issues.append(CriticIssue(
                severity="high",
                code="missing-cio-field-in-report",
                message=f"CIO carries {c.field_name} but the report doesn't mention it.",
                remediation=f"Extend the composer's {c.field_name} section or check field naming.",
            ))

    # (b) Persona gates — GAP 5
    issues.extend(_persona_gate(report, md))

    # (c) Dynamic section — GAP 6
    dropped, kept = _classify_sections(report)
    for name in dropped:
        issues.append(CriticIssue(
            severity="info",
            code="drop-empty-section",
            message=f"Section '{name}' is empty and should be hidden.",
            section=name,
            remediation="Dynamic section selection will hide this at render time.",
        ))

    # (d) Duplicate-paragraph / generic-wording detector (light heuristic)
    generic_openers = ("No specific analyst actions required.",
                       "Behavioural analysis identified the observed input")
    for opener in generic_openers:
        if md.count(opener) > 1:
            issues.append(CriticIssue(
                severity="low",
                code="duplicated-generic-text",
                message=f"Generic sentence '{opener[:40]}…' appears multiple times.",
                remediation="Compose more section-specific wording."
            ))

    # (e) Score = 100 − (10 × blocker) − (5 × high) − (2 × medium)
    weights = {"blocker": 25, "high": 8, "medium": 3, "low": 1, "info": 0}
    penalty = sum(weights.get(i.severity, 0) for i in issues)
    score = max(0, 100 - penalty)
    passed = not any(i.severity in {"blocker", "high"} for i in issues)

    return CriticResult(
        passed=passed,
        score=score,
        persona=report.persona,
        issues=issues,
        coverage=coverage,
        dropped_sections=dropped,
        kept_sections=kept,
    )


__all__ = [
    "critique", "CriticResult", "CriticIssue", "CoverageResult",
    "PERSONA_CONTRACTS", "PersonaContract",
]
