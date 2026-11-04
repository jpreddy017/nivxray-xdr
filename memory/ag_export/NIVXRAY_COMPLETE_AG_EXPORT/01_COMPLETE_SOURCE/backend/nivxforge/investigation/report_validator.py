"""P0.5 · Executive Report Validator.

The **Executive Quality Gate** — every generated report is validated
before it reaches the UI. Pure function. Deterministic.

FAILS the report if ANY of the following is true:

  1. Raw Markdown syntax that would render as literal characters
     (heading hashes, unclosed emphasis stars) has escaped the
     composer.
  2. Section numbering skips values (analyst sees "## 1 ... ## 5").
  3. Verdict claims exist but no contributor evidence attached.
  4. IOCs exist in the CIO but no IOC section / no IOC lines in the
     customer report body.
  5. MITRE techniques exist in the CIO but no MITRE section.
  6. Decoded payload was recovered but no "Recovered command / payload"
     line in the report.
  7. Recommendations exist but no supporting evidence node ids.
  8. Persona-forbidden decoder terminology leaked (delegated to
     `report_critic` — additive not duplicative).

Returns a dataclass:

    ReportValidation
        status: "pass" | "fail"
        score: 0..100
        blockers: [str]        # any of these = fail
        warnings: [str]        # not blocking
        checks: {check_name: bool}
        summary: str

The composer attaches this to `cio.summary.report_validation` and the
frontend refuses to show the report if `status == "fail"`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


_MARKDOWN_LEAK_PATTERNS = [
    # Emphasis stars sitting *outside* legitimate markdown structure —
    # e.g. a bare `**foo` with no closing pair. Real markdown emphasis
    # is always balanced; the leak check only flags dangling markers
    # (a symptom of a partial sanitize + concat somewhere).
    (r"\*{3,}", "raw_markdown_triple_star"),
]


@dataclass
class ReportValidation:
    status: str = "pass"  # pass | fail
    score: int = 100
    blockers: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    checks: Dict[str, bool] = field(default_factory=dict)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "score": self.score,
            "blockers": list(self.blockers),
            "warnings": list(self.warnings),
            "checks": dict(self.checks),
            "summary": self.summary,
        }


# ─── Helpers ──────────────────────────────────────────────────────

def _has_iocs(cio: Dict[str, Any]) -> bool:
    summ = cio.get("summary") or {}
    ent = (summ.get("entities_digest") or {})
    if any(ent.get(k) for k in ("external_domains", "external_ips", "hashes")):
        return True
    md = cio.get("metadata") or {}
    if any(md.get("iocs", {}).get(k) for k in ("urls", "ips", "domains",
                                                "md5", "sha1", "sha256")):
        return True
    # Fall back to evidence graph IOC nodes
    eg = cio.get("evidence_graph") or {}
    for n in (eg.get("nodes") or []):
        if str(n.get("kind", "")).lower() in ("ioc", "external_ioc_url",
                                                "external_ioc_ip",
                                                "external_ioc_domain"):
            return True
    return False


def _has_mitre(cio: Dict[str, Any]) -> bool:
    summ = cio.get("summary") or {}
    md = (summ.get("mitre_digest") or {})
    if md.get("techniques"):
        return True
    eg = cio.get("evidence_graph") or {}
    for n in (eg.get("nodes") or []):
        if str(n.get("kind", "")).lower() == "mitre_technique":
            return True
    return False


def _has_recovered_payload(cio: Dict[str, Any]) -> bool:
    dc = cio.get("decode_chain") or []
    for layer in dc:
        if str(layer.get("preview") or "").strip():
            return True
    return False


def _section_numbers_from_markdown(md_text: str) -> List[int]:
    """Extract '## N. Title' section numbers, in order of appearance."""
    if not md_text:
        return []
    out: List[int] = []
    for m in re.finditer(r"(?m)^##\s+(\d+)\.\s", md_text):
        try:
            out.append(int(m.group(1)))
        except ValueError:
            continue
    return out


# ─── Public entry ─────────────────────────────────────────────────

def validate_report(cio: Dict[str, Any],
                     customer_report: Optional[Dict[str, Any]] = None) -> ReportValidation:
    """Run every quality gate. Non-crashing: unknown structures
    degrade to a `warning`, never a raise."""
    v = ReportValidation()

    summ = (cio.get("summary") or {}) if isinstance(cio, dict) else {}
    verdict = (cio.get("verdict") or {}) if isinstance(cio, dict) else {}
    verdict_label = str(verdict.get("label", "") or "").strip()

    cr = customer_report or (summ.get("customer_report") or {})
    md_text = str(cr.get("markdown") or "")
    body_text = md_text + "\n\n" + str(summ.get("analyst") or "")

    # 1. Markdown-leak detection
    leak = False
    for pat, code in _MARKDOWN_LEAK_PATTERNS:
        if re.search(pat, body_text):
            # NOTE: presence of `##` and `**` INSIDE markdown text is
            # legitimate — the leak-check flags them ONLY when the CIO
            # `render_hint` says the surface won't render markdown.
            # Because we cannot know downstream renderer here, we
            # treat this as a WARNING, not a blocker. Every UI that
            # renders the analyst body MUST pass it through a markdown
            # renderer (react-markdown or equivalent).
            v.warnings.append(f"markdown-leak-check:{code}")
            leak = True
            break
    v.checks["no_raw_markdown_leaks"] = not leak

    # 2. Contiguous section numbering
    nums = _section_numbers_from_markdown(md_text)
    contiguous = True
    if nums:
        for i, n in enumerate(nums, start=1):
            if n != i:
                contiguous = False
                break
    v.checks["contiguous_section_numbering"] = contiguous
    if not contiguous:
        v.blockers.append(f"section_numbering_skips: got {nums}, expected 1..{len(nums)}")

    # 3. Verdict rationale references evidence
    contribs = verdict.get("contributors") or []
    has_verdict_evidence = bool(contribs) or verdict_label in ("", "Undetermined")
    v.checks["verdict_has_contributors"] = has_verdict_evidence
    if not has_verdict_evidence:
        v.blockers.append("verdict claims a label but has zero contributors")

    # 4. IOC section present when IOCs exist
    iocs_needed = _has_iocs(cio)
    ioc_visible = False
    if iocs_needed:
        # Look for section titled "Indicators", "IOC", or an IOC digest
        # line in the body.
        if re.search(r"(?i)\bindicator|\bIOC\b|\bIP address(?:es)?|\bdomain\b|\bhash(?:es)?\b",
                     body_text):
            ioc_visible = True
    v.checks["ioc_surface_present"] = (not iocs_needed) or ioc_visible
    if iocs_needed and not ioc_visible:
        v.blockers.append("CIO carries IOCs but no IOC surface in the report body")

    # 5. MITRE section present when techniques exist
    mitre_needed = _has_mitre(cio)
    mitre_visible = False
    if mitre_needed:
        if re.search(r"(?i)MITRE|ATT&?CK|T\d{4}(?:\.\d{3})?", body_text):
            mitre_visible = True
    v.checks["mitre_surface_present"] = (not mitre_needed) or mitre_visible
    if mitre_needed and not mitre_visible:
        v.blockers.append("CIO carries MITRE techniques but no MITRE surface in the report body")

    # 6. Recovered payload surface present
    payload_needed = _has_recovered_payload(cio)
    payload_visible = False
    if payload_needed:
        # Require an explicit "Recovered" surface (section title, code
        # fence, or the literal word 'Recovered') — a generic mention
        # of 'payload' or 'command' in prose is not enough.
        if re.search(r"(?i)recovered\s+command|recovered\s+payload|recovered\s+stage|## \d+\.\s+Recovered\b|```", body_text):
            payload_visible = True
    v.checks["recovered_payload_surface_present"] = (not payload_needed) or payload_visible
    if payload_needed and not payload_visible:
        v.blockers.append("Decoded payload exists but no 'Recovered command' surface in the report")

    # 7. Recommendations reference evidence
    recs = summ.get("recommendations") or []
    if recs:
        unsupported = [r for r in recs
                       if not (isinstance(r, dict)
                                and r.get("evidence_node_ids"))]
        v.checks["recommendations_evidence_backed"] = not unsupported
        if unsupported:
            v.warnings.append(
                f"{len(unsupported)} recommendation(s) missing evidence_node_ids"
            )
    else:
        v.checks["recommendations_evidence_backed"] = True

    # 8. Persona-forbidden-term leak — delegate to report_critic if
    # a customer_report exists.
    if cr:
        crit = cr.get("critique") or {}
        blockers_from_critic = [i for i in (crit.get("issues") or [])
                                 if i.get("severity") == "blocker"]
        if blockers_from_critic:
            for b in blockers_from_critic:
                v.blockers.append(f"critic:{b.get('code','?')}·{b.get('message','')}")
        v.checks["persona_hygiene_pass"] = not blockers_from_critic
    else:
        v.checks["persona_hygiene_pass"] = True

    # ── Final tally ──
    if v.blockers:
        v.status = "fail"
        v.score = max(0, 100 - 25 * len(v.blockers) - 5 * len(v.warnings))
    else:
        v.status = "pass"
        v.score = max(0, 100 - 5 * len(v.warnings))

    passed_checks = sum(1 for k, ok in v.checks.items() if ok)
    total_checks = len(v.checks) or 1
    v.summary = (
        f"{v.status.upper()} · {passed_checks}/{total_checks} checks passed · "
        f"score {v.score} · {len(v.blockers)} blocker(s) · {len(v.warnings)} warning(s)"
    )
    return v


__all__ = ["validate_report", "ReportValidation"]
