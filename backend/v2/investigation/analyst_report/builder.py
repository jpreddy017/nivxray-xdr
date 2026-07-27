"""Analyst Report builder.

Deterministic. Every conclusion is derived from the
InvestigationResult; no LLM, no fabrication. Same input → same
report, byte-identical across runs.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ..intent.models import Intent, IntentCategory, RiskBand
from ..verdict import VerdictBand
from .models import IOC, AnalystReport, MITREItem, Recommendation

if TYPE_CHECKING:
    from ..pipeline import InvestigationResult


# ── MITRE technique catalogue (analyst-facing labels only for the
# ── techniques the current intent rules can cite). Locked in code
# ── so the report never renders an ID without its human name.
_MITRE_NAMES: dict[str, str] = {
    "T1105":     "Ingress Tool Transfer",
    "T1197":     "BITS Jobs",
    "T1204.002": "User Execution: Malicious File",
    "T1027":     "Obfuscated Files or Information",
    "T1059.001": "PowerShell",
    "T1218.005": "Signed Binary Proxy Execution: Mshta",
    "T1218.010": "Signed Binary Proxy Execution: Regsvr32",
    "T1218.011": "Signed Binary Proxy Execution: Rundll32",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1053.005": "Scheduled Task",
    "T1543.003": "Windows Service",
    "T1546.003": "WMI Event Subscription",
    "T1003":     "OS Credential Dumping",
    "T1003.001": "LSASS Memory Dumping",
    "T1003.002": "Security Account Manager",
    "T1555.003": "Credentials from Web Browsers",
    "T1562.001": "Disable or Modify Tools (AMSI/Defender)",
    "T1562.006": "Indicator Blocking (ETW)",
    "T1564.003": "Hide Artifacts: Hidden Window",
    "T1033":     "System Owner/User Discovery",
    "T1087":     "Account Discovery",
    "T1087.002": "Domain Account",
    "T1482":     "Domain Trust Discovery",
    "T1016":     "System Network Configuration Discovery",
    "T1057":     "Process Discovery",
    "T1082":     "System Information Discovery",
}


_URL_RE      = re.compile(r"(?i)\bhttps?://[a-z0-9\-._~%!$&()*+,;=:@/?#\[\]]+")
_IPV4_RE     = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_REG_RE      = re.compile(r"(?i)HK(?:LM|CU|CR|U|CC)[:\\][^\s\"'`]+")
_FILE_RE     = re.compile(r"(?i)\b[A-Z]:\\[^\s\"'`]+")
# Env-var paths — capture just the filename dropped after the env
# variable, regardless of intervening whitespace / `+` concatenation.
_ENV_PATH_RE = re.compile(
    r"(?i)\$env:(?:temp|appdata|localappdata|programdata|public|userprofile|windir|systemroot)"
    r"[^\n]{0,80}?\\([A-Za-z0-9._\-]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|scr|msi))"
)
_BARE_EXE_RE = re.compile(r"(?i)['\"]([A-Za-z0-9._\-]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|scr|msi))['\"]")


# ── Recommendation catalogue — one per intent category, conservative
# ── language only.
_RECS: dict[IntentCategory, list[Recommendation]] = {
    IntentCategory.STAGING: [
        Recommendation(
            priority="immediate",
            action="Capture the remote URL, block it at the egress proxy, and pull the content for analysis.",
            rationale="Retrieved content becomes the effective payload — analysing it is the only way to know what would have executed.",
        ),
    ],
    IntentCategory.REMOTE_EXECUTION: [
        Recommendation(
            priority="immediate",
            action="Quarantine the affected host and pull PowerShell / EDR script-block logs.",
            rationale="Execution-primitive combined with a fetch means downstream code may have run in-process, invisible to file-based scanners.",
        ),
    ],
    IntentCategory.DEFENSE_EVASION: [
        Recommendation(
            priority="immediate",
            action="Verify AMSI / Defender / ETW status on the host and re-baseline security tooling.",
            rationale="Defense-evasion primitives leave the host in a degraded telemetry state — subsequent activity may not be logged.",
        ),
    ],
    IntentCategory.PERSISTENCE: [
        Recommendation(
            priority="immediate",
            action="Enumerate autoruns (Sysinternals Autoruns) and remove the persistence artefact.",
            rationale="Persistence survives reboot — remediation of the running process alone leaves the mechanism intact.",
        ),
    ],
    IntentCategory.CREDENTIAL_ACCESS: [
        Recommendation(
            priority="immediate",
            action="Rotate credentials for every principal that logged into the host recently.",
            rationale="Credential-access primitives typically extract cached / interactive credentials that are now considered compromised.",
        ),
    ],
    IntentCategory.DISCOVERY: [
        Recommendation(
            priority="short_term",
            action="Review authentication and directory logs for follow-on lateral movement from the observed host / account.",
            rationale="Reconnaissance output typically drives lateral movement or targeted exfiltration.",
        ),
    ],
    IntentCategory.RUNTIME_DEPENDENT: [
        Recommendation(
            priority="short_term",
            action="Attempt live-fetch or sandbox reproduction to obtain the runtime-only content, then re-analyse.",
            rationale="Static analysis cannot resolve runtime-dependent branches — verdict cannot be finalised without that content.",
        ),
    ],
}


def _dedup(seq):
    seen = set()
    out = []
    for x in seq:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def _extract_iocs(intents: list[Intent], effective_payload: str) -> list[IOC]:
    """Deterministically extract IOCs from intent evidence + payload."""
    text_pool = effective_payload + "\n" + "\n".join(
        ev.observation for i in intents for ev in i.evidence
    )
    iocs: list[IOC] = []
    for url in _dedup(_URL_RE.findall(text_pool)):
        iocs.append(IOC(kind="url", value=url,
                         context="Remote source referenced by the effective payload"))
    for ip in _dedup(_IPV4_RE.findall(text_pool)):
        iocs.append(IOC(kind="ip", value=ip, context="IP address referenced in the payload"))
    for reg in _dedup(_REG_RE.findall(text_pool)):
        iocs.append(IOC(kind="registry", value=reg,
                         context="Registry path referenced in the payload"))
    for f in _dedup(_FILE_RE.findall(text_pool)):
        iocs.append(IOC(kind="file", value=f,
                         context="Filesystem path referenced in the payload"))
    for env_file in _dedup(_ENV_PATH_RE.findall(text_pool)):
        iocs.append(IOC(kind="file", value=env_file,
                         context="Filename dropped into an environment-variable path (e.g. %TEMP%)"))
    # Bare quoted executable names (e.g. "'scwxc.exe'"). Skip anything
    # already emitted as an env-path finding above.
    seen_names = {i.value for i in iocs if i.kind == "file"}
    for name in _dedup(_BARE_EXE_RE.findall(text_pool)):
        if name in seen_names:
            continue
        iocs.append(IOC(kind="file", value=name,
                         context="Executable / script filename referenced in the payload"))
    return iocs


def _mitre(intents: list[Intent]) -> list[MITREItem]:
    """Deduplicated MITRE list with per-intent provenance."""
    seen: set[tuple[str, str]] = set()
    out: list[MITREItem] = []
    for i in intents:
        for tid in i.mitre_ids:
            key = (tid, i.category.value)
            if key in seen:
                continue
            seen.add(key)
            out.append(MITREItem(
                id=tid,
                name=_MITRE_NAMES.get(tid, tid),
                intent=i.category.value,
                confidence=i.confidence,
            ))
    return out


def _unknowns(result: "InvestigationResult") -> list[str]:
    """Enumerate what the tool honestly does not know."""
    out: list[str] = []
    for intent in result.intent.intents:
        if intent.risk == RiskBand.UNKNOWN:
            out.append(intent.rationale)
    if result.rte.stop_reason.value == "no_transformation" and result.rte.depth == 0:
        # No transformations applied at all — but only surface if the
        # verdict is not benign (benign inputs legitimately have no
        # transformations to apply).
        if result.verdict.band != VerdictBand.BENIGN:
            out.append(
                "No further deterministic transformations were applicable; "
                "the effective payload above may still contain runtime "
                "branches that only resolve during execution."
            )
    return _dedup(out)


def _executive_summary(result: "InvestigationResult") -> str:
    v = result.verdict
    top = v.top_intents[0] if v.top_intents else None
    if v.band == VerdictBand.BENIGN:
        return ("Static analysis found no adversarial intent in the effective "
                 "payload. The artefact appears benign and no immediate action is required.")
    lead = {
        VerdictBand.MALICIOUS:         "The artefact is assessed as MALICIOUS.",
        VerdictBand.SUSPICIOUS:        "The artefact is assessed as SUSPICIOUS.",
        VerdictBand.RUNTIME_DEPENDENT: "The artefact's behaviour is RUNTIME-DEPENDENT — static analysis alone cannot finalise the verdict.",
    }[v.band]
    if top:
        return f"{lead} {v.reason} Primary observed behaviour: {top.purpose}"
    return f"{lead} {v.reason}"


def _observed_behaviors(intents: list[Intent]) -> list[dict[str, str]]:
    """Compact list of intents fired — labelled with risk band."""
    return [{
        "category":  i.category.value,
        "purpose":   i.purpose,
        "risk":      i.risk.value,
        "confidence": str(i.confidence),
    } for i in intents]


def _intent_narrative(intents: list[Intent]) -> list[dict[str, str]]:
    """Full per-intent narrative block — purpose + rationale."""
    return [{
        "category":  i.category.value,
        "purpose":   i.purpose,
        "rationale": i.rationale,
        "risk":      i.risk.value,
    } for i in intents]


def _evidence_by_source(intents: list[Intent]) -> list[dict[str, str]]:
    """Flat evidence citation list — analyst-facing, deduplicated by
    (source, observation)."""
    seen = set()
    out: list[dict[str, str]] = []
    for i in intents:
        for ev in i.evidence:
            key = (ev.source, ev.observation)
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "source":      ev.source,
                "observation": ev.observation,
                "rationale":   ev.rationale,
                "confidence":  str(ev.confidence),
                "intent":      i.category.value,
            })
    return out


def _recommendations(intents: list[Intent], verdict_band: VerdictBand) -> list[Recommendation]:
    """Deterministic recommendations from fired intents + verdict band."""
    if verdict_band == VerdictBand.BENIGN:
        return []
    seen_actions: set[str] = set()
    out: list[Recommendation] = []
    cats_fired = _dedup([i.category for i in intents])
    for cat in cats_fired:
        for rec in _RECS.get(cat, []):
            if rec.action in seen_actions:
                continue
            seen_actions.add(rec.action)
            out.append(rec)
    return out


def _confidence_signals(result: "InvestigationResult") -> dict[str, str]:
    """Investigation-specific analyst signals — NOT engineering
    quality metrics. Locked with user directive: do NOT surface
    Trust-harness numbers here."""
    intents = result.intent.intents
    ev_count = sum(len(i.evidence) for i in intents)
    if ev_count >= 4:
        strength = "strong"
    elif ev_count >= 2:
        strength = "moderate"
    elif ev_count >= 1:
        strength = "limited"
    else:
        strength = "insufficient"

    conf = result.verdict.confidence
    if conf >= 85:
        conf_band = "high"
    elif conf >= 65:
        conf_band = "medium"
    elif conf > 0:
        conf_band = "low"
    else:
        conf_band = "unknown"

    unknowns_present = any(i.risk == RiskBand.UNKNOWN for i in intents)
    return {
        "confidence":         conf_band,
        "evidence_strength":  strength,
        "unknowns_present":   "yes" if unknowns_present else "no",
        "reasoning":          "fully_explainable" if intents or result.verdict.band == VerdictBand.BENIGN
                              else "no_analyst_intent",
    }


def generate(result: "InvestigationResult") -> AnalystReport:
    """Produce the deterministic Analyst Report."""
    intents = result.intent.intents
    effective_payload = (result.cre.effective_payload
                          if result.cre and result.cre.effective_payload
                          else result.input)

    return AnalystReport(
        executive_summary=_executive_summary(result),
        observed_behaviors=_observed_behaviors(intents),
        intent_narrative=_intent_narrative(intents),
        evidence=_evidence_by_source(intents),
        mitre=_mitre(intents),
        iocs=_extract_iocs(intents, effective_payload),
        unknowns=_unknowns(result),
        recommendations=_recommendations(intents, result.verdict.band),
        confidence_signals=_confidence_signals(result),
    )


__all__ = ["generate"]
