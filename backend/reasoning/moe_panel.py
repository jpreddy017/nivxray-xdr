"""NivXRay Mixture-of-Experts (MoE) Analyst Panel — Feb 2026.

Extends the single Claude tiebreaker into 3 specialist critics + a
synthesiser for deep-mode investigation reports.

Critics (run in parallel via asyncio.gather):
    * malware_analyst  — behavioural analysis, IOC extraction, MITRE ATT&CK
    * red_team         — offensive tradecraft, evasion, LOLBAS abuse
    * defensive        — detection engineering, Sigma/YARA, containment

Synthesiser:
    * merges the 3 critic reports
    * flags consensus + disagreements
    * emits a single confidence-scored verdict

Anti-hallucination rules (hard-enforced, both in prompt AND post-filter):
    1. Every finding MUST carry ``evidence_refs`` — a list of {type, value}
       pointing at concrete decoded artefacts (chain step, IOC, LOLBin,
       MITRE technique, or decoded_text_span).
    2. Findings with no evidence_refs get dropped from the response.
    3. If no LLM key is configured, the module falls back to a
       deterministic-only mode that generates findings directly from the
       evidence bundle — same schema, zero AI risk.

Integrates with:
    * ``analysis_core.deterministic_best_decode`` — evidence source
    * ``operations.extract_iocs`` / ``mitre_map`` — IOCs + MITRE
    * ``lolbas.scan_lolbas`` — LOLBins
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple


# ─── Data classes ─────────────────────────────────────────────────────────
@dataclass
class EvidenceRef:
    """A single pointer to a concrete artefact in the evidence bundle."""

    type: str   # chain | ioc | lolbin | mitre | decoded_text | verdict
    value: str  # op name / IOC value / LOLBin name / T-ID / snippet

    def to_dict(self) -> Dict[str, str]:
        return {"type": self.type, "value": self.value}


@dataclass
class Finding:
    title: str
    description: str
    severity: str  # critical | high | medium | low | info
    confidence: float  # 0.0 – 1.0
    evidence_refs: List[EvidenceRef] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": round(float(self.confidence), 3),
            "evidence_refs": [e.to_dict() for e in self.evidence_refs],
            "tags": list(self.tags),
        }


@dataclass
class ReviewerReport:
    reviewer: str
    findings: List[Finding] = field(default_factory=list)
    summary: str = ""
    provider: str = "static-fallback"
    duration_ms: int = 0
    error: Optional[str] = None
    extras: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reviewer": self.reviewer,
            "provider": self.provider,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "duration_ms": self.duration_ms,
            "error": self.error,
            **({"extras": self.extras} if self.extras else {}),
        }


# ─── Evidence normalisation ──────────────────────────────────────────────
def _flatten_iocs(iocs: Any) -> List[str]:
    """iocs may be a dict of lists or a flat list — return flat unique list."""
    if isinstance(iocs, list):
        return [str(x) for x in iocs if x]
    if isinstance(iocs, dict):
        out: List[str] = []
        for v in iocs.values():
            if isinstance(v, list):
                out.extend(str(x) for x in v if x)
            elif isinstance(v, str) and v:
                out.append(v)
        return list(dict.fromkeys(out))
    return []


def _flatten_mitre(mitre: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not mitre:
        return out
    for m in mitre:
        if isinstance(m, dict):
            tid = m.get("id") or m.get("technique_id") or ""
            if tid:
                out.append({
                    "id": str(tid),
                    "technique": m.get("technique") or m.get("name") or "",
                    "tactic": m.get("tactic") or "",
                })
        elif isinstance(m, str):
            out.append({"id": m, "technique": "", "tactic": ""})
    # Dedupe on id
    seen = set()
    dedup = []
    for m in out:
        if m["id"] not in seen:
            seen.add(m["id"])
            dedup.append(m)
    return dedup


def _flatten_lolbins(lolbins: Any) -> List[Dict[str, Any]]:
    if not lolbins:
        return []
    out: List[Dict[str, Any]] = []
    for l in lolbins:
        if isinstance(l, dict):
            name = l.get("name") or l.get("binary") or l.get("bin") or ""
            if name:
                out.append({
                    "name": str(name),
                    "mitre": l.get("mitre") or l.get("technique") or "",
                    "purpose": l.get("purpose") or l.get("category") or "",
                })
        elif isinstance(l, str):
            out.append({"name": l, "mitre": "", "purpose": ""})
    return out


def normalise_evidence(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Build a compact, LLM-friendly evidence bundle from a raw dict."""
    chain = evidence.get("chain") or evidence.get("steps") or []
    chain_ops = []
    for s in chain[:20]:
        if isinstance(s, dict):
            chain_ops.append(s.get("op") or s.get("name") or "")
        elif isinstance(s, str):
            chain_ops.append(s)
    chain_ops = [x for x in chain_ops if x]

    iocs = _flatten_iocs(evidence.get("iocs"))
    mitre = _flatten_mitre(evidence.get("mitre") or evidence.get("mitre_techniques"))
    lolbins = _flatten_lolbins(evidence.get("lolbins") or evidence.get("lolbas"))
    decoded = str(evidence.get("decoded_output") or evidence.get("output") or "")[:2000]
    inp = str(evidence.get("input") or "")[:1000]
    verdict = evidence.get("verdict") or {}
    if isinstance(verdict, str):
        verdict = {"label": verdict}

    return {
        "input": inp,
        "decoded_output": decoded,
        "chain": chain_ops,
        "iocs": iocs,
        "mitre": mitre,
        "lolbins": lolbins,
        "verdict": verdict,
    }


# ─── Reviewer prompts ─────────────────────────────────────────────────────
_SYSTEM_ANTI_HALLUC = (
    "Every finding you emit MUST include at least one evidence_ref pointing "
    "at a concrete item from the EVIDENCE bundle. evidence_ref types allowed: "
    "chain, ioc, lolbin, mitre, decoded_text, verdict. If you cannot cite an "
    "evidence item, do NOT emit the finding. Do not speculate about "
    "capabilities not visible in the evidence. Reply with JSON only."
)


def _reviewer_system(role: str) -> str:
    if role == "malware_analyst":
        return (
            "You are a senior malware analyst reviewing a decoded payload. "
            "Focus on: behavioural intent, execution flow, IOC pivots, "
            "MITRE ATT&CK mapping, and stager vs final-payload classification. "
            "Do NOT invent capabilities not visible in the evidence. "
            + _SYSTEM_ANTI_HALLUC
        )
    if role == "red_team":
        return (
            "You are a red team operator reviewing an intercepted payload. "
            "Focus on: offensive tradecraft, evasion techniques, LOLBAS "
            "abuse patterns, likely detection bypasses, and infrastructure "
            "reuse. Explain what the operator TRIED TO ACHIEVE and how they "
            "hid it. " + _SYSTEM_ANTI_HALLUC
        )
    if role == "defensive":
        return (
            "You are a detection engineer + threat hunter. Focus on: "
            "Sigma / YARA / KQL rule ideas, containment recommendations, "
            "specific hunting queries, and gaps in current telemetry. "
            "Every rule idea MUST cite the evidence artefact that motivates "
            "it. " + _SYSTEM_ANTI_HALLUC
        )
    return "You are a security analyst. " + _SYSTEM_ANTI_HALLUC


def _reviewer_user_prompt(role: str, ev: Dict[str, Any]) -> str:
    hdr = {
        "malware_analyst": "As the MALWARE ANALYST",
        "red_team": "As the RED TEAM REVIEWER",
        "defensive": "As the DEFENSIVE REVIEWER (detection engineering + hunting)",
    }.get(role, "As the SECURITY ANALYST")

    schema_hint = {
        "malware_analyst": (
            'Schema: {"summary":"1-3 sentences","findings":[{'
            '"title":"","description":"","severity":"critical|high|medium|low|info",'
            '"confidence":0.0-1.0,"evidence_refs":[{"type":"chain|ioc|lolbin|mitre|decoded_text","value":"..."}],'
            '"tags":["behavioral","ioc","mitre"]}]}'
        ),
        "red_team": (
            'Schema: {"summary":"1-3 sentences","findings":[{'
            '"title":"","description":"","severity":"critical|high|medium|low|info",'
            '"confidence":0.0-1.0,"evidence_refs":[{"type":"chain|ioc|lolbin|mitre|decoded_text","value":"..."}],'
            '"tags":["evasion","lolbas","staging"]}],'
            '"techniques":["<short verb-object descriptions>"]}'
        ),
        "defensive": (
            'Schema: {"summary":"1-3 sentences","findings":[{'
            '"title":"","description":"","severity":"critical|high|medium|low|info",'
            '"confidence":0.0-1.0,"evidence_refs":[{"type":"chain|ioc|lolbin|mitre|decoded_text","value":"..."}],'
            '"tags":["sigma","yara","kql","hunting"]}],'
            '"sigma_rules":[{"title":"","logsource":"","detection":"<one-line>"}],'
            '"hunting_queries":["<KQL or Splunk one-liner>"]}'
        ),
    }.get(role, "")

    return (
        f"{hdr}, review this decoded payload and produce a structured "
        f"finding list. Keep it dense — 2-5 findings max. Only cite items "
        f"from the EVIDENCE bundle below.\n\n"
        f"EVIDENCE:\n{json.dumps(ev, indent=2)}\n\n"
        f"{schema_hint}\n"
        f"Reply with JSON only. No markdown."
    )


# ─── LLM invocation (parallel Claude via Emergent) ────────────────────────
async def _call_claude(system: str, user: str, session_id: str) -> Tuple[Dict[str, Any], str]:
    """Return (parsed_json, provider_label). Raises on failure.

    Wrapped in asyncio.wait_for so a single stuck reviewer can't drag the
    whole panel past the 85 s request-hardening budget.
    """
    key = os.environ.get("EMERGENT_LLM_KEY", "")
    if not key:
        raise RuntimeError("no-llm-key")
    from emergentintegrations.llm.chat import LlmChat, UserMessage
    chat = (
        LlmChat(api_key=key, session_id=session_id, system_message=system)
        .with_model("anthropic", "claude-sonnet-4-5-20250929")
        .with_params(max_tokens=1400)
    )
    resp = await asyncio.wait_for(
        chat.send_message(UserMessage(text=user)),
        timeout=25.0,
    )
    raw = (resp if isinstance(resp, str) else str(resp)).strip()
    # Strip accidental code fences
    m = re.search(r"```(?:json)?\s*(.*?)\s*```", raw, re.DOTALL)
    if m:
        raw = m.group(1)
    if not raw.lstrip().startswith("{"):
        m2 = re.search(r"\{.*\}", raw, re.DOTALL)
        if m2:
            raw = m2.group(0)
    return json.loads(raw), "emergent-claude"


# ─── Evidence-ref validator ──────────────────────────────────────────────
def _valid_evidence_refs(refs: List[Any], ev: Dict[str, Any]) -> List[EvidenceRef]:
    """Keep only refs whose value points at something real in the bundle."""
    if not isinstance(refs, list):
        return []
    valid: List[EvidenceRef] = []
    chain_set = {s.lower() for s in ev.get("chain", [])}
    ioc_set = {s.lower() for s in ev.get("iocs", [])}
    lolbin_set = {l["name"].lower() for l in ev.get("lolbins", [])}
    mitre_set = {m["id"].upper() for m in ev.get("mitre", [])}
    decoded_low = (ev.get("decoded_output") or "").lower()
    for r in refs[:5]:
        if not isinstance(r, dict):
            continue
        t = str(r.get("type") or "").strip().lower()
        v = str(r.get("value") or "").strip()
        if not t or not v:
            continue
        vl = v.lower()
        ok = False
        if t == "chain" and vl in chain_set:
            ok = True
        elif t == "ioc" and vl in ioc_set:
            ok = True
        elif t == "lolbin" and vl in lolbin_set:
            ok = True
        elif t == "mitre" and v.upper() in mitre_set:
            ok = True
        elif t == "decoded_text":
            # Accept if the cited snippet actually appears in decoded output.
            if len(vl) >= 3 and vl[:120] in decoded_low:
                ok = True
        elif t == "verdict":
            ok = True  # verdict is always in the bundle when present
        if ok:
            valid.append(EvidenceRef(type=t, value=v))
    return valid


def _parse_finding_dict(d: Any, ev: Dict[str, Any]) -> Optional[Finding]:
    if not isinstance(d, dict):
        return None
    title = str(d.get("title") or "").strip()
    desc = str(d.get("description") or "").strip()
    if not title or not desc:
        return None
    sev = str(d.get("severity") or "medium").lower()
    if sev not in ("critical", "high", "medium", "low", "info"):
        sev = "medium"
    try:
        conf = float(d.get("confidence") or 0.5)
    except (TypeError, ValueError):
        conf = 0.5
    conf = max(0.0, min(1.0, conf))
    refs = _valid_evidence_refs(d.get("evidence_refs") or [], ev)
    if not refs:
        # Anti-hallucination: drop findings that don't cite evidence.
        return None
    tags = [str(t).strip() for t in (d.get("tags") or []) if str(t).strip()][:6]
    return Finding(title=title[:160], description=desc[:600],
                   severity=sev, confidence=conf,
                   evidence_refs=refs, tags=tags)


# ─── Deterministic fallback reviewers (no LLM) ────────────────────────────
def _fallback_malware_analyst(ev: Dict[str, Any]) -> ReviewerReport:
    findings: List[Finding] = []
    chain = ev["chain"]
    iocs = ev["iocs"]
    mitre = ev["mitre"]
    lolbins = ev["lolbins"]
    decoded = ev["decoded_output"]
    d_low = decoded.lower()

    if chain:
        findings.append(Finding(
            title=f"Multi-stage decode: {' → '.join(chain[:6])}",
            description=(f"Deterministic engine peeled {len(chain)} layer(s) of "
                         f"obfuscation ({', '.join(chain[:8])}). Chain depth "
                         "indicates deliberate evasion rather than casual encoding."),
            severity="high" if len(chain) >= 3 else "medium",
            confidence=0.85 if len(chain) >= 3 else 0.65,
            evidence_refs=[EvidenceRef("chain", op) for op in chain[:3]],
            tags=["behavioral", "obfuscation"],
        ))

    dl_indicators = [k for k in ("downloadstring", "downloadfile", "iwr",
                                  "invoke-webrequest", "wget", "curl",
                                  "certutil", "bitsadmin", "start-bitstransfer")
                     if k in d_low]
    if dl_indicators:
        findings.append(Finding(
            title="Second-stage download indicator",
            description=(f"Payload calls {', '.join(dl_indicators[:3])} — "
                         "consistent with a stager fetching the true "
                         "second-stage from an external host."),
            severity="high",
            confidence=0.8,
            evidence_refs=[EvidenceRef("decoded_text", k) for k in dl_indicators[:2]],
            tags=["behavioral", "stager"],
        ))

    exec_indicators = [k for k in ("iex", "invoke-expression", "invoke-command",
                                    "-encodedcommand", "-enc ", "assembly.load",
                                    "system.reflection.assembly", "eval(")
                       if k in d_low]
    if exec_indicators:
        findings.append(Finding(
            title="In-memory execution primitive",
            description=(f"Detected {', '.join(exec_indicators[:3])} — payload "
                         "executes without dropping to disk, defeating naive "
                         "AV file scanners."),
            severity="high",
            confidence=0.82,
            evidence_refs=[EvidenceRef("decoded_text", k) for k in exec_indicators[:2]],
            tags=["behavioral", "in-memory"],
        ))

    if iocs:
        top_iocs = iocs[:3]
        findings.append(Finding(
            title=f"{len(iocs)} network IOC(s) recovered",
            description=("Extracted network indicators from the decoded payload. "
                         f"Pivot candidates: {', '.join(top_iocs)}. "
                         "Cross-reference in your TIP before enrichment."),
            severity="medium",
            confidence=0.7,
            evidence_refs=[EvidenceRef("ioc", v) for v in top_iocs],
            tags=["ioc", "pivot"],
        ))

    if mitre:
        top_mitre = mitre[:3]
        findings.append(Finding(
            title=f"MITRE ATT&CK coverage · {len(mitre)} technique(s)",
            description=("Mapped techniques: "
                         + ", ".join(f"{m['id']} {m['technique']}".strip() for m in top_mitre)),
            severity="medium",
            confidence=0.75,
            evidence_refs=[EvidenceRef("mitre", m["id"]) for m in top_mitre],
            tags=["mitre", "attribution"],
        ))

    if lolbins:
        top_lolbins = lolbins[:3]
        findings.append(Finding(
            title=f"{len(lolbins)} LOLBin invocation(s)",
            description=("Living-off-the-land binary abuse: "
                         + ", ".join(l["name"] for l in top_lolbins)
                         + ". Signed OS tooling used to blend with legitimate admin activity."),
            severity="high",
            confidence=0.8,
            evidence_refs=[EvidenceRef("lolbin", l["name"]) for l in top_lolbins],
            tags=["lolbas", "defense-evasion"],
        ))

    if not findings:
        findings.append(Finding(
            title="No malicious primitives observed",
            description=("Decoded output contains no known execution, download, "
                         "IOC, or LOLBin signatures. Payload may be benign or "
                         "use unfamiliar tradecraft."),
            severity="info", confidence=0.3,
            evidence_refs=[EvidenceRef("decoded_text", decoded[:120] or "empty")],
            tags=["benign-candidate"],
        )) if decoded else None

    summary = (f"Deterministic malware review: chain depth {len(chain)}, "
               f"{len(iocs)} IOC(s), {len(mitre)} MITRE technique(s), "
               f"{len(lolbins)} LOLBin(s). Confidence based on artefact density.")
    return ReviewerReport(reviewer="malware_analyst",
                          findings=findings, summary=summary,
                          provider="static-fallback")


def _fallback_red_team(ev: Dict[str, Any]) -> ReviewerReport:
    findings: List[Finding] = []
    chain = ev["chain"]
    lolbins = ev["lolbins"]
    decoded_low = (ev["decoded_output"] or "").lower()
    inp_low = (ev["input"] or "").lower()

    evasion_hits: List[Tuple[str, str]] = []
    if any(op in ("base64-decode", "utf16le-decode", "gzip-decode",
                   "zlib-decode", "hex-decode") for op in chain):
        evasion_hits.append(("chain", chain[0]))
    if "-enc " in inp_low or "-encodedcommand" in inp_low:
        evasion_hits.append(("decoded_text", "-encodedcommand"))
    if "-nop" in inp_low or "-noprofile" in inp_low:
        evasion_hits.append(("decoded_text", "-nop"))
    if "-w hidden" in inp_low or "-windowstyle hidden" in inp_low:
        evasion_hits.append(("decoded_text", "-w hidden"))

    if evasion_hits:
        refs = [EvidenceRef(t, v) for t, v in evasion_hits if
                (t == "chain" and v in ev["chain"]) or
                (t == "decoded_text" and v in decoded_low or v in inp_low)]
        # Fall back to a chain-only ref if none matched
        if not refs and chain:
            refs = [EvidenceRef("chain", chain[0])]
        if refs:
            findings.append(Finding(
                title="Layered command obfuscation",
                description=("Operator stacked encoding + flag-based evasion "
                             "(hidden window, no profile, encoded command) — "
                             "standard offensive playbook for defender-blind "
                             "one-liners."),
                severity="high", confidence=0.78,
                evidence_refs=refs, tags=["evasion", "obfuscation"],
            ))

    if lolbins:
        for lb in lolbins[:2]:
            findings.append(Finding(
                title=f"LOLBin abuse · {lb['name']}",
                description=(f"{lb['name']} is a Microsoft-signed binary; "
                             "invoking it lets the operator inherit trust from "
                             "the signature chain and evade user-space AV."),
                severity="high", confidence=0.82,
                evidence_refs=[EvidenceRef("lolbin", lb["name"])],
                tags=["lolbas", "trusted-binary"],
            ))

    if any(x in decoded_low for x in ("downloadstring", "iwr", "invoke-webrequest",
                                       "wget", "curl")):
        findings.append(Finding(
            title="Fileless download cradle",
            description=("Cradle fetches the true payload directly into memory "
                         "and pipes into IEX — no dropper touches disk, "
                         "defeats file-hash blocklists."),
            severity="high", confidence=0.8,
            evidence_refs=[EvidenceRef("decoded_text", "downloadstring")]
            if "downloadstring" in decoded_low else
            [EvidenceRef("decoded_text", "iwr")],
            tags=["staging", "cradle"],
        ))

    techniques = []
    if evasion_hits:
        techniques.append("Obfuscated encoded PowerShell one-liner")
    if lolbins:
        techniques.append(f"LOLBin abuse ({lolbins[0]['name']})")
    if "iex" in decoded_low:
        techniques.append("In-memory IEX cradle")

    if not findings and chain:
        findings.append(Finding(
            title="Minimal-visibility decode chain",
            description=("Payload used " + " → ".join(chain[:3]) +
                         " to stay under signature-based detection."),
            severity="medium", confidence=0.55,
            evidence_refs=[EvidenceRef("chain", chain[0])],
            tags=["evasion"],
        ))

    summary = (f"Red team perspective: {len(evasion_hits)} evasion signal(s), "
               f"{len(lolbins)} LOLBin(s), tradecraft rating: "
               f"{'advanced' if len(lolbins) >= 2 else 'commodity'}.")
    return ReviewerReport(reviewer="red_team", findings=findings,
                          summary=summary, provider="static-fallback",
                          extras={"techniques": techniques})


def _fallback_defensive(ev: Dict[str, Any]) -> ReviewerReport:
    findings: List[Finding] = []
    sigma_rules: List[Dict[str, str]] = []
    hunting: List[str] = []
    chain = ev["chain"]
    lolbins = ev["lolbins"]
    iocs = ev["iocs"]

    if lolbins:
        for lb in lolbins[:3]:
            name = lb["name"]
            findings.append(Finding(
                title=f"Detection idea · {name}",
                description=(f"Alert when {name} spawns from unusual parents "
                             "(word / excel / outlook / chrome) or with "
                             "network-transfer flags."),
                severity="high", confidence=0.8,
                evidence_refs=[EvidenceRef("lolbin", name)],
                tags=["sigma", "detection"],
            ))
            sigma_rules.append({
                "title": f"Suspicious {name} invocation",
                "logsource": "windows/process_creation",
                "detection": f"Image endswith '\\{name}' AND ParentImage in office_binaries",
            })
            hunting.append(f"DeviceProcessEvents | where FileName =~ '{name}' "
                            "| where InitiatingProcessFileName in ('winword.exe','excel.exe','outlook.exe')")

    if iocs:
        for ioc in iocs[:2]:
            findings.append(Finding(
                title="Network IOC block candidate",
                description=(f"Push {ioc} to perimeter (URL/IP block-list) "
                             "and hunt historical DNS + firewall logs for prior hits."),
                severity="medium", confidence=0.75,
                evidence_refs=[EvidenceRef("ioc", ioc)],
                tags=["ioc", "containment"],
            ))
        hunting.append("DnsEvents | where Name has_any (@iocs) | "
                       "summarize count() by DeviceName, Timestamp")

    if any(op in ("utf16le-decode", "base64-decode") for op in chain) and \
       any(x in (ev["input"] or "").lower() for x in ("-enc ", "-encodedcommand")):
        findings.append(Finding(
            title="Sigma: PowerShell -EncodedCommand",
            description=("Enable Microsoft-Windows-PowerShell/Operational "
                         "channel 4104 (Script Block Logging). Alert on "
                         "commandline containing -e / -en / -enc / -encodedcommand."),
            severity="high", confidence=0.85,
            evidence_refs=[EvidenceRef("chain", "base64-decode")]
            if "base64-decode" in chain else [EvidenceRef("chain", chain[0])],
            tags=["sigma", "powershell"],
        ))
        sigma_rules.append({
            "title": "PowerShell EncodedCommand",
            "logsource": "windows/process_creation",
            "detection": "CommandLine|contains: ['-encodedcommand','-enc ','-e ']",
        })
        hunting.append("SecurityEvent | where EventID == 4688 | "
                       "where CommandLine has_any('-enc ','-encodedcommand')")

    if not findings and chain:
        findings.append(Finding(
            title="Detection gap — no LOLBin, no IOC",
            description=("Payload decoded but yielded no LOLBin or network "
                         "IOC. Consider AMSI + Script-Block logging to catch "
                         "the in-memory execution."),
            severity="info", confidence=0.5,
            evidence_refs=[EvidenceRef("chain", chain[0])],
            tags=["gap"],
        ))

    summary = (f"Defensive review: {len(sigma_rules)} Sigma rule idea(s), "
               f"{len(hunting)} hunting query(ies). Recommended controls: "
               f"AMSI, Script-Block logging, LOLBin baselines, "
               f"perimeter IOC blocks.")
    return ReviewerReport(reviewer="defensive", findings=findings,
                          summary=summary, provider="static-fallback",
                          extras={"sigma_rules": sigma_rules,
                                  "hunting_queries": hunting})


# ─── LLM-backed reviewer wrapper ─────────────────────────────────────────
async def _run_reviewer(role: str, ev: Dict[str, Any],
                          fallback_fn, session_prefix: str) -> ReviewerReport:
    t0 = time.time()
    try:
        raw, provider = await _call_claude(
            _reviewer_system(role),
            _reviewer_user_prompt(role, ev),
            session_id=f"{session_prefix}-{role}",
        )
        findings = []
        for d in (raw.get("findings") or [])[:6]:
            f = _parse_finding_dict(d, ev)
            if f:
                findings.append(f)
        # If Claude answered but every finding got dropped by the guardrail,
        # graft the deterministic fallback so the analyst still gets value.
        if not findings:
            fb = fallback_fn(ev)
            fb.provider = "static-fallback (LLM findings dropped by guardrail)"
            fb.duration_ms = int((time.time() - t0) * 1000)
            return fb
        summary = str(raw.get("summary") or "").strip()[:600]
        extras: Dict[str, Any] = {}
        for key in ("techniques", "sigma_rules", "hunting_queries", "yara_rules"):
            v = raw.get(key)
            if isinstance(v, list) and v:
                # Truncate to keep response tight
                extras[key] = v[:8]
        return ReviewerReport(
            reviewer=role, findings=findings, summary=summary,
            provider=provider,
            duration_ms=int((time.time() - t0) * 1000),
            extras=extras,
        )
    except Exception as e:
        fb = fallback_fn(ev)
        fb.provider = f"static-fallback ({type(e).__name__})"
        fb.error = str(e)[:200]
        fb.duration_ms = int((time.time() - t0) * 1000)
        return fb


# ─── Synthesiser ──────────────────────────────────────────────────────────
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _finding_key(f: Finding) -> str:
    """Cheap dedup key = normalised title + top evidence ref value."""
    ev = f.evidence_refs[0].value.lower() if f.evidence_refs else ""
    return re.sub(r"[^a-z0-9]+", " ", (f.title + " " + ev).lower()).strip()


def _synthesise(reports: List[ReviewerReport],
                  ev: Dict[str, Any]) -> Dict[str, Any]:
    """Merge reviewer findings → consensus, disagreements, verdict."""
    # Collect all findings with reviewer origin
    all_findings: List[Tuple[str, Finding]] = []
    for r in reports:
        for f in r.findings:
            all_findings.append((r.reviewer, f))

    # Consensus: keys that ≥2 reviewers hit (cross-reviewer agreement)
    key_to_reviewers: Dict[str, List[str]] = {}
    key_to_finding: Dict[str, Finding] = {}
    for reviewer, f in all_findings:
        k = _finding_key(f)
        key_to_reviewers.setdefault(k, []).append(reviewer)
        # Keep the highest-confidence variant per key
        if k not in key_to_finding or f.confidence > key_to_finding[k].confidence:
            key_to_finding[k] = f

    consensus: List[Dict[str, Any]] = []
    disagreements: List[Dict[str, Any]] = []
    unique_by_reviewer: Dict[str, List[Dict[str, Any]]] = {}

    for k, revs in key_to_reviewers.items():
        f = key_to_finding[k]
        entry = {**f.to_dict(), "reviewers": sorted(set(revs))}
        if len(set(revs)) >= 2:
            consensus.append(entry)
        else:
            unique_by_reviewer.setdefault(revs[0], []).append(f.to_dict())

    # Severity disagreements: same title-key, different severity across reviewers
    sev_map: Dict[str, Dict[str, List[str]]] = {}
    for reviewer, f in all_findings:
        k = _finding_key(f)
        sev_map.setdefault(k, {}).setdefault(f.severity, []).append(reviewer)
    for k, sev_dict in sev_map.items():
        if len(sev_dict) > 1:
            disagreements.append({
                "title": key_to_finding[k].title,
                "severity_by_reviewer": sev_dict,
                "resolution": "escalate-to-highest",
                "escalated_severity": max(
                    sev_dict.keys(),
                    key=lambda s: _SEVERITY_ORDER.get(s, 0),
                ),
            })

    # Global confidence & verdict
    if all_findings:
        avg_conf = sum(f.confidence for _, f in all_findings) / len(all_findings)
    else:
        avg_conf = 0.0
    max_sev = max((f.severity for _, f in all_findings),
                  key=lambda s: _SEVERITY_ORDER.get(s, 0),
                  default="info")

    verdict_label = {
        "critical": "malicious", "high": "malicious",
        "medium": "suspicious", "low": "suspicious",
        "info": "unknown",
    }[max_sev]
    if not ev["chain"] and not ev["iocs"] and not ev["lolbins"]:
        verdict_label = "benign-candidate"

    # Consensus boost: every ≥2-reviewer finding shrinks doubt
    verdict_confidence = min(1.0, avg_conf + 0.03 * len(consensus))

    # Recommended actions (deterministic, evidence-driven)
    actions: List[str] = []
    if ev["iocs"]:
        actions.append("Push extracted IOCs to TAXII collection + perimeter blocklist")
    if ev["lolbins"]:
        actions.append("Deploy Sigma rules for observed LOLBin(s); baseline "
                        "parent-child in DeviceProcessEvents")
    if ev["chain"]:
        actions.append("Add captured payload to regression corpus with expected chain")
    actions.append("Enrich IOCs (VirusTotal / OTX / AbuseIPDB) via the Enrichment panel")

    return {
        "verdict": {
            "label": verdict_label,
            "severity": max_sev,
            "confidence": round(verdict_confidence, 3),
        },
        "consensus": consensus[:12],
        "disagreements": disagreements[:8],
        "unique_findings": unique_by_reviewer,
        "recommended_actions": actions,
        "n_findings_total": len(all_findings),
        "n_consensus": len(consensus),
        "n_reviewers_reporting": sum(1 for r in reports if r.findings),
    }


# ─── Public entry points ──────────────────────────────────────────────────
def moe_available() -> bool:
    """MoE always available — deterministic fallback works without LLM."""
    return True


async def run_panel_async(evidence: Dict[str, Any],
                            session_id: str = "moe-panel") -> Dict[str, Any]:
    """Run the 3 critics in parallel + synthesiser. Never raises."""
    ev = normalise_evidence(evidence)
    t_all = time.time()

    if os.environ.get("EMERGENT_LLM_KEY"):
        reports = await asyncio.gather(
            _run_reviewer("malware_analyst", ev, _fallback_malware_analyst, session_id),
            _run_reviewer("red_team",         ev, _fallback_red_team,         session_id),
            _run_reviewer("defensive",        ev, _fallback_defensive,        session_id),
        )
    else:
        # Zero-LLM path — evidence-driven deterministic reviewers only.
        reports = [
            _fallback_malware_analyst(ev),
            _fallback_red_team(ev),
            _fallback_defensive(ev),
        ]

    synthesis = _synthesise(list(reports), ev)
    return {
        "provider": "hybrid" if os.environ.get("EMERGENT_LLM_KEY") else "static",
        "reviewers": {r.reviewer: r.to_dict() for r in reports},
        "synthesis": synthesis,
        "evidence": ev,
        "durations_ms": {
            "total": int((time.time() - t_all) * 1000),
            **{r.reviewer: r.duration_ms for r in reports},
        },
    }


def run_panel(evidence: Dict[str, Any], session_id: str = "moe-panel") -> Dict[str, Any]:
    """Sync wrapper for tests / CLI. FastAPI paths should use the async version."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(
                    lambda: asyncio.new_event_loop().run_until_complete(
                        run_panel_async(evidence, session_id)
                    )
                )
                return fut.result(timeout=90)
    except RuntimeError:
        pass
    return asyncio.run(run_panel_async(evidence, session_id))
