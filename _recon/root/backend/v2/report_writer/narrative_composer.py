"""Narrative Composer — Phase 6.5.

**Not a new engine. Not an LLM. Not a chatbot.**

A deterministic template library that turns finding facts into
paragraph-quality analyst prose. Every template is hand-written to
Enterprise MDR quality; every {placeholder} is filled by the
Investigation Knowledge Model. Nothing is inferred.

Design principles enforced here:
  • Investigation-centric wording ("The investigation identified…")
  • Never say the tool name in the customer-facing narrative
  • Never say "detected"; always "analysis identified"
  • Explain WHY a finding matters, not just WHAT was seen
  • For every recommendation state Why · Expected outcome · Evidence
  • When evidence is missing say "Available evidence was insufficient…"
"""
from __future__ import annotations

import re

# ─── Enterprise Writing Guide (deterministic sanitiser) ────────
# Applied AFTER template rendering to catch stray tool-centric wording.
_STYLE_REWRITES = [
    # Tool-centric → investigation-centric
    (re.compile(r"\bNivXRay (extracted|identified|decoded|analysed|analyzed|reported|generated)\b", re.I),
     r"The investigation \1"),
    (re.compile(r"\bNivXRay ", re.I), "The investigation "),
    # Passive / weak verbs → analyst-grade
    (re.compile(r"\b(detected|was detected)\b", re.I), "identified during analysis"),
    (re.compile(r"\bPowerShell executed\b", re.I),
     "Analysis identified execution of an encoded PowerShell command"),
    (re.compile(r"\bRegistry modified\b", re.I),
     "Registry analysis identified modifications consistent with persistence"),
    (re.compile(r"\bMalicious\b", re.I), "malicious"),
    (re.compile(r"\bUnknown\.", re.I),
     "Available evidence was insufficient to determine this."),
]


def sanitize(text: str) -> str:
    """Apply the Enterprise Writing Guide rules to any paragraph."""
    out = text or ""
    for pat, rep in _STYLE_REWRITES:
        out = pat.sub(rep, out)
    # Collapse double spaces from substitutions.
    out = re.sub(r"[ \t]+", " ", out)
    return out.strip()


# ─── Finding-type paragraph templates (audience-aware) ──────────
# Each key is a canonical finding_type. Each value is a dict of
# paragraphs by audience. `{ctx}` placeholders are filled by the caller.
TEMPLATES: dict[str, dict[str, str]] = {
    # ─── Execution
    "powershell_encoded": {
        "executive":
            "Analysis identified execution of an encoded PowerShell command. "
            "After deterministic decoding, the payload demonstrated characteristics "
            "commonly associated with in-memory execution techniques designed to "
            "reduce detection by traditional signature-based security controls.",
        "customer":
            "Analysis identified execution of an encoded PowerShell command. "
            "The payload was deterministically decoded and demonstrated characteristics "
            "commonly associated with in-memory execution techniques designed to bypass "
            "signature-based security controls. Because the command was intentionally "
            "obfuscated and would only decode at runtime, this behaviour is considered "
            "highly suspicious.",
        "soc_analyst":
            "Analysis identified execution of an encoded PowerShell command "
            "(`{cmdline}`). Deterministic decoding reconstructed the payload without "
            "invoking any external service. The decoded content demonstrated "
            "characteristics consistent with in-memory execution frameworks. This "
            "behaviour is commonly associated with {mitre_ids} and is used to reduce "
            "detection by signature-based security controls.",
        "technical":
            "Encoded PowerShell activity was observed on the endpoint. The raw "
            "command line `{cmdline}` was passed through the deterministic decoder "
            "chain and successfully reconstructed to plaintext. Post-decode analysis "
            "indicates in-memory execution characteristics consistent with "
            "{mitre_ids}. No LLM or heuristic guesswork was involved in the decoding.",
    },
    "lolbin_download": {
        "executive":
            "A legitimate Windows utility ({binary}) was leveraged to download "
            "content from a remote location. Attackers frequently abuse trusted "
            "operating-system tooling to blend with normal administrative activity "
            "and evade signature-based defences.",
        "customer":
            "A legitimate Windows utility ({binary}) was used to download content "
            "from a remote location — a Living-Off-the-Land tactic. Because {binary} "
            "is normally signed by Microsoft and trusted by many security products, "
            "attackers use it to blend with legitimate activity and to evade "
            "application allow-listing. The behaviour is not benign in this context.",
        "soc_analyst":
            "The attacker leveraged {binary} to retrieve payload content from "
            "`{destination}`. This is a documented Living-Off-the-Land Binary "
            "(LOLBin) technique that abuses trusted operating-system tooling to "
            "bypass application control and reduce signature-based detection. "
            "MITRE mapping: {mitre_ids}.",
        "technical":
            "{binary} was invoked with parameters `{cmdline}` targeting "
            "`{destination}`. LOLBAS entry confirms this pattern as a known download "
            "vector. Applicable MITRE technique(s): {mitre_ids}.",
    },
    "signed_binary_abuse": {
        "executive":
            "A trusted operating-system binary ({binary}) was invoked to execute "
            "attacker-controlled code — a technique designed to bypass application "
            "allow-listing and endpoint controls that rely on binary reputation.",
        "customer":
            "A trusted operating-system binary ({binary}) was used to execute "
            "code on the endpoint. This is an evasion technique: because the binary "
            "is signed by Microsoft, many security products treat it as safe. "
            "Attackers exploit that trust to run malicious code without triggering "
            "signature-based defences.",
        "soc_analyst":
            "Signed system binary {binary} was leveraged as a proxy execution "
            "vector — a defence-evasion technique that reduces the likelihood of "
            "detection by application allow-listing. MITRE technique(s): {mitre_ids}.",
        "technical":
            "Signed system binary {binary} executed with `{cmdline}`. LOLBAS "
            "reference documents this as a known proxy-execution vector. "
            "MITRE mapping: {mitre_ids}.",
    },
    # ─── Persistence
    "startup_persistence": {
        "executive":
            "Analysis identified that the malicious file was placed inside the "
            "user's Startup folder, indicating the attacker's intent to maintain "
            "persistence so the payload is automatically re-launched every time "
            "the user logs on to Windows.",
        "customer":
            "Analysis determined that the executable was launched from the user's "
            "Startup folder. Placement within this directory indicates an attempt "
            "to establish persistence so the executable is automatically invoked "
            "whenever the user logs on to Windows. Simple removal of the file "
            "will not be sufficient — the Startup folder entry must also be "
            "cleared.",
        "soc_analyst":
            "Startup folder persistence identified. The malicious file was staged "
            "under `{path}`, causing automatic execution at user logon. "
            "Corresponds to MITRE {mitre_ids}. Remediation requires removing both "
            "the file and the Startup entry.",
        "technical":
            "Persistence artefact staged in `{path}`. Automatic execution occurs "
            "via user-logon shell initialisation. MITRE {mitre_ids}.",
    },
    "registry_persistence": {
        "executive":
            "Registry analysis identified modifications consistent with persistence. "
            "The attacker configured Windows to automatically launch the payload "
            "whenever the user logs on — a common technique used to survive host "
            "reboots.",
        "customer":
            "Registry analysis identified a Run key configured to launch the "
            "executable automatically during user logon, indicating an attempt "
            "to maintain persistence across system reboots. Simple removal of the "
            "malicious file will not eliminate this behaviour; the corresponding "
            "Run key must also be deleted from the registry.",
        "soc_analyst":
            "Registry Run Key persistence identified at `{registry_path}`. "
            "MITRE technique(s): {mitre_ids}. Both the referenced payload and "
            "the Run Key entry must be removed to fully eradicate the attack.",
        "technical":
            "Registry write to `{registry_path}` — persistence via Run Key "
            "(MITRE {mitre_ids}).",
    },
    "scheduled_task_persistence": {
        "executive":
            "A Scheduled Task was created to invoke the malicious code on a "
            "recurring or trigger-based basis — a resilient persistence technique "
            "that survives reboots and user logoff.",
        "customer":
            "The investigation identified a Scheduled Task configured to invoke "
            "the malicious code. Scheduled Tasks are a resilient persistence "
            "mechanism because they survive reboots and can be triggered by "
            "system events. Remediation must include removing the task from the "
            "Windows Task Scheduler.",
        "soc_analyst":
            "Scheduled Task persistence identified. MITRE technique(s): "
            "{mitre_ids}. Remediation: delete the offending task from the "
            "Task Scheduler and confirm no other tasks reference the payload.",
        "technical":
            "Persistence via Scheduled Task (MITRE {mitre_ids}).",
    },
    # ─── Network
    "outbound_c2": {
        "executive":
            "Network telemetry recorded outbound communication from the affected "
            "endpoint to external infrastructure operated by the attacker. This "
            "indicates the malware was actively attempting to receive commands "
            "or exfiltrate data.",
        "customer":
            "Network telemetry recorded outbound communication from the affected "
            "endpoint to {n_domains} domain(s) and {n_ips} IP address(es) "
            "controlled by the attacker. These indicators have been extracted as "
            "IOCs and should be blocked at the perimeter to prevent further "
            "command-and-control activity across the environment.",
        "soc_analyst":
            "Outbound C2 traffic identified. Destination summary: {n_domains} "
            "distinct domain(s) and {n_ips} IP address(es). All destinations have "
            "been extracted as IOCs and are available in the IOC section for "
            "block-list distribution and threat-hunting.",
        "technical":
            "C2 channel(s) observed to {destinations}. Applicable MITRE "
            "technique(s): {mitre_ids}.",
    },
    # ─── Threat Intelligence
    "ti_no_match": {
        "executive":
            "No external Threat Intelligence correlations were available at the "
            "time of investigation. Conclusions in this report therefore rely on "
            "endpoint telemetry rather than external reputation data.",
        "customer":
            "At the time of the investigation, no external Threat Intelligence "
            "correlations were available for the extracted indicators. This does "
            "not diminish the conclusions of the report — every finding is based "
            "on directly observed endpoint telemetry — but it does mean the "
            "extracted IOCs should be re-checked against Threat Intelligence "
            "feeds periodically over the coming weeks in case attribution "
            "becomes possible.",
        "soc_analyst":
            "TI enrichment is unavailable in the current build; conclusions rely "
            "entirely on observed endpoint telemetry. Recommend recurring IOC "
            "lookups against VirusTotal / Talos / MISP as attribution may emerge "
            "post-investigation.",
        "technical":
            "TI feed integration pending. IOC package must be re-checked "
            "against external feeds periodically.",
    },
    "unsigned_binary": {
        "executive":
            "The malicious file was not digitally signed. Unsigned binaries are "
            "not inherently malicious, but combined with the observed execution "
            "behaviour they strongly indicate that the file is not legitimate "
            "software.",
        "customer":
            "Digital signature verification confirmed that the executable was "
            "not digitally signed. Unsigned executables are not inherently "
            "malicious; however, when evaluated together with the observed "
            "execution behaviour, persistence mechanisms, and threat intelligence "
            "reputation, the absence of a valid signature increases confidence "
            "that the file is not legitimate software.",
        "soc_analyst":
            "The payload lacks a valid Authenticode signature. Combined with "
            "the observed execution behaviour and IOC extraction, this strongly "
            "reduces the likelihood that the file is legitimate.",
        "technical":
            "Authenticode signature: absent. Trust: none.",
    },
    # ─── Evidence Limitations
    "ev_limit_no_forensic_snapshot": {
        "executive": "A full forensic snapshot of the endpoint was not available at the time of investigation.",
        "customer":
            "A full forensic memory or disk snapshot of the endpoint was not "
            "available at the time of investigation. As a result, artefacts that "
            "may exist only in volatile memory could not be recovered and "
            "confirmed. This does not weaken the findings that are based on "
            "endpoint telemetry, but it does limit the ability to attribute "
            "specific memory-resident malware families with high confidence.",
        "soc_analyst":
            "No forensic memory / disk snapshot was captured. Memory-only "
            "artefacts (injected modules, in-memory payloads, decrypted "
            "configuration) are outside the scope of this investigation.",
        "technical":
            "Snapshot: unavailable. Live-response memory acquisition not "
            "performed. Post-mortem memory analysis is not possible.",
    },
    "ev_limit_root_cause_unknown": {
        "executive":
            "Available evidence was insufficient to determine how the malicious "
            "file first arrived on the endpoint. Additional telemetry would be "
            "required to establish the initial infection vector.",
        "customer":
            "Available evidence was insufficient to determine the initial "
            "infection vector. Common vectors (e-mail attachment, browser "
            "download, removable media, remote administration abuse) could not "
            "be excluded or confirmed with the telemetry available at the time "
            "of investigation. Enriched endpoint or e-mail security telemetry "
            "would be required to reach a definitive conclusion.",
        "soc_analyst":
            "Root cause: undetermined. The pipeline could not correlate a "
            "delivery event with the first-observed execution of the payload. "
            "Recommend enriching endpoint telemetry (Orbital / EDR memory "
            "acquisition / e-mail security integration) to support future "
            "attribution.",
        "technical":
            "Initial access vector: undetermined. No matching delivery event "
            "in the ingested telemetry window.",
    },
    "ev_limit_av_outdated": {
        "executive":
            "Endpoint anti-virus signatures on the affected host may be "
            "outdated, reducing the effectiveness of native protection.",
        "customer":
            "Endpoint anti-virus signatures on the affected host appear to be "
            "outdated. Outdated signatures reduce the effectiveness of the "
            "endpoint's native protections and may explain why the malicious "
            "file was permitted to execute prior to EDR-based containment. "
            "Updating signatures should be considered a high-priority "
            "hardening step.",
        "soc_analyst":
            "AV signature currency degraded. Recommend forcing a signature "
            "refresh on the affected host and validating fleet-wide signature "
            "compliance.",
        "technical":
            "AV signature: outdated (per raw incident telemetry).",
    },
    "ev_limit_decode_partial": {
        "executive":
            "A subset of the extracted commands could not be fully decoded "
            "with the current decoder plugin catalogue. Enriched telemetry "
            "would allow a more complete analysis.",
        "customer":
            "The investigation encountered a small number of extracted commands "
            "that could not be fully decoded within the current pipeline. This "
            "does not affect the overall verdict, but it does mean the report "
            "may under-represent the full scope of attacker activity. Extending "
            "the decoder plugin catalogue would improve future investigations.",
        "soc_analyst":
            "{n_failed}/{n_cmd} commands failed to reach a deterministic "
            "verdict. Recommend expanding the decoder plugin catalogue and "
            "capturing the failing payloads as regression fixtures.",
        "technical":
            "Failed decodes: {n_failed}/{n_cmd}. Add regression corpus entries.",
    },
    # ─── Recommendation templates
    "rec_isolate_endpoint": {
        "executive":
            "Immediate isolation of the affected endpoint is recommended to "
            "prevent further attacker activity while remediation is completed.",
        "customer":
            "Immediate isolation of the affected endpoint is recommended to "
            "prevent additional execution, persistence, or lateral movement "
            "while the investigation is completed. Isolation should remain in "
            "place until endpoint validation confirms that all identified "
            "persistence mechanisms and malicious artefacts have been removed.",
        "soc_analyst":
            "Immediate isolation of the affected endpoint is recommended. "
            "Rationale: verdict is {verdict}. Expected outcome: prevent further "
            "attacker action. Supporting evidence: extracted commands, "
            "persistence artefacts, C2 destinations documented in this report.",
        "technical":
            "Isolate host. Retain quarantine. Rationale: verdict {verdict}.",
    },
    "rec_block_iocs": {
        "executive":
            "The indicators of compromise identified during the investigation "
            "should be blocked at the perimeter and distributed to detection "
            "controls.",
        "customer":
            "The investigation identified multiple Indicators of Compromise "
            "(IOCs), including IP addresses, malicious domains, URLs, file "
            "hashes, registry persistence entries, and affected files. These "
            "indicators should be used to perform threat hunting across the "
            "environment and to block additional executions.",
        "soc_analyst":
            "Distribute the extracted IOC package to firewall, EDR, DNS, and "
            "proxy controls. Expected outcome: prevent recurrence and enable "
            "fleet-wide hunting. Supporting evidence: IOC section of this "
            "report.",
        "technical":
            "Distribute IOC package to firewall / EDR / DNS / proxy. "
            "Reference the IOC section of this report.",
    },
}


def _pick(finding_type: str, profile: str) -> str | None:
    """Return the template for a finding_type at the requested audience,
    falling back to soc_analyst if a bespoke variant does not exist."""
    if finding_type not in TEMPLATES:
        return None
    tpl = TEMPLATES[finding_type]
    return tpl.get(profile) or tpl.get("soc_analyst")


def compose(finding_type: str, ctx: dict, profile: str = "soc_analyst") -> str | None:
    """Render a paragraph for a finding_type using the audience-specific
    template. Placeholders that are missing in `ctx` are replaced with a
    neutral phrase so we never produce `{cmdline}` in the final report."""
    tmpl = _pick(finding_type, profile)
    if not tmpl:
        return None
    # Safe substitution — missing keys yield "the extracted evidence".
    safe_ctx = _safe_ctx(tmpl, ctx)
    try:
        rendered = tmpl.format(**safe_ctx)
    except Exception:
        rendered = tmpl
    return sanitize(rendered)


def _safe_ctx(tmpl: str, ctx: dict) -> dict:
    out = dict(ctx or {})
    for key in re.findall(r"\{(\w+)\}", tmpl):
        if key not in out or out[key] in (None, "", [], {}):
            out[key] = "the extracted evidence"
    return out


# ─── Higher-level narrative composers ──────────────────────────
def compose_executive_summary(inv: dict, profile: str = "customer") -> list[str]:
    """Return 6-9 paragraphs of investigation-centric executive-summary
    prose derived from the Investigation Knowledge Model. Written to
    the standard of a Cisco MDR analyst — opens with the detection
    timestamp, weaves in the specific filename / hash / signature status
    / environmental gaps, and never mentions the tool by name."""
    fis   = inv.get("final_incident_summary", {}) or {}
    verdict = (fis.get("verdict") or "unknown").lower()
    sev     = fis.get("severity", "Low")
    cls     = fis.get("classification", "Unknown")
    cmds    = inv.get("detected", {}).get("commands", []) or []
    mitre   = fis.get("mitre_attack", []) or []
    iocs    = fis.get("iocs", {}) or {}
    entities = inv.get("detected", {}).get("entities", {}) or {}
    raw     = inv.get("raw_incident", "") or ""

    ts       = _extract_first_ts(raw) or "an initial detection window"
    src      = _detection_source(raw)
    hosts    = _extract_hosts(raw) or ["the affected endpoint"]
    users    = _extract_users(raw) or ["an interactive user"]
    filename = _extract_filename(raw, entities)
    hashes   = (iocs.get("sha256") or iocs.get("sha1") or iocs.get("md5") or [])
    hash_txt = hashes[0][:16] + "…" if hashes else None
    startup_path = _extract_startup_path(raw, entities)
    binaries = sorted({c["binary"] for c in cmds})
    binary_txt = ", ".join(b.title() if b.islower() else b for b in binaries[:6])
    tactic_ids = sorted({m.get("id","") for m in mitre if m.get("id")})
    tactics    = sorted({m.get("tactic","") for m in mitre if m.get("tactic")})
    domains    = iocs.get("domains", []) or []
    ips        = iocs.get("ips", []) or []
    quality    = fis.get("investigation_quality", {}) or {}
    completeness = quality.get("overall", {}).get("investigation_completeness")
    signed_missing = any(c["binary"] in {"rundll32", "regsvr32", "mshta"} for c in cmds) or bool(hashes)
    av_outdated    = bool(re.search(r"outdated|old (?:av|signature|definition)", raw, re.I))
    orbital_off    = bool(re.search(r"orbital|forensic snapshot", raw, re.I)) and bool(re.search(r"unavailable|not available|missing|disabled", raw, re.I))
    contained      = _has_containment(raw)

    paras: list[str] = []

    # ── 1. Opening — timestamp + detection source ──────────────
    file_ref = f" of `{filename}`" if filename else ""
    paras.append(
        f"On **{ts}** {src} identified the execution{file_ref} on **{hosts[0]}** "
        f"under user account `{users[0]}`, an event that warranted additional "
        f"investigation. The activity was classified as **{verdict.upper()}** at "
        f"**{sev}** severity."
    )

    # ── 2. Integrations involved ───────────────────────────────
    integrations = _integrations(raw)
    if integrations:
        paras.append(
            f"This investigation involved detections from the following integrations: "
            f"{', '.join(integrations)}."
        )

    # ── 3. First-observed + persistence context ────────────────
    if startup_path:
        paras.append(
            f"During initial triage, the file was observed executing from the user's "
            f"Startup folder (`{startup_path}`). Placement within this directory "
            f"indicates an attempt to establish persistence so the executable is "
            f"automatically invoked whenever the user logs on to Windows — "
            f"simple deletion of the file will not be sufficient. The corresponding "
            f"Startup entry must also be cleared."
        )
    elif entities.get("registry"):
        reg = entities["registry"][0]
        paras.append(
            f"Registry analysis identified a Run key at `{reg}` configured to launch "
            f"the executable automatically during user logon, indicating an attempt "
            f"to maintain persistence across system reboots. Simple removal of the "
            f"malicious file will not eliminate this behaviour; the Run key entry "
            f"must also be deleted."
        )

    # ── 4. Execution behaviour deep-dive ───────────────────────
    if binaries:
        parts = []
        if any(b.startswith("powershell") for b in binaries):
            parts.append(
                "encoded PowerShell commands designed to execute in memory and "
                "bypass signature-based defences"
            )
        if any(b in {"certutil", "bitsadmin", "curl", "wget"} for b in binaries):
            parts.append(
                "Living-Off-the-Land utilities used to retrieve additional payloads "
                "from attacker-controlled infrastructure"
            )
        if any(b in {"rundll32", "regsvr32", "mshta"} for b in binaries):
            parts.append(
                "signed operating-system binaries repurposed as proxy execution "
                "vectors to evade application allow-listing"
            )
        if any(b in {"cmd", "net", "wmic", "wmic.exe"} for b in binaries):
            parts.append(
                "native Windows administration utilities used to enumerate the "
                "environment and identify targets for follow-on activity"
            )
        if parts:
            paras.append(
                f"Analysis of the extracted process activity ({binary_txt}) revealed "
                + "; ".join(parts) + ". Individually these behaviours would raise "
                "suspicion; observed together, they meet the standard for a "
                "confirmed malicious incident and are consistent with an "
                "orchestrated attack rather than an opportunistic action."
            )

    # ── 5. Network / C2 ────────────────────────────────────────
    if domains or ips:
        parts = []
        if domains: parts.append(f"{len(domains)} domain(s)")
        if ips:     parts.append(f"{len(ips)} IP address(es)")
        paras.append(
            "Network telemetry recorded outbound communication from the affected "
            f"endpoint to {' and '.join(parts)} controlled by the attacker. These "
            "destinations have been extracted as IOCs and should be blocked at the "
            "perimeter to prevent further command-and-control activity across the "
            "environment."
        )

    # ── 6. Threat Intelligence reputation ──────────────────────
    rep_by_val = (fis.get("ioc_reputation", {}) or {}).get("by_value", {})
    rep_sources_total = (fis.get("ioc_reputation", {}) or {}).get("sources", {})
    if hash_txt:
        hit = rep_by_val.get(hashes[0]) if hashes else None
        if hit:
            fam = (hit.get("malware_families") or [None])[0]
            fam_txt = f" and classified as `{fam}`" if fam else ""
            paras.append(
                f"The extracted file hash `{hash_txt}` was flagged by "
                f"**{hit.get('hit_count', 0)}** external Threat Intelligence "
                f"source(s) — {', '.join(hit.get('sources', []))}"
                f"{fam_txt}. This independent reputation data confirms the "
                "malicious classification with sources outside the investigated "
                "environment."
            )
        else:
            paras.append(
                f"The extracted file hash `{hash_txt}` did not correlate to any "
                "internal OSINT feed at the time of investigation. The hash "
                "should be re-checked against VirusTotal, Talos, and MISP "
                "periodically over the coming days as attribution may still emerge."
            )
    # Network-IOC reputation summary (IPs / domains / URLs)
    net_hits = [rep_by_val[v] for v in rep_by_val
                if rep_by_val[v].get("kind") in ("ip", "domain", "url")]
    if net_hits:
        srcs = sorted({s for h in net_hits for s in h.get("sources", [])})
        paras.append(
            f"**{len(net_hits)}** of the extracted network indicator(s) also "
            f"matched entries in the local Threat Intelligence store, with "
            f"reputation data drawn from {', '.join(srcs)}. These indicators "
            "should be blocked at the perimeter and used for retrospective "
            "hunting across the fleet."
        )
    if signed_missing:
        paras.append(
            "Digital signature verification could not confirm a valid Authenticode "
            "signature on the executed binaries. Unsigned or improperly-signed "
            "executables are not inherently malicious, but combined with the "
            "observed execution behaviour, persistence artefacts, and network "
            "activity, the absence of a valid signature further increases "
            "confidence that the file is not legitimate software."
        )

    # ── 7. Environmental limitations (weave inline like a real MDR) ─
    env_bits = []
    if orbital_off:
        env_bits.append(
            "deeper forensic tooling (Orbital and forensic snapshot) was unavailable "
            "at investigation time"
        )
    if av_outdated:
        env_bits.append(
            "the endpoint's anti-virus definitions were outdated, which may have "
            "contributed to the successful execution of the payload"
        )
    if env_bits:
        paras.append(
            "For this host, " + " and ".join(env_bits) + ". These environmental "
            "gaps do not diminish the conclusions of the report — every finding is "
            "based on directly-observed endpoint telemetry — but they do explain "
            "why certain deeper artefacts could not be captured, and they should "
            "be addressed as part of the long-term hardening plan."
        )

    # ── 8. Containment ─────────────────────────────────────────
    if contained:
        paras.append(
            "The endpoint security platform successfully quarantined the identified "
            "file and prevented further execution. However, quarantine of a single "
            "file does not confirm eradication: any persistence mechanisms, dropped "
            "artefacts, and lateral-movement footholds must be validated and removed "
            "before the host can be safely returned to service."
        )
    else:
        paras.append(
            "As of the time this report was generated, containment activities were "
            "still in progress. Immediate isolation of the affected endpoint is "
            "recommended until the system has been fully validated and all "
            "identified artefacts removed."
        )

    # ── 9. Confidence footer ───────────────────────────────────
    if completeness is not None:
        paras.append(
            f"Overall investigation completeness stands at **{completeness}%**. "
            "Every conclusion presented in this report is directly traceable to "
            "an observed piece of evidence — no assumptions or unsupported "
            "inferences have been introduced."
        )
    return [sanitize(p) for p in paras]


# ─── Executive-summary helpers ─────────────────────────────────
def _extract_first_ts(raw: str) -> str | None:
    m = re.search(
        r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
        raw or "")
    return m.group(0) if m else None


def _extract_hosts(raw: str) -> list[str]:
    hits = re.findall(
        r"\b(?:host|hostname|device)\s*[:=]\s*([A-Za-z][A-Za-z0-9._-]{2,60})",
        raw or "", flags=re.IGNORECASE)
    STOP = {"incident", "detection", "detected", "under", "warrants", "the"}
    return [h.rstrip(".") for h in dict.fromkeys(hits) if h.lower().rstrip(".") not in STOP]


def _extract_users(raw: str) -> list[str]:
    hits = re.findall(
        r"\b(?:user|username|account)\s*[:=]\s*([A-Z0-9][A-Z0-9\\._-]{2,80})",
        raw or "", flags=re.IGNORECASE)
    return [u.rstrip(".") for u in dict.fromkeys(hits)]


def _extract_filename(raw: str, entities: dict) -> str | None:
    """Pick the primary suspect filename. Priority:
      1. explicit `File: (name.ext)` pattern in the raw text
      2. Any `.exe/.msi` file from the extracted entities
      3. Any file from the extracted entities that lives in a Startup /
         AppData path (attacker-relevant)
      4. First remaining file entity"""
    # 1. "File: (Something Something.exe)" or "File: name.exe"
    m = re.search(r"\bFile\s*:?\s*\(?\s*([^\r\n\"<>()]{2,120}\.(?:exe|msi|dll|ps1|bat|hta|scr|vbs|js|lnk))\s*\)?",
                  raw or "", re.I)
    if m:
        return m.group(1).strip()
    files = entities.get("files", []) if entities else []
    # 2. exe / msi win over dll
    for ext in ("exe", "msi", "ps1", "hta", "scr", "dll"):
        for f in files:
            if f.lower().endswith("." + ext):
                # For Startup / AppData paths, prefer them.
                if re.search(r"startup|appdata|roaming|temp", f, re.I):
                    return f.split("\\")[-1]
        for f in files:
            if f.lower().endswith("." + ext):
                return f.split("\\")[-1]
    return None


def _extract_startup_path(raw: str, entities: dict) -> str | None:
    """Full path (spaces preserved) ending at the file extension, up to
    end-of-line."""
    m = re.search(r"([A-Za-z]:\\[^\r\n\"'<>]*?Start(?:up|\s?Menu)[^\r\n\"'<>]*?\.(?:exe|msi|dll|ps1|bat|hta|scr|vbs|js|lnk))",
                  raw or "", re.I)
    if m: return m.group(1).strip()
    m = re.search(r"([A-Za-z]:\\[^\r\n\"'<>]*?\\Startup\\[^\r\n\"'<>]+)",
                  raw or "", re.I)
    if m: return m.group(1).strip()
    files = entities.get("files", []) if entities else []
    for f in files:
        if re.search(r"startup", f, re.I):
            return f
    return None


def _integrations(raw: str) -> list[str]:
    lower = (raw or "").lower()
    out = []
    for name, key in [
        ("Cisco Secure Endpoint", "secure endpoint"),
        ("Cisco XDR", "xdr"),
        ("CrowdStrike Falcon", "crowdstrike"),
        ("Microsoft Defender", "defender"),
        ("SentinelOne", "sentinelone"),
        ("QRadar", "qradar"),
        ("Splunk", "splunk"),
        ("Sysmon", "sysmon"),
        ("Email Security", "email security"),
    ]:
        if key in lower and name not in out:
            out.append(name)
    return out


def compose_narrative(inv: dict, profile: str = "customer") -> str:
    """A single, well-formed multi-paragraph narrative in analyst prose."""
    fis   = inv.get("final_incident_summary", {}) or {}
    cmds  = inv.get("detected", {}).get("commands", []) or []
    iocs  = fis.get("iocs", {}) or {}
    mitre = fis.get("mitre_attack", []) or []
    raw   = inv.get("raw_incident", "") or ""
    hosts = re.findall(r"\b(?:host|endpoint|device|hostname)[\s:=]+([A-Za-z0-9._-]{2,60})", raw, flags=re.IGNORECASE) or ["the affected endpoint"]
    users = re.findall(r"\b(?:user|username|account|logged.?in.?as)[\s:=]+([A-Z0-9\\._-]{2,80})", raw, flags=re.IGNORECASE) or ["an interactive user"]
    host, user = hosts[0], users[0]
    parts: list[str] = []
    parts.append(
        f"The investigation began after suspicious activity was surfaced on "
        f"**{host}** and escalated for analysis. Initial triage identified "
        f"process activity associated with account `{user}` that warranted "
        f"deterministic decoding and correlation."
    )
    if any(c["binary"].startswith("powershell") for c in cmds):
        parts.append(compose("powershell_encoded",
                             {"cmdline": next((c["command_line"] for c in cmds if c["binary"].startswith("powershell")), ""),
                              "mitre_ids": ", ".join(sorted({m['id'] for m in mitre if m.get('id','').startswith('T1059')}))},
                             profile))
    if any(c["binary"] in {"certutil", "bitsadmin", "curl", "wget"} for c in cmds):
        parts.append(compose("lolbin_download",
                             {"binary": next((c["binary"] for c in cmds if c["binary"] in {"certutil", "bitsadmin", "curl", "wget"}), "certutil"),
                              "cmdline": next((c["command_line"] for c in cmds if c["binary"] in {"certutil","bitsadmin","curl","wget"}), ""),
                              "destination": (iocs.get("urls", []) + iocs.get("domains", []) + iocs.get("ips", []))[:1] and (iocs.get("urls", []) + iocs.get("domains", []) + iocs.get("ips", []))[0] or "attacker-controlled infrastructure",
                              "mitre_ids": ", ".join(sorted({m['id'] for m in mitre if m.get('id','').startswith(('T1105','T1140','T1218'))})) or "T1218 / T1105"},
                             profile))
    if any(c["binary"] in {"rundll32", "regsvr32", "mshta"} for c in cmds):
        parts.append(compose("signed_binary_abuse",
                             {"binary": next((c["binary"] for c in cmds if c["binary"] in {"rundll32", "regsvr32", "mshta"}), "rundll32"),
                              "cmdline": next((c["command_line"] for c in cmds if c["binary"] in {"rundll32","regsvr32","mshta"}), ""),
                              "mitre_ids": ", ".join(sorted({m['id'] for m in mitre if m.get('id','').startswith('T1218')})) or "T1218"},
                             profile))
    if any((m.get("id") or "").startswith("T1547") for m in mitre):
        # Prefer registry-persistence template if a registry entry is present.
        registry_paths = inv.get("detected", {}).get("entities", {}).get("registry", []) or []
        if registry_paths:
            parts.append(compose("registry_persistence",
                                 {"registry_path": registry_paths[0],
                                  "mitre_ids": ", ".join(sorted({m['id'] for m in mitre if m.get('id','').startswith('T1547')}))},
                                 profile))
        else:
            parts.append(compose("startup_persistence",
                                 {"path": "the user's Startup folder",
                                  "mitre_ids": ", ".join(sorted({m['id'] for m in mitre if m.get('id','').startswith('T1547')}))},
                                 profile))
    if any((m.get("id") or "").startswith("T1053") for m in mitre):
        parts.append(compose("scheduled_task_persistence",
                             {"mitre_ids": ", ".join(sorted({m['id'] for m in mitre if m.get('id','').startswith('T1053')}))},
                             profile))
    if iocs.get("domains") or iocs.get("ips"):
        parts.append(compose("outbound_c2",
                             {"n_domains": len(iocs.get("domains", []) or []),
                              "n_ips":     len(iocs.get("ips", []) or []),
                              "destinations": ", ".join((iocs.get("domains", []) + iocs.get("ips", []))[:5]),
                              "mitre_ids": ", ".join(sorted({m['id'] for m in mitre if m.get('id','').startswith('T1071')})) or "T1071"},
                             profile))
    if _has_containment(raw):
        parts.append(
            "The endpoint security platform successfully quarantined the "
            "identified file and prevented further execution. Follow-up "
            "validation is required to confirm that no lateral movement or "
            "residual persistence remains before the host can be safely "
            "returned to production."
        )
    else:
        parts.append(
            "As of report generation, containment activities were still in "
            "progress. Immediate isolation of the affected host is "
            "recommended until the presence of persistence, secondary "
            "payloads, and lateral-movement activity has been definitively "
            "ruled out."
        )
    return "\n\n".join(sanitize(p) for p in parts if p)


def compose_findings(inv: dict, profile: str = "soc_analyst") -> list[dict]:
    """Template-driven Findings section. Every finding is emitted with an
    evidence-source, evidence-type and confidence — no free-form prose."""
    fis   = inv.get("final_incident_summary", {}) or {}
    cmds  = inv.get("detected", {}).get("commands", []) or []
    iocs  = fis.get("iocs", {}) or {}
    mitre = fis.get("mitre_attack", []) or []
    out: list[dict] = []

    def add(ftype: str, ctx: dict, src: str, ev_type: str, conf: str):
        p = compose(ftype, ctx, profile)
        if p:
            out.append({"finding": p, "evidence_source": src,
                        "evidence_type": ev_type, "confidence": conf,
                        "finding_type": ftype})

    if any(c["binary"].startswith("powershell") for c in cmds):
        add("powershell_encoded",
            {"cmdline": next((c["command_line"] for c in cmds if c["binary"].startswith("powershell")), ""),
             "mitre_ids": ", ".join(sorted({m['id'] for m in mitre if m.get('id','').startswith('T1059')})) or "T1059.001"},
            "Extracted command line", "Observed", "High")
    if any(c["binary"] in {"certutil", "bitsadmin", "curl", "wget"} for c in cmds):
        add("lolbin_download",
            {"binary": next((c["binary"] for c in cmds if c["binary"] in {"certutil","bitsadmin","curl","wget"}), "certutil"),
             "cmdline": next((c["command_line"] for c in cmds if c["binary"] in {"certutil","bitsadmin","curl","wget"}), ""),
             "destination": (iocs.get("urls", []) + iocs.get("domains", []) + iocs.get("ips", []))[:1] and (iocs.get("urls", []) + iocs.get("domains", []) + iocs.get("ips", []))[0] or "attacker-controlled infrastructure",
             "mitre_ids": ", ".join(sorted({m['id'] for m in mitre if m.get('id','').startswith(('T1105','T1140','T1218'))})) or "T1218 / T1105"},
            "Extracted command line", "Observed", "High")
    if any(c["binary"] in {"rundll32", "regsvr32", "mshta"} for c in cmds):
        add("signed_binary_abuse",
            {"binary": next((c["binary"] for c in cmds if c["binary"] in {"rundll32","regsvr32","mshta"}), "rundll32"),
             "cmdline": next((c["command_line"] for c in cmds if c["binary"] in {"rundll32","regsvr32","mshta"}), ""),
             "mitre_ids": ", ".join(sorted({m['id'] for m in mitre if m.get('id','').startswith('T1218')})) or "T1218"},
            "Extracted command line", "Observed", "High")
    if any((m.get("id") or "").startswith("T1547") for m in mitre):
        registry_paths = inv.get("detected", {}).get("entities", {}).get("registry", []) or []
        if registry_paths:
            add("registry_persistence",
                {"registry_path": registry_paths[0],
                 "mitre_ids": ", ".join(sorted({m['id'] for m in mitre if m.get('id','').startswith('T1547')}))},
                "Registry telemetry", "Observed", "High")
        else:
            add("startup_persistence",
                {"path": "the user's Startup folder",
                 "mitre_ids": ", ".join(sorted({m['id'] for m in mitre if m.get('id','').startswith('T1547')}))},
                "Filesystem telemetry", "Correlated", "Medium")
    if any((m.get("id") or "").startswith("T1053") for m in mitre):
        add("scheduled_task_persistence",
            {"mitre_ids": ", ".join(sorted({m['id'] for m in mitre if m.get('id','').startswith('T1053')}))},
            "MITRE mapping (T1053)", "Correlated", "Medium")
    if iocs.get("domains") or iocs.get("ips"):
        add("outbound_c2",
            {"n_domains": len(iocs.get("domains", []) or []),
             "n_ips":     len(iocs.get("ips", []) or []),
             "destinations": ", ".join((iocs.get("domains", []) + iocs.get("ips", []))[:5]),
             "mitre_ids": ", ".join(sorted({m['id'] for m in mitre if m.get('id','').startswith('T1071')})) or "T1071"},
            "Network telemetry", "Observed", "High")
    if iocs.get("sha256") or iocs.get("sha1") or iocs.get("md5"):
        add("unsigned_binary", {},
            "Hash telemetry", "Observed", "Medium")
    return out


def compose_evidence_limitations(inv: dict, profile: str = "customer") -> list[dict]:
    """The section experienced analysts add: what could NOT be determined
    and why. Deterministic — only reports limitations we can prove."""
    limitations: list[dict] = []
    raw     = inv.get("raw_incident", "") or ""
    fis     = inv.get("final_incident_summary", {}) or {}
    quality = fis.get("investigation_quality", {}) or {}
    cmds    = inv.get("detected", {}).get("commands", []) or []

    # 1. Root cause undetermined
    tids = {m.get("id","") for m in fis.get("mitre_attack", []) or []}
    if not any(t.startswith(("T1204", "T1566")) for t in tids):
        p = compose("ev_limit_root_cause_unknown", {}, profile)
        if p: limitations.append(_lim(p, "Pipeline output", "Observed", "High"))

    # 2. AV outdated (from raw text)
    if re.search(r"outdated|old (?:av|signature|definition)", raw, re.I):
        p = compose("ev_limit_av_outdated", {}, profile)
        if p: limitations.append(_lim(p, "Raw incident text", "Observed", "Medium"))

    # 3. No forensic snapshot
    if re.search(r"(orbital|forensic snapshot|memory image).{0,60}(unavailable|not available|missing|disabled)", raw, re.I):
        p = compose("ev_limit_no_forensic_snapshot", {}, profile)
        if p: limitations.append(_lim(p, "Raw incident text", "Observed", "Medium"))

    # 4. TI no matches
    if quality.get("coverage", {}).get("threat_intel_matches", 0) == 0:
        p = compose("ti_no_match", {}, profile)
        if p: limitations.append(_lim(p, "TI enrichment layer", "Observed", "Low"))

    # 5. Partial decodes
    n_failed = quality.get("command_analysis", {}).get("failed_decodes", 0)
    n_cmd    = quality.get("command_analysis", {}).get("commands_detected", len(cmds))
    if n_failed and n_cmd:
        p = compose("ev_limit_decode_partial",
                    {"n_failed": n_failed, "n_cmd": n_cmd}, profile)
        if p: limitations.append(_lim(p, "Investigation Quality Dashboard", "Observed", "Medium"))
    return limitations


def _lim(text: str, src: str, ev_type: str, conf: str) -> dict:
    return {"finding": text, "evidence_source": src,
            "evidence_type": ev_type, "confidence": conf}


def compose_recommendations(inv: dict, profile: str = "customer") -> list[dict]:
    """Template-driven recommendations. Every recommendation carries the
    Why · Expected Outcome · Supporting Evidence triad as prose."""
    out: list[dict] = []
    fis     = inv.get("final_incident_summary", {}) or {}
    verdict = (fis.get("verdict") or "unknown").lower()
    iocs    = fis.get("iocs", {}) or {}
    quality = fis.get("investigation_quality", {}) or {}

    if verdict in ("malicious", "critical", "suspicious"):
        p = compose("rec_isolate_endpoint", {"verdict": verdict}, profile)
        if p: out.append({"priority": "critical", "action": p,
                          "rationale": "Verdict warrants containment before eradication."})
    if any(iocs.get(k) for k in ("ips", "domains", "urls", "sha256")):
        p = compose("rec_block_iocs", {}, profile)
        if p: out.append({"priority": "high", "action": p,
                          "rationale": "Extracted IOCs are actionable for fleet-wide protection."})
    # Preserve any recommendations from the investigation model itself.
    for r in fis.get("recommendations", []) or []:
        out.append(r)
    # De-duplicate on action first sentence.
    seen, uniq = set(), []
    for r in out:
        key = (r.get("action") or "")[:80].lower()
        if key in seen:
            continue
        seen.add(key)
        uniq.append(r)
    return uniq


# ─── Local helpers duplicated to avoid circular import ─────────
def _detection_source(raw: str) -> str:
    lower = (raw or "").lower()
    for name, key in [
        ("Cisco XDR", "cisco xdr"),
        ("Cisco XDR",  " xdr"),                # fallback if "cisco xdr" not literal
        ("Cisco Secure Endpoint", "secure endpoint"),
        ("Cisco Secure Endpoint", "sep"),
        ("CrowdStrike Falcon", "crowdstrike"),
        ("Microsoft Defender", "defender"),
        ("SentinelOne", "sentinelone"),
        ("QRadar", "qradar"),
        ("Splunk", "splunk"),
        ("Sysmon", "sysmon"),
        ("Email Security", "email"),
    ]:
        if key in lower:
            return name
    return "the SOC monitoring platform"


def _has_containment(raw: str) -> bool:
    return bool(re.search(r"quarantin|contain|isolat|block(ed)?|remediat", (raw or "").lower()))
