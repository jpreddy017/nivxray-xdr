/**
 * investigationSynthesizer.js — ADR-0013 §2.2 client-side synthesiser.
 *
 * Consumes an unmodified /api/decode/smart OR /api/v2/auto-investigate
 * response and returns a canonical presentation model:
 *
 *   {
 *     executive:      { verdict, severity, confidence, headline, primary_finding },
 *     technical:      { engine, chain_ids, layers, output, output_raw, notes },
 *     threatIntel:    { hits: [{ provider, family, subject, confidence }], hasData },
 *     osint:          { providers: [{ name, status, note }], hasData },
 *     iocs:           { grouped: { ips, urls, domains, hashes, emails, files }, total, provenance },
 *     mitre:          { techniques: [{ id, name, tactic }] },
 *     timeline:       [{ step, kind, label, detail, badge }],
 *     narrative:      { when, what, why, where, how },
 *     mitigation:     [{ severity, title, why, actions: [] }],
 *     evidence:       { explainability, decodeChains, rawOutput, unknowns },
 *     meta:           { partial, cause, truncationNote, mode }
 *   }
 *
 * Determinism invariants (ADR-0013 §2.2):
 * - No LLM anywhere.
 * - Verdict / severity / confidence read verbatim from the backend.
 * - Narrative is composed from explainability + IOCs + MITRE + chain.
 * - Mitigation prefers backend `mdr_investigation.recommendations`,
 *   otherwise falls back to the static MITRE-technique map below.
 */

// ─── ADR-0013 §2.2 · Deterministic Narrative Engine (Path B, slice-4) ────
//
// Attack-lifecycle block ordering (operator-approved 2026-02-28):
//   Detection → Execution → Payload → Network → Tradecraft →
//   Post-Execution Behaviour → Negative Findings → Malware Context →
//   Risk Assessment → Recommendations
//
// The rendered narrative should read like an analyst walking through an
// attack chain, not an attribute dump.
//
// Additional slice-4 improvements:
//   · Evidence-aware recommendations (derived from actual IOCs/LOLBins,
//     not just ATT&CK mappings).
//   · Explicit negative findings ("what was NOT observed").
//   · Confidence qualifiers — Observed / Recovered / Likely / May indicate.
//   · Facts vs interpretation — fact clause + explicit interpretation
//     clause, tied by a signal word.

// Confidence qualifier — chooses the right verb based on evidence source.
//   directly_present  → "Observed" (in decoded output)
//   from_ioc_bag      → "Recovered" (extracted IOC)
//   pattern_mapped    → "Likely" (inferred from ATT&CK match)
//   partial_or_inferred → "May indicate" (runtime-dependent / partial decode)
function qualifierFor(strength) {
  switch (strength) {
    case "observed":   return "Observed:";
    case "recovered":  return "Recovered:";
    case "likely":     return "Likely:";
    case "may_indicate": return "May indicate:";
    default:           return "";
  }
}

const NARRATIVE_BLOCKS = {
  // ── DETECTION (opening) — what the analyst is looking at ─────────────
  opening: (ev) => {
    const when = ev.whenPhrase ? `On ${ev.whenPhrase}` : "During this investigation";
    const artifact = ev.artifactPhrase;
    if (ev.partial) {
      return `${when}, NivXRay analyzed ${artifact} that decoded partially before the byte stream became unreadable. Because recovery is incomplete, all downstream findings carry a partial_recovery provenance and should be treated as best-effort.`;
    }
    if (ev.observedBehavior) {
      return `${when}, NivXRay analyzed ${artifact} that decoded into a command which ${ev.observedBehavior}.`;
    }
    if (ev.detectedTypeLabel) {
      return `${when}, NivXRay analyzed ${artifact} and identified it as ${ev.detectedTypeLabel}.`;
    }
    return `${when}, NivXRay analyzed ${artifact} and processed it through the deterministic decoding pipeline.`;
  },

  // ── EXECUTION — how the code ran ─────────────────────────────────────
  execution: (ev) => {
    const t = (ev.decodedText || "").toLowerCase();
    const lolbin = (lolbinName(ev.lolbins[0]) || "").toLowerCase();
    if (/regsvr32/.test(lolbin)) {
      return "The command uses regsvr32.exe with /i:<remote_script> arguments — a signed-binary proxy pattern (Squiblydoo) that bypasses application-control defences by executing scriptlet content under a Microsoft-signed binary.";
    }
    if (/mshta/.test(lolbin)) {
      return "The command invokes mshta.exe against a remote script — a signed-binary proxy pattern that executes HTA/JScript payloads outside browser sandboxing.";
    }
    if (/rundll32/.test(lolbin)) {
      return "The command invokes rundll32.exe to proxy DLL execution — a signed-binary proxy pattern that shifts execution to a Microsoft-signed loader.";
    }
    if (/bitsadmin/.test(lolbin)) {
      return "The command uses bitsadmin.exe to transfer content — an intelligent-background-transfer abuse pattern that bypasses many user-agent-based egress controls.";
    }
    if (/certutil/.test(lolbin)) {
      return "The command uses certutil.exe outside its intended cryptographic role — most commonly to download or decode a follow-on payload.";
    }
    if (/wmic/.test(t) || /wmic/.test(lolbin)) {
      return "The command uses wmic.exe to execute WMI queries or spawn processes — a common lateral-movement or discovery pattern.";
    }
    if (ev.detectedTypeLabel && /encoded/i.test(ev.detectedTypeLabel)) {
      return "The command uses PowerShell's -EncodedCommand parameter, which conceals the underlying script content from command-line-based detections until decoding.";
    }
    if (/powershell/.test(t) || /powershell/.test(ev.detectedTypeLabel || "")) {
      return "The command executes under powershell.exe, PowerShell's interpreter for scripts and inline expressions.";
    }
    if (/wscript|cscript|\.vbs/.test(t)) {
      return "The command runs under Windows Script Host (wscript.exe or cscript.exe), executing VBScript or JScript content.";
    }
    return null;
  },

  // ── PAYLOAD STAGE — what content the command retrieves / executes ────
  payload_stage: (ev) => {
    const t = (ev.decodedText || "").toLowerCase();
    const has = (name) => ev.mitreIds.some((id) => id === name || id.startsWith(name + "."));
    const dl = /downloadstring|invoke-webrequest|iwr\b|wget\b|curl\b|bitsadmin\b|certutil.*-urlcache/i.test(t);
    const iex = /\biex\b|invoke-expression/i.test(t);
    if (dl && iex) {
      return "Fact: the command implements a classic download-and-execute staging workflow — it retrieves a follow-on script over HTTP(S) and evaluates it in memory via Invoke-Expression. Interpretation: this pattern is commonly associated with staged malware delivery and post-exploitation tooling, although the submitted artifact alone does not confirm successful execution on any endpoint.";
    }
    if (dl && !iex) {
      return "Fact: the command retrieves a follow-on payload from a remote host. Interpretation: whether that payload is executed on-host depends on the retrieved script and downstream behaviour, which are not visible in the submitted artifact.";
    }
    if (has("T1105") && !dl) {
      return "The behaviour maps to ingress tool transfer (T1105): the payload is designed to bring additional content into the environment for later execution.";
    }
    if (iex && !dl) {
      return "The command evaluates dynamically-constructed content via Invoke-Expression, executing code that is not visible in the command line itself.";
    }
    return null;
  },

  // ── NETWORK — infrastructure indicators, benign-aware ────────────────
  network: (ev) => {
    // If every recovered host is well-known benign infrastructure, say so
    // plainly. Do NOT tell the analyst these are "active leads".
    if (ev.allInfraBenign && ev.benignClassifications.length) {
      const primary = ev.benignClassifications[0];
      const others = ev.benignClassifications.slice(1);
      const otherClause = others.length
        ? ` The remaining indicator${others.length === 1 ? "" : "s"} (${others.map((c) => c.host).join(", ")}) belong${others.length === 1 ? "s" : ""} to the same class of legitimate infrastructure.`
        : "";
      return `Every network indicator recovered from the payload belongs to well-known legitimate infrastructure. The primary host ${primary.host} is a ${primary.category} used for ${primary.role}, which is expected background traffic on managed Windows endpoints and does not indicate malicious activity.${otherClause}`;
    }
    // Mixed / all-unknown → normal recovery language, but explicitly call
    // out any benign hosts individually so the analyst isn't misled.
    const parts = [];
    if (ev.url0) parts.push(`the URL ${ev.url0}`);
    if (ev.ip0) parts.push(`the IP address ${ev.ip0}`);
    if (ev.domain0 && !ev.url0?.includes(ev.domain0)) parts.push(`the domain ${ev.domain0}`);
    if (parts.length) {
      const list = parts.length === 1 ? parts[0] : (parts.slice(0, -1).join(", ") + " and " + parts.slice(-1));
      let base = `${qualifierFor("recovered")} network indicators from the payload include ${list}.`;
      if (ev.benignClassifications.length) {
        const benignList = ev.benignClassifications.map((c) => `${c.host} (${c.category})`).join("; ");
        base += ` Of these, the following are well-known legitimate infrastructure and should be excluded from any blocking action: ${benignList}.`;
      }
      base += " The remaining indicators should be treated as investigation leads pending validation.";
      return base;
    }
    if (ev.partial) {
      return `${qualifierFor("may_indicate")} the corrupted portion of the payload may have contained outbound network indicators that did not survive into the analysable prefix; no infrastructure was recoverable from the readable bytes.`;
    }
    return "No outbound network indicators were recovered from the analysed bytes.";
  },

  // ── TRADECRAFT — obfuscation + evasion tactics observed ──────────────
  tradecraft: (ev) => {
    const clauses = [];
    const has = (name) => ev.mitreIds.some((id) => id === name || id.startsWith(name + "."));
    if (has("T1027.010") || /encoded/i.test(ev.detectedTypeLabel || "")) clauses.push("Base64 encoding of the command line");
    if (/utf-?16/i.test(ev.detectedTypeLabel || "") || /-encodedcommand/i.test(ev.decodedText || "")) clauses.push("UTF-16LE string encoding — the standard PowerShell -EncodedCommand format");
    if (has("T1140")) clauses.push("runtime deobfuscation of the payload before execution");
    if (has("T1027.002")) clauses.push("packing of the executable content");
    if (!clauses.length) return null;
    const list = clauses.length === 1
      ? clauses[0]
      : clauses.slice(0, -1).join(", ") + " and " + clauses.slice(-1);
    return `${qualifierFor("observed")} the artifact uses ${list} to conceal its intent from static command-line signatures. Interpretation: obfuscation of this shape is a strong intent-to-evade signal, though it is not by itself a determination of maliciousness.`;
  },

  // ── POST-EXECUTION BEHAVIOUR — persistence + credential access ───────
  post_execution: (ev) => {
    const has = (name) => ev.mitreIds.some((id) => id === name || id.startsWith(name + "."));
    const bits = [];
    if (has("T1053")) bits.push("Scheduled Task creation (T1053) — attacker intent to persist across reboots");
    if (has("T1547.001")) bits.push("Run-key modification (T1547.001) — per-user autostart persistence");
    if (has("T1543")) bits.push("Service creation or modification (T1543) — system-level persistence");
    if (has("T1136")) bits.push("Local account creation (T1136) — access-preservation objective");
    if (has("T1003")) bits.push("OS credential dumping (T1003) — LSASS or SAM access should be assumed");
    if (has("T1555")) bits.push("Credential store access (T1555) — browser / password-manager targeting");
    if (has("T1552")) bits.push("Credentials-in-files access (T1552) — unattended-credentials hunt");
    if (!bits.length) return null;
    return `${qualifierFor("observed")} the following post-execution behaviours were mapped: ${bits.join("; ")}.`;
  },

  // ── NEGATIVE FINDINGS — explicit callouts of what was NOT observed ──
  //
  // Mature XDR platforms (Cisco, Microsoft, CrowdStrike) always tell the
  // analyst what wasn't recovered so they don't have to wonder whether
  // those areas were checked. Deterministic, evidence-driven.
  negative_findings: (ev) => {
    const has = (name) => ev.mitreIds.some((id) => id === name || id.startsWith(name + "."));
    const misses = [];
    const hasPersistence = has("T1053") || has("T1547") || has("T1136") || has("T1543");
    const hasCredAccess  = has("T1003") || has("T1555") || has("T1552");
    const hasRegistry    = has("T1112") || /registry|reg\s+add|reg\s+delete/i.test(ev.decodedText || "");
    const hasLateral     = has("T1021") || has("T1570") || has("T1210");
    const hasDefEvasion  = has("T1562") || has("T1548");
    if (!hasPersistence) misses.push("no persistence mechanisms (Scheduled Task, Run key, Service, or Account Creation) were identified");
    if (!hasCredAccess)  misses.push("no credential-access behaviour (LSASS dumping, SAM access, or credential-store targeting) was identified");
    if (!hasRegistry)    misses.push("no registry modification was observed in the recovered command");
    if (!hasLateral)     misses.push("no lateral-movement or remote-execution primitives were recovered");
    if (!hasDefEvasion)  misses.push("no explicit defence-tampering (e.g. AMSI bypass, ETW patching, security-tool disabling) was identified");
    // Only surface the block when we ran enough evidence extraction to
    // make the negative statements meaningful. If the artifact is
    // essentially empty we skip.
    if (!ev.mitreIds.length && !ev.decodedText) return null;
    return "Negative findings — " + misses.join("; ") + ".";
  },

  // ── MALWARE CONTEXT — family match, always caveated ─────────────────
  malware_context: (ev) => {
    if (ev.familyName) {
      return `${qualifierFor("likely")} the decoder chain structurally matched ${ev.familyName}-family tradecraft. Interpretation: family match is a structural resemblance signal — the artifact resembles known ${ev.familyName} samples, but this is not a definitive identification without additional evidence such as C2 traffic or a hash match.`;
    }
    return null;
  },

  // ── RISK ASSESSMENT — verdict-aware; NEVER contradict the verdict class ──
  risk_assessment: (ev) => {
    const verdict = ev.verdictWord;
    const confidence = ev.confidence;
    const conf = (confidence !== null && confidence !== undefined) ? ` (confidence ${confidence}/100)` : "";
    // Benign / Informational — the tone MUST match. Never say "warrants
    // further investigation" when the engine itself concluded no high-signal
    // behaviour was observed.
    if (ev.verdictClass === "benign") {
      let base = `The activity is assessed as ${verdict}${conf}.`;
      if (ev.allInfraBenign && ev.benignClassifications.length) {
        base += ` The recovered network indicators resolve entirely to legitimate infrastructure (${ev.benignClassifications.map((c) => c.category).slice(0, 2).join(", ")}), and no high-signal execution or persistence behaviours were recovered from the artifact.`;
      } else if ((ev.because || []).some((b) => /no high[- ]?signal|no download|no persistence/i.test(String(b)))) {
        base += ` The engine's own signal review reports no high-signal execution, download, or persistence behaviours in the recovered content.`;
      } else {
        base += ` No high-signal behaviours were recovered from the analysed content.`;
      }
      base += ` This finding is informational and does not on its own warrant active response; retain it for context if the same artifact resurfaces alongside stronger signals.`;
      return base;
    }
    // Partial-decode caveat.
    if (ev.partial) {
      return `Because only a partial recovery was possible, the activity is assessed as ${verdict}${conf}; severity is intentionally capped and derived evidence carries the provenance=partial_recovery label. A definitive assessment is not possible from the readable prefix alone.`;
    }
    // Attention / suspicious / malicious — the "because combines X, Y, Z" phrasing.
    const tcs = ev.tradecraftClauses;
    if (tcs.length >= 2) {
      const list = tcs.length === 1 ? tcs[0] : tcs.slice(0, -1).join(", ") + (tcs.length > 2 ? "," : "") + " and " + tcs.slice(-1);
      return `Because the recovered content combines ${list}, the activity is assessed as ${verdict}${conf} and warrants further investigation.`;
    }
    if (tcs.length === 1) {
      return `Because the recovered content demonstrates ${tcs[0]}, the activity is assessed as ${verdict}${conf} and warrants further investigation.`;
    }
    return `The activity is assessed as ${verdict}${conf}.`;
  },

  // ── RECOMMENDATIONS — evidence-aware, actionable per SOC role ────────
  //
  // Selected by observed evidence class, not by MITRE mapping alone.
  //   URL/IP recovered   → proxy / DNS / firewall / NetFlow hunts + block
  //   PowerShell artifact → -EncodedCommand sweep · SBL logs · AMSI
  //   regsvr32 / mshta / rundll32 / certutil → LOLBin-specific hunts
  //   Family match      → threat-intel sweep for family IoCs
  //   Partial decode    → preserve forensic artifacts
  recommendations: (ev) => {
    // Operator directive (2026-02-28 slice-6): deliver an EXACTLY 7-step
    // remediation playbook in Senior MDR Threat Hunter voice. Each step
    // is a numbered forensic action; the mapping to evidence is preserved.
    //
    // Playbook slots (fixed order, filled from evidence with fallback):
    //   1. Triage & scoping — extent-of-compromise sweep for the artifact
    //   2. Contain — isolate / block based on verdict class
    //   3. Preserve — forensic capture (memory, disk, event logs)
    //   4. Hunt — cross-fleet telemetry sweep for related IOCs / tradecraft
    //   5. Enrich — TIP / OSINT correlation for IOCs and family
    //   6. Harden — detection tuning + policy change addressing this tradecraft
    //   7. Report & close — RCA, IR docs, lessons learned
    const lolbinNames = [...new Set(ev.lolbins.map(lolbinName).filter(Boolean))];
    const nonBenignUrl = ev.url0 && !ev.benignHostSet?.has(urlHost(ev.url0));
    const nonBenignIp = ev.ip0;
    const nonBenignDomain = ev.domain0 && !ev.benignHostSet?.has(ev.domain0);
    const isPs = /powershell/i.test(ev.decodedText || ev.detectedTypeLabel || "") ||
                 /encoded/i.test(ev.detectedTypeLabel || "");

    // For benign verdicts, the 7-step playbook shifts entirely toward
    // context-verification and record-keeping rather than active response.
    if (ev.verdictClass === "benign") {
      return [
        "NivXRay recommends the following 7-step verification playbook:",
        "1. **Triage & scoping** — confirm the submitting host / user / process context that produced the artifact so the analyst can rule out cover-of-benign impersonation",
        "2. **Baseline check** — verify the recovered infrastructure (Verisign CRL / vendor consoles) is on the environment's normal traffic baseline; flag any first-seen deviation",
        "3. **Evidence preservation** — retain the raw artifact + decoded output + this investigation record in the case store for pattern-matching",
        "4. **Low-noise hunt** — no active hunt required, but log a soft-flag for the tradecraft pattern (encoded PowerShell referencing vendor infra) so future high-signal matches surface faster",
        "5. **No enrichment escalation** — do not push these indicators to threat-intel feeds; they are known-benign vendor infrastructure",
        "6. **Detection hygiene** — confirm existing detection rules do not fire on this artifact shape in future (suppress a known-benign pattern if it does)",
        "7. **Close as Informational** — document the assessment and close the case with a 'reviewed / informational / no action required' disposition",
      ].join("\n");
    }

    // Suspicious / attention / malicious — full 7-step response playbook.
    const step1 = nonBenignUrl || nonBenignIp || lolbinNames.length
      ? `Sweep endpoint command-line, proxy, and DNS telemetry (past 30 days) for the recovered artifact and any variant of the same tradecraft; identify every host that has touched ${nonBenignUrl ? ev.url0 : (ev.ip0 || ev.domain0 || "the observed infrastructure")}`
      : "Sweep endpoint command-line telemetry (past 30 days) for additional executions of the recovered artifact shape across the fleet";
    const step2 = ev.verdictClass === "malicious"
      ? `Immediately isolate any host that executed this artifact at the network layer, disable any user session that ran it, and block ${nonBenignUrl ? ev.url0 + " and " : ""}${nonBenignIp ? ev.ip0 + " and " : ""}${nonBenignDomain && !ev.url0?.includes(ev.domain0) ? ev.domain0 : (nonBenignUrl || nonBenignIp || "the observed C2 infrastructure")} at the perimeter proxy, DNS resolver, and firewall`
      : nonBenignUrl || nonBenignIp || nonBenignDomain
        ? `Block ${nonBenignUrl ? ev.url0 : ""}${nonBenignUrl && nonBenignIp ? " and " : ""}${nonBenignIp || ""}${(nonBenignUrl || nonBenignIp) && nonBenignDomain && !ev.url0?.includes(ev.domain0) ? " and " : ""}${nonBenignDomain && !ev.url0?.includes(ev.domain0) ? ev.domain0 : ""} at the perimeter proxy, DNS resolver, and firewall pending confirmation`
        : "Consider preemptive host isolation if additional signals surface during the hunt in step 1";
    const step3 = ev.verdictClass === "malicious"
      ? "Acquire volatile memory (full RAM dump), Prefetch, AmCache, USN journal, PowerShell operational logs, Sysmon logs, and Security event logs from every affected host; hash and store to the evidence locker before any remediation"
      : "Preserve the original artifact bytes, decoded output, PowerShell operational logs (Event ID 4104), and Sysmon logs from any host that executed the same content";
    const step4 = isPs
      ? "Hunt across the fleet for related PowerShell tradecraft: additional `-EncodedCommand` executions, `Invoke-Expression` + `WebClient.DownloadString` combinations, and any AMSI-bypass patterns; alert on new matches"
      : lolbinNames.length
        ? `Hunt across the fleet for additional invocations of ${lolbinNames.slice(0, 3).join(", ")} with the observed argument shape and any lateral-movement or persistence primitives that could be riding the same access`
        : "Hunt across the fleet for additional artifacts matching the recovered command-line shape and any lateral-movement primitives";
    const step5 = ev.familyName
      ? `Correlate the ${ev.familyName}-family structural match against TIP / OSINT feeds (VirusTotal / AbuseIPDB / URLScan / OTX / MalwareBazaar / ThreatFox) for known C2 infrastructure, YARA rules, hashes, and campaign attribution`
      : (nonBenignUrl || nonBenignIp || nonBenignDomain)
        ? `Enrich the recovered indicators (${[nonBenignUrl ? ev.url0 : null, nonBenignIp ? ev.ip0 : null].filter(Boolean).join(", ")}) against TIP / OSINT feeds; look for related samples, WHOIS pivots, and passive-DNS history`
        : "Enrich the recovered tradecraft against threat-intel feeds for matching campaigns and TTPs";
    const step6 = isPs
      ? "Harden PowerShell posture: enforce Constrained Language Mode where feasible, require signed scripts, enable Script-Block Logging + Module Logging + AMSI, and add Sigma detections for the specific tradecraft (`FromBase64String`, `IEX`, `DownloadString`)"
      : lolbinNames.length
        ? `Harden ${lolbinNames[0]} posture: AppLocker / WDAC rules to deny execution from user-writable paths (%TEMP%, %APPDATA%, network shares) and Sigma detections for the observed argument shape`
        : "Harden the detection stack against the observed tradecraft (Sigma / EDR custom detections) and validate coverage with a purple-team replay of the recovered artifact";
    const step7 = "Author the incident RCA and close-out: document the affected hosts and users, timeline, evidence collected, MITRE ATT&CK mapping, indicators, containment actions, lessons learned, and any detection or policy improvements made; brief the SOC and update the runbook";

    return [
      "NivXRay recommends the following 7-step remediation playbook:",
      `1. **Triage & scoping** — ${step1}`,
      `2. **Contain** — ${step2}`,
      `3. **Preserve** — ${step3}`,
      `4. **Hunt** — ${step4}`,
      `5. **Enrich** — ${step5}`,
      `6. **Harden** — ${step6}`,
      `7. **Report & close** — ${step7}`,
    ].join("\n");
  },
};

function composeAnalystNarrative(evidence) {
  // ── ADR-0013 §2.2 · slice-5 · Cisco-XDR-style 3-paragraph rendering ──
  //
  // The block engine produces evidence-driven CLAUSES (short fact sentences).
  // The renderer WEAVES those clauses into three dense analyst paragraphs
  // that mirror the operator's reference summary structure:
  //
  //   ¶1 · Detection statement           (one sentence — what happened)
  //   ¶2 · Priority statement            (one sentence — why it matters)
  //   ¶3 · Investigation-shows paragraph (one dense paragraph woven from
  //                                       every non-empty block, in past-tense
  //                                       analyst voice with citations)
  //
  // Then the recommendations block appears as a checklist prefaced by
  // "NivXRay recommends that you:" — matching the "CSOC recommends" style.

  // ── Paragraph 1 · Detection statement — reference template match:
  //     "On [Date/Time], [Tool] detected [File/Behaviour] on [Asset]."
  const whenTs = evidence.whenPhrase ? `On ${evidence.whenPhrase} UTC` : "During this investigation";
  const toolName = evidence.mode === "auto" ? "NivXRay Auto-Investigate" : "NivXRay Smart Decoder";
  const detectedNoun = evidence.detectedTypeLabel || evidence.artifactPhrase;
  const onAsset = evidence.hostAsset ? ` on ${evidence.hostAsset}` : "";
  let paraDetection;
  if (evidence.observedBehavior) {
    paraDetection = `${whenTs}, ${toolName} detected ${detectedNoun}${onAsset} — a payload which ${evidence.observedBehavior}.`;
  } else if (evidence.detectedTypeLabel) {
    paraDetection = `${whenTs}, ${toolName} detected ${detectedNoun}${onAsset} and identified it as ${evidence.detectedTypeLabel}.`;
  } else {
    paraDetection = `${whenTs}, ${toolName} analysed ${evidence.artifactPhrase}${onAsset} through the deterministic decoding pipeline.`;
  }

  // ── Paragraph 2 · Priority / severity statement ────────────────────
  const verdict = evidence.verdictWord;
  const conf = (evidence.confidence !== null && evidence.confidence !== undefined) ? ` (confidence ${evidence.confidence}/100)` : "";
  let paraPriority;
  if (evidence.verdictClass === "benign") {
    if (evidence.allInfraBenign && evidence.benignClassifications.length) {
      const cats = [...new Set(evidence.benignClassifications.map((c) => c.category))].slice(0, 2).join(" and ");
      paraPriority = `This is a low-priority informational finding${conf} because every recovered network indicator resolves to well-known legitimate infrastructure (${cats}), and no high-signal execution, download, or persistence behaviour was recovered from the artifact.`;
    } else {
      paraPriority = `This is a low-priority informational finding${conf} because no high-signal execution, download, or persistence behaviour was recovered from the artifact.`;
    }
  } else if (evidence.verdictClass === "malicious") {
    const rat = evidence.familyName ? `the recovered content structurally matches ${evidence.familyName}-family tradecraft` : "the recovered content combines high-signal execution and infrastructure indicators";
    paraPriority = `This is a high-priority alert${conf} because ${rat} and the payload attempts staged execution against attacker-controlled infrastructure.`;
  } else if (evidence.verdictClass === "suspicious") {
    const tcs = evidence.tradecraftClauses;
    if (tcs.length >= 2) {
      const list = tcs.slice(0, -1).join(", ") + " and " + tcs.slice(-1);
      paraPriority = `This is a ${evidence.partial ? "capped-severity" : "medium-priority"} finding${conf} because the recovered content combines ${list}, a pattern associated with staged malware delivery.`;
    } else if (tcs.length === 1) {
      paraPriority = `This is a ${evidence.partial ? "capped-severity" : "medium-priority"} finding${conf} because the recovered content demonstrates ${tcs[0]}.`;
    } else {
      paraPriority = `This finding is assessed as ${verdict}${conf}.`;
    }
    if (evidence.partial) {
      paraPriority += " Severity is capped because only a partial recovery was possible from the input bytes.";
    }
  } else {
    // attention / unknown class — matter-of-fact.
    paraPriority = `This finding is assessed as ${verdict}${conf}; the recovered content has attention-worthy signals but no single behaviour is conclusive on its own.`;
  }

  // ── Paragraph 3 · Investigation-shows narrative (dense, woven) ─────
  // Assemble evidence-cited clauses in past-tense analyst voice.
  const clauses = [];
  clauses.push("Investigation shows that this verdict was reached as follows.");

  // Endpoint-telemetry framing (if the caller provided host / user / parent).
  if (evidence.hostAsset || evidence.userAsset || evidence.parentProc) {
    const tel = [];
    if (evidence.hostAsset) tel.push(`the affected host is ${evidence.hostAsset}`);
    if (evidence.userAsset) tel.push(`the invoking user is ${evidence.userAsset}`);
    if (evidence.parentProc) tel.push(`the parent process is ${evidence.parentProc}`);
    const joined = tel.join(", ");
    clauses.push(joined.charAt(0).toUpperCase() + joined.slice(1) + ".");
  }

  // What was analysed + how it decoded.
  if (evidence.decodedText && evidence.decodedText.length > 5) {
    const excerpt = evidence.decodedText.trim().replace(/\s+/g, " ").slice(0, 200);
    clauses.push(`The submitted artifact decoded to: "${excerpt}${evidence.decodedText.length > 200 ? "…" : ""}".`);
  }

  // Execution chain — synthetic chain walked from the recovered command.
  if (evidence.executionChain && evidence.executionChain.length >= 2) {
    clauses.push(`The recovered execution chain — walked line-by-line from the decoded command — is: ${evidence.executionChain.join(" → ")}.`);
  }

  // How the code ran — execution tradecraft (only when observed).
  const execClause = NARRATIVE_BLOCKS.execution(evidence);
  if (execClause) clauses.push("Analysis of the recovered content indicates that " + execClause.charAt(0).toLowerCase() + execClause.slice(1));
  // Payload staging (only when observed).
  const payloadClause = NARRATIVE_BLOCKS.payload_stage(evidence);
  if (payloadClause) clauses.push(payloadClause);

  // Infrastructure — benign-aware.
  if (evidence.allInfraBenign && evidence.benignClassifications.length) {
    const primary = evidence.benignClassifications[0];
    clauses.push(`This is supported by the network indicators recovered from the payload, all of which belong to legitimate infrastructure: the primary host ${primary.host} is a ${primary.category} used for ${primary.role}, which is expected background traffic on managed Windows endpoints.`);
    const others = evidence.benignClassifications.slice(1);
    if (others.length) {
      clauses[clauses.length - 1] += ` The remaining ${others.length === 1 ? "indicator resolves" : "indicators resolve"} to the same class of vendor infrastructure (${others.map((c) => `${c.host} — ${c.category}`).join("; ")}).`;
    }
  } else if (evidence.benignClassifications.length) {
    const benignList = evidence.benignClassifications.map((c) => `${c.host} (${c.category})`).join("; ");
    clauses.push(`Of the recovered network indicators, the following are well-known legitimate infrastructure and should be excluded from blocking: ${benignList}. The remaining indicators — ${[evidence.url0, evidence.ip0, evidence.domain0].filter((x) => x && !evidence.benignHostSet.has(String(x))).filter(Boolean).slice(0, 2).join(", ") || "if any"} — should be treated as investigation leads pending validation.`);
  } else if (evidence.url0 || evidence.ip0 || evidence.domain0) {
    const parts = [];
    if (evidence.url0) parts.push(`the URL ${evidence.url0}`);
    if (evidence.ip0) parts.push(`the IP address ${evidence.ip0}`);
    if (evidence.domain0 && !evidence.url0?.includes(evidence.domain0)) parts.push(`the domain ${evidence.domain0}`);
    const list = parts.length === 1 ? parts[0] : (parts.slice(0, -1).join(", ") + " and " + parts.slice(-1));
    clauses.push(`Network indicators recovered from the payload include ${list}.`);
  }

  // Tradecraft (obfuscation) — only when present.
  const tradecraftClause = NARRATIVE_BLOCKS.tradecraft(evidence);
  if (tradecraftClause && evidence.verdictClass !== "benign") clauses.push(tradecraftClause);

  // Family match — always caveated + delivery-vector inference (slice-6).
  const familyClause = NARRATIVE_BLOCKS.malware_context(evidence);
  if (familyClause) {
    let combined = familyClause;
    if (evidence.deliveryVector) {
      combined += ` Where ${evidence.familyName}-family samples have been observed in the wild, the most common delivery vector is ${evidence.deliveryVector}; this is context for the analyst, not a claim about this specific artifact's delivery.`;
    }
    clauses.push(combined);
  }

  // Post-execution (persistence + credential) — only when present.
  const postExecClause = NARRATIVE_BLOCKS.post_execution(evidence);
  if (postExecClause) clauses.push(postExecClause);

  // Negative-findings — always closing evidence, but succinct.
  // For benign verdicts we emphasize the "no high-signal" story is what
  // ANCHORS the low-priority conclusion.
  if (evidence.verdictClass === "benign") {
    const engineBecause = (evidence.because || []).map((b) => typeof b === "string" ? b : String(b?.reason || b || "")).filter(Boolean);
    if (engineBecause.length) {
      clauses.push(`The engine's own signal review reports: ${engineBecause.slice(0, 5).join("; ")}. This is the primary basis for the informational classification.`);
    }
  } else {
    const negClause = NARRATIVE_BLOCKS.negative_findings(evidence);
    if (negClause) clauses.push(negClause);
  }

  const paraInvestigation = clauses.join(" ");

  // ── Recommendations paragraph (checklist-style, verdict-aware) ─────
  const recsClause = NARRATIVE_BLOCKS.recommendations(evidence);
  // Split the recommendations block on newlines so each numbered step
  // renders as its own paragraph in the UI (single-<p> joining flattens
  // the playbook into one wall of text).
  const recsParagraphs = recsClause
    ? recsClause.split(/\n/).map((s) => s.trim()).filter(Boolean)
    : [];

  return [paraDetection, paraPriority, paraInvestigation, ...recsParagraphs].filter(Boolean);
}

// ─── Benign-infrastructure classifier ────────────────────────────────────
// Recognises well-known legitimate infrastructure so the narrative doesn't
// recommend blocking crl.verisign.com or sinkholing cisco.com. The list is
// intentionally conservative — only inclusions we can defend to an auditor.
const BENIGN_INFRA = [
  // Certificate Authorities · CRL / OCSP endpoints
  { rx: /(^|\.)verisign\.com$/i,          category: "certificate-authority (Verisign)",       role: "CRL / OCSP / code-signing timestamps" },
  { rx: /(^|\.)thawte\.com$/i,            category: "certificate-authority (Thawte)",         role: "CRL / OCSP / code-signing timestamps" },
  { rx: /(^|\.)digicert\.com$/i,          category: "certificate-authority (DigiCert)",       role: "CRL / OCSP / code-signing timestamps" },
  { rx: /(^|\.)symantec\.com$/i,          category: "certificate-authority (Symantec)",       role: "CRL / OCSP / code-signing timestamps" },
  { rx: /(^|\.)globalsign\.(net|com)$/i,  category: "certificate-authority (GlobalSign)",     role: "CRL / OCSP / code-signing timestamps" },
  { rx: /(^|\.)entrust\.(net|com)$/i,     category: "certificate-authority (Entrust)",        role: "CRL / OCSP / code-signing timestamps" },
  { rx: /(^|\.)letsencrypt\.org$/i,       category: "certificate-authority (Let's Encrypt)",  role: "CRL / OCSP" },
  { rx: /(^|\.)pki\.goog$/i,              category: "certificate-authority (Google Trust)",   role: "CRL / OCSP" },
  { rx: /^(crl|ocsp|s|r)\d?\.[a-z0-9-]+\.(com|net|org)$/i, category: "certificate revocation / OCSP responder", role: "CRL / OCSP" },
  // Microsoft
  { rx: /(^|\.)windowsupdate\.com$/i,     category: "Microsoft Windows Update",               role: "OS updates" },
  { rx: /(^|\.)update\.microsoft\.com$/i, category: "Microsoft Windows Update",               role: "OS updates" },
  { rx: /(^|\.)microsoft\.com$/i,         category: "Microsoft",                               role: "Microsoft services" },
  { rx: /(^|\.)msn\.com$/i,               category: "Microsoft",                               role: "Microsoft services" },
  { rx: /(^|\.)office\.com$/i,            category: "Microsoft Office 365",                    role: "productivity suite" },
  { rx: /(^|\.)office365\.com$/i,         category: "Microsoft Office 365",                    role: "productivity suite" },
  // Security vendors / their own consoles
  { rx: /(^|\.)cisco\.com$/i,             category: "Cisco (vendor infrastructure)",           role: "vendor console / telemetry" },
  { rx: /(^|\.)amp\.cisco\.com$/i,        category: "Cisco Secure Endpoint (AMP) console",     role: "customer's own XDR/EDR console" },
  { rx: /(^|\.)crowdstrike\.com$/i,       category: "CrowdStrike (vendor infrastructure)",     role: "vendor console / telemetry" },
  { rx: /(^|\.)sentinelone\.(net|com)$/i, category: "SentinelOne (vendor infrastructure)",     role: "vendor console / telemetry" },
  { rx: /(^|\.)paloaltonetworks\.com$/i,  category: "Palo Alto Networks (vendor)",             role: "vendor console / telemetry" },
  { rx: /(^|\.)fortinet\.com$/i,          category: "Fortinet (vendor infrastructure)",        role: "vendor console / telemetry" },
];

function classifyBenignInfra(hostname) {
  if (!hostname) return null;
  const h = hostname.toLowerCase().split(":")[0].split("/")[0].replace(/^https?:\/\//, "");
  for (const entry of BENIGN_INFRA) {
    if (entry.rx.test(h)) return { host: h, category: entry.category, role: entry.role };
  }
  return null;
}

// Given a URL, extract its hostname.
function urlHost(url) {
  try { return new URL(String(url)).hostname; }
  catch { const m = /^(?:https?:\/\/)?([^\/?#:]+)/i.exec(String(url) || ""); return m ? m[1] : null; }
}

// Verdict severity classification for narrative gating.
//   benign      → no action recommended (Informational / Clean / Benign)
//   attention   → attention needed but not "block everything" (Runtime Dependent / Undetermined)
//   suspicious  → warrants investigation (Suspicious / Partial Decode)
//   malicious   → escalation (Malicious / Critical)
function verdictSeverityClass(verdict, because = []) {
  const v = String(verdict || "").toLowerCase();
  const bTxt = (because || []).join(" ").toLowerCase();
  const highSignalObserved = /high[- ]?signal/.test(bTxt) && !/no high[- ]?signal/.test(bTxt);
  if (/informational|clean|benign/i.test(v)) return "benign";
  if (/malicious|critical/i.test(v)) return "malicious";
  if (/suspicious|partial/i.test(v)) return "suspicious";
  if (/runtime|undetermined|dependent/i.test(v)) return highSignalObserved ? "suspicious" : "attention";
  return "attention";
}

// ─── Rule-ID → plain-English humaniser ────────────────────────────────────
// Internal rule identifiers should NEVER surface in an analyst-facing
// narrative. This map converts the identifiers we see coming out of the
// verdict engine's `explainability.contributors` array into readable
// phrases an MDR threat-hunter would actually write.
const RULE_HUMANISER = {
  "url_in_decoded_output":         "the decoded command contains an outbound download URL",
  "ioc_url":                       "a URL indicator was recovered from the payload",
  "ioc_ip":                        "an IP address was recovered from the payload",
  "ioc_domain":                    "a domain was recovered from the payload",
  "ioc_hash":                      "a file-hash indicator was recovered from the payload",
  "base64_encoded_command":        "the input was Base64-encoded to evade command-line signatures",
  "utf16_encoded_command":         "the payload used UTF-16 encoding — a classic PowerShell -EncodedCommand pattern",
  "invoke_expression":             "the recovered command uses Invoke-Expression to run downloaded content in memory",
  "webclient_downloadstring":      "the recovered command uses .NET WebClient.DownloadString to fetch a follow-on stage",
  "iex":                           "IEX (Invoke-Expression) was observed — in-memory script execution",
  "reflection":                    "the command relies on reflection to load code without touching disk",
  "encryption_detected":           "the payload is encrypted — content is only knowable at runtime",
  "dynamic_execution":             "the command decrypts/decodes content at runtime and executes it",
  "download_execute":              "the payload downloads and executes a follow-on stage",
  "lolbin_regsvr32":               "regsvr32.exe was invoked as a signed-binary proxy (Squiblydoo pattern)",
  "lolbin_mshta":                  "mshta.exe was invoked to execute HTA/remote script content",
  "lolbin_rundll32":               "rundll32.exe was invoked to proxy DLL execution",
  "lolbin_certutil":               "certutil.exe was invoked outside its intended cryptographic role",
  "lolbin_bitsadmin":              "bitsadmin.exe was invoked to transfer content, bypassing user-agent controls",
  "lolbin_wmic":                   "wmic.exe was invoked to execute WMI queries or spawn processes",
  "lolbin_powershell":             "powershell.exe was used to execute the payload",
};

// MITRE ATT&CK technique-id → short tradecraft phrase (analyst-facing).
// Used in the "combines X, Y, and Z" clause of the Executive Assessment.
const MITRE_TRADECRAFT = {
  "T1059":     "scripted execution",
  "T1059.001": "PowerShell execution",
  "T1059.003": "Windows command-shell execution",
  "T1059.005": "VBScript / WScript execution",
  "T1027":     "content obfuscation",
  "T1027.010": "Base64 obfuscation",
  "T1027.002": "software packing",
  "T1140":     "runtime deobfuscation",
  "T1105":     "remote payload retrieval",
  "T1071":     "web-protocol C2",
  "T1071.001": "web-protocol C2",
  "T1218":     "signed-binary proxy execution",
  "T1218.005": "mshta script proxy execution",
  "T1218.010": "regsvr32 signed-binary proxy execution",
  "T1218.011": "rundll32 proxy execution",
  "T1053.005": "scheduled-task persistence",
  "T1197":     "BITS-based transfer abuse",
  "T1055":     "process injection",
  "T1547.001": "Run-key persistence",
  "T1136":     "local account creation",
};

function tradecraftForTechniqueId(id) {
  if (!id) return null;
  return MITRE_TRADECRAFT[id] || MITRE_TRADECRAFT[id.split(".")[0]] || null;
}

// Analyst-facing description of the artifact type — from the detected_type
// label. Falls back to a generic "submitted artifact" phrase.
function analystArtifactPhrase(detectedTypeLabel, decodedText) {
  const label = String(detectedTypeLabel || "").toLowerCase();
  if (label.includes("encoded") && label.includes("powershell")) {
    return "a PowerShell command using the -EncodedCommand option";
  }
  if (label.includes("powershell")) return "a PowerShell command";
  if (label.includes("javascript")) return "a JavaScript payload";
  if (label.includes("vbscript") || label.includes("vbs")) return "a VBScript payload";
  if (label.includes("shell")) return "a shell command";
  if (label.includes("hta")) return "an HTA payload";
  const t = String(decodedText || "").toLowerCase();
  if (t.includes("powershell") || t.includes("iex ") || t.includes("invoke-expression")) return "a PowerShell command";
  if (t.includes("regsvr32")) return "a regsvr32 command line";
  if (t.includes("mshta")) return "an mshta command line";
  return "a submitted artifact";
}

// Detect the observed behaviour from the recovered command — produces the
// active-voice "attempts to download / and executes / abuses X" phrasing.
function detectObservedBehavior(decodedText, urls, lolbins) {
  const t = String(decodedText || "");
  const lower = t.toLowerCase();
  const url0 = (urls || [])[0];
  const parts = [];

  const downloadMatch =
    /downloadstring|invoke-webrequest|iwr\s|wget\s|curl\s|bitsadmin\s|certutil.*-urlcache/i.test(lower);
  if (downloadMatch && url0) {
    parts.push(`attempts to download an additional payload from ${url0}`);
  } else if (downloadMatch) {
    parts.push("attempts to download an additional payload from a remote host");
  } else if (url0) {
    parts.push(`references the remote resource ${url0}`);
  }

  if (/\biex\b|invoke-expression/i.test(lower)) {
    parts.push("and executes it in memory via Invoke-Expression");
  } else if (/\.exe\s+/i.test(lower) && (parts.length === 0)) {
    parts.push("invokes an executable directly");
  }

  const lbName = (lolbins || []).map(lolbinName).filter(Boolean)[0];
  if (lbName) {
    // Suppress the tautological "using powershell as an execution vehicle"
    // when the artifact itself is already a PowerShell command — the
    // interpreter is not a "vehicle" in that context.
    const artifactIsPs = /powershell/i.test(t) || /-enc(odedcommand)?\b/i.test(t);
    if (/regsvr32/i.test(lbName)) parts.push("using regsvr32.exe as a signed-binary proxy (Squiblydoo pattern)");
    else if (/mshta/i.test(lbName)) parts.push("using mshta.exe to proxy execution of remote script content");
    else if (/rundll32/i.test(lbName)) parts.push("using rundll32.exe to proxy DLL execution");
    else if (/certutil/i.test(lbName)) parts.push("using certutil.exe to fetch and decode the payload");
    else if (/bitsadmin/i.test(lbName)) parts.push("using bitsadmin.exe to transfer the payload");
    else if (/powershell/i.test(lbName) && artifactIsPs) {
      // Skip — PowerShell interpreter is already implied by the artifact type.
    } else parts.push(`using ${lbName} as an execution vehicle`);
  }

  if (!parts.length) return null;
  return parts.join(", ");
}

// LOLBin display-name helper — real responses put the name in `.binary`
// but auto-investigate sometimes uses `.name`. Normalise once.
function lolbinName(l) {
  if (!l || typeof l !== "object") return null;
  return String(l.name || l.binary || l.bin || "").replace(/\.exe$/i, "") || null;
}

// Strip decorative ASCII banners that some backends prepend to `output` /
// `output_raw` so we don't quote box-drawing characters as if they were
// the decoded command. Returns the first substantive content block.
function extractCleanDecodedText(output) {
  if (!output) return "";
  const s = String(output);
  // Remove long runs of box-drawing / dash / equals separators.
  const cleaned = s.replace(/[━─═\-]{6,}/g, "\n").split("\n").map((l) => l.trim()).filter(Boolean);
  // If we see a "Normalized Command:" or "Decoded Output:" label, prefer the
  // value that follows it.
  for (let i = 0; i < cleaned.length; i++) {
    if (/^(Normalized Command|Decoded Output|Decoded Command|Recovered Command)\s*:?$/i.test(cleaned[i])) {
      if (cleaned[i + 1]) return cleaned[i + 1].slice(0, 400);
    }
  }
  // Drop known banner lines.
  const bannerLine = /^(▼|▲|▶|▼\s*[A-Z ]+|[A-Z][A-Z ]{6,}[A-Z]|Profile:|Original Input:|Base64 decoded|PowerShell -EncodedCommand|CMD RUNTIME|NIVXRAY INVESTIGATION|DECODED OUTPUT)$/;
  for (const line of cleaned) {
    if (line.length < 6) continue;
    if (bannerLine.test(line)) continue;
    if (/^[▼▲▶◀]\s/.test(line)) continue;
    // First substantive line wins.
    return line.slice(0, 400);
  }
  // Fallback: return whitespace-collapsed original, capped.
  return s.replace(/\s+/g, " ").trim().slice(0, 400);
}

// Extract a synthetic execution chain from the decoded command line.
// The tool doesn't receive EDR parent-process telemetry — this walks the
// command's *stated* execution primitives (interpreter → API → target)
// which is the best proxy we can compute deterministically. When the
// caller supplies real telemetry (host / parent / user), those are woven
// into the narrative alongside.
function extractExecutionChain(decoded, url0) {
  const t = String(decoded || "");
  if (!t) return [];
  const chain = [];
  if (/powershell(\.exe)?/i.test(t)) chain.push("powershell.exe");
  else if (/regsvr32(\.exe)?/i.test(t)) chain.push("regsvr32.exe");
  else if (/mshta(\.exe)?/i.test(t)) chain.push("mshta.exe");
  else if (/rundll32(\.exe)?/i.test(t)) chain.push("rundll32.exe");
  else if (/certutil(\.exe)?/i.test(t)) chain.push("certutil.exe");
  else if (/bitsadmin(\.exe)?/i.test(t)) chain.push("bitsadmin.exe");
  else if (/wscript|cscript/i.test(t)) chain.push(/cscript/i.test(t) ? "cscript.exe" : "wscript.exe");
  else if (/cmd(\.exe)?/i.test(t)) chain.push("cmd.exe");
  if (/-encodedcommand|-enc\b/i.test(t)) chain.push("Base64-decoded PowerShell block");
  if (/net\.webclient/i.test(t)) chain.push("System.Net.WebClient");
  else if (/invoke-webrequest|iwr\b/i.test(t)) chain.push("Invoke-WebRequest");
  else if (/downloadstring/i.test(t)) chain.push("WebClient.DownloadString");
  else if (/\bcurl\b|\bwget\b/i.test(t)) chain.push(/curl/i.test(t) ? "curl" : "wget");
  else if (/-urlcache/i.test(t)) chain.push("certutil -urlcache");
  else if (/\/i:https?:/i.test(t)) chain.push("/i:<remote_script> proxy fetch");
  if (url0) chain.push(`fetch → ${url0}`);
  if (/\biex\b|invoke-expression/i.test(t)) chain.push("Invoke-Expression (in-memory execution)");
  else if (/scrobj\.dll/i.test(t)) chain.push("scrobj.dll (scriptlet execution)");
  return chain;
}

// Delivery-vector inference from the malware family — connects the
// family attribution to a likely delivery mechanism in analyst voice.
const DELIVERY_VECTORS = {
  "Emotet":       "phishing email attachment (weaponised Office document) followed by a PowerShell downloader",
  "Qakbot":       "phishing email delivering a weaponised Office document, ZIP, or ISO archive",
  "Cobaltstrike": "beacon delivered via an initial-access loader (spear-phish, drive-by, or supply-chain vector)",
  "Bumblebee":    "ISO / IMG delivery via phishing email, dropped by a JavaScript / DLL loader",
  "Agent Tesla":  "phishing email attachment (weaponised Office document or archive) with a .NET stealer payload",
};

function familyDeliveryVector(name) {
  if (!name) return null;
  return DELIVERY_VECTORS[name] || null;
}

// Extract the family label from decoder chain ids (e.g. "family-emotet" → "Emotet").
function familyFromChain(chainIds) {
  for (const c of chainIds || []) {
    const m = /^family[-_](.+)$/i.exec(String(c));
    if (m) return m[1].replace(/[-_]+/g, " ").replace(/\b\w/g, (ch) => ch.toUpperCase());
  }
  return null;
}

function humaniseContributor(c) {
  const rule = typeof c === "string" ? c : (c?.rule || c?.id || c?.name || "");
  const reason = typeof c === "object" ? (c?.reason || c?.description || "") : "";
  const mitreMatch = /mitre_technique[:\-_]?(T\d+(?:\.\d+)?)/i.exec(rule);
  if (mitreMatch) {
    const tc = tradecraftForTechniqueId(mitreMatch[1]);
    return tc
      ? `${tc} (ATT&CK ${mitreMatch[1]}) was mapped from the recovered content`
      : `ATT&CK ${mitreMatch[1]} was mapped from the recovered content`;
  }
  const lower = String(rule).toLowerCase().replace(/[^a-z0-9]+/g, "_");
  if (RULE_HUMANISER[lower]) return RULE_HUMANISER[lower];
  if (reason && reason.length > 6) return reason;
  return rule.replace(/[_\-:]+/g, " ");
}

// ─── Static MITRE-technique → mitigation map (ADR-0013 §2.2) ──────────────
// Deliberately small and curated. Slice-1 covers the top techniques we
// see in production; slice-2 will extend from the Knowledge Base.
const MITRE_MITIGATIONS = {
  "T1059.001": {
    title: "Restrict PowerShell execution",
    why: "PowerShell was invoked to execute encoded/scripted commands.",
    actions: [
      "Enforce Constrained Language Mode where possible.",
      "Set ExecutionPolicy to AllSigned and require signed scripts.",
      "Enable PowerShell Script-Block Logging (Event ID 4104) + Module Logging.",
      "Alert on `-EncodedCommand`, `-e`, `-enc`, `IEX`, `Invoke-Expression` in command lines.",
    ],
  },
  "T1027": {
    title: "Detect obfuscated payloads",
    why: "Base64/UTF-16/XOR obfuscation was observed — a strong intent-to-evade signal.",
    actions: [
      "Alert on high-entropy strings in command lines (Shannon entropy > 4.5).",
      "Deploy Sigma rules for `FromBase64String`, `atob(`, `System.Convert::FromBase64String`.",
      "Sweep EDR history for the recovered command variant across the fleet.",
    ],
  },
  "T1105": {
    title: "Block ingress tool transfer",
    why: "The payload attempted to download a follow-on stage.",
    actions: [
      "Blocklist the observed URL/IP at the proxy and DNS layers.",
      "Restrict outbound HTTP(S) from workstation subnets to a proxy allowlist.",
      "Alert on `DownloadString`, `Invoke-WebRequest`, `curl`, `wget`, `bitsadmin /transfer` from user-context processes.",
    ],
  },
  "T1140": {
    title: "Deobfuscate / Decode detection",
    why: "Decoded artifacts imply staged execution.",
    actions: [
      "Enable AMSI in Windows Defender for PowerShell + WSH engines.",
      "Sigma: `certutil -urlcache`, `certutil -decode`, `-decodehex`.",
    ],
  },
  "T1071.001": {
    title: "Web-protocol C2 detection",
    why: "HTTP(S) to a suspicious host was observed in the payload.",
    actions: [
      "Sinkhole or block the observed C2 host at proxy + DNS.",
      "Enable JA3/TLS fingerprinting on the perimeter proxy.",
      "Hunt for the URL across proxy logs (past 30 days).",
    ],
  },
  "T1218.010": {
    title: "Signed-binary proxy (regsvr32 / Squiblydoo)",
    why: "regsvr32.exe invoked with `/i:` remote script — classic LOLBin proxy execution.",
    actions: [
      "Alert on `regsvr32.exe /i:http` and `scrobj.dll` invocations from user processes.",
      "Deploy Sigma `win_regsvr32_anomalous.yml`.",
      "AppLocker: block regsvr32 execution from user-writable directories.",
    ],
  },
  "T1218.005": {
    title: "Mshta abuse",
    why: "mshta.exe was used to execute an HTA or remote script.",
    actions: [
      "Alert on `mshta.exe http` and mshta launching from Office parent processes.",
      "AppLocker: deny mshta from user-writable paths.",
    ],
  },
  "T1218.011": {
    title: "Rundll32 abuse",
    why: "rundll32.exe invoked to proxy DLL execution.",
    actions: [
      "Alert on `rundll32.exe` with anomalous DLLs from `%TEMP%`, `%APPDATA%`, network shares.",
      "Sigma: `win_rundll32_ordinal_export.yml`.",
    ],
  },
  "T1053.005": {
    title: "Scheduled Task persistence",
    why: "schtasks / Register-ScheduledTask observed — likely persistence.",
    actions: [
      "Enable Security-Task-Scheduler operational log; alert on Event IDs 106/140/141.",
      "Baseline scheduled tasks and alert on new task creation by non-admin users.",
    ],
  },
  "T1197": {
    title: "BITS jobs abuse",
    why: "bitsadmin observed transferring content — commonly used to bypass proxies.",
    actions: [
      "Alert on bitsadmin /transfer with external URLs.",
      "Log BITS-Client operational events (Event IDs 3, 59, 60).",
    ],
  },
  "T1059.005": {
    title: "VBScript / WScript abuse",
    why: "WScript.Shell / VBS execution observed.",
    actions: [
      "Disable Windows Script Host on workstations where feasible.",
      "AppLocker: deny cscript.exe/wscript.exe from user-writable paths.",
    ],
  },
};

// Universal fallback mitigations when we have IOCs but no mapped techniques.
const GENERIC_MITIGATIONS = [
  {
    severity: "immediate",
    title: "Sweep for the extracted IOCs",
    why: "Any IOC surfaced from a decoded artifact should be hunted across EDR / proxy / DNS logs immediately.",
    actions: [
      "Search EDR command-line telemetry for the recovered command variant (past 30 days).",
      "Search proxy + DNS logs for the observed URLs / IPs / domains.",
      "Search email/mail-gateway logs for the observed sender domains and any related campaigns.",
    ],
  },
  {
    severity: "short-term",
    title: "Preserve forensic evidence",
    why: "Any host that executed this payload should be treated as compromised until proven otherwise.",
    actions: [
      "Isolate the host at the network layer while triage completes.",
      "Collect volatile memory + prefetch + amcache + ScheduledTasks + ShellBags.",
      "Rotate credentials for any interactive session on the host in the past 7 days.",
    ],
  },
];

// ─── Helpers ────────────────────────────────────────────────────────────
const _asArray = (v) => (Array.isArray(v) ? v : []);
const _pickInt = (v) => (typeof v === "number" ? v : parseInt(v, 10) || 0);

function _extractIOCGroups(iocs) {
  if (!iocs) return { grouped: {}, total: 0, provenance: null };
  if (Array.isArray(iocs)) {
    // Already-flat shape.
    const grouped = {};
    iocs.forEach((it) => {
      const k = it.kind || "unknown";
      (grouped[k] = grouped[k] || []).push(it.value);
    });
    return { grouped, total: iocs.length, provenance: null };
  }
  const grouped = {};
  let total = 0;
  for (const [kind, arr] of Object.entries(iocs)) {
    if (kind === "provenance" || kind === "truncation_note") continue;
    if (kind === "hashes" && arr && typeof arr === "object") {
      for (const [algo, hs] of Object.entries(arr)) {
        if (Array.isArray(hs) && hs.length) {
          grouped[algo] = hs.slice(0, 50);
          total += hs.length;
        }
      }
      continue;
    }
    if (Array.isArray(arr) && arr.length) {
      grouped[kind] = arr.slice(0, 50);
      total += arr.length;
    }
  }
  return { grouped, total, provenance: iocs.provenance || null };
}

// ─── Public API ──────────────────────────────────────────────────────────
export function synthesize(result) {
  if (!result || typeof result !== "object") return null;

  // Detect response mode.
  const mode = result.executive_card || result.final_incident_summary || result.mdr_investigation
    ? "auto"
    : "decode";

  // Executive — read verbatim.
  const vc = result.verdict_card || {};
  const ec = result.executive_card || {};
  const executive = {
    mode,
    verdict: vc.verdict_display || vc.label || vc.verdict || ec.verdict_pretty || ec.verdict || result.verdict || "—",
    severity: vc.severity_cap || (mode === "auto" ? ec.severity : null) || null,
    confidence: vc.confidence || vc.confidence_band || ec.confidence || null,
    headline: vc.headline || ec.what_happened?.primary_finding || result.detected_type?.label || "Investigation complete",
    primary_finding: ec.what_happened?.primary_finding || vc.headline || vc.reason || null,
    recovered_behavior: ec.what_happened?.recovered_behavior || null,
    because: _asArray(ec.because),
    // ADR-0012 partial-decode flags.
    partial: result.verdict === "partial_decode" || vc.verdict === "partial_decode",
    cause: result.cause || vc.cause || null,
  };

  // Technical.
  const _safeStr = (v) => (v == null ? "" : typeof v === "string" ? v : (typeof v === "number" || typeof v === "boolean") ? String(v) : (v?.message || v?.text || v?.title || JSON.stringify(v)));
  // Engine field can be an object on some auto-investigate responses
  // (e.g. { orchestrator_reports, version, cache_hits }). Normalise to a
  // short string so the section badge stays readable.
  let _engineLabel = "smart-decoder";
  if (typeof result.engine === "string" && result.engine) {
    _engineLabel = result.engine;
  } else if (result.engine && typeof result.engine === "object") {
    _engineLabel = result.engine.version || result.engine.name || "auto-investigate";
  }
  const technical = {
    engine: _engineLabel,
    chain_ids: _asArray(result.chain_ids).map(_safeStr).filter(Boolean),
    layers: _asArray(result.recipe),
    output: _safeStr(result.output),
    output_raw: _safeStr(result.output_raw || result.output),
    notes: _asArray(result.notes).map(_safeStr).filter(Boolean),
    reached_shellcode: !!result.reached_shellcode,
    detectedType: _safeStr(result.detected_type?.label) || null,
    recoveredLayers: _safeStr(result.recovered_layers) || null,
  };

  // Threat Intel — from ti_shield.
  const tiHits = [];
  const tiShield = result.ti_shield || {};
  for (const layer of _asArray(tiShield.layers)) {
    for (const hit of _asArray(layer.ti_hits)) {
      tiHits.push({
        provider: hit.provider || "internal",
        family: hit.label || hit.family || null,
        subject: hit.subject || null,
        confidence: hit.confidence || null,
      });
    }
  }
  const threatIntel = { hits: tiHits, hasData: tiHits.length > 0 };

  // OSINT — slice-1: only backend-provided providers. Real API-key
  // providers show "not configured" placeholders (ADR-0013 §2.3).
  const osintProviders = [
    { name: "VirusTotal", status: "not_configured" },
    { name: "AbuseIPDB", status: "not_configured" },
    { name: "URLScan", status: "not_configured" },
    { name: "AlienVault OTX", status: "not_configured" },
    { name: "MalwareBazaar", status: "not_configured" },
    { name: "ThreatFox", status: "not_configured" },
    { name: "Shodan", status: "not_configured" },
  ];
  const osint = { providers: osintProviders, hasData: false };

  // IOCs (Lab response has `iocs` object; auto has `final_incident_summary.iocs`).
  const rawIocs = result.iocs || result.final_incident_summary?.iocs || null;
  const iocs = _extractIOCGroups(rawIocs);

  // MITRE.
  const mitreSource = mode === "auto"
    ? _asArray(result.final_incident_summary?.mitre_attack)
    : _asArray(result.mitre);
  const mitre = {
    techniques: mitreSource.map((t) => ({
      id: t.id || t.technique_id || null,
      name: t.name || t.technique || null,
      tactic: t.tactic || null,
      provenance: t.provenance || null,
    })).filter((t) => t.id || t.name),
  };

  // Timeline — one step per decoder layer + one step per assessment stage.
  const timeline = [];
  _asArray(result.trace).forEach((tr, i) => {
    timeline.push({
      step: timeline.length + 1,
      kind: "decode",
      label: tr.op || `Layer ${i + 1}`,
      detail: tr.reason || tr.output_preview || "",
      badge: (tr.output_length ?? "").toString() + " bytes",
    });
  });
  if (iocs.total > 0) {
    timeline.push({
      step: timeline.length + 1,
      kind: "extract",
      label: "IOC Extraction",
      detail: `${iocs.total} indicator${iocs.total === 1 ? "" : "s"} recovered`,
      badge: "ADR-0008",
    });
  }
  if (mitre.techniques.length > 0) {
    timeline.push({
      step: timeline.length + 1,
      kind: "map",
      label: "MITRE ATT&CK Mapping",
      detail: mitre.techniques.map((t) => t.id).filter(Boolean).join(", "),
      badge: `${mitre.techniques.length} technique${mitre.techniques.length === 1 ? "" : "s"}`,
    });
  }
  if (executive.verdict && executive.verdict !== "—") {
    timeline.push({
      step: timeline.length + 1,
      kind: "verdict",
      label: "Verdict Assembly",
      detail: executive.headline,
      badge: executive.confidence ? String(executive.confidence) : "—",
    });
  }

  // Narrative — Executive prose + When/What/Why/Where/How woven into
  // sentences. This is SOC-ticket-style, not a labelled grid. Deterministic
  // — every clause comes from a verified backend field or a small set of
  // fixed templates. No LLM.
  const explainability = vc.explainability || {};
  const contributors = _asArray(explainability.contributors);
  const created = result.created_at || result.timestamp || null;

  // ── MDR-analyst prose composer (ADR-0013 §2.2 Path B · block engine) ──
  //
  // Deterministic invariants preserved:
  //   - Verdict, severity, confidence, IOCs, MITRE, LOLBins → read verbatim.
  //   - Same input → same prose (each block is a pure function of evidence).
  //   - No LLM. No template placeholders. No rule IDs leak to prose.
  //
  // Evidence bundle assembled here → passed to composeAnalystNarrative().

  const _hasTimestamp = !!created;
  const whenPhrase = _hasTimestamp
    ? new Date(created).toISOString().replace("T", " ").slice(0, 19) + " UTC"
    : null;

  const url0 = iocs.grouped.urls?.[0] || null;
  const ip0 = iocs.grouped.ips?.[0] || null;
  const domain0 = iocs.grouped.domains?.[0] || null;
  const rawLolbins = _asArray(result.lolbas);

  // ── Benign-infrastructure classification (all IOCs, not just the first) ──
  // The narrative and recommendations MUST NOT treat legitimate cert-authority
  // CRLs, Windows Update endpoints, or security-vendor consoles as active
  // investigation leads. Classify every URL/domain we see.
  const _allUrlHosts = _asArray(iocs.grouped.urls).map(urlHost).filter(Boolean);
  const _allDomains = _asArray(iocs.grouped.domains);
  const _allHosts = [..._allUrlHosts, ..._allDomains];
  const benignClassifications = _allHosts.map(classifyBenignInfra).filter(Boolean);
  const _benignHostSet = new Set(benignClassifications.map((c) => c.host));
  const hasBenignInfra = benignClassifications.length > 0;
  const allInfraBenign = _allHosts.length > 0 && benignClassifications.length === _allHosts.length;

  // Verdict-severity gating — the narrative tone MUST match the verdict.
  const verdictClass = verdictSeverityClass(executive.verdict, executive.because);

  // MITRE tradecraft phrases (analyst-facing) — collect per technique id,
  // then suppress parent-technique phrases when a child sub-technique of
  // the same family is present to avoid redundant "combines X, Y, and X"
  // clauses in the risk assessment.
  const seenIds = mitre.techniques.map((t) => t.id).filter(Boolean);
  const suppressed = new Set();
  for (const id of seenIds) {
    if (/\./.test(id)) suppressed.add(id.split(".")[0]); // T1218.010 → suppress T1218
  }
  const tradecraftClauses = mitre.techniques
    .filter((t) => t.id && !suppressed.has(t.id))
    .slice(0, 5)
    .map((t) => tradecraftForTechniqueId(t.id))
    .filter(Boolean);
  const uniqueTradecraft = [...new Set(tradecraftClauses)];

  const mitreList = mitre.techniques.slice(0, 6)
    .filter((t) => t.id)
    .map((t) => t.name ? `${t.id} (${t.name})` : t.id);
  const mitreIds = mitre.techniques.map((t) => t.id).filter(Boolean);

  const artifactPhrase = analystArtifactPhrase(technical.detectedType, technical.output);
  // Strip decorative ASCII banners from `output` before quoting or pattern-matching.
  const decodedTextClean = extractCleanDecodedText(technical.output_raw || technical.output);
  const observedBehavior = detectObservedBehavior(decodedTextClean, iocs.grouped.urls, rawLolbins);
  const familyName = familyFromChain(_asArray(result.chain_ids));
  // ADR-0013 slice-6 · synthetic execution chain + delivery-vector inference
  // + optional endpoint-telemetry ingest (host/user/parent — passed through
  // when the caller supplies them; empty when only the artifact was sent).
  const executionChain = extractExecutionChain(decodedTextClean, url0);
  const deliveryVector = familyDeliveryVector(familyName);
  const hostAsset = _safeStr(result.host) || _safeStr(result.focus) || null;
  const userAsset = _safeStr(result.user) || null;
  const parentProc = _safeStr(result.parent_process) || null;

  const evidenceBundle = {
    whenPhrase,
    partial: executive.partial,
    verdictWord: executive.verdict !== "—" ? executive.verdict : "Requires Review",
    verdictClass,
    confidence: executive.confidence,
    severity: executive.severity,
    because: executive.because,
    artifactPhrase,
    detectedTypeLabel: technical.detectedType,
    decodedText: decodedTextClean,
    url0, ip0, domain0,
    lolbins: rawLolbins,
    mitreIds,
    mitreList,
    tradecraftClauses: uniqueTradecraft,
    familyName,
    observedBehavior,
    benignClassifications,
    hasBenignInfra,
    allInfraBenign,
    benignHostSet: _benignHostSet,
    // slice-6
    executionChain,
    deliveryVector,
    hostAsset,
    userAsset,
    parentProc,
    mode,
  };

  const investigationParagraphs = composeAnalystNarrative(evidenceBundle);

  // Executive Summary — length adapts to what the tool actually found.
  // No fixed paragraph count. Only include paragraphs that carry
  // per-input evidence; empty blocks drop out. An analyst writes as much
  // as the evidence warrants, no more.
  const executiveParagraphs = [
    NARRATIVE_BLOCKS.opening(evidenceBundle),
    NARRATIVE_BLOCKS.risk_assessment(evidenceBundle),
  ].filter(Boolean);

  const narrative = {
    executive_paragraphs: executiveParagraphs,
    investigation_paragraphs: investigationParagraphs,
    when: whenPhrase || "at the moment of submission",
    what: NARRATIVE_BLOCKS.opening(evidenceBundle),
    why: NARRATIVE_BLOCKS.risk_assessment(evidenceBundle),
    where: [url0, ip0, domain0].filter(Boolean).join(" · "),
    how: mitreList.join(" · "),
  };

  // Mitigation — prefer backend recommendations (Workspace/MDR path), else
  // fall back to MITRE-technique map (Lab/decode path).
  let mitigation = [];
  const mdrRecs = _asArray(result.mdr_investigation?.recommendations);
  if (mdrRecs.length) {
    mitigation = mdrRecs.map((r) => ({
      severity: r.severity || "recommended",
      title: r.title || "Recommended action",
      why: r.why || r.rationale || "",
      actions: _asArray(r.actions),
    }));
  } else {
    const seen = new Set();
    for (const t of mitre.techniques) {
      const m = MITRE_MITIGATIONS[t.id];
      if (m && !seen.has(t.id)) {
        seen.add(t.id);
        mitigation.push({
          severity: "immediate",
          title: `[${t.id}] ${m.title}`,
          why: m.why,
          actions: m.actions,
        });
      }
    }
    if (iocs.total > 0) mitigation.push(...GENERIC_MITIGATIONS);
  }

  // Evidence — raw explainability + decode chains + unknowns.
  const evidence = {
    explainability,
    decodeChains: _asArray(result.decode_pipeline?.chains),
    rawOutput: result.output_raw || result.output || "",
    unknowns: _asArray(result.unknowns),
    partial_recovery: result.partial_recovery || null,
    trace: _asArray(result.trace),
  };

  return {
    executive,
    technical,
    threatIntel,
    osint,
    iocs,
    mitre,
    timeline,
    narrative,
    mitigation,
    evidence,
    meta: {
      mode,
      partial: executive.partial,
      cause: executive.cause,
      truncationNote: rawIocs?.truncation_note || null,
      provenance: iocs.provenance,
      // ADR-0013 slice-5 · benign-infrastructure classification signal
      // surfaced for the UI badge on the Network section.
      infra_classification: allInfraBenign
        ? "trusted_vendor"
        : (hasBenignInfra ? "mixed" : "unknown"),
      benign_classifications: benignClassifications,
    },
  };
}

export default synthesize;
