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

// ─── ADR-0013 §2.2 · Deterministic Narrative Engine (Path B) ─────────────
//
// Composable evidence-block architecture (operator-approved 2026-02-28):
//   opening → execution → obfuscation → network → payload_stage →
//   persistence → credential → malware_context → risk_assessment →
//   recommendations
//
// Each block has multiple variants selected by observable evidence. Empty
// blocks are dropped. The result is combinatorial variation — the same
// payload family produces the same prose (deterministic invariant), but
// two payloads with different evidence produce genuinely different prose.
// No LLM, no template placeholders, no rule IDs leaking to prose.

const NARRATIVE_BLOCKS = {
  // ── OPENING ──────────────────────────────────────────────────────────
  opening: (ev) => {
    const when = ev.whenPhrase ? `On ${ev.whenPhrase}` : "During this investigation";
    const artifact = ev.artifactPhrase;
    if (ev.partial) {
      return `${when}, NivXRay analyzed ${artifact} that decoded partially before the byte stream became unreadable.`;
    }
    if (ev.observedBehavior) {
      return `${when}, NivXRay analyzed ${artifact} that decoded into a command which ${ev.observedBehavior}.`;
    }
    if (ev.detectedTypeLabel) {
      return `${when}, NivXRay analyzed ${artifact} and identified it as ${ev.detectedTypeLabel}.`;
    }
    return `${when}, NivXRay analyzed ${artifact} and processed it through the deterministic decoding pipeline.`;
  },

  // ── EXECUTION ────────────────────────────────────────────────────────
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

  // ── OBFUSCATION ──────────────────────────────────────────────────────
  obfuscation: (ev) => {
    const clauses = [];
    const has = (name) => ev.mitreIds.some((id) => id === name || id.startsWith(name + "."));
    if (has("T1027.010") || /encoded/i.test(ev.detectedTypeLabel || "")) clauses.push("Base64 encoding of the command line");
    if (/utf-?16/i.test(ev.detectedTypeLabel || "") || /-encodedcommand/i.test(ev.decodedText || "")) clauses.push("UTF-16LE string encoding, which is the standard PowerShell -EncodedCommand format");
    if (has("T1140")) clauses.push("runtime deobfuscation of the payload before execution");
    if (has("T1027.002")) clauses.push("packing of the executable content");
    if (!clauses.length) return null;
    if (clauses.length === 1) return `The artifact uses ${clauses[0]} to conceal its intent from static command-line signatures.`;
    return `The artifact combines ${clauses.slice(0, -1).join(", ")} and ${clauses.slice(-1)} to conceal its intent from static command-line signatures.`;
  },

  // ── NETWORK ──────────────────────────────────────────────────────────
  network: (ev) => {
    const parts = [];
    if (ev.url0) parts.push(`the URL ${ev.url0}`);
    if (ev.ip0) parts.push(`the IP address ${ev.ip0}`);
    if (ev.domain0 && !ev.url0?.includes(ev.domain0)) parts.push(`the domain ${ev.domain0}`);
    if (parts.length) {
      const list = parts.length === 1 ? parts[0] : (parts.slice(0, -1).join(", ") + " and " + parts.slice(-1));
      return `Network indicators recovered from the payload include ${list}. These should be treated as active investigation leads until proven benign.`;
    }
    if (ev.partial) {
      return "No outbound infrastructure was recoverable from the readable bytes; if the corrupted portion contained a URL, it did not survive into the analysable prefix.";
    }
    return "No outbound network indicators were recovered from the analysed bytes.";
  },

  // ── PAYLOAD STAGE ────────────────────────────────────────────────────
  payload_stage: (ev) => {
    const t = (ev.decodedText || "").toLowerCase();
    const has = (name) => ev.mitreIds.some((id) => id === name || id.startsWith(name + "."));
    const dl = /downloadstring|invoke-webrequest|iwr\b|wget\b|curl\b|bitsadmin\b|certutil.*-urlcache/i.test(t);
    const iex = /\biex\b|invoke-expression/i.test(t);
    if (dl && iex) {
      return "The command implements a classic download-and-execute staging workflow: it retrieves a follow-on script over HTTP(S) and evaluates it in memory via Invoke-Expression, avoiding a payload on disk.";
    }
    if (dl && !iex) {
      return "The command retrieves a follow-on payload from a remote host; whether that payload is executed on-host depends on the recovered script and downstream behaviour on the endpoint.";
    }
    if (has("T1105") && !dl) {
      return "The behaviour maps to ingress tool transfer (T1105): the payload is designed to bring additional content into the environment for later execution.";
    }
    if (iex && !dl) {
      return "The command evaluates dynamically-constructed content via Invoke-Expression, executing code that is not visible in the command line itself.";
    }
    return null;
  },

  // ── PERSISTENCE ──────────────────────────────────────────────────────
  persistence: (ev) => {
    const has = (name) => ev.mitreIds.some((id) => id === name || id.startsWith(name + "."));
    const bits = [];
    if (has("T1053")) bits.push("Scheduled Task creation (T1053) suggests attacker intent to persist across reboots");
    if (has("T1547.001")) bits.push("Run-key modification (T1547.001) indicates a per-user autostart persistence attempt");
    if (has("T1543")) bits.push("Service creation or modification (T1543) points to system-level persistence");
    if (has("T1136")) bits.push("Local account creation (T1136) is consistent with a persistence-and-access-preservation objective");
    if (bits.length) return bits.join(". ") + ".";
    if (ev.mitreIds.length > 0) return "No persistence behaviour was recovered from the analysed content.";
    return null;
  },

  // ── CREDENTIAL ACCESS ────────────────────────────────────────────────
  credential: (ev) => {
    const has = (name) => ev.mitreIds.some((id) => id === name || id.startsWith(name + "."));
    const bits = [];
    if (has("T1003")) bits.push("OS-credential-dumping activity (T1003) was recovered — LSASS or SAM access should be assumed");
    if (has("T1555")) bits.push("Credential store access (T1555) suggests browser/password-manager targeting");
    if (has("T1552")) bits.push("Credentials-in-files access (T1552) indicates an unattended-credentials hunt");
    if (bits.length) return bits.join(". ") + ".";
    return null;
  },

  // ── MALWARE CONTEXT ──────────────────────────────────────────────────
  malware_context: (ev) => {
    if (ev.familyName) {
      return `The decoder chain structurally matched ${ev.familyName}-family tradecraft. Family match is a structural signal — it means the artifact resembles known ${ev.familyName} samples, not a definitive identification.`;
    }
    return null;
  },

  // ── RISK ASSESSMENT ──────────────────────────────────────────────────
  risk_assessment: (ev) => {
    const tcs = ev.tradecraftClauses;
    const verdict = ev.verdictWord;
    const confidence = ev.confidence;
    const conf = (confidence !== null && confidence !== undefined) ? ` (confidence ${confidence}/100)` : "";
    if (tcs.length >= 2) {
      const list = tcs.length === 1 ? tcs[0] : tcs.slice(0, -1).join(", ") + (tcs.length > 2 ? "," : "") + " and " + tcs.slice(-1);
      return `Because the recovered content combines ${list}, the activity is assessed as ${verdict}${conf} and warrants further investigation.`;
    }
    if (tcs.length === 1) {
      return `Because the recovered content demonstrates ${tcs[0]}, the activity is assessed as ${verdict}${conf} and warrants further investigation.`;
    }
    if (ev.partial) {
      return `Because only a partial recovery was possible, the activity is assessed as ${verdict}${conf}; severity is intentionally capped and derived evidence carries the provenance=partial_recovery label. A definitive assessment is not possible from the readable prefix alone.`;
    }
    return `The activity is assessed as ${verdict}${conf}.`;
  },

  // ── RECOMMENDATIONS ──────────────────────────────────────────────────
  recommendations: (ev) => {
    const bits = [];
    if (ev.url0) bits.push(`Determine whether ${ev.url0} was successfully retrieved or executed on the affected host`);
    if (ev.ip0) bits.push(`Block outbound communications with ${ev.ip0} at the proxy and DNS layers pending confirmation`);
    if (ev.lolbins.length) {
      const lb = [...new Set(ev.lolbins.map(lolbinName).filter(Boolean))].slice(0, 3).join(", ");
      if (lb) bits.push(`Search endpoint telemetry for additional invocations of ${lb} matching this pattern`);
    } else if (/powershell|encoded/i.test(ev.decodedText || ev.detectedTypeLabel || "")) {
      bits.push("Search endpoint telemetry for additional PowerShell -EncodedCommand executions across the fleet");
    }
    bits.push("Review proxy, DNS, and EDR telemetry for related hosts communicating with the same infrastructure");
    if (ev.url0 || ev.lolbins.length) bits.push("Acquire the downloaded payload (if retained) for further malware analysis");
    if (ev.partial) bits.push("Preserve the original artifact and any surrounding logs — the corrupted portion may be recoverable from a different source");
    if (!bits.length) return null;
    return `NivXRay recommends that analysts: ${bits.join("; ")}.`;
  },
};

function composeAnalystNarrative(evidence) {
  const order = [
    "opening", "execution", "obfuscation", "network", "payload_stage",
    "persistence", "credential", "malware_context", "risk_assessment",
    "recommendations",
  ];
  const paragraphs = [];
  for (const key of order) {
    const fn = NARRATIVE_BLOCKS[key];
    if (!fn) continue;
    const out = fn(evidence);
    if (out && typeof out === "string" && out.length > 0) paragraphs.push(out);
  }
  return paragraphs;
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

  const evidenceBundle = {
    whenPhrase,
    partial: executive.partial,
    verdictWord: executive.verdict !== "—" ? executive.verdict : "Requires Review",
    confidence: executive.confidence,
    severity: executive.severity,
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
  };

  const investigationParagraphs = composeAnalystNarrative(evidenceBundle);

  // Executive Summary = Opening + Risk Assessment (compact, high-signal).
  // Investigation Summary = full block sequence (detailed narrative).
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
    },
  };
}

export default synthesize;
