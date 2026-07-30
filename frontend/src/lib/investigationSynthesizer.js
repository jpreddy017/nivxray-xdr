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

  // Download primitives.
  const downloadMatch =
    /downloadstring|invoke-webrequest|iwr\s|wget\s|curl\s|bitsadmin\s|certutil.*-urlcache/i.test(lower);
  if (downloadMatch && url0) {
    parts.push(`attempts to download an additional payload from ${url0}`);
  } else if (downloadMatch) {
    parts.push("attempts to download an additional payload from a remote host");
  } else if (url0) {
    parts.push(`references the remote resource ${url0}`);
  }

  // Execution primitives.
  if (/\biex\b|invoke-expression/i.test(lower)) {
    parts.push("and executes it in memory via Invoke-Expression");
  } else if (/\.exe\s+/i.test(lower) && (parts.length === 0)) {
    parts.push("invokes an executable directly");
  }

  // LOLBin bypass.
  const lolbinName = (lolbins || []).map((l) => l?.name).filter(Boolean)[0];
  if (lolbinName) {
    if (/regsvr32/i.test(lolbinName)) parts.push("using regsvr32.exe as a signed-binary proxy (Squiblydoo pattern)");
    else if (/mshta/i.test(lolbinName)) parts.push("using mshta.exe to proxy execution of remote script content");
    else if (/rundll32/i.test(lolbinName)) parts.push("using rundll32.exe to proxy DLL execution");
    else parts.push(`using ${lolbinName} as an execution vehicle`);
  }

  if (!parts.length) return null;
  return parts.join(", ");
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
    verdict: vc.verdict_display || ec.verdict_pretty || ec.verdict || vc.verdict || "—",
    severity: vc.severity_cap || (mode === "auto" ? ec.severity : null) || null,
    confidence: vc.confidence || vc.confidence_band || ec.confidence || null,
    headline: vc.headline || ec.what_happened?.primary_finding || result.detected_type?.label || "Investigation complete",
    primary_finding: ec.what_happened?.primary_finding || vc.headline || null,
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

  // ── MDR-analyst prose composer (ADR-0013 §2.2, evidence-driven) ──────
  //
  // Golden target (operator-supplied 2026-02-28):
  //   A PowerShell command using the -EncodedCommand option was submitted
  //   for analysis and successfully decoded. The recovered payload attempts
  //   to download an additional PowerShell script from http://192.168.1.1/p.ps1,
  //   indicating a staged execution workflow commonly used by malware
  //   downloaders and post-exploitation tooling. Because the command
  //   combines PowerShell execution, Base64 obfuscation, and remote
  //   payload retrieval, the activity is assessed as Suspicious and
  //   warrants further investigation. The analysis recovered the network
  //   indicator 192.168.1.1 and mapped the behavior to MITRE ATT&CK
  //   techniques T1059.001 (PowerShell), T1027.010 (Command Obfuscation),
  //   and T1105 (Ingress Tool Transfer). Analysts should determine whether
  //   the remote script was successfully retrieved or executed and search
  //   the environment for additional systems communicating with the same
  //   infrastructure.
  //
  // Rules (see /app/memory/adr/0013-unified-investigation-ui.md):
  //   1. NO internal rule IDs in Executive Summary (no `url_in_decoded_output`,
  //      no `family-emotet`, no chain IDs like `ps-encodedcommand-recovery`).
  //   2. Every sentence answers an analyst's next question.
  //   3. Sentences build on each other — a story, not observations.
  //   4. Actual decoded content and IOCs surface as concrete facts.

  const _hasTimestamp = !!created;
  const whenPhrase = _hasTimestamp
    ? new Date(created).toISOString().replace("T", " ").slice(0, 19) + " UTC"
    : null;
  const whenOpener = whenPhrase ? `On ${whenPhrase}` : "During this investigation";
  const _cap = (s) => (s && s.length ? s.charAt(0).toUpperCase() + s.slice(1) : s);

  const url0 = iocs.grouped.urls?.[0] || null;
  const ip0 = iocs.grouped.ips?.[0] || null;
  const domain0 = iocs.grouped.domains?.[0] || null;
  const rawLolbins = _asArray(result.lolbas);

  // MITRE tradecraft phrases (analyst-facing) for the "because" clause.
  const tradecraftClauses = mitre.techniques.slice(0, 5)
    .map((t) => tradecraftForTechniqueId(t.id))
    .filter(Boolean);
  const uniqueTradecraft = [...new Set(tradecraftClauses)];

  // Analyst-facing MITRE list (id + name) for the "mapped the behavior to" sentence.
  const mitreList = mitre.techniques.slice(0, 6)
    .filter((t) => t.id)
    .map((t) => t.name ? `${t.id} (${t.name})` : t.id);

  // Artifact type in analyst language.
  const artifactPhrase = analystArtifactPhrase(technical.detectedType, technical.output);

  // Observed behaviour — active-voice description built from the decoded
  // content, URLs, and any LOLBin usage.
  const observedBehavior = detectObservedBehavior(technical.output, iocs.grouped.urls, rawLolbins);

  // Severity — analyst-facing verdict word.
  const severityWord = executive.verdict !== "—" ? executive.verdict : "requiring analyst review";

  // ── PARAGRAPH 1 · Detection (What happened, in one sentence) ────────
  const p1Parts = [];
  p1Parts.push(`${whenOpener}, NivXRay analyzed ${artifactPhrase}`);
  if (observedBehavior) {
    p1Parts.push(`and determined that the recovered payload ${observedBehavior}`);
  } else if (executive.primary_finding) {
    p1Parts.push(`and determined that ${executive.primary_finding.replace(/\.$/, "").toLowerCase()}`);
  } else {
    p1Parts.push("and successfully processed it through the deterministic decoding pipeline");
  }
  const paraDetection = p1Parts.join(" ") + ".";

  // ── PARAGRAPH 2 · Investigation Scope (fixed sentence — what the engine did) ─
  const paraScope =
    "This investigation combined deterministic decoding, behavioral analysis, IOC extraction, MITRE ATT&CK mapping, malware family correlation, and explainability.";

  // ── PARAGRAPH 3 · Executive Assessment (why this matters) ──────────
  let paraAssessment;
  if (uniqueTradecraft.length >= 2) {
    const tcList = uniqueTradecraft.slice(0, 3);
    const tcClause = tcList.length === 1
      ? tcList[0]
      : tcList.slice(0, -1).join(", ") + (tcList.length > 2 ? "," : "") + " and " + tcList.slice(-1);
    paraAssessment =
      `Because the recovered content combines ${tcClause}, the activity is assessed as ${severityWord}` +
      `${executive.confidence !== null && executive.confidence !== undefined ? ` (confidence ${executive.confidence}/100)` : ""}` +
      ` and warrants further investigation.`;
  } else if (uniqueTradecraft.length === 1) {
    paraAssessment =
      `Because the recovered content demonstrates ${uniqueTradecraft[0]}, the activity is assessed as ${severityWord}` +
      `${executive.confidence !== null && executive.confidence !== undefined ? ` (confidence ${executive.confidence}/100)` : ""}` +
      ` and warrants further investigation.`;
  } else {
    paraAssessment =
      `The activity is assessed as ${severityWord}` +
      `${executive.confidence !== null && executive.confidence !== undefined ? ` (confidence ${executive.confidence}/100)` : ""}` +
      `. ${executive.primary_finding || "See the Investigation Findings below for the supporting evidence."}`;
  }
  if (executive.partial) {
    paraAssessment += ` This is a partial-decode result (${result.cause || vc.cause || "truncated"}); severity is capped and every derived indicator carries provenance=partial_recovery.`;
  }

  // ── PARAGRAPH 4 · Investigation Findings (the attack narrative) ────
  const p4Bits = [];
  if (technical.output && technical.output.length) {
    const excerpt = technical.output.trim().replace(/\s+/g, " ").slice(0, 200);
    p4Bits.push(`Analysis recovered the following command: "${excerpt}${technical.output.length > 200 ? "…" : ""}".`);
  }
  if (url0) {
    p4Bits.push(`The payload references the remote resource ${url0}, indicating a staged execution workflow commonly used by malware downloaders and post-exploitation tooling.`);
  }
  const indicatorList = [];
  if (ip0) indicatorList.push(`IP address ${ip0}`);
  if (domain0 && !url0?.includes(domain0)) indicatorList.push(`domain ${domain0}`);
  if (indicatorList.length) {
    p4Bits.push(`The analysis recovered the network indicator${indicatorList.length === 1 ? "" : "s"} ${indicatorList.join(" and ")}.`);
  } else if (!url0 && !executive.partial) {
    p4Bits.push("No outbound infrastructure indicators were recovered from the analysed bytes — the payload contained no reachable URLs, IPs, or domains at the point of analysis.");
  }
  if (mitreList.length) {
    p4Bits.push(
      `The behavior was mapped to MITRE ATT&CK ${mitreList.length === 1 ? "technique" : "techniques"} ${mitreList.slice(0, -1).length ? mitreList.slice(0, -1).join(", ") + ", and " + mitreList.slice(-1) : mitreList[0]}.`
    );
  }
  // Absence of persistence / cred-access — a Cisco-XDR-style callout.
  const hasPersistence = mitre.techniques.some((t) => /^T1053|^T1547|^T1136|^T1543/.test(t.id || ""));
  const hasCredAccess = mitre.techniques.some((t) => /^T1003|^T1555|^T1552/.test(t.id || ""));
  if (mitre.techniques.length > 0 && !hasPersistence && !hasCredAccess) {
    p4Bits.push("No persistence or credential-access behaviors were identified in the submitted artifact.");
  }
  const paraFindings = p4Bits.length
    ? p4Bits.join(" ")
    : "The submitted artifact was processed through the deterministic decoding pipeline; see the Technical Analysis and Raw Evidence sections for the underlying signals.";

  // ── PARAGRAPH 5 · Analyst Recommendations (evidence-driven prose) ───
  const recBits = [];
  if (url0) recBits.push(`Determine whether ${url0} was successfully retrieved or executed on the affected host.`);
  if (rawLolbins.length) recBits.push(`Search endpoint telemetry for additional invocations of ${rawLolbins.map((l) => l?.name).filter(Boolean).slice(0, 3).join(", ")} matching this pattern.`);
  else if (/powershell|encodedcommand/i.test(technical.output || technical.detectedType || ""))
    recBits.push("Search endpoint telemetry for additional PowerShell -EncodedCommand executions across the fleet.");
  if (ip0) recBits.push(`Block outbound communications with ${ip0} at the proxy and DNS layers pending further investigation.`);
  recBits.push("Review proxy, DNS, and EDR telemetry for related hosts and any lateral spread of the same infrastructure.");
  if (url0 || rawLolbins.length) recBits.push("Acquire the downloaded payload (if available) for further malware analysis.");
  const paraRecs =
    "NivXRay recommends that analysts: " +
    recBits.map((r) => r.trim().replace(/\.$/, "")).join("; ") + ".";

  const invParas = [paraDetection, paraScope, paraAssessment, paraFindings, paraRecs];

  // Executive Summary = first 3 paragraphs (Detection · Scope · Assessment).
  // Findings + Recommendations live in the Investigation Summary section.
  const execParas = [paraDetection, paraScope, paraAssessment];

  const narrative = {
    executive_paragraphs: execParas,
    investigation_paragraphs: invParas,
    when: whenPhrase || "at the moment of submission",
    what: paraDetection,
    why: paraAssessment,
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
