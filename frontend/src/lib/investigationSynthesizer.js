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
  const technical = {
    engine: result.engine || "smart-decoder",
    chain_ids: _asArray(result.chain_ids),
    layers: _asArray(result.recipe),
    output: result.output || "",
    output_raw: result.output_raw || result.output || "",
    notes: _asArray(result.notes),
    reached_shellcode: !!result.reached_shellcode,
    detectedType: result.detected_type?.label || null,
    recoveredLayers: result.recovered_layers || null,
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

  // Narrative — When / What / Why / Where / How, deterministic.
  const explainability = vc.explainability || {};
  const contributors = _asArray(explainability.contributors);
  const created = result.created_at || result.timestamp || null;

  const whereBits = [];
  if (iocs.grouped.urls?.length) whereBits.push(`URL: ${iocs.grouped.urls[0]}`);
  if (iocs.grouped.ips?.length) whereBits.push(`IP: ${iocs.grouped.ips[0]}`);
  if (iocs.grouped.domains?.length) whereBits.push(`Domain: ${iocs.grouped.domains[0]}`);
  if (iocs.grouped.file_paths?.length) whereBits.push(`Path: ${iocs.grouped.file_paths[0]}`);

  const howBits = [];
  const topTechniques = mitre.techniques.slice(0, 3);
  topTechniques.forEach((t) => {
    if (t.id) howBits.push(`${t.id}${t.name ? ` (${t.name})` : ""}`);
  });
  const lolbins = _asArray(result.lolbas);
  lolbins.slice(0, 3).forEach((l) => {
    if (l.name) howBits.push(`LOLBin: ${l.name}`);
  });

  const narrative = {
    when: created
      ? new Date(created).toISOString().replace("T", " ").slice(0, 19) + " UTC"
      : "Observed at the moment the artifact was submitted to the platform.",
    what: [
      executive.verdict !== "—" ? `Verdict: ${executive.verdict}` : null,
      executive.primary_finding,
      executive.recovered_behavior,
      technical.detectedType,
    ].filter(Boolean).join(" · ") || "Artifact processed; see Technical Analysis for detail.",
    why: contributors.length
      ? contributors.slice(0, 5).map((c) => c.reason || c.rule || String(c)).join(" · ")
      : executive.because.length
        ? executive.because.slice(0, 3).join(" · ")
        : "No explainability contributors surfaced; see Technical Analysis for the raw signal.",
    where: whereBits.length ? whereBits.join(" · ") : "No infrastructure indicators recovered from this artifact.",
    how: howBits.length
      ? howBits.join(" · ")
      : (technical.chain_ids.length
          ? `Decoded through ${technical.chain_ids.join(" → ")}.`
          : "Decoded and analysed by the deterministic engine."),
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
