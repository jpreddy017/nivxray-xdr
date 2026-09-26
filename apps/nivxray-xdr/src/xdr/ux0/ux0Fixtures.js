/**
 * E2E-UX0 · DESIGN-STATE FIXTURES.
 *
 * These are NOT production data and are never written anywhere. They exist so
 * the owner can review layout, density, hierarchy and interaction before any
 * production page is touched. Every surface that renders them is badged
 * `DESIGN-STATE` in the UI.
 *
 * The Command Intelligence panel deliberately does NOT use fixtures — it calls
 * the real `POST /api/analyze/command` so the composition is proven against the
 * real contract.
 */

export const INCIDENT = {
  id: "INC-2291",
  title: "Credential theft via obfuscated PowerShell on FIN-WS-014",
  severity: "critical",
  verdict: "malicious",
  confidence: 0.91,
  priority: { code: "P1", label: "High business impact" },
  lifecycle: "in_progress",
  assessment:
    "Obfuscated PowerShell reconstructed a payload at runtime and executed it " +
    "in memory on one finance workstation, then read browser credential " +
    "stores. No outbound exfiltration has been observed.",
  facts: [
    { k: "Status",      v: "In progress" },
    { k: "Assignee",    v: "a.rahman" },
    { k: "SLA",         v: "02:14 left", warn: true },
    { k: "First seen",  v: "14 Jun 09:22:11Z" },
    { k: "Last activity", v: "14 Jun 11:48:02Z" },
    { k: "Assets",      v: "3" },
    { k: "Detections",  v: "4" },
  ],
  correlation: {
    detections: 4,
    rules: 2,
    pivot: "identity + process ancestry (strong identifier)",
    sources: ["Sysmon", "EDR", "DNS"],
    sourcesConnected: 3,
    sourcesTotal: 5,
  },
};

export const METRICS = [
  { key: "assets", label: "Assets", value: 3,
    sub: "1 malicious · 2 affected", kind: "assets" },
  { key: "observables", label: "Observables", value: 17,
    sub: "4 malicious · 3 suspicious", kind: "observables" },
  { key: "indicators", label: "Indicators", value: 6,
    sub: "2 malicious · 4 unscored", kind: "indicators" },
];

export const STAGES = [
  { key: "initial-access", label: "Initial access", state: "done" },
  { key: "execution",      label: "Execution",      state: "active" },
  { key: "evasion",        label: "Defense evasion", state: "done" },
  { key: "discovery",      label: "Discovery",      state: "pending" },
  { key: "impact",         label: "Impact",         state: "pending" },
];

export const CLAIMS = [
  {
    stage: "Initial access",
    severity: "high",
    claim: "A macro-enabled attachment opened from Outlook spawned a shell.",
    basis: "Sysmon EventID 1 · process 6120 · parent outlook.exe · FIN-WS-014",
    provenance: "observed",
    evidence: 2,
    proof: [
      { label: "process 6120", kind: "process" },
      { label: "FIN-WS-014", kind: "asset" },
    ],
  },
  {
    stage: "Execution",
    severity: "critical",
    claim:
      "powershell.exe launched with -ExecutionPolicy bypass and reconstructed " +
      "its payload from string fragments at runtime before executing it.",
    basis: "Sysmon EventID 1 · process 7412 · FIN-WS-014",
    provenance: "reconstructed",
    evidence: 3,
    open: true,
    proof: [
      { label: "command artifact", kind: "command" },
      { label: "process 7412", kind: "process" },
      { label: "parent: outlook.exe", kind: "process" },
    ],
  },
  {
    stage: "Defense evasion",
    severity: "high",
    claim: "AMSI was disabled in-process before the payload was executed.",
    basis: "Decoded layer 1 · AmsiUtils reflection · amsiInitFailed",
    provenance: "decoded",
    evidence: 1,
    proof: [{ label: "decoded layer 1", kind: "command" }],
  },
  {
    stage: "Discovery",
    severity: "medium",
    claim: "Browser credential stores were enumerated on the local profile.",
    basis: "Sysmon EventID 11 · 4 file reads under \\User Data\\Default\\",
    provenance: "observed",
    evidence: 4,
    proof: [{ label: "4 file reads", kind: "evidence" }],
  },
];

export const EVIDENCE = [
  { id: "e1", verdict: "malicious", entity: "powershell.exe -ExecutionPolicy bypass -c \"$EbaYA; …\"",
    type: "command", seen: "09:22:14Z", source: "Sysmon", remediation: "not required",
    provenance: "observed", kind: "command" },
  { id: "e2", verdict: "malicious", entity: "185.199.108.153",
    type: "ip", seen: "09:22:51Z", source: "Zeek", remediation: "blocked",
    provenance: "observed", kind: "observable" },
  { id: "e3", verdict: "suspicious", entity: "C:\\Users\\Public\\svc-update.ps1",
    type: "file", seen: "09:23:02Z", source: "Sysmon", remediation: "quarantined",
    provenance: "observed", kind: "file" },
  { id: "e4", verdict: "suspicious", entity: "cdn-assets-eu.workers.dev",
    type: "domain", seen: "09:23:05Z", source: "DNS", remediation: "pending",
    provenance: "observed", kind: "observable" },
  { id: "e5", verdict: "benign", entity: "outlook.exe",
    type: "process", seen: "09:21:58Z", source: "Sysmon", remediation: "not required",
    provenance: "observed", kind: "process" },
  { id: "e6", verdict: "malicious", entity: "$BnWKB (runtime-assembled Base64)",
    type: "artifact", seen: "09:22:14Z", source: "Command Intelligence",
    remediation: "not applicable", provenance: "reconstructed", kind: "command" },
];

export const ENTITIES = [
  { id: "a1", name: "FIN-WS-014", type: "endpoint", role: "primary",
    risk: 88, os: "Windows 11 23H2", owner: "a.silva", verdict: "malicious" },
  { id: "a2", name: "a.silva@nivxray.io", type: "identity", role: "affected",
    risk: 62, os: "—", owner: "Finance", verdict: "suspicious" },
  { id: "a3", name: "FIN-FS-02", type: "server", role: "touched",
    risk: 21, os: "Windows Server 2022", owner: "infra", verdict: "benign" },
];

export const ACTIVITY = [
  { t: "11:48:02Z", who: "a.rahman", role: "Tier 2 analyst",
    what: "Added note: payload reconstruction is partial — awaiting decoder R-4.",
    basis: "manual" },
  { t: "10:12:44Z", who: "Automation", role: "rule: contain-on-credential-access",
    what: "Isolated FIN-WS-014 from the network. Approval: auto (policy scope).",
    basis: "policy" },
  { t: "09:41:19Z", who: "a.rahman", role: "Tier 2 analyst",
    what: "Assigned incident to self and moved status to In progress.",
    basis: "manual" },
  { t: "09:23:10Z", who: "Correlation engine", role: "system",
    what: "Correlated 4 detections into INC-2291 on identity + process ancestry.",
    basis: "engine" },
];

/** The sample the Command Intelligence panel analyses by default. */
export const CI_SAMPLE =
  'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe ' +
  '-ExecutionPolicy bypass -c "$EbaYA; ' +
  "$BnWKB = 'ZWxlYXN' + 9 + 'lDQppcGNvbmZpZyAvcmVuZ' + 9 + " +
  "'XcNCm5ldHNoIHdpbnNvY2sgcmVzZXQNCg=='; " +
  '$EbaYA = [System.Text.Encoding]::UTF8.GetString(' +
  '[Convert]::FromBase64String($BnWKB)); ' +
  'Invoke-Command -ScriptBlock ([ScriptBlock]::Create($EbaYA))"';
