/**
 * Build a lightweight attack-graph payload for the KILL-CHAIN view from
 * whatever we already have after DECODE / Run Recipe / AUTO INVESTIGATE,
 * so the graph doesn't have to wait for a full AI describe.
 *
 * The synthesised graph mirrors the shape the backend AI produces:
 *   nodes: [{ id, label, type, tactic?, malicious? }]
 *   edges: [{ from, to, label? }]
 *
 * Ordering follows a canonical MITRE kill-chain:
 *   Initial Access → Execution → Credential Access → Command & Control →
 *   Exfiltration / Impact
 */
export function buildFallbackGraph({ input = "", output = "", analysis = {}, verdict = null }) {
  const nodes = [];
  const edges = [];
  const seen = new Set();

  const push = (n) => {
    if (seen.has(n.id)) return;
    seen.add(n.id);
    nodes.push(n);
  };
  const link = (a, b, label) => {
    if (!a || !b) return;
    edges.push({ from: a, to: b, label });
  };

  // 1) Entry point — raw payload
  const entryId = "raw-input";
  push({
    id: entryId,
    label: input ? `Raw Payload (${input.length}c)` : "Raw Payload",
    type: "file", tactic: "Initial Access",
  });

  // 2) Decode chain — one node per hop
  const chainSteps = Array.isArray(analysis?.chain)
    ? analysis.chain
    : Array.isArray(analysis?.chain?.steps)
      ? analysis.chain.steps
      : [];
  let prev = entryId;
  chainSteps.slice(0, 6).forEach((step, i) => {
    const opName = (typeof step === "string" ? step : step?.op || step?.name || "decode");
    const id = `chain-${i}-${opName.replace(/[^a-z0-9]+/gi, "-")}`;
    push({ id, label: String(opName).toUpperCase(), type: "action",
           tactic: "Execution" });
    link(prev, id, i === 0 ? "decode" : "next");
    prev = id;
  });

  // 3) Decoded payload node (if we have output text)
  let decodedId = null;
  if (output && output !== input) {
    decodedId = "decoded";
    push({
      id: decodedId,
      label: `Decoded (${output.length}c)`,
      type: "script", tactic: "Execution",
    });
    link(prev, decodedId, "yields");
    prev = decodedId;
  }

  // 4) LOLBins as process nodes
  const lolbins = analysis?.lolbins || [];
  lolbins.slice(0, 6).forEach((l) => {
    const bin = l.binary || l.bin || "lolbin";
    const id = `lolbin-${bin.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
    push({ id, label: bin, type: "process",
           tactic: "Defense Evasion", malicious: true });
    link(prev, id, "spawns");
  });

  // 5) IOCs (URLs / IPs / domains / hashes) — one node each, capped
  const iocs = analysis?.iocs || {};
  const iocGroups = [
    { key: "urls",    type: "url",    tactic: "Command and Control", malicious: true, label: "URL" },
    { key: "ips",     type: "ip",     tactic: "Command and Control", malicious: true, label: "IP" },
    { key: "domains", type: "domain", tactic: "Command and Control", malicious: true, label: "Domain" },
    { key: "hashes",  type: "hash",   tactic: "Execution",            malicious: true, label: "Hash" },
    { key: "emails",  type: "email",  tactic: "Initial Access",       malicious: false, label: "Email" },
  ];
  // Safely stringify potentially-object IOC values so nothing becomes
  // "[object Object]" in the graph (Feb 2026 · RMM screenshot fix).
  const toStr = (v) => {
    if (v == null) return "";
    if (typeof v === "string") return v;
    if (typeof v === "number" || typeof v === "boolean") return String(v);
    // object → prefer a semantic field, never fall back to raw String(obj)
    return v.value || v.ioc || v.url || v.ip || v.domain || v.hash || v.email
        || v.text || v.label || "";
  };
  iocGroups.forEach(({ key, type, tactic, malicious }) => {
    const list = Array.isArray(iocs[key]) ? iocs[key] : [];
    list.slice(0, 3).forEach((val, idx) => {
      const s = toStr(val);
      if (!s) return;
      const short = s.length > 22 ? s.slice(0, 20) + "…" : s;
      const id = `ioc-${key}-${idx}`;
      push({ id, label: short, type, tactic, malicious });
      link(prev, id, key.slice(0, -1));
    });
  });

  // 6) MITRE technique chips — humanise T-codes so analysts can read the
  // graph without a MITRE cheat-sheet open. Feb 2026 · RMM readability fix.
  const MITRE_LABELS = {
    "T1059":     "Command & Scripting",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows CMD",
    "T1059.005": "Visual Basic",
    "T1078":     "Valid Accounts",
    "T1078.002": "Domain Accounts",
    "T1078.004": "Cloud Accounts",
    "T1021":     "Remote Services",
    "T1021.001": "RDP",
    "T1021.002": "SMB / Admin Shares",
    "T1021.006": "WinRM",
    "T1105":     "Ingress Tool Transfer",
    "T1218":     "System Binary Proxy Execution",
    "T1218.010": "Regsvr32",
    "T1218.011": "Rundll32",
    "T1140":     "Deobfuscate / Decode Files",
    "T1562.001": "Impair Defenses (Defender)",
    "T1555":     "Credentials from Password Stores",
    "T1555.003": "Browser Credentials",
    "T1555.004": "Windows Credential Manager",
    "T1518.001": "Security Software Discovery",
    "T1057":     "Process Discovery",
    "T1082":     "System Info Discovery",
    "T1049":     "Network Config Discovery",
    "T1071":     "Application-Layer Protocol",
    "T1071.001": "Web Protocols (C2)",
    "T1027":     "Obfuscated Files / Info",
    "T1204.002": "Malicious File Execution",
  };
  const mitre = Array.isArray(analysis?.mitre) ? analysis.mitre
              : Array.isArray(analysis?.mitre_techniques) ? analysis.mitre_techniques
              : [];
  mitre.slice(0, 5).forEach((t, i) => {
    // Harden against unexpected object shapes (Feb 2026 · [OBJECT OBJECT] fix)
    let tid = "T?";
    if (typeof t === "string") tid = t;
    else if (t && typeof t === "object") {
      tid = t.id || t.technique_id || t.tid || t.technique || t.code || "T?";
      if (typeof tid !== "string") tid = "T?";
    }
    const human = MITRE_LABELS[tid] || tid;
    const label = MITRE_LABELS[tid] ? `${tid} · ${human}` : tid;
    const id = `mitre-${i}-${tid}`;
    push({ id, label, type: "action", tactic: "Discovery" });
    link(prev, id, "attributed");
  });

  // 7) Crown jewel = verdict node
  const vLabel = (verdict?.label || verdict?.verdict || analysis?.ai_verdict || "Verdict").toString();
  const vId = "verdict";
  push({ id: vId, label: vLabel.toUpperCase(), type: "action",
         tactic: "Impact",
         malicious: /malicious|suspicious/i.test(vLabel) });
  link(prev, vId, "impact");

  return { nodes, edges };
}
