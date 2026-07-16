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
  iocGroups.forEach(({ key, type, tactic, malicious }) => {
    const list = Array.isArray(iocs[key]) ? iocs[key] : [];
    list.slice(0, 3).forEach((val, idx) => {
      const short = String(val).length > 22 ? String(val).slice(0, 20) + "…" : String(val);
      const id = `ioc-${key}-${idx}`;
      push({ id, label: short, type, tactic, malicious });
      link(prev, id, key.slice(0, -1));
    });
  });

  // 6) MITRE technique chips as action nodes (attribution)
  const mitre = Array.isArray(analysis?.mitre) ? analysis.mitre
              : Array.isArray(analysis?.mitre_techniques) ? analysis.mitre_techniques
              : [];
  mitre.slice(0, 3).forEach((t, i) => {
    const tid = typeof t === "string" ? t : (t.id || t.technique_id || t.tid || `T?`);
    const id = `mitre-${i}-${tid}`;
    push({ id, label: tid, type: "action", tactic: "Discovery" });
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
