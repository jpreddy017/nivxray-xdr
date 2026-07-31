/**
 * ADR-0022 §8 · CIO → LabV2 view-model projector.
 *
 * The frontend NEVER computes investigation results. This module is
 * the ONLY place that translates the Canonical Investigation Object
 * into the shape LabV2's UI slots consume. When no CIO is present,
 * it returns the coherent PowerShell demo case (`ev-01…ev-11`) so
 * the workspace still renders — the operator's prompt §4 mandate.
 *
 * All demo constants live in `labv2.demo.js` so the projector stays
 * a thin transform.
 */
import { DEMO_CASE, DEMO_EV, DEMO_STAGES } from "./labv2.demo";

// ── helpers ──────────────────────────────────────────────────────────
const truncate = (s, n) =>
  typeof s === "string" && s.length > n ? s.slice(0, n - 1) + "…" : s || "";

const humanTime = (iso) => {
  try {
    return new Date(iso).toISOString().slice(11, 19);
  } catch {
    return "--:--:--";
  }
};

// Confidence 0..1 → "●●●●○" style (5 dots, one per 20%)
const dots = (conf) => {
  const c = Math.max(0, Math.min(1, Number(conf) || 0));
  const filled = Math.round(c * 5);
  return "●".repeat(filled) + "○".repeat(5 - filled);
};

const inputTypeLabel = (input_kind) => {
  if (!input_kind) return "TEXT";
  if (typeof input_kind === "string") return input_kind.toUpperCase();
  const label = input_kind.label || input_kind.type || "text";
  return String(label).toUpperCase().replace(/_/g, " ");
};

const confidenceBucket = (pct) => {
  if (pct >= 85) return "CRITICAL";
  if (pct >= 65) return "HIGH";
  if (pct >= 40) return "MEDIUM";
  if (pct >= 20) return "LOW";
  return "MINIMAL";
};

const severityFromWeight = (w) => {
  if (w >= 8) return { g: "crit", gly: "▲" };
  if (w >= 6) return { g: "high", gly: "◆" };
  if (w >= 4) return { g: "med", gly: "●" };
  if (w >= 1) return { g: "low", gly: "●" };
  return { g: "unk", gly: "○" };
};

// ── main projector ───────────────────────────────────────────────────
export function projectCIO(cio) {
  // Empty state: no investigation yet. Every panel renders an
  // "awaiting input" state — nothing is fabricated.
  if (!cio || !cio.cio_id) {
    return { view: buildEmptyView(), sourceIsDemo: false, sourceIsEmpty: true };
  }

  const shortId = String(cio.cio_id || "").slice(-4).toUpperCase() || "CIO-";
  const fileName =
    (cio.artifacts && cio.artifacts[0] && cio.artifacts[0].name) ||
    (cio.input_kind && cio.input_kind.label) ||
    "investigation";

  const time = humanTime(cio.created_at);
  const inputType = inputTypeLabel(cio.input_kind);

  const verdictLabel = (cio.verdict && cio.verdict.label) || "Undetermined";
  const verdictPct = (cio.verdict && cio.verdict.confidence_pct) || 0;
  const verdictConf = (cio.verdict && cio.verdict.confidence) || 0;
  const contribs = (cio.verdict && cio.verdict.contributors) || [];
  const notCounted = (cio.verdict && cio.verdict.not_counted) || [];

  const summary = cio.summary || {};
  const nodes = (cio.evidence_graph && cio.evidence_graph.nodes) || [];
  const edges = (cio.evidence_graph && cio.evidence_graph.edges) || [];
  // Nodes use `id` (backend model); older code paths may still emit
  // `node_id`. Normalise so downstream code always reads `.id`.
  nodes.forEach((n) => { n.id = n.id || n.node_id; });
  const nodeById = Object.fromEntries(nodes.map((n) => [n.id, n]));

  // Build an EV map keyed by node id — every panel points here.
  const ev = {};
  nodes.forEach((n) => {
    const kind = n.kind || "node";
    const label = n.label || n.value || n.id;
    ev[n.id] = {
      s: `${kind} · confidence ${Math.round((n.confidence || 0) * 100)}%`,
      t: `Verdict ▸ Evidence ▸ ${kind}`,
      c: `<b>${escapeHTML(String(label))}</b>`,
      sup: (n.mitre_techniques || []).map((t) => `${t} ATT&CK technique`),
      frag: String(label).slice(0, 32),
    };
  });

  // ── Behavior graph projection (ADR-0022 §8, operator directive §1)
  //    Bucket every real evidence node into one of four capability lanes.
  //    Edges come straight from `evidence_graph.edges`. No second model.
  const graph = buildBehaviorGraph(nodes, edges);

  // Case Spine: derive stage states from reasoning_steps rules.
  // A stage is "done" if any step's rule matches its bucket; otherwise
  // "pending". The most recent step's bucket marks "active".
  const stageBuckets = {
    input: /^input\./,
    understand: /^(detect|classify|understand)\./,
    decode: /^decode\./,
    normalize: /^(normalize|canonical)\./,
    evidence: /^(evidence|extract|ioc)\./,
    behavior: /^(behavior|behaviour)\./,
    correlate: /^(correlate|mitre|attack)\./,
    verdict: /^verdict\./,
    report: /^report\./,
  };
  const steps = cio.reasoning_steps || [];
  const seen = new Set();
  steps.forEach((s) => {
    for (const key of Object.keys(stageBuckets)) {
      if (stageBuckets[key].test(s.rule || "")) seen.add(key);
    }
  });
  const activeKey = (() => {
    if (verdictLabel !== "Undetermined") return "correlate";
    if (seen.has("behavior")) return "correlate";
    if (seen.has("evidence")) return "behavior";
    if (seen.has("decode")) return "normalize";
    return "understand";
  })();

  const stages = DEMO_STAGES.map((s) => {
    const state = seen.has(s.id) ? "done" : s.id === activeKey ? "active" : "pending";
    let meta = s.meta;
    if (s.id === "input") meta = `${(cio.input_text || "").length} chars · ${shortId}`;
    if (s.id === "understand") meta = inputType.toLowerCase();
    if (s.id === "decode") meta = `${(cio.decode_chain || []).length} layers unwrapped`;
    if (s.id === "evidence") meta = `${nodes.length} observations`;
    if (s.id === "behavior") meta = `${nodes.filter((n) => n.kind === "behaviour" || n.kind === "behavior").length} behaviors · ${edges.length} links`;
    if (s.id === "correlate") meta = `${(summary.mitre_digest && Object.keys(summary.mitre_digest).length) || 0} tactics`;
    if (s.id === "verdict") meta = String(verdictLabel).toLowerCase();
    if (s.id === "report") meta = summary.report_sections ? "sections ready" : "awaiting enrichment";
    return { ...s, state, meta };
  });

  // Story text — prefer analyst/attack_story from summary; fall back
  // to the verdict reason so we never render blank.
  const storyParagraphs = buildStoryParagraphs(summary, verdictLabel, verdictPct, cio);

  // Findings — from summary.key_findings when present; else contributors.
  const findings = (summary.key_findings && summary.key_findings.length
    ? summary.key_findings.map((kf, i) => ({
        ...severityFromWeight(kf.weight || 5),
        t: kf.label || `Finding ${i + 1}`,
        sub: `weight ${kf.weight || "?"} · confidence ${Math.round((kf.confidence || 0) * 100)}%`,
        evs: kf.evidence_node_ids || [],
      }))
    : contribs.slice(0, 6).map((c) => ({
        ...severityFromWeight(c.weight),
        t: c.label || c.kind,
        sub: `${c.kind} · confidence ${Math.round((c.confidence || 0) * 100)}%`,
        evs: [c.node_id],
      }))
  );

  // Ledger — verdict contributors + not-counted.
  const ledgerRows = [
    ...contribs.map((c) => ({
      sign: c.weight >= 8 ? "+++" : c.weight >= 6 ? "++" : "+",
      cls: "up",
      t: c.label || c.kind,
      evs: [c.node_id],
    })),
    ...notCounted.slice(0, 3).map((c) => ({
      sign: "–",
      cls: "dn",
      t: c.label || `${c.kind} (not counted)`,
      evs: [c.node_id],
    })),
  ];

  // Unknowns
  const unknowns =
    (summary.unknowns && summary.unknowns.length
      ? summary.unknowns.map((u) => ({
          t: typeof u === "string" ? u : u.label || "Unknown",
          sub: typeof u === "string" ? "" : u.reason || "",
        }))
      : [{ t: "No unknowns recorded by the engine.", sub: "" }]);

  // Next actions
  const actions =
    (summary.recommendations && summary.recommendations.length
      ? summary.recommendations
      : cio.recommendations || []
    ).slice(0, 4).map((r) => ({
      n: r.action || r.label || "Recommended action",
      w: (r.priority || "later").toString().toUpperCase() === "HIGH" ? "Contain now" : "Investigate next",
      wCls: (r.priority || "").toLowerCase() === "high" ? "" : "later",
      b: r.rationale || "",
    }));

  // ATT&CK grid — from summary.mitre_digest
  const attack = buildAttackGrid(summary.mitre_digest, nodes);

  // OSINT rows — every IOC-shaped node gets a row with placeholders
  // for provider hits. When the backend adds real threat-intel enrichment
  // this projector will pick them up automatically from node.enrichment[].
  const osint = nodes
    .filter((n) => /ioc|url|domain|ip|hash|email/i.test(n.kind || ""))
    .map((n) => {
      const enrich = n.enrichment || {};
      const providers = Array.isArray(enrich.providers) ? enrich.providers : [];
      return {
        node_id: n.id,
        kind: n.kind,
        value: n.label || n.value || n.id,
        confidence: Math.round((n.confidence || 0) * 100),
        first_seen: enrich.first_seen || null,
        last_seen: enrich.last_seen || null,
        reputation: enrich.reputation || null,
        providers: providers.length
          ? providers
          : [
              { name: "VirusTotal", state: "pending" },
              { name: "AbuseIPDB", state: "pending" },
              { name: "AlienVault OTX", state: "pending" },
              { name: "URLhaus", state: "pending" },
            ],
      };
    });

  // Decode ladder — from decode_chain
  const decodeLadder = (cio.decode_chain || []).map((r, i) => ({
    layer: `L${i}`,
    name: r.name || r.layer || `Layer ${i}`,
    meta: r.meta || "",
    code: r.output || r.code || r.text || "",
  }));

  // Behavior graph nodes — kind='behaviour'/'lolbin'/'external_ioc_*'
  const behaviorNodes = nodes
    .filter((n) => /behavi|lolbin|process|url|domain|ip|hash|persist/i.test(n.kind || ""))
    .slice(0, 8);

  // Evbar default selection: first contributor node
  const defaultEv =
    (contribs[0] && contribs[0].node_id) || nodes[0]?.id || null;

  // Story stats
  const stats = {
    obs: nodes.length,
    beh: nodes.filter((n) => /behaviour|behavior/.test(n.kind || "")).length,
    tech: attack.techniqueCount,
    unk: unknowns.length,
    elapsed: `${(steps.length * 1.2).toFixed(1)}s`,
  };

  return {
    view: {
      hasCase: true,
      rawInput: cio.input_text || "",
      caseId: shortId,
      file: truncate(fileName, 42),
      time,
      inputType,
      verdict: {
        label: verdictLabel.toUpperCase(),
        dots: dots(verdictConf),
        pct: verdictPct,
        bucket: confidenceBucket(verdictPct),
        reason: (cio.verdict && cio.verdict.reason) || "",
      },
      stages,
      ev,
      story: storyParagraphs,
      stats,
      ledger: ledgerRows,
      findings,
      unknowns,
      actions,
      attack,
      osint,
      decodeLadder,
      behaviorNodes,
      graph,
      defaultEv,
    },
    sourceIsDemo: false,
  };
}

// ── story projector ──────────────────────────────────────────────────
function buildStoryParagraphs(summary, verdictLabel, verdictPct, cio) {
  const paras = [];
  const analystTxt = summary.analyst || summary.executive || "";
  const attackStory = summary.attack_story || "";
  const technical = summary.technical || "";

  // Lede: prefer summary.analyst first sentence; else verdict reason.
  const lede =
    (analystTxt.split(/(?<=[.!?])\s+/).find(Boolean) ||
      (cio.verdict && cio.verdict.reason) ||
      `${verdictLabel} verdict at ${verdictPct}% confidence.`);
  paras.push({ kind: "lede", text: lede });

  // Additional paragraphs from analyst body (after lede), split on sentences.
  if (analystTxt) {
    const rest = analystTxt.replace(lede, "").trim();
    if (rest) paras.push({ kind: "p", text: rest });
  }

  if (attackStory && attackStory !== analystTxt) {
    paras.push({ kind: "p", text: attackStory });
  }

  if (technical && technical !== analystTxt && technical !== attackStory) {
    paras.push({ kind: "quiet", text: technical });
  }

  if (paras.length === 1) {
    paras.push({
      kind: "quiet",
      text:
        "Full narrative pending — the summary composer produced no additional prose for this investigation.",
    });
  }
  return paras;
}

// ── ATT&CK grid projector ────────────────────────────────────────────
function buildAttackGrid(mitre_digest, nodes) {
  // mitre_digest can be:
  //   { tactic_id: { techniques: [{id, name, confidence, evidence_node_ids}] } }
  // or a flat list, or empty.
  const cols = { Execution: [], "Defense evasion": [], "Command & control": [], Persistence: [] };
  let techniqueCount = 0;

  if (mitre_digest && typeof mitre_digest === "object" && !Array.isArray(mitre_digest)) {
    for (const [tacticKey, val] of Object.entries(mitre_digest)) {
      if (!val) continue;
      const label = normaliseTactic(tacticKey);
      const bucket = cols[label] || (cols[label] = []);
      const techs = Array.isArray(val) ? val : val.techniques || [];
      techs.forEach((t) => {
        bucket.push({
          id: t.technique_id || t.id || t.tech_id || t,
          nm: t.name || t.title || t.technique_id || "",
          dots: dots(t.confidence || 0.6),
          evs: t.evidence_node_ids || t.evidence || [],
        });
        techniqueCount++;
      });
    }
  }

  return { columns: cols, techniqueCount };
}

function normaliseTactic(k) {
  const map = {
    execution: "Execution",
    ta0002: "Execution",
    "defense-evasion": "Defense evasion",
    defense_evasion: "Defense evasion",
    ta0005: "Defense evasion",
    "command-and-control": "Command & control",
    command_and_control: "Command & control",
    ta0011: "Command & control",
    persistence: "Persistence",
    ta0003: "Persistence",
  };
  return map[String(k).toLowerCase()] || String(k);
}

function escapeHTML(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ── Behavior graph builder ───────────────────────────────────────────
// Buckets every real evidence-graph node into one of four capability
// lanes and lays them out on a 860×468 SVG canvas. Edges come from
// `evidence_graph.edges` verbatim — no second graph model.
const LANE_DEFS = [
  { id: "evade",   label: "EVADE",             y: 6,   testKinds: /evasion|hide|hidden|bypass|obfusc/i,     mitre: /T1027|T1140|T1564|T1620/i },
  { id: "decode",  label: "DECODE",            y: 126, testKinds: /decode|transform|normalize|artifact|encoding|cipher/i, mitre: /T1027|T1140/i },
  { id: "acquire", label: "ACQUIRE",           y: 246, testKinds: /ioc|url|domain|ip|hash|network|download|fetch|c2/i,     mitre: /T1105|T1071/i },
  { id: "execute", label: "EXECUTE · PERSIST", y: 366, testKinds: /lolbin|process|execute|persist|verdict|behaviour|behavior|entity|command/i, mitre: /T1059|T1053|T1547|T1543/i },
];

function bucketNode(node) {
  const kind = String(node.kind || "");
  const mitre = (node.mitre_techniques || []).join(" ");
  for (const lane of LANE_DEFS) {
    if (lane.testKinds.test(kind) || (mitre && lane.mitre.test(mitre))) return lane.id;
  }
  // Default: place unknown-kind nodes in EXECUTE lane so nothing is
  // silently dropped. Analyst still sees every observation.
  return "execute";
}

function buildBehaviorGraph(nodes, edges) {
  if (!nodes || nodes.length === 0) {
    return { lanes: [], edges: [], empty: true, width: 860, height: 468 };
  }
  const byLane = { evade: [], decode: [], acquire: [], execute: [] };
  nodes.forEach((n) => {
    // Skip artifacts (input placeholder) and verdict summary node — those
    // are structural, not observable behaviours.
    if (n.kind === "artifact") return;
    byLane[bucketNode(n)].push(n);
  });

  // Layout: for each lane, evenly distribute node boxes along x.
  const laneW = 860;
  const boxW = 160;
  const boxH = 52;
  const positions = {};
  const lanes = LANE_DEFS.map((lane) => {
    const items = byLane[lane.id];
    const count = items.length;
    const laneNodes = items.map((n, i) => {
      const availableW = laneW - 40 - boxW;
      const step = count > 1 ? availableW / (count - 1) : 0;
      const x = 40 + (count === 1 ? availableW / 2 : step * i);
      const y = lane.y + 32; // inside lane, below label
      positions[n.id] = { x, y, w: boxW, h: boxH, lane: lane.id };
      return {
        id: n.id,
        title: prettifyLabel(n),
        subtitle: `${n.kind || ""} · ${Math.round((n.confidence || 0) * 100)}%`,
        hot: (n.confidence || 0) >= 0.7,
        x, y, w: boxW, h: boxH,
      };
    });
    return { id: lane.id, label: lane.label, y: lane.y, nodes: laneNodes };
  });

  // Edges — resolve endpoints, mark hot if weight >= 0.6 or kind ∈ hot list.
  const HOT_KINDS = /contributes_to|produces|drives/i;
  const drawnEdges = edges
    .map((e) => {
      const src = positions[e.source];
      const dst = positions[e.target];
      if (!src || !dst) return null;
      const hot = (e.weight || 0) >= 0.6 && HOT_KINDS.test(e.kind || "");
      return {
        x1: src.x + src.w / 2,
        y1: src.y + src.h / 2,
        x2: dst.x + dst.w / 2,
        y2: dst.y + dst.h / 2,
        hot,
      };
    })
    .filter(Boolean);

  return {
    lanes,
    edges: drawnEdges,
    width: 860,
    height: 468,
    empty: false,
    totalNodes: nodes.length - (byLane.evade.length + byLane.decode.length + byLane.acquire.length + byLane.execute.length ? 0 : 0),
  };
}

function prettifyLabel(n) {
  const raw = String(n.label || n.value || n.id || "");
  // Turn "URL · http://..." into just the value part when possible.
  const stripped = raw.replace(/^[A-Z]+·\s*/i, "").replace(/^[A-Z ]+·\s*/i, "");
  return stripped.length > 28 ? stripped.slice(0, 27) + "…" : stripped || n.id;
}

// ── empty (tool-idle) state ──────────────────────────────────────────
// This is the DEFAULT before any input is submitted. Every panel is
// truly empty — no verdict, no case id, no fake evidence. Like an
// editor with no file open.
function buildEmptyView() {
  return {
    caseId: "",
    file: "",
    time: "",
    inputType: "",
    hasCase: false,
    verdict: { label: "", dots: "", pct: 0, bucket: "", reason: "" },
    stages: [
      { id: "input", name: "Input", meta: "awaiting", lens: "exec", state: "pending" },
      { id: "understand", name: "Understand", meta: "", lens: "exec", state: "pending" },
      { id: "decode", name: "Decode", meta: "", lens: "source", state: "pending" },
      { id: "normalize", name: "Normalize", meta: "", lens: "source", state: "pending" },
      { id: "evidence", name: "Evidence", meta: "", lens: "story", state: "pending" },
      { id: "behavior", name: "Behavior", meta: "", lens: "behavior", state: "pending" },
      { id: "correlate", name: "Correlate", meta: "", lens: "attack", state: "pending" },
      { id: "verdict", name: "Verdict", meta: "", lens: "exec", state: "pending" },
      { id: "report", name: "Report", meta: "", lens: "exec", state: "pending" },
    ],
    ev: {},
    story: [],
    stats: { obs: 0, beh: 0, tech: 0, unk: 0, elapsed: "—" },
    ledger: [],
    findings: [],
    unknowns: [],
    actions: [],
    attack: { columns: { Execution: [], "Defense evasion": [], "Command & control": [], Persistence: [] }, techniqueCount: 0 },
    osint: [],
    decodeLadder: [],
    behaviorNodes: [],
    graph: { lanes: [], edges: [], empty: true },
    defaultEv: null,
    rawInput: "",
  };
}

// ── demo (Storybook only) ────────────────────────────────────────────
export function buildDemoView() {
  return {
    hasCase: true,
    rawInput: 'powershell.exe -nop -w hidden -enc SQBFAFgA…',
    caseId: DEMO_CASE.id,
    file: DEMO_CASE.file,
    time: DEMO_CASE.time,
    inputType: DEMO_CASE.inputType,
    verdict: {
      label: DEMO_CASE.verdict,
      dots: DEMO_CASE.confidenceDots,
      pct: 80,
      bucket: DEMO_CASE.confidenceLabel,
      reason: "Download → write → execute chain observed post-decode.",
    },
    stages: DEMO_STAGES,
    ev: DEMO_EV,
    story: [
      { kind: "lede", text: "An obfuscated PowerShell command that downloads a remote executable to a temporary directory and runs it." },
      { kind: "p", text: "The command was submitted with its execution policy bypassed and its window hidden EV_01 EV_02. Neither flag is required for legitimate administration in this context." },
      { kind: "p", text: "The payload was Base64-encoded in UTF-16LE, with a second layer of gzip compression EV_03. Two independent obfuscation layers is itself a signal." },
      { kind: "p", text: "Once unwrapped, the script constructs a web client, fetches a file from a remote host, writes it into %TEMP% and starts it EV_07 EV_08 EV_11. That download → write → execute sequence is what drives the verdict." },
      { kind: "quiet", text: "The fetch host did not resolve at investigation time, so the payload itself was never retrieved. Two of four intelligence sources were unreachable." },
    ],
    stats: DEMO_CASE.stats,
    ledger: [
      { sign: "+++", cls: "up", t: "Download → write → execute chain", evs: ["ev-07", "ev-08", "ev-11"] },
      { sign: "++", cls: "up", t: "Two-layer obfuscation (b64 → gzip)", evs: ["ev-03"] },
      { sign: "++", cls: "up", t: "Policy bypass with hidden window", evs: ["ev-01", "ev-02"] },
      { sign: "+", cls: "up", t: "Non-standard TLD on fetch host", evs: ["ev-09"] },
      { sign: "–", cls: "dn", t: "No known-bad hash match", evs: [] },
      { sign: "?", cls: "q", t: "C2 host unresolved — target offline", evs: [] },
    ],
    findings: [
      { g: "crit", gly: "▲", t: "Download-write-execute chain", sub: "behavior · 3 linked nodes", evs: ["ev-07", "ev-08", "ev-11"] },
      { g: "crit", gly: "▲", t: "Dual-layer obfuscation", sub: "decode · 2 transforms", evs: ["ev-03"] },
      { g: "high", gly: "◆", t: "Execution policy bypassed, window hidden", sub: "evidence · flags", evs: ["ev-01", "ev-02"] },
      { g: "med", gly: "●", t: "Fetch host on non-standard TLD", sub: "intel · 2 of 4 sources", evs: ["ev-09"] },
    ],
    unknowns: [
      { t: "C2 host did not resolve", sub: "target offline at 14:22 → retry / sandbox" },
      { t: "Payload never retrieved", sub: "no hash to check against intel" },
    ],
    actions: [
      { n: "Block cdn-update[.]tld at egress", w: "Contain now", wCls: "", b: "A download-write-execute chain fetched from this host. Affects 1 observed host." },
      { n: "Hunt %TEMP%\\a.exe across estate", w: "Contain now", wCls: "", b: "Copy-ready KQL generated from the behavior chain." },
      { n: "Re-run when host is reachable", w: "Investigate next", wCls: "later", b: "Resolves both unknowns and would raise confidence to conclusive." },
    ],
    attack: {
      columns: {
        Execution: [{ id: "T1059.001", nm: "PowerShell", dots: "●●●●○", evs: ["ev-01", "ev-04"] }],
        "Defense evasion": [
          { id: "T1027", nm: "Obfuscated files or information", dots: "●●●●●", evs: ["ev-03"] },
          { id: "T1564.003", nm: "Hidden window", dots: "●●●●○", evs: ["ev-02"] },
        ],
        "Command & control": [{ id: "T1105", nm: "Ingress tool transfer", dots: "●●●●○", evs: ["ev-07"] }],
        Persistence: [],
      },
      techniqueCount: 4,
    },
    osint: [
      {
        node_id: "N-101",
        kind: "external_ioc_domain",
        value: "cdn-update[.]tld",
        confidence: 78,
        first_seen: "12 min prior",
        last_seen: "14:22:07",
        reputation: "suspicious",
        providers: [
          { name: "VirusTotal", state: "pending" },
          { name: "AbuseIPDB", state: "pending" },
          { name: "AlienVault OTX", state: "hit", detail: "1 pulse · dropper infrastructure" },
          { name: "URLhaus", state: "pending" },
        ],
      },
      {
        node_id: "N-102",
        kind: "external_ioc_path",
        value: "%TEMP%\\a.exe",
        confidence: 60,
        first_seen: null,
        last_seen: null,
        reputation: null,
        providers: [
          { name: "VirusTotal", state: "no-hash" },
          { name: "Hybrid Analysis", state: "no-hash" },
        ],
      },
    ],
    decodeLadder: [],  // rendered from prototype static content in LabV2
    behaviorNodes: [],
    graph: buildBehaviorGraph(
      [
        { id: "N-01", kind: "evasion", label: "Hide window · -w hidden", confidence: 0.9 },
        { id: "N-02", kind: "evasion", label: "Bypass policy · -nop", confidence: 0.85 },
        { id: "N-03", kind: "decode", label: "Base64 decode · utf-16le", confidence: 1.0 },
        { id: "N-04", kind: "decode", label: "Gzip inflate", confidence: 0.9 },
        { id: "N-07", kind: "url", label: "cdn-update[.]tld", confidence: 0.8 },
        { id: "N-08", kind: "ioc", label: "%TEMP%\\a.exe", confidence: 0.7 },
        { id: "N-11", kind: "lolbin", label: "Start process · hidden", confidence: 0.9 },
      ],
      [
        { source: "N-03", target: "N-07", kind: "produces", weight: 0.9 },
        { source: "N-07", target: "N-08", kind: "contributes_to", weight: 0.8 },
        { source: "N-08", target: "N-11", kind: "contributes_to", weight: 0.9 },
      ]
    ),
    defaultEv: "ev-07",
  };
}
