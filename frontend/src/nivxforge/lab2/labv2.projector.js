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

  // ── G1 · Attack graph (lane-based · EVADE/DECODE/ACQUIRE/EXECUTE).
  //    Enrichment: subtitle carries TTP IDs + ev-id.
  const attackGraph = buildBehaviorGraph(nodes, edges);

  // ── G2 · Decoder graph (linear, reads `cio.decode_chain`).
  //    Rectangles with title = decoder op, subtitle = reason · ev-XX.
  //    Selection node id = the fragment node attached to each layer.
  const decodeGraph = buildDecodeGraph(nodes, edges);

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

  // OSINT rows — every IOC-shaped node gets a row with the 11-field
  // provider cards emitted by the backend's `osint_enricher` (P1-01).
  // `node.attrs.enrichment` is the CIO-native location; `node.enrichment`
  // is a legacy alias kept for backward compatibility with the shape
  // demo cases still emit.
  const osint = nodes
    .filter((n) => /ioc|url|domain|ip|hash|email/i.test(n.kind || ""))
    .map((n) => {
      const enrich = (n.attrs && n.attrs.enrichment) || n.enrichment || {};
      const providers = Array.isArray(enrich.providers) ? enrich.providers : [];
      // 11-field provider card shape:
      //   { name, state, malicious, suspicious, harmless, reputation,
      //     detail, first_seen, last_seen, tags, link }
      const normalized = providers.length
        ? providers.map((p) => ({
            name: p.name || "Provider",
            state: p.state || "pending",
            malicious: p.malicious ?? null,
            suspicious: p.suspicious ?? null,
            harmless: p.harmless ?? null,
            reputation: p.reputation ?? null,
            detail: p.detail || "",
            first_seen: p.first_seen || null,
            last_seen: p.last_seen || null,
            tags: Array.isArray(p.tags) ? p.tags : [],
            link: p.link || null,
          }))
        : [
            { name: "VirusTotal", state: "pending", malicious: null, suspicious: null, harmless: null, reputation: null, detail: "", first_seen: null, last_seen: null, tags: [], link: null },
            { name: "AbuseIPDB",  state: "pending", malicious: null, suspicious: null, harmless: null, reputation: null, detail: "", first_seen: null, last_seen: null, tags: [], link: null },
            { name: "AlienVault OTX", state: "pending", malicious: null, suspicious: null, harmless: null, reputation: null, detail: "", first_seen: null, last_seen: null, tags: [], link: null },
            { name: "URLhaus",   state: "pending", malicious: null, suspicious: null, harmless: null, reputation: null, detail: "", first_seen: null, last_seen: null, tags: [], link: null },
          ];
      return {
        node_id: n.id,
        kind: n.kind,
        value: n.label || n.value || n.id,
        confidence: Math.round((n.confidence || 0) * 100),
        first_seen: enrich.first_seen || null,
        last_seen: enrich.last_seen || null,
        reputation: enrich.reputation ?? null,
        hit_count: enrich.hit_count ?? normalized.filter((p) => p.state === "hit").length,
        providers: normalized,
      };
    });

  // Decode ladder — from decode_chain (CIO field names: op / preview / reason / input_kind / output_kind / node_id)
  const decodeLadder = (cio.decode_chain || []).map((r, i) => ({
    layer: `L${r.idx ?? i}`,
    name: r.op || r.name || r.layer || `Layer ${i}`,
    meta: r.reason || r.meta || [r.input_kind, r.output_kind].filter(Boolean).join(" → ") || "",
    code: r.preview || r.output || r.code || r.text || "",
    nodeId: r.node_id || null,
    inputKind: r.input_kind || "",
    outputKind: r.output_kind || "",
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
      rules: buildRulesView(cio),
      lolbas: buildLolbasView(cio),
      tihits: buildTiHitsView(cio),
      decodeLadder,
      behaviorNodes,
      decodeGraph,
      attackGraph,
      graph: attackGraph, // legacy alias for older refs (Storybook)
      defaultEv,
    },
    sourceIsDemo: false,
  };
}

// ── Workspace-parity renderer views (P1-03/04/05) ────────────────────
// These consume the shared backend fields already stashed into
// `cio.metadata` (see /app/backend/routers/{ops,auto_investigate}.py).
// Renderer-only — never invent new intelligence.

function buildRulesView(cio) {
  const meta = (cio && cio.metadata) || {};
  const raw = meta.custom_recipes_matched || meta.recipes_matched || meta.rules_hit || [];
  const rows = [];
  const seen = new Set();
  for (const r of Array.isArray(raw) ? raw : []) {
    if (typeof r === "string") {
      if (seen.has(r)) continue;
      seen.add(r);
      rows.push({ name: r, category: "", score: 0, description: "" });
      continue;
    }
    if (!r || typeof r !== "object") continue;
    const name = String(r.name || r.rule || r.id || "").trim();
    if (!name || seen.has(name)) continue;
    seen.add(name);
    rows.push({
      name,
      category: String(r.category || r.family || r.type || "").trim(),
      score:    Number(r.score || r.weight || 0) || 0,
      severity: String(r.severity || "").trim(),
      description: String(r.description || r.desc || r.doc || "").trim(),
    });
  }
  return { count: rows.length, rows };
}

function buildLolbasView(cio) {
  const meta = (cio && cio.metadata) || {};
  const rows = [];
  const seen = new Set();
  const _push = (item, bucket) => {
    if (!item) return;
    if (typeof item === "string") {
      const name = item.trim();
      if (!name || seen.has(name.toLowerCase())) return;
      seen.add(name.toLowerCase());
      rows.push({ name, bucket, tid: "", description: "" });
      return;
    }
    if (typeof item !== "object") return;
    const name = String(item.name || item.binary || item.exe || "").trim();
    if (!name || seen.has(name.toLowerCase())) return;
    seen.add(name.toLowerCase());
    rows.push({
      name,
      bucket,
      tid:         String(item.mitre_id || item.tid || item.technique || "").trim(),
      description: String(item.description || item.category || "").trim(),
    });
  };
  for (const it of meta.lolbas || []) _push(it, "referenced");
  const v2 = meta.lolbins_v2 || {};
  for (const b of ["executed", "referenced", "expanded"]) {
    for (const it of v2[b] || []) _push(it, b);
  }
  return { count: rows.length, rows };
}

function buildTiHitsView(cio) {
  const meta = (cio && cio.metadata) || {};
  const shield = meta.ti_shield || {};
  const layers = Array.isArray(shield.layers) ? shield.layers : [];
  const rows = [];
  for (const layer of layers) {
    if (!layer || typeof layer !== "object") continue;
    const hits = layer.hits || layer.matches || [];
    for (const h of Array.isArray(hits) ? hits : []) {
      rows.push({
        indicator: String(h.indicator || h.value || h.ioc || "").trim(),
        provider:  String(h.provider  || h.source || layer.name || "").trim(),
        family:    String(h.family    || h.malware_family || "").trim(),
        first_seen: String(h.first_seen || h.first || "").trim(),
        last_seen:  String(h.last_seen  || h.last  || "").trim(),
        severity:  String(h.severity  || h.risk || "").trim(),
        tags:      Array.isArray(h.tags) ? h.tags : [],
      });
    }
  }
  // Also honour a top-level ti_hits[] list if present.
  for (const h of Array.isArray(meta.ti_hits) ? meta.ti_hits : []) {
    if (!h || typeof h !== "object") continue;
    rows.push({
      indicator: String(h.indicator || h.value || "").trim(),
      provider:  String(h.provider  || h.source || "").trim(),
      family:    String(h.family    || "").trim(),
      first_seen: String(h.first_seen || "").trim(),
      last_seen:  String(h.last_seen  || "").trim(),
      severity:  String(h.severity  || "").trim(),
      tags:      Array.isArray(h.tags) ? h.tags : [],
    });
  }
  return { count: rows.length, rows };
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
// Layered layout: (1) bucket nodes into capability lanes, (2) assign
// each node a column via longest-path topological ordering so edges
// always flow left→right, (3) stack rows within a lane cell to prevent
// overlap, (4) route edges as cubic Bezier curves. All positions are
// deterministic for a given (nodes, edges) input — critical so the
// selection state stays anchored across CIO updates.
const LANE_DEFS = [
  { id: "evade",   label: "EVADE",             y: 20,  testKinds: /evasion|hide|hidden|bypass|obfusc/i, mitre: /T1027|T1140|T1564|T1620|T1497/i },
  { id: "decode",  label: "DECODE",            y: 180, testKinds: /decode|transform|normalize|artifact|encoding|cipher|decoded_fragment/i, mitre: /T1027|T1140/i },
  { id: "acquire", label: "ACQUIRE",           y: 340, testKinds: /ioc|url|domain|ip|hash|network|download|fetch|c2|external_ioc/i, mitre: /T1105|T1071|T1197/i },
  { id: "execute", label: "EXECUTE · PERSIST", y: 500, testKinds: /lolbin|process|execute|persist|verdict|behaviour|behavior|entity|command|mitre_technique|technique/i, mitre: /T1059|T1053|T1547|T1543|T1218|T1082/i },
];
const LANE_HEIGHT = 150;
const ROW_HEIGHT = 74;
const NODE_W = 220;
const NODE_H = 60;
const COL_W = 260;
const LEFT_PAD = 80;

function bucketNode(node) {
  const kind = String(node.kind || "");
  const mitre = (node.mitre_techniques || []).join(" ");
  // If the node itself IS a MITRE technique, use its id + tactic to route.
  const nodeMitreId =
    kind === "mitre_technique"
      ? String(node.value || node.label || "").match(/T\d{4}(?:\.\d+)?/)?.[0] || ""
      : "";
  const tactic = String(node.attrs?.tactic || "").toLowerCase();
  for (const lane of LANE_DEFS) {
    if (lane.testKinds.test(kind)) return lane.id;
    if (mitre && lane.mitre.test(mitre)) return lane.id;
    if (nodeMitreId && lane.mitre.test(nodeMitreId)) return lane.id;
    // Tactic-based routing for mitre_technique nodes.
    if (tactic && lane.id === "evade" && /evasion/.test(tactic)) return lane.id;
    if (tactic && lane.id === "acquire" && /(command|control|c2|initial)/.test(tactic)) return lane.id;
    if (tactic && lane.id === "execute" && /(execution|persist|discovery)/.test(tactic)) return lane.id;
  }
  return "execute";
}

function longestPathColumns(nodes, edges) {
  // Directed graph. Column = longest incoming path length. Nodes with
  // no incoming edges start at column 0. Cycles are broken naturally
  // because we stop revisiting once a node's column stops growing.
  const cols = {};
  const incoming = {};
  const outgoingByFrom = {};
  nodes.forEach((n) => { cols[n.id] = 0; incoming[n.id] = 0; });
  edges.forEach((e) => {
    if (cols[e.source] === undefined || cols[e.target] === undefined) return;
    (outgoingByFrom[e.source] = outgoingByFrom[e.source] || []).push(e.target);
    incoming[e.target] = (incoming[e.target] || 0) + 1;
  });
  // Kahn-ish BFS relaxation for longest path.
  let changed = true;
  let guard = 0;
  while (changed && guard++ < nodes.length * 4) {
    changed = false;
    for (const [src, targets] of Object.entries(outgoingByFrom)) {
      for (const tgt of targets) {
        const proposed = cols[src] + 1;
        if (proposed > cols[tgt]) {
          cols[tgt] = proposed;
          changed = true;
        }
      }
    }
  }
  return cols;
}

function buildBehaviorGraph(nodes, edges) {
  if (!nodes || nodes.length === 0) {
    return { lanes: [], edges: [], empty: true, width: 900, height: 720, chainLabel: "" };
  }

  // 1. Filter out only structural nodes so the graph reads like the
  //    operator reference (single Behavior graph with EVADE / DECODE /
  //    ACQUIRE / EXECUTE·PERSIST lanes all in one canvas).
  const OMIT_KINDS = /^(artifact|verdict|persist_note|note|report)$/i;
  const observable = nodes.filter((n) => !OMIT_KINDS.test(String(n.kind || "")));
  if (observable.length === 0) {
    return { lanes: [], edges: [], empty: true, width: 900, height: 720, chainLabel: "" };
  }
  const observableIds = new Set(observable.map((n) => n.id));

  // 2. Prune noisy edges: (a) any edge whose endpoint is off-graph
  //    (structural node), (b) `references` edges from the input
  //    artifact that carry no analytic value, (c) duplicates.
  const seenEdgeKey = new Set();
  const cleanEdges = edges.filter((e) => {
    if (!observableIds.has(e.source) || !observableIds.has(e.target)) return false;
    if ((e.kind || "").toLowerCase() === "references") return false;
    const key = `${e.source}→${e.target}`;
    if (seenEdgeKey.has(key)) return false;
    seenEdgeKey.add(key);
    return true;
  });

  // 2. Bucket into lanes.
  const laneOfNode = {};
  const byLane = { evade: [], decode: [], acquire: [], execute: [] };
  observable.forEach((n) => {
    const laneId = bucketNode(n);
    laneOfNode[n.id] = laneId;
    byLane[laneId].push(n);
  });

  // 3. Topological columns from the pruned edge list.
  const cols = longestPathColumns(observable, cleanEdges);

  // 4. Normalise columns per lane so every lane starts at column 0 for
  //    a compact left-aligned look, and within-lane collisions get
  //    stacked in rows.
  const positions = {};
  let maxCol = 0;
  LANE_DEFS.forEach((lane) => {
    const items = byLane[lane.id];
    if (items.length === 0) return;

    // Sort by column so lower-cost paths appear left. Nodes at the
    // same column get sequential rows within the lane.
    items.sort((a, b) => (cols[a.id] || 0) - (cols[b.id] || 0));
    // Compact columns: e.g. columns [2,5,5,7] → [0,1,1,2]
    const uniqueCols = Array.from(new Set(items.map((n) => cols[n.id] || 0))).sort((a, b) => a - b);
    const rowByColKey = {};
    items.forEach((n) => {
      const c = uniqueCols.indexOf(cols[n.id] || 0);
      const key = c;
      const row = (rowByColKey[key] = (rowByColKey[key] || 0));
      rowByColKey[key] = row + 1;
      const x = LEFT_PAD + c * COL_W;
      const y = lane.y + row * ROW_HEIGHT;
      positions[n.id] = { x, y, w: NODE_W, h: NODE_H, lane: lane.id };
      maxCol = Math.max(maxCol, c);
    });
  });

  // 5. Compute lane row-heights so lanes grow when they hold many rows.
  const laneRows = { evade: 1, decode: 1, acquire: 1, execute: 1 };
  Object.entries(byLane).forEach(([id, items]) => {
    if (items.length === 0) return;
    // Count rows = max row index used
    const rowCounts = {};
    items.forEach((n) => {
      const p = positions[n.id];
      const r = Math.round((p.y - LANE_DEFS.find((l) => l.id === id).y) / ROW_HEIGHT);
      rowCounts[r] = (rowCounts[r] || 0) + 1;
    });
    laneRows[id] = Math.max(1, Object.keys(rowCounts).length);
  });

  // 6. Adjust lane Y positions so lanes stack based on their row count.
  const laneY = {};
  let cursorY = 20;
  LANE_DEFS.forEach((lane) => {
    laneY[lane.id] = cursorY;
    cursorY += Math.max(LANE_HEIGHT, laneRows[lane.id] * ROW_HEIGHT + 40);
  });
  // Reposition nodes into their lane's new Y band.
  Object.keys(positions).forEach((id) => {
    const p = positions[id];
    const originalLaneY = LANE_DEFS.find((l) => l.id === p.lane).y;
    const offset = p.y - originalLaneY;
    p.y = laneY[p.lane] + 40 + offset - LANE_DEFS.find((l) => l.id === p.lane).y + LANE_DEFS.find((l) => l.id === p.lane).y - 20;
    // Simpler: put node at laneY + 40 + row*ROW_HEIGHT (recompute row)
    const items = byLane[p.lane];
    items.sort((a, b) => (cols[a.id] || 0) - (cols[b.id] || 0));
    const uniqueCols = Array.from(new Set(items.map((n) => cols[n.id] || 0))).sort((a, b) => a - b);
    const c = uniqueCols.indexOf(cols[id] || 0);
    // Count rows used in this column before this node
    let row = 0;
    for (const it of items) {
      if (it.id === id) break;
      const ic = uniqueCols.indexOf(cols[it.id] || 0);
      if (ic === c) row++;
    }
    p.x = LEFT_PAD + c * COL_W;
    p.y = laneY[p.lane] + 40 + row * ROW_HEIGHT;
  });

  // 7. Build lane view models.
  const lanes = LANE_DEFS.map((lane) => ({
    id: lane.id,
    label: lane.label,
    y: laneY[lane.id],
    height: Math.max(LANE_HEIGHT, laneRows[lane.id] * ROW_HEIGHT + 40),
    nodes: byLane[lane.id].map((n) => {
      const p = positions[n.id];
      const ttps = (n.mitre_techniques || []).slice(0, 2).join(" ");
      const kind = String(n.kind || "").replace(/^external_ioc_/, "");
      const subtitle = ttps
        ? `${ttps} · ${n.id}`
        : `${kind} · ${n.id}`;
      return {
        id: n.id,
        title: prettifyLabel(n),
        subtitle,
        hot: (n.confidence || 0) >= 0.7,
        x: p.x, y: p.y, w: p.w, h: p.h,
      };
    }),
  }));

  // 8. Route edges as cubic Bezier curves. Every edge exits the right
  //    edge of the source and enters the left edge of the target;
  //    control points push horizontally by half the x-distance so
  //    cross-lane edges naturally arc down/up.
  const HOT_KINDS = /contributes_to|produces|drives/i;
  const drawnEdges = edges
    .map((e) => {
      const src = positions[e.source];
      const dst = positions[e.target];
      if (!src || !dst) return null;
      const hot = (e.weight || 0) >= 0.6 && HOT_KINDS.test(e.kind || "");
      // Anchor points: right-center of source, left-center of destination.
      const sx = src.x + src.w;
      const sy = src.y + src.h / 2;
      const tx = dst.x;
      const ty = dst.y + dst.h / 2;
      // Cubic Bezier — bend based on dx so lane crossings curve gently.
      const dx = Math.max(48, (tx - sx) * 0.55);
      const path = `M ${sx} ${sy} C ${sx + dx} ${sy}, ${tx - dx} ${ty}, ${tx} ${ty}`;
      return { path, hot };
    })
    .filter(Boolean);

  // 9. Chain label — pick the longest hot causal path across lanes.
  const chainLabel = deriveChainLabel(observable, edges, laneOfNode);

  const totalHeight = cursorY + 40;
  const totalWidth = LEFT_PAD + (maxCol + 1) * COL_W + 40;

  return { lanes, edges: drawnEdges, width: totalWidth, height: totalHeight, empty: false, chainLabel };
}

function deriveChainLabel(nodes, edges, laneOfNode) {
  // Follow the heaviest outgoing edges from the highest-confidence
  // node in each lane and pick the sequence of lanes touched.
  const HOT = /contributes_to|produces|drives/i;
  const outByFrom = {};
  edges.forEach((e) => {
    if (!HOT.test(e.kind || "") || (e.weight || 0) < 0.5) return;
    (outByFrom[e.source] = outByFrom[e.source] || []).push(e);
  });
  // Rank starting nodes by out-degree.
  const starts = Object.entries(outByFrom).sort((a, b) => b[1].length - a[1].length);
  if (starts.length === 0) return "";
  const seenLanes = [];
  let current = starts[0][0];
  const guard = new Set();
  while (current && !guard.has(current)) {
    guard.add(current);
    const lane = laneOfNode[current];
    if (lane && seenLanes[seenLanes.length - 1] !== lane) seenLanes.push(lane);
    const out = (outByFrom[current] || []).sort((a, b) => (b.weight || 0) - (a.weight || 0));
    current = out.length > 0 ? out[0].target : null;
  }
  if (seenLanes.length < 2) return "";
  const laneLabels = { evade: "EVADE", decode: "DECODE", acquire: "DOWNLOAD", execute: "EXECUTE" };
  return `CHAIN: ${seenLanes.map((l) => laneLabels[l] || l.toUpperCase()).join(" → ")}  ·  drives verdict`;
}

function prettifyLabel(n) {
  const raw = String(n.label || n.value || n.id || "");
  // Turn "URL · http://..." into just the value part when possible.
  let stripped = raw.replace(/^[A-Z]+·\s*/i, "").replace(/^[A-Z ]+·\s*/i, "");
  if (stripped.startsWith("http")) {
    try { stripped = new URL(stripped.replace("[.]", ".")).hostname.replace(".", "[.]"); } catch { /* keep */ }
  }
  return stripped.length > 32 ? stripped.slice(0, 31) + "…" : stripped || n.id;
}

// ── Decode Graph (G1) — linear left-to-right chain of decode layers.
// Renders ONLY nodes with a decode-flavoured kind so the analyst sees
// the unwrapping recipe as a chain, not mixed with behaviour nodes.
function buildDecodeGraph(nodes, edges) {
  const decodeNodes = (nodes || []).filter((n) =>
    /decode|transform|normalize|extract|wrapper|cipher/i.test(String(n.kind || ""))
    || /^Layer\s+\d+/i.test(String(n.label || ""))
  );
  if (decodeNodes.length === 0) {
    return { nodes: [], edges: [], empty: true, width: 900, height: 160 };
  }
  // Sort by layer number if the label starts with "Layer N:"; else keep order.
  decodeNodes.sort((a, b) => {
    const na = parseInt(String(a.label || "").match(/Layer\s+(\d+)/i)?.[1] || 9999, 10);
    const nb = parseInt(String(b.label || "").match(/Layer\s+(\d+)/i)?.[1] || 9999, 10);
    return na - nb;
  });
  const NW = 220, NH = 60, GAP = 40, PAD_X = 40, PAD_Y = 40;
  const layouted = decodeNodes.map((n, i) => ({
    id: n.id,
    title: prettifyLabel(n),
    subtitle: `layer ${i} · ${Math.round((n.confidence || 0) * 100)}%`,
    hot: (n.confidence || 0) >= 0.7,
    x: PAD_X + i * (NW + GAP),
    y: PAD_Y,
    w: NW,
    h: NH,
  }));
  // Edges: connect consecutive decode nodes with cubic Beziers.
  const linkEdges = [];
  for (let i = 0; i < layouted.length - 1; i++) {
    const a = layouted[i], b = layouted[i + 1];
    const sx = a.x + a.w, sy = a.y + a.h / 2;
    const tx = b.x, ty = b.y + b.h / 2;
    const dx = Math.max(24, (tx - sx) * 0.5);
    linkEdges.push({
      path: `M ${sx} ${sy} C ${sx + dx} ${sy}, ${tx - dx} ${ty}, ${tx} ${ty}`,
      hot: true,
    });
  }
  return {
    nodes: layouted,
    edges: linkEdges,
    empty: false,
    width: PAD_X * 2 + layouted.length * NW + (layouted.length - 1) * GAP,
    height: PAD_Y * 2 + NH,
  };
}

// ── G2 · Topological L-shape Decoder Graph ────────────────────────────
// Projects `cio.decode_chain[]` into a dark topological visual (like
// the operator's reference): circular icon nodes on a grid-dot dark
// canvas, L-shape edge routing, and category labels beneath each node
// (FILE / ACTION / SCRIPT). The root is an amber "Raw Payload" file
// node; every decoder step is a purple ACTION node; the final decoded
// payload is a SCRIPT node with a subtle target badge if MITRE
// techniques attached to it.
//
// Layout:
//   nodes[0..half-1]        vertical column at x=V_X, y increases
//   L-bend at the last vertical node
//   nodes[half..N-1]        horizontal row at y=H_Y, x increases
//
// Selection: each layer keeps its evidence-graph node_id so clicks
// on a G2 node still light up the Ledger/Findings/Story chips.
const G2_R = 30;                 // circle radius
const G2_V_X = 110;              // vertical column x
const G2_V_Y0 = 90;              // first node y
const G2_V_GAP = 170;            // vertical spacing between nodes
const G2_H_GAP = 260;            // horizontal spacing between nodes
const G2_H_Y_PAD = 100;          // gap between end of vertical column and horizontal row
const G2_H_X0_PAD = 200;         // gap between vertical column and first horizontal node

function buildDecodeGraphTopo(decodeChain, allNodes, cio) {
  if (!decodeChain || decodeChain.length === 0) {
    return { nodes: [], edges: [], empty: true, width: 900, height: 400 };
  }

  // Nodes: [Raw Payload] + [each decoder layer] + [Decoded final] + [MITRE technique if present]
  const raw = [];

  // 1. Root FILE node — raw payload.
  const inputLen = ((cio && cio.input_text) || "").length;
  raw.push({
    id: "g2-root",
    title: `Raw Payload${inputLen ? ` (${inputLen}c)` : ""}`,
    category: "FILE",
    kind: "file",
    color: "amber",
    icon: "file",
    badge: "spark",                // small blue spark above
  });

  // 2. One ACTION node per decoder layer, ordered by layer idx.
  const sortedLayers = [...decodeChain].sort(
    (a, b) => (a.idx ?? 0) - (b.idx ?? 0)
  );
  sortedLayers.forEach((layer, i) => {
    raw.push({
      id: layer.node_id || `g2-L${layer.idx ?? i}`,
      title: prettifyDecoderOp(layer.op).toUpperCase(),
      subtitle: layer.reason
        ? String(layer.reason).replace(/^Applied\s+/i, "").slice(0, 32)
        : "",
      category: "ACTION",
      kind: "action",
      color: "purple",
      icon: "shield",
    });
  });

  // 3. Terminal SCRIPT node — the decoded payload (last layer's preview).
  const lastLayer = sortedLayers[sortedLayers.length - 1];
  const decodedText = lastLayer && lastLayer.preview ? String(lastLayer.preview) : "";
  if (decodedText) {
    raw.push({
      id: "g2-decoded",
      title: `Decoded (${decodedText.length}c)`,
      category: "SCRIPT",
      kind: "script",
      color: "purple",
      icon: "script",
      target: true,                 // small red target badge
    });
  }

  // 4. If verdict has any contributor with MITRE tags, add a terminal
  //    verdict-ish node showing the top technique. Skip when nothing.
  const nodeById = Object.fromEntries((allNodes || []).map((n) => [n.id, n]));
  const contribIds = ((cio && cio.verdict && cio.verdict.contributors) || [])
    .map((c) => c.node_id);
  let topTechnique = "";
  let topTechniqueName = "";
  for (const cid of contribIds) {
    const nd = nodeById[cid];
    if (!nd) continue;
    const tt = (nd.mitre_techniques || [])[0];
    if (tt) {
      topTechnique = tt;
      // Try to enrich with a short name from the summary mitre digest.
      const mitre = (cio.summary && cio.summary.mitre_digest) || {};
      for (const val of Object.values(mitre)) {
        const techs = Array.isArray(val) ? val : (val && val.techniques) || [];
        for (const t of techs) {
          if ((t.technique_id || t.id) === tt) {
            topTechniqueName = t.name || t.title || "";
            break;
          }
        }
        if (topTechniqueName) break;
      }
      break;
    }
  }
  if (topTechnique) {
    raw.push({
      id: "g2-mitre",
      title: `${topTechnique} · ${topTechniqueName || "Technique"}`,
      category: "ACTION",
      kind: "verdict",
      color: "purple",
      icon: "shield",
      crown: true,                  // yellow crown badge for the verdict
    });
  }

  // Deduplicate nodes by id, preserving order (in case a layer's
  // node_id coincides with a MITRE contributor id, though rare).
  const seen = new Set();
  const nodes = [];
  raw.forEach((n) => {
    if (seen.has(n.id)) return;
    seen.add(n.id);
    nodes.push(n);
  });

  // Split into vertical & horizontal segments.
  const N = nodes.length;
  const half = Math.min(4, Math.max(2, Math.ceil(N / 2)));
  const H_Y = G2_V_Y0 + (half - 1) * G2_V_GAP + G2_H_Y_PAD;
  const H_X0 = G2_V_X + G2_H_X0_PAD;

  nodes.forEach((n, i) => {
    if (i < half) {
      // Vertical column at x=G2_V_X
      n.cx = G2_V_X;
      n.cy = G2_V_Y0 + i * G2_V_GAP;
    } else {
      // Horizontal row at y=H_Y
      n.cx = H_X0 + (i - half) * G2_H_GAP;
      n.cy = H_Y;
    }
  });

  // Edges — sequential i → i+1. Route:
  //   - if both nodes in vertical col     → straight vertical
  //   - if bend point (i == half-1)       → L-shape (down then right)
  //   - else                              → straight horizontal
  // Colour: first edge (root FILE → first ACTION) = amber; the last
  // hop leading INTO the MITRE/verdict node = red hot; all others =
  // muted purple. Matches the operator reference exactly.
  const edges = [];
  const lastIdx = N - 1;
  const mitreEndIdx = nodes[lastIdx] && nodes[lastIdx].crown ? lastIdx : -1;
  for (let i = 0; i < N - 1; i++) {
    const a = nodes[i], b = nodes[i + 1];
    let path;
    if (i < half - 1) {
      // Vertical connection between two vertical nodes.
      path = `M ${a.cx} ${a.cy + G2_R} L ${b.cx} ${b.cy - G2_R}`;
    } else if (i === half - 1 && N > half) {
      // L-bend: vertical from a down to H_Y, then horizontal to b.
      path = `M ${a.cx} ${a.cy + G2_R} L ${a.cx} ${b.cy} L ${b.cx - G2_R} ${b.cy}`;
    } else {
      // Horizontal connection.
      path = `M ${a.cx + G2_R} ${a.cy} L ${b.cx - G2_R} ${b.cy}`;
    }
    // Colour flavour:
    let flavor = "purple";
    if (i === 0) flavor = "amber";                   // root FILE edge is amber
    if (mitreEndIdx > 0 && i + 1 === mitreEndIdx) flavor = "red";  // last hop into verdict is red
    edges.push({ path, flavor, from: a.id, to: b.id });
  }

  // Canvas size.
  const rightMostX = Math.max(
    G2_V_X + 200,
    H_X0 + Math.max(0, N - half - 1) * G2_H_GAP + G2_R + 200
  );
  const bottomMostY = H_Y + G2_R + 120;

  return {
    nodes,
    edges,
    empty: false,
    width: Math.max(rightMostX, 900),
    height: Math.max(bottomMostY, 500),
  };
}

function prettifyDecoderOp(op) {
  if (!op) return "Decoder";
  const s = String(op).replace(/[-_]/g, " ").trim();
  // Common short-forms → friendly titles.
  const MAP = {
    "ps encodedcommand recovery": "PS EncodedCommand",
    "extract payload": "Extract payload",
    "ioc extract": "IOC extract",
    "base64 decode": "Base64 decode",
    "utf16 decode": "UTF-16 decode",
    "hex decode": "Hex decode",
    "gzip inflate": "Gzip inflate",
    "gzip decompress": "Gzip decompress",
    "charcode decode": "Charcode decode",
    "rot decode": "ROT decode",
    "xor decode": "XOR decode",
  };
  const key = s.toLowerCase();
  if (MAP[key]) return MAP[key];
  return s
    .split(" ")
    .map((w) => (w.length <= 4 ? w.toUpperCase() : w[0].toUpperCase() + w.slice(1)))
    .join(" ");
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
    decodeGraph: { nodes: [], edges: [], empty: true, width: 900, height: 200 },
    attackGraph: { lanes: [], edges: [], empty: true, width: 900, height: 500, chainLabel: "" },
    graph: { lanes: [], edges: [], empty: true, width: 900, height: 500, chainLabel: "" },
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
