import React, { useMemo } from "react";
import { X } from "lucide-react";

/**
 * NodeInspector v2 — every clicked node in the EvidenceGraphCanvas opens
 * this drawer. It projects the selected node's full downstream truth:
 *
 *   • Node fields         — id, kind, class, confidence, subtype
 *   • Process context     — image, command line, parent, children (when
 *                            the CIO carries process artifacts)
 *   • Graph neighbours    — direct predecessors + successors from
 *                            evidence_graph.edges (upstream / downstream)
 *   • OSINT enrichment    — per-provider chips with state (HIT/NO-HIT/…)
 *   • MITRE ties          — technique nodes connected to this node
 *   • Rules / LOLBAS      — metadata records that cite this node id
 *   • Confidence timeline — verdict.confidence_timeline stages referencing
 *                            this node's label
 *   • Investigation Ledger — Truth-Model reasoning trail filtered to this
 *                            node: Observation → Finding → Hypothesis →
 *                            Validation → Decision → Recommendation
 *
 * Reads ONLY from the CIO passed in. No fetch, no cache.
 */
export function NodeInspector({ nodeId, cio, onClose }) {
  const info = useMemo(() => resolveNode(nodeId, cio), [nodeId, cio]);

  if (!nodeId) return null;
  if (!info) {
    return (
      <aside className="eg-inspector" data-testid="eg-inspector">
        <header>
          <h4>Node inspector</h4>
          <button className="eg-inspector-close" onClick={onClose} data-testid="eg-inspector-close">
            <X size={14} />
          </button>
        </header>
        <div className="eg-inspector-empty">
          Selected node <code>{nodeId}</code> is not present in cio.evidence_graph.
        </div>
      </aside>
    );
  }

  const {
    node, attrs, providers, mitreTies, timelineHits, findings,
    upstream, downstream, rules, lolbasCitations, ledger,
    image, commandLine, parent, children,
  } = info;

  return (
    <aside className="eg-inspector" data-testid="eg-inspector">
      <header>
        <div>
          <div className="eg-inspector-kind">{(node.kind || "node").toUpperCase()}</div>
          <h4 title={node.label}>{node.label || node.id}</h4>
          <div className="eg-inspector-id">{node.id}</div>
        </div>
        <button className="eg-inspector-close" onClick={onClose} data-testid="eg-inspector-close">
          <X size={14} />
        </button>
      </header>

      <section>
        <div className="eg-inspector-row"><span>Confidence</span><b>{typeof node.confidence === "number" ? `${Math.round(node.confidence > 1 ? node.confidence : node.confidence * 100)}%` : "—"}</b></div>
        {attrs.class ? <div className="eg-inspector-row"><span>Class</span><b>{attrs.class}</b></div> : null}
        {attrs.tactic ? <div className="eg-inspector-row"><span>Tactic</span><b>{attrs.tactic}</b></div> : null}
        {attrs.technique_id ? <div className="eg-inspector-row"><span>Technique</span><b>{attrs.technique_id}</b></div> : null}
        {attrs.ioc_kind ? <div className="eg-inspector-row"><span>IOC kind</span><b>{attrs.ioc_kind}</b></div> : null}
        {attrs.layer !== undefined ? <div className="eg-inspector-row"><span>Layer</span><b>L{attrs.layer}</b></div> : null}
        {attrs.op ? <div className="eg-inspector-row"><span>Operation</span><b>{attrs.op}</b></div> : null}
      </section>

      {(image || commandLine || parent || (children && children.length > 0)) ? (
        <section data-testid="eg-inspector-process">
          <h5>Process context</h5>
          {image ? <div className="eg-inspector-row"><span>Image</span><b>{image}</b></div> : null}
          {commandLine ? (
            <div className="eg-inspector-code">
              <span className="quiet">Command line</span>
              <pre>{commandLine}</pre>
            </div>
          ) : null}
          {parent ? <div className="eg-inspector-row"><span>Parent</span><b>{parent}</b></div> : null}
          {children && children.length > 0 ? (
            <div className="eg-inspector-row"><span>Children</span><b>{children.join(", ")}</b></div>
          ) : null}
        </section>
      ) : null}

      {(upstream.length > 0 || downstream.length > 0) ? (
        <section data-testid="eg-inspector-neighbours">
          <h5>Graph neighbours</h5>
          {upstream.length > 0 ? (
            <div>
              <div className="eg-inspector-sublabel">Upstream · led to this node</div>
              <ul className="eg-inspector-neighbours">
                {upstream.slice(0, 8).map((n) => (
                  <li key={n.id}>
                    <b>{n.label || n.id}</b>
                    <span className="quiet"> · {n.kind}</span>
                    {n.relation ? <span className="eg-relation"> {n.relation}</span> : null}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {downstream.length > 0 ? (
            <div>
              <div className="eg-inspector-sublabel">Downstream · caused by this node</div>
              <ul className="eg-inspector-neighbours">
                {downstream.slice(0, 8).map((n) => (
                  <li key={n.id}>
                    <b>{n.label || n.id}</b>
                    <span className="quiet"> · {n.kind}</span>
                    {n.relation ? <span className="eg-relation"> {n.relation}</span> : null}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </section>
      ) : null}

      {providers.length > 0 ? (
        <section data-testid="eg-inspector-osint">
          <h5>OSINT · enrichment providers</h5>
          <ul className="eg-inspector-providers">
            {providers.map((p, i) => (
              <li key={i} data-testid={`eg-inspector-provider-${p.name}`}>
                <span className="eg-provider-name">{p.name}</span>
                <span className={`eg-provider-state eg-state-${(p.state || "unknown").toLowerCase()}`}>{p.state || "?"}</span>
                {p.reputation ? <span className="eg-provider-note">{p.reputation}</span> : null}
                {p.hit_count ? <span className="eg-provider-note">{p.hit_count}</span> : null}
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {mitreTies.length > 0 ? (
        <section data-testid="eg-inspector-mitre">
          <h5>MITRE ties</h5>
          <ul className="eg-inspector-mitre">
            {mitreTies.map((t) => (
              <li key={t.id}><b>{t.technique_id || ""}</b> · {t.label} <span className="quiet">· {t.tactic || ""}</span></li>
            ))}
          </ul>
        </section>
      ) : null}

      {(rules.length > 0 || lolbasCitations.length > 0) ? (
        <section data-testid="eg-inspector-rules">
          <h5>Rules & LOLBAS citations</h5>
          {rules.length > 0 ? (
            <ul className="eg-inspector-mitre">
              {rules.slice(0, 6).map((r, i) => (
                <li key={`r${i}`}><b>{r.rule_id || r.name || "rule"}</b> <span className="quiet">· {r.family || r.class || ""}</span></li>
              ))}
            </ul>
          ) : null}
          {lolbasCitations.length > 0 ? (
            <ul className="eg-inspector-mitre">
              {lolbasCitations.slice(0, 6).map((l, i) => (
                <li key={`l${i}`}><b>{l.binary || l.name || "LOLBin"}</b> <span className="quiet">· {(l.techniques || []).join(" · ")}</span></li>
              ))}
            </ul>
          ) : null}
        </section>
      ) : null}

      {timelineHits.length > 0 ? (
        <section data-testid="eg-inspector-timeline">
          <h5>Confidence timeline hits</h5>
          <ul className="eg-inspector-timeline">
            {timelineHits.map((h, i) => (
              <li key={i}>Stage {h.stage} · {h.confidence_pct}% · <span className="quiet">{h.class}</span></li>
            ))}
          </ul>
        </section>
      ) : null}

      {ledger && (ledger.observation || ledger.finding || ledger.hypothesis || ledger.validation || ledger.decision || ledger.recommendation) ? (
        <section data-testid="eg-inspector-ledger" className="eg-inspector-ledger">
          <h5>Investigation Ledger · Truth-model reasoning trail</h5>
          <ol className="eg-ledger-chain">
            {ledger.observation ? <li className="ledger-step ledger-observation"><span className="ledger-kind">Observation</span><span className="ledger-body">{ledger.observation}</span></li> : null}
            {ledger.finding ? <li className="ledger-step ledger-finding"><span className="ledger-kind">Finding</span><span className="ledger-body">{ledger.finding}</span></li> : null}
            {ledger.hypothesis ? <li className="ledger-step ledger-hypothesis"><span className="ledger-kind">Hypothesis</span><span className="ledger-body">{ledger.hypothesis}</span></li> : null}
            {ledger.validation ? <li className="ledger-step ledger-validation"><span className="ledger-kind">Validation</span><span className="ledger-body">{ledger.validation}</span></li> : null}
            {ledger.decision ? <li className="ledger-step ledger-decision"><span className="ledger-kind">Decision</span><span className="ledger-body">{ledger.decision}</span></li> : null}
            {ledger.recommendation ? <li className="ledger-step ledger-recommendation"><span className="ledger-kind">Recommendation</span><span className="ledger-body">{ledger.recommendation}</span></li> : null}
          </ol>
        </section>
      ) : null}

      {findings.length > 0 ? (
        <section data-testid="eg-inspector-findings">
          <h5>All truth findings citing this node</h5>
          <ul className="eg-inspector-findings">
            {findings.map((f, i) => (
              <li key={i}><b>{f.label || "finding"}</b><br/><span className="quiet">{f.rationale || f.observation || ""}</span></li>
            ))}
          </ul>
        </section>
      ) : null}
    </aside>
  );
}

/**
 * Walks the CIO to resolve every downstream projection for `nodeId`.
 * Kept as a pure function so the inspector re-renders deterministically.
 */
function resolveNode(nodeId, cio) {
  if (!nodeId || !cio) return null;
  const graph = cio.evidence_graph || {};
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  const node = nodes.find((n) => n.id === nodeId);
  if (!node) return null;
  const attrs = node.attrs || {};
  const md = cio.metadata || {};

  // Providers — inline or via enrichment.providers.
  const providers = (attrs.enrichment && attrs.enrichment.providers) || node.enrichment?.providers || [];

  // MITRE ties — edges from this node to mitre_technique nodes.
  const mitre = new Map();
  nodes.forEach((n) => { if (n.kind === "mitre_technique") mitre.set(n.id, n); });
  const tied = new Set();
  edges.forEach((e) => {
    if (e.source === nodeId && mitre.has(e.target)) tied.add(e.target);
    if (e.target === nodeId && mitre.has(e.source)) tied.add(e.source);
  });
  const mitreTies = Array.from(tied).map((id) => {
    const m = mitre.get(id);
    return { id, label: m.label || id, technique_id: m.attrs?.technique_id, tactic: m.attrs?.tactic };
  });

  // Neighbours — upstream (edge.target = nodeId) + downstream (edge.source = nodeId).
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const upstream = edges
    .filter((e) => e.target === nodeId && byId.has(e.source))
    .map((e) => ({ ...byId.get(e.source), relation: e.relation || e.label }));
  const downstream = edges
    .filter((e) => e.source === nodeId && byId.has(e.target))
    .map((e) => ({ ...byId.get(e.target), relation: e.relation || e.label }));

  // Timeline hits — verdict.confidence_timeline entries whose contributor
  // label matches the node label (best-effort).
  const tl = cio.verdict?.confidence_timeline || [];
  const timelineHits = tl.filter((entry) => {
    const lbl = (entry.contributor_label || "").toString();
    return node.label && lbl.includes(node.label.toString().slice(0, 24));
  });

  // Findings that cite this node id.
  const truthFindings = cio.truth?.findings || [];
  const findings = truthFindings.filter((f) => (f.evidence_node_ids || f.node_ids || []).includes(nodeId));

  // Rules / LOLBAS citations.
  const rulesAll = md.custom_recipes_matched || md.recipes_matched || md.rules_hit || [];
  const rules = rulesAll.filter((r) => {
    const ids = r.node_ids || r.evidence_node_ids || [];
    return ids.includes(nodeId) || (r.label && node.label && r.label.includes(node.label));
  });
  const lolbasAll = md.lolbas || [];
  const lolbasCitations = lolbasAll.filter((l) => {
    const ids = l.node_ids || l.evidence_node_ids || [];
    if (ids.includes(nodeId)) return true;
    // fallback: match by binary name against the node label
    return node.label && (l.binary || l.name) && String(node.label).toLowerCase().includes(String(l.binary || l.name).toLowerCase());
  });

  // Process context — from attrs (some CIO builds carry these on process
  // artifacts). Falls back to input_text for the seed artifact.
  const image = attrs.image || attrs.process_name || attrs.binary || (node.kind === "lolbin" ? node.label : null);
  const commandLine = attrs.command_line || attrs.args || (node.kind === "artifact" ? (cio.input_text || "").slice(0, 400) : null);
  const parent = attrs.parent_image || attrs.parent_name || null;
  const children = (attrs.children || []).map((c) => c.image || c.name || c);

  // Ledger — walk Truth-Model chains to find the first Observation / Finding
  // / Hypothesis / Validation / Decision / Recommendation touching this node.
  const ledger = buildLedgerForNode(nodeId, node, cio);

  return {
    node, attrs, providers, mitreTies, timelineHits, findings,
    upstream, downstream, rules, lolbasCitations, ledger,
    image, commandLine, parent, children,
  };
}

function buildLedgerForNode(nodeId, node, cio) {
  const truth = cio.truth || {};
  const cite = (rec) => {
    if (!rec) return false;
    const ids = rec.evidence_node_ids || rec.node_ids || rec.node_id;
    if (Array.isArray(ids)) return ids.includes(nodeId);
    if (ids) return ids === nodeId;
    // Fallback: text match against the node label.
    const txt = (rec.observation || rec.label || rec.statement || rec.rationale || rec.summary || "").toString();
    return node.label && txt.includes(String(node.label).slice(0, 20));
  };

  const obs = (truth.observations || []).find(cite);
  const fnd = (truth.findings || []).find(cite);
  const hyp = (truth.hypotheses || []).find(cite);
  const val = (truth.validations || []).find(cite);
  const dec = truth.decision && cite(truth.decision) ? truth.decision : truth.decision || null;
  const rec = (truth.recommendations || []).find(cite);

  const fmt = (o, keys) => {
    if (!o) return null;
    for (const k of keys) {
      if (o[k]) return String(o[k]).slice(0, 240);
    }
    return null;
  };

  return {
    observation: fmt(obs, ["observation", "statement", "label", "summary"]),
    finding: fmt(fnd, ["label", "finding", "summary", "rationale"]),
    hypothesis: fmt(hyp, ["hypothesis", "label", "statement"]),
    validation: fmt(val, ["validation", "label", "statement", "result"]),
    decision: fmt(dec, ["verdict", "label", "summary", "rationale"]),
    recommendation: fmt(rec, ["recommendation", "action", "label", "summary"]),
  };
}
