import React, { useMemo } from "react";
import { X } from "lucide-react";

/**
 * NodeInspector — right-side drawer that projects a single evidence-graph
 * node into its downstream truths: what it means, its MITRE ties, its OSINT
 * enrichment, and its position in the confidence timeline. Reads only from
 * the CIO passed in — no separate API calls.
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

  const { node, attrs, providers, mitreTies, timelineHits, findings } = info;

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

      {providers.length > 0 ? (
        <section>
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
        <section>
          <h5>MITRE ties</h5>
          <ul className="eg-inspector-mitre">
            {mitreTies.map((t) => (
              <li key={t.id}><b>{t.technique_id || ""}</b> · {t.label} <span className="quiet">· {t.tactic || ""}</span></li>
            ))}
          </ul>
        </section>
      ) : null}

      {timelineHits.length > 0 ? (
        <section>
          <h5>Confidence timeline hits</h5>
          <ul className="eg-inspector-timeline">
            {timelineHits.map((h, i) => (
              <li key={i}>Stage {h.stage} · {h.confidence_pct}% · <span className="quiet">{h.class}</span></li>
            ))}
          </ul>
        </section>
      ) : null}

      {findings.length > 0 ? (
        <section>
          <h5>Truth · findings citing this node</h5>
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

function resolveNode(nodeId, cio) {
  if (!nodeId || !cio) return null;
  const graph = cio.evidence_graph || {};
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  const node = nodes.find((n) => n.id === nodeId);
  if (!node) return null;
  const attrs = node.attrs || {};

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

  // Timeline hits — verdict.confidence_timeline entries whose contributor
  // label matches the node label (best-effort).
  const tl = cio.verdict?.confidence_timeline || [];
  const timelineHits = tl.filter((entry) => {
    const lbl = (entry.contributor_label || "").toString();
    return node.label && lbl.includes(node.label.toString().slice(0, 24));
  });

  // Findings that cite this node id (many truth models carry evidence_node_ids).
  const truthFindings = cio.truth?.findings || [];
  const findings = truthFindings.filter((f) => (f.evidence_node_ids || f.node_ids || []).includes(nodeId));

  return { node, attrs, providers, mitreTies, timelineHits, findings };
}
