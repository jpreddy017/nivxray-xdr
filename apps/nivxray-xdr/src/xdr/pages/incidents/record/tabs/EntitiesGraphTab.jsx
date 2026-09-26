/**
 * Entities · the incident investigation workspace.
 *
 * Information architecture (owner directive §D):
 *   Graph | Table switch → entity class filters with authoritative counts
 *   → LEFT graph controls + analysis overlays → DOMINANT causality canvas
 *   → RIGHT persistent Entity Details pane → BOTTOM related-event lanes.
 *
 * Source of truth: `GET /api/incidents/{id}/attack-graph` (nodes, edges,
 * primary_path, alternative_paths, counts, investigation_gaps). Nothing on
 * this surface is synthesised: a class the engine did not count reads `—`,
 * an edge without an evidence reference is drawn as INFERRED, and a graph
 * with no process relationship says so instead of drawing ancestry.
 *
 * The advanced graph (attack chain · MITRE chain · process lineage · path
 * replay) is preserved verbatim under progressive disclosure — no
 * capability was deleted, it simply stopped being primary chrome.
 */
import React, { useEffect, useMemo, useRef, useState } from "react";
import { ChevronLeft, ChevronRight, Download, Loader2, Search } from "lucide-react";

import api from "@/lib/api";
import {
  NxInvSection, NxInvTable, NxInvEmpty, NxInvTech, NxInvValue,
  ABSENCE, fmtTime,
} from "@/xdr/nx";
import { capabilityLabel } from "@/xdr/nx/capabilityLabels";
import NxGraphCanvas, { kindToken, relVerb, nodeContext }
  from "./attack_graph/NxGraphCanvas";
import AttackGraphTab from "./AttackGraphTab";
import "@/xdr/nx/nx-workspace.css";

const CLASSES = [
  { key: "processes", label: "Processes", kinds: ["process", "commandline"] },
  { key: "events", label: "Events", kinds: ["event", "event_id", "signature"] },
  { key: "files", label: "Files", kinds: ["file", "hash"] },
  { key: "network", label: "Network", kinds: ["ip", "domain", "url", "network"] },
  { key: "registry", label: "Registry", kinds: ["registry"] },
  { key: "users", label: "Users", kinds: ["user"] },
  { key: "hosts", label: "Hosts", kinds: ["host"] },
];
const CLASSIFIED = new Set(CLASSES.flatMap((c) => c.kinds));
const STATES = ["OBSERVED", "SUPPORTED", "POSSIBLE", "NOT_OBSERVED"];

const LANES = [
  { key: "process", label: "Process", kinds: ["process", "commandline"] },
  { key: "file", label: "File", kinds: ["file", "hash"] },
  { key: "registry", label: "Registry", kinds: ["registry"] },
  { key: "network", label: "Network", kinds: ["ip", "domain", "url", "network"] },
  { key: "other", label: "Other", kinds: null },
];

export default function EntitiesGraphTab({ incident, onNavigateTab }) {
  const [g, setG] = useState(null);
  const [err, setErr] = useState(null);
  const [loading, setLoading] = useState(true);

  const [mode, setMode] = useState("graph");
  const [cls, setCls] = useState([]);
  const [states, setStates] = useState([]);
  const [showFilters, setShowFilters] = useState(false);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(null);
  const [paneTab, setPaneTab] = useState("details");
  const [railOpen, setRailOpen] = useState(true);
  const [paneOpen, setPaneOpen] = useState(true);
  const [cmd, setCmd] = useState(null);
  const [o, setO] = useState({
    showNeighbors: true, focusSelection: false, showAllPaths: false,
    groupSimilar: false, showLegend: false,
    overlays: { attack: false, confidence: false, risk: true, dataflow: false },
  });
  const seq = useRef(0);

  useEffect(() => {
    if (!incident?.id) return undefined;
    let live = true;
    setLoading(true); setErr(null);
    api.get(`/incidents/${encodeURIComponent(incident.id)}/attack-graph`)
      .then(({ data }) => { if (live) setG(data); })
      .catch((e) => {
        const d = e?.response?.data?.detail;
        if (live) setErr(typeof d === "object"
          ? (d.reason || d.message || JSON.stringify(d))
          : (d || e?.message || "unavailable"));
      })
      .finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, [incident?.id]);

  const nodes = g?.nodes || [];
  const edges = g?.edges || [];

  const counts = useMemo(() => {
    const c = { all: nodes.length || null, more: 0 };
    CLASSES.forEach((k) => { c[k.key] = 0; });
    nodes.forEach((n) => {
      const cl = CLASSES.find((k) => k.kinds.includes(n.kind));
      if (cl) c[cl.key] += 1;
      else if (!CLASSIFIED.has(n.kind)) c.more += 1;
    });
    // A class the engine did not report is NOT zero.
    Object.keys(c).forEach((k) => { if (c[k] === 0) c[k] = null; });
    return c;
  }, [nodes]);

  const times = useMemo(() => {
    const t = [];
    edges.forEach((e) => { if (e.timestamp) t.push(e.timestamp); });
    (g?.timeline || []).forEach((e) => { if (e.at || e.timestamp)
      t.push(e.at || e.timestamp); });
    return t.sort();
  }, [edges, g]);

  const visibleNodes = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const kinds = cls.length
      ? new Set(cls.flatMap((k) => (CLASSES.find((x) => x.key === k)?.kinds
        || [])))
      : null;
    const wantMore = cls.includes("more");
    return nodes.filter((n) => {
      if (kinds && !(kinds.has(n.kind) || (wantMore && !CLASSIFIED.has(n.kind))))
        return false;
      if (states.length && !states.includes(String(n.state))) return false;
      if (!needle) return true;
      return `${n.label} ${n.id} ${JSON.stringify(n.attrs || {})}`
        .toLowerCase().includes(needle);
    });
  }, [nodes, cls, states, q]);

  const visibleIds = useMemo(
    () => new Set(visibleNodes.map((n) => n.id)), [visibleNodes]);

  const selNode = useMemo(
    () => nodes.find((n) => n.id === sel) || null, [nodes, sel]);
  const selEdges = useMemo(() => edges.filter(
    (e) => e.src === sel || e.dst === sel), [edges, sel]);
  const selEvidence = useMemo(() => {
    const s = new Set();
    if (selNode?.attrs?.evidence_refs)
      (selNode.attrs.evidence_refs || []).forEach((r) => s.add(r));
    selEdges.forEach((e) => (e.evidence_refs || []).forEach((r) => s.add(r)));
    return Array.from(s);
  }, [selNode, selEdges]);

  const relsOf = (id) => edges.filter((e) => e.src === id || e.dst === id);
  const evidenceOf = (id) => {
    const s = new Set();
    relsOf(id).forEach((e) => (e.evidence_refs || []).forEach((r) => s.add(r)));
    return Array.from(s);
  };

  const hasTechnique = useMemo(() => edges.some((e) => e.technique_id)
    || nodes.some((n) => n.kind === "technique" || n.kind === "stage"), [edges, nodes]);
  const hasConfidence = useMemo(
    () => nodes.some((n) => n.attrs?.confidence != null), [nodes]);
  const hasRisk = useMemo(() => nodes.some((n) => n.attrs?.verdict
    || n.kind === "detection" || n.kind === "gap"), [nodes]);
  const hasFlow = useMemo(() => nodes.some(
    (n) => ["ip", "domain", "url", "network", "file", "hash"].includes(n.kind)),
    [nodes]);

  const dimIds = useMemo(() => {
    if (o.overlays.dataflow && hasFlow) {
      const keep = new Set(nodes.filter((n) =>
        ["ip", "domain", "url", "network", "file", "hash", "process"]
          .includes(n.kind)).map((n) => n.id));
      return new Set([...visibleIds].filter((x) => keep.has(x)));
    }
    if (o.focusSelection && sel) {
      const keep = new Set([sel]);
      selEdges.forEach((e) => { keep.add(e.src); keep.add(e.dst); });
      return keep;
    }
    if (cls.length || states.length || q.trim()) return visibleIds;
    return null;
  }, [o.overlays.dataflow, hasFlow, nodes, visibleIds, o.focusSelection, sel,
      selEdges, cls, states, q]);

  const fire = (kind) => { seq.current += 1;
    setCmd({ kind, n: seq.current }); };

  const exportGraph = () => {
    const blob = new Blob([JSON.stringify(g, null, 2)],
      { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${incident?.id || "incident"}-attack-graph.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const laneItems = useMemo(() => {
    const out = {};
    LANES.forEach((l) => { out[l.key] = []; });
    visibleNodes.forEach((n) => {
      const l = LANES.find((x) => x.kinds && x.kinds.includes(n.kind));
      out[l ? l.key : "other"].push(n);
    });
    return out;
  }, [visibleNodes]);

  if (loading) return (
    <div className="inv-empty" data-testid="inv-entities-loading">
      <Loader2 size={12} className="rl-spin"
               style={{ verticalAlign: -2, marginRight: 6 }} />
      READING THE ACTIVITY GRAPH…
    </div>
  );

  const railBtn = (label, on, action, disabled, note) => (
    <button className="inv-rail__btn" key={label}
            aria-pressed={on || undefined} disabled={disabled}
            title={disabled ? `${label}: ${ABSENCE.NOT_OBSERVED}` : label}
            onClick={action}
            data-testid={`inv-graph-ctl-${label.toLowerCase()
              .replace(/[^a-z]+/g, "-")}`}>
      {label}
      {(note || disabled) && <span className="inv-rail__n">
        {note || "—"}</span>}
    </button>
  );

  return (
    <div className="inv" data-testid="incident-entities-workspace">
      {/* ── Representation switch + entity class filters ────────── */}
      <NxInvSection
        title="Entities and relationships"
        subtitle={`${nodes.length} entit${nodes.length === 1 ? "y" : "ies"} · ${edges.length} relationship(s) · one graph, two representations`}
        testid="inv-entities-head"
        actions={
          <span style={{ display: "inline-flex", gap: 4 }}>
            <button className="inv-chip" aria-pressed={mode === "graph"}
                    onClick={() => setMode("graph")}
                    data-testid="inv-entities-mode-graph">Graph</button>
            <button className="inv-chip" aria-pressed={mode === "table"}
                    onClick={() => setMode("table")}
                    data-testid="inv-entities-mode-table">Table</button>
          </span>
        }>
        <div className="inv-filters" data-testid="inv-entities-filters">
          <button className="inv-chip" aria-pressed={cls.length === 0}
                  onClick={() => setCls([])}
                  data-testid="inv-entities-class-all">
            Entities<span className="inv-chip__n">{counts.all ?? "—"}</span>
          </button>
          {[...CLASSES, { key: "more", label: "More" }].map((c) => (
            <button key={c.key} className="inv-chip"
                    aria-pressed={cls.includes(c.key)}
                    disabled={counts[c.key] == null}
                    title={counts[c.key] == null
                      ? `${c.label}: ${ABSENCE.NOT_OBSERVED}` : c.label}
                    onClick={() => setCls(cls.includes(c.key)
                      ? cls.filter((x) => x !== c.key) : [...cls, c.key])}
                    data-testid={`inv-entities-class-${c.key}`}>
              {c.label}
              <span className="inv-chip__n">{counts[c.key] ?? "—"}</span>
            </button>
          ))}
          <span className="inv-filters__sp inv-cov__k"
                style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
            <Search size={11} />
            <input value={q} onChange={(e) => setQ(e.target.value)}
                   data-testid="inv-entities-search"
                   placeholder="Search entities, hashes, IPs…"
                   style={{ fontSize: 11, background: "transparent",
                            border: "none", outline: "none", width: 250,
                            color: "var(--nx-text, var(--text))",
                            textTransform: "none", letterSpacing: 0 }} />
          </span>
          <button className="inv-chip" disabled={times.length === 0}
                  title={times.length === 0
                    ? `Time range: ${ABSENCE.NOT_OBSERVED} — no entity or relationship in this graph carries a timestamp`
                    : `${fmtTime(times[0])} → ${fmtTime(times[times.length - 1])}`}
                  data-testid="inv-entities-timerange">
            Time Range
            <span className="inv-chip__n">
              {times.length === 0 ? "—" : `${times.length} stamped`}
            </span>
          </button>
          <button className="inv-chip" aria-pressed={showFilters}
                  onClick={() => setShowFilters((v) => !v)}
                  data-testid="inv-entities-filters-toggle">Filters</button>
        </div>

        {showFilters && (
          <div className="inv-filters" data-testid="inv-entities-state-filters">
            {STATES.map((s) => {
              const n = nodes.filter((x) => x.state === s).length;
              return (
                <button key={s} className="inv-chip" disabled={n === 0}
                        aria-pressed={states.includes(s)}
                        onClick={() => setStates(states.includes(s)
                          ? states.filter((x) => x !== s) : [...states, s])}
                        data-testid={`inv-entities-state-${s}`}>
                  {s.replace("_", " ")}
                  <span className="inv-chip__n">{n || "—"}</span>
                </button>
              );
            })}
            <span className="inv-filters__sp inv-sec__s">
              {visibleNodes.length} of {nodes.length} entities shown
            </span>
          </div>
        )}
      </NxInvSection>

      {err && (
        <NxInvEmpty testid="inv-entities-error"
          title={`${ABSENCE.NOT_AVAILABLE} — the activity graph could not be read`}
          body={String(err)} />
      )}

      {!err && nodes.length === 0 && (
        <NxInvEmpty testid="inv-entities-empty"
          title="NO ENTITY RELATIONSHIP EVIDENCE"
          body="The graph engine produced no entities for this incident. Nothing is drawn: an empty graph is reported as empty, never filled with inferred ancestry."
          points={[`Engine · ${g?.engine_id || ABSENCE.NOT_RECORDED}`,
                   `Generated · ${fmtTime(g?.generated_at) || ABSENCE.NOT_RECORDED}`]} />
      )}

      {!err && nodes.length > 0 && mode === "graph" && (
        <div className="inv-wk" data-testid="inv-entities-graph-wk"
             data-rail={railOpen ? "open" : "collapsed"}
             data-pane={paneOpen ? "open" : "closed"}>
          {/* ── LEFT · graph controls + analysis overlays ───────── */}
          <div className="inv-wk__rail">
            <button className="inv-rail__btn" onClick={() => setRailOpen((v) => !v)}
                    data-testid="inv-graph-rail-toggle"
                    title={railOpen ? "Collapse graph controls"
                      : "Expand graph controls"}>
              {railOpen ? <ChevronLeft size={12} /> : <ChevronRight size={12} />}
              {railOpen && "Graph controls"}
            </button>
            {railOpen && (
              <>
                <div className="inv-rail__g">
                  {railBtn("Center", false, () => fire("center"))}
                  {railBtn("Fit to view", false, () => fire("fit"))}
                  {railBtn("Expand selection", o.focusSelection,
                    () => setO((p) => ({ ...p, focusSelection: !p.focusSelection })),
                    !sel, sel ? null : "select a node")}
                  {railBtn("Show neighbors", o.showNeighbors,
                    () => setO((p) => ({ ...p, showNeighbors: !p.showNeighbors })),
                    !sel, sel ? null : "select a node")}
                  {railBtn("Show all paths", o.showAllPaths,
                    () => setO((p) => ({ ...p, showAllPaths: !p.showAllPaths })),
                    (g?.primary_path || []).length === 0)}
                  {railBtn("Group similar", o.groupSimilar,
                    () => setO((p) => ({ ...p, groupSimilar: !p.groupSimilar })))}
                  {railBtn("Show legend", o.showLegend,
                    () => setO((p) => ({ ...p, showLegend: !p.showLegend })))}
                </div>
                <div className="inv-rail__t">Analysis overlays</div>
                <div className="inv-rail__g">
                  {railBtn("ATT&CK", o.overlays.attack,
                    () => setO((p) => ({ ...p,
                      overlays: { ...p.overlays, attack: !p.overlays.attack } })),
                    !hasTechnique)}
                  {railBtn("Confidence", o.overlays.confidence,
                    () => setO((p) => ({ ...p,
                      overlays: { ...p.overlays,
                        confidence: !p.overlays.confidence } })),
                    !hasConfidence)}
                  {railBtn("Risk indicators", o.overlays.risk,
                    () => setO((p) => ({ ...p,
                      overlays: { ...p.overlays, risk: !p.overlays.risk } })),
                    !hasRisk)}
                  {railBtn("Data flow", o.overlays.dataflow,
                    () => setO((p) => ({ ...p,
                      overlays: { ...p.overlays,
                        dataflow: !p.overlays.dataflow } })),
                    !hasFlow)}
                </div>
                <div className="inv-rail__g">
                  <button className="inv-rail__btn" onClick={exportGraph}
                          data-testid="inv-graph-export">
                    <Download size={11} /> Export Graph
                  </button>
                </div>
              </>
            )}
          </div>

          {/* ── CENTRE · the causality canvas ──────────────────── */}
          <div className="inv-wk__main">
            <NxGraphCanvas nodes={nodes} edges={edges}
                           primaryPath={g?.primary_path || []}
                           altPaths={g?.alternative_paths || []}
                           selectedId={sel}
                           onSelect={(id) => { setSel(id); setPaneOpen(true); }}
                           cmd={cmd} opts={o} dimIds={dimIds} />

            {/* BOTTOM · related events, synchronised with selection */}
            <div className="inv-lanes" data-testid="inv-graph-lanes">
              {LANES.map((l) => {
                const items = laneItems[l.key] || [];
                const related = new Set(selEdges.flatMap((e) => [e.src, e.dst]));
                return (
                  <div className="inv-lane" key={l.key}
                       data-testid={`inv-graph-lane-${l.key}`}>
                    <div className="inv-lane__k">{l.label}</div>
                    <div className="inv-lane__b">
                      {items.length === 0 && (
                        <span className="inv-tb__na">{ABSENCE.NOT_OBSERVED}</span>
                      )}
                      {items.slice(0, 14).map((n) => (
                        <button key={n.id} className="inv-chip"
                                aria-pressed={n.id === sel
                                  || related.has(n.id) || undefined}
                                onClick={() => { setSel(n.id); setPaneOpen(true); }}
                                title={`${kindToken(n.kind)} · ${n.state}`}
                                data-testid={`inv-graph-lane-item-${n.id}`}>
                          {String(n.label).slice(0, 22)}
                        </button>
                      ))}
                      {items.length > 14 && (
                        <span className="inv-sec__s">
                          +{items.length - 14} more in Table view
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
              <div className="inv-lane">
                <div className="inv-lane__k">Timeline</div>
                <div className="inv-lane__b">
                  <button className="inv-chip"
                          onClick={() => onNavigateTab && onNavigateTab("timeline")}
                          data-testid="inv-graph-view-in-timeline">
                    View in Timeline →
                  </button>
                  <span className="inv-sec__s">
                    {times.length === 0
                      ? "no relationship in this graph carries a timestamp — the Timeline tab reads the endpoint event stream"
                      : `${times.length} stamped relationship(s)`}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* ── RIGHT · persistent entity details ──────────────── */}
          {paneOpen && (
            <div className="inv-wk__pane" data-testid="inv-entity-pane">
              <div className="inv-pane__h">
                <span style={{ minWidth: 0 }}>
                  <div className="inv-pane__k">
                    {selNode ? kindToken(selNode.kind) : "ENTITY DETAILS"}
                  </div>
                  <div className="inv-pane__t" data-testid="inv-entity-pane-title">
                    {selNode ? selNode.label : "No entity selected"}
                  </div>
                </span>
                <button className="inv-chip" style={{ marginLeft: "auto" }}
                        onClick={() => setPaneOpen(false)}
                        data-testid="inv-entity-pane-close">Close</button>
              </div>

              {!selNode && (
                <div className="inv-pane__b">
                  <NxInvEmpty testid="inv-entity-pane-empty"
                    title="Select an entity"
                    body="Click a node on the canvas or a row in Table view to inspect it here without leaving the incident." />
                </div>
              )}

              {selNode && (
                <>
                  <div className="inv-pane__tabs" role="tablist">
                    {[["details", "Details"],
                      ["relationships", `Relationships (${selEdges.length})`],
                      ["evidence", `Evidence (${selEvidence.length})`],
                      ["context", "Context"]].map(([k, label]) => (
                      <button key={k} className="inv-pane__tab" role="tab"
                              aria-selected={paneTab === k}
                              onClick={() => setPaneTab(k)}
                              data-testid={`inv-entity-pane-tab-${k}`}>
                        {label}
                      </button>
                    ))}
                  </div>
                  <div className="inv-pane__b">
                    {paneTab === "details" && (
                      <dl className="inv-kv" data-testid="inv-entity-details">
                        <dt>Entity</dt>
                        <dd><NxInvValue value={selNode.label} /></dd>
                        <dt>Class</dt>
                        <dd>{kindToken(selNode.kind)}</dd>
                        <dt>Engine state</dt>
                        <dd className="mono"><NxInvValue value={selNode.state}
                          absent={ABSENCE.NOT_EVALUATED} /></dd>
                        <dt>Identifying context</dt>
                        <dd>{nodeContext(selNode).length
                          ? nodeContext(selNode).join(" · ")
                          : <span className="inv-tb__na">
                              {ABSENCE.NOT_OBSERVED}</span>}</dd>
                        {selNode.attrs?.capability && (
                          <>
                            <dt>Capability</dt>
                            <dd>{capabilityLabel(selNode.attrs.capability)}</dd>
                          </>
                        )}
                        <dt>Relationships</dt>
                        <dd>{selEdges.length || <span className="inv-tb__na">
                          {ABSENCE.NOT_OBSERVED}</span>}</dd>
                        <dt>Engine node id</dt>
                        <dd className="mono">{selNode.id}</dd>
                      </dl>
                    )}

                    {paneTab === "relationships" && (
                      selEdges.length === 0
                        ? <NxInvEmpty testid="inv-entity-rel-empty"
                            title={ABSENCE.NOT_OBSERVED}
                            body="No relationship in this graph references this entity." />
                        : selEdges.map((e) => {
                          const other = e.src === sel ? e.dst : e.src;
                          const on = nodes.find((n) => n.id === other);
                          const inferred = !(e.evidence_refs || []).length;
                          return (
                            <button className="inv-pane__row" key={e.id}
                                    onClick={() => setSel(other)}
                                    data-testid={`inv-entity-rel-${e.id}`}>
                              <span className="inv-pane__verb">
                                {e.src === sel ? relVerb(e.rel)
                                  : `← ${relVerb(e.rel)}`}
                              </span>
                              <span style={{ minWidth: 0 }}>
                                <b>{on ? on.label : other}</b>
                                <div className="inv-sec__s">
                                  {on ? kindToken(on.kind) : "UNRESOLVED"}
                                  {inferred
                                    ? " · INFERRED · no evidence reference"
                                    : ` · ${(e.evidence_refs || []).length} evidence ref(s)`}
                                  {e.reason ? ` · ${e.reason}` : ""}
                                </div>
                              </span>
                            </button>
                          );
                        })
                    )}

                    {paneTab === "evidence" && (
                      selEvidence.length === 0
                        ? <NxInvEmpty testid="inv-entity-ev-empty"
                            title={ABSENCE.EVIDENCE_INCOMPLETE}
                            body="No canonical evidence reference reaches this entity through the graph. It is drawn from a relationship the engine derived, not from an evidence record." />
                        : selEvidence.map((ref) => (
                          <button className="inv-pane__row" key={ref}
                                  onClick={() => onNavigateTab
                                    && onNavigateTab("evidence")}
                                  data-testid={`inv-entity-ev-${ref}`}>
                            <span className="inv-pane__verb">evidence</span>
                            <span className="mono"
                                  style={{ wordBreak: "break-all" }}>
                              {ref} →
                            </span>
                          </button>
                        ))
                    )}

                    {paneTab === "context" && (
                      <dl className="inv-kv" data-testid="inv-entity-context">
                        <dt>On the primary path</dt>
                        <dd>{(g?.primary_path || []).includes(sel)
                          ? "YES — this entity is on the incident's primary causal path"
                          : "NO — not on the primary causal path"}</dd>
                        <dt>Alternative paths</dt>
                        <dd>{(g?.alternative_paths || []).length
                          ? `${(g.alternative_paths || [])
                              .filter((p) => (p || []).includes(sel)).length} of ${(g.alternative_paths || []).length}`
                          : <span className="inv-tb__na">
                              {ABSENCE.NOT_OBSERVED}</span>}</dd>
                        <dt>Investigation gaps</dt>
                        <dd>{(g?.investigation_gaps || []).length
                          ? (g.investigation_gaps || []).map((x) => x.key).join(", ")
                          : <span className="inv-tb__na">
                              {ABSENCE.NOT_OBSERVED}</span>}</dd>
                        <dt>Engine attributes</dt>
                        <dd className="mono">
                          {JSON.stringify(selNode.attrs || {})}</dd>
                      </dl>
                    )}
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      )}

      {!err && nodes.length > 0 && mode === "table" && (
        <div className="inv-split" data-pane={paneOpen && selNode ? "open" : "closed"}
             data-testid="inv-entities-table-wk">
          <div className="inv-split__t">
            <NxInvTable testid="inv-entities-table" rows={visibleNodes}
                        rowKey={(r) => r.id}
                        onRowClick={(r) => { setSel(r.id); setPaneOpen(true); }}
                        columns={[
                          { key: "label", label: "Entity",
                            render: (r) => <NxInvValue value={r.label} /> },
                          { key: "kind", label: "Class", width: 130,
                            render: (r) => kindToken(r.kind) },
                          { key: "state", label: "State", width: 120,
                            render: (r) => <NxInvValue value={r.state} mono
                              absent={ABSENCE.NOT_EVALUATED} /> },
                          { key: "rels", label: "Relationships", width: 110,
                            num: true, render: (r) => relsOf(r.id).length || "—" },
                          { key: "ev", label: "Evidence", width: 110, num: true,
                            render: (r) => evidenceOf(r.id).length || "—" },
                          { key: "ctx", label: "Context",
                            render: (r) => (nodeContext(r).join(" · ")
                              || <span className="inv-tb__na">
                                {ABSENCE.NOT_OBSERVED}</span>) },
                        ]}
                        empty={<NxInvEmpty testid="inv-entities-table-empty"
                          title="No entity matches the current filters"
                          body="Clear the class, state or search filters to see every entity the engine reported." />} />
          </div>
          {paneOpen && selNode && (
            <div className="inv-split__p" data-testid="inv-entities-table-pane">
              <div className="inv-pane__h">
                <span style={{ minWidth: 0 }}>
                  <div className="inv-pane__k">{kindToken(selNode.kind)}</div>
                  <div className="inv-pane__t">{selNode.label}</div>
                </span>
                <button className="inv-chip" style={{ marginLeft: "auto" }}
                        onClick={() => setSel(null)}
                        data-testid="inv-entities-table-pane-close">Close</button>
              </div>
              <div className="inv-pane__b">
                <dl className="inv-kv">
                  <dt>Engine state</dt>
                  <dd className="mono"><NxInvValue value={selNode.state}
                    absent={ABSENCE.NOT_EVALUATED} /></dd>
                  <dt>Context</dt>
                  <dd>{nodeContext(selNode).join(" · ")
                    || <span className="inv-tb__na">{ABSENCE.NOT_OBSERVED}</span>}</dd>
                  <dt>Relationships</dt>
                  <dd>{selEdges.length
                    ? selEdges.map((e) => `${relVerb(e.rel)} ${
                        e.src === sel ? e.dst : e.src}`).join(" · ")
                    : <span className="inv-tb__na">
                        {ABSENCE.NOT_OBSERVED}</span>}</dd>
                  <dt>Evidence</dt>
                  <dd className="mono">{selEvidence.join(", ")
                    || <span className="inv-tb__na">
                      {ABSENCE.EVIDENCE_INCOMPLETE}</span>}</dd>
                </dl>
              </div>
            </div>
          )}
        </div>
      )}

      <NxInvTech label="Advanced graph · attack chain · ATT&CK chain · process lineage · path replay"
                 testid="inv-entities-advanced">
        <AttackGraphTab incident={incident} onNavigateTab={onNavigateTab} />
      </NxInvTech>

      <NxInvTech label="Technical details · graph engine"
                 testid="inv-entities-tech">
        <dl className="inv-kv">
          <dt>Read</dt>
          <dd className="mono">GET /api/incidents/{incident?.id}/attack-graph</dd>
          <dt>Engine</dt>
          <dd className="mono"><NxInvValue value={g?.engine_id}
            absent={ABSENCE.NOT_RECORDED} /> · <NxInvValue
            value={g?.engine_version} absent={ABSENCE.NOT_RECORDED} /></dd>
          <dt>Schema</dt>
          <dd className="mono"><NxInvValue value={g?.schema_version}
            absent={ABSENCE.NOT_RECORDED} /></dd>
          <dt>Counts</dt>
          <dd className="mono">{JSON.stringify(g?.counts || {})}</dd>
          <dt>Metrics</dt>
          <dd className="mono">{JSON.stringify(g?.metrics || {})}</dd>
          <dt>Honesty note</dt>
          <dd>{g?.honesty_note || ABSENCE.NOT_RECORDED}</dd>
        </dl>
      </NxInvTech>
    </div>
  );
}
