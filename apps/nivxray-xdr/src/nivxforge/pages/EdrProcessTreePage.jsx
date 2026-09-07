/**
 * NivXForge EDR · Process Tree page.
 *
 * Reuses the canonical Activity Inventory (SSOT) that already backs
 * Device Trajectory.  We do NOT introduce a second process-correlation
 * model.  Empty state is honest — no fake trees.
 *
 * Each process node exposes contextual pivots:
 *   • Device Trajectory (existing /edr/trajectory)
 *   • Command Intelligence (existing /analyze, only when a command
 *     line is present on the entity)
 */
import React, { useEffect, useState, useMemo } from "react";
import { Link } from "react-router-dom";
import { Loader2, GitBranch, ChevronRight, Terminal, Radar } from "lucide-react";

import { useSearchParams } from "react-router-dom";
import NivXForgeConsole, { useIncidentContext } from "@/nivxforge/NivXForgeConsole";
import { getEdrProcessTree,
         getEndpointProcessTree } from "@/nivxforge/edrApi";
import { EndpointNotResolved,
         notResolved } from "@/nivxforge/components/EndpointNotResolved";

function useTree(incidentId, endpointId) {
  const pivot = endpointId || incidentId;
  const [state, setState] = useState({
    loading: !!pivot, error: null, tree: null,
  });
  useEffect(() => {
    if (!pivot) { setState({ loading: false, error: null, tree: null }); return; }
    let cancelled = false;
    (async () => {
      setState({ loading: true, error: null, tree: null });
      try {
        const data = endpointId
          ? await getEndpointProcessTree(endpointId)
          : await getEdrProcessTree(incidentId);
        if (!cancelled) setState({ loading: false, error: null, tree: data });
      } catch (e) {
        if (!cancelled) setState({
          loading: false,
          error: e?.response?.data?.detail || e?.message || "Failed to load process tree.",
          tree: null,
        });
      }
    })();
    return () => { cancelled = true; };
  }, [pivot, endpointId, incidentId]);
  return state;
}

export default function EdrProcessTreePage() {
  const ctx = useIncidentContext();
  const [params] = useSearchParams();
  const endpointId = params.get("endpoint_id") || params.get("device");
  const { loading, error, tree } = useTree(ctx.incident_id, endpointId);
  const pivot = endpointId || ctx.incident_id;

  const byId = useMemo(() => {
    const m = new Map();
    (tree?.nodes || []).forEach(
      (n) => m.set(n.entity_id || n.process_iid, n));
    return m;
  }, [tree]);

  return (
    <NivXForgeConsole activeTab="process-tree">
      <h1 className="page-h1" data-testid="edr-processtree-heading">Process Tree</h1>
      <div className="page-sub">
        {endpointId
          ? "Real ancestry from NivXForge sensor evidence. Links are "
            + "canonical process identities, never pid alone — Linux "
            + "reuses pids. A ghost parent is a visibility gap, not an "
            + "absent process."
          : "Reuses the canonical Activity Inventory (parent → child "
            + "process relationships). No parallel correlation engine."}
      </div>

      {!pivot && (
        <div className="x-empty" data-testid="edr-processtree-noctx">
          Process Tree is scoped to an incident.
          Open this page from an incident's <b>NivXForge EDR</b> launcher.
        </div>
      )}
      {pivot && loading && (
        <div className="x-empty" data-testid="edr-processtree-loading">
          <Loader2 size={13} className="spin" style={{ verticalAlign: "middle", marginRight: 6 }} />
          Loading process tree …
        </div>
      )}
      {pivot && !loading && error && (
        <div className="x-empty" style={{ color: "#ff9494" }}
             data-testid="edr-processtree-error">
          {String(error)}
        </div>
      )}
      {pivot && !loading && !error && notResolved(tree) && (
        <EndpointNotResolved supplied={endpointId} payload={tree}
                             testid="edr-processtree-not-resolved" />
      )}
      {pivot && !loading && !error && tree && !notResolved(tree)
        && tree.reason === "no_matching_evidence" && (
        <div className="x-empty" data-testid="edr-processtree-empty">
          <b>NO MATCHING EVIDENCE</b>
          <div style={{ marginTop: 4 }}>
            {tree.note
             || "No canonical timeline attached to this incident."}
          </div>
        </div>
      )}
      {pivot && !loading && !error && tree
        && tree.reason === "ok" && (
        <>
          {tree.counts && (
            <div style={{ marginBottom: 8, fontSize: 10.5,
                          color: "var(--faint)" }}
                 data-testid="edr-processtree-counts">
              {tree.counts.observed} observed processes ·{" "}
              {tree.counts.roots} root{tree.counts.roots === 1 ? "" : "s"}
              {tree.counts.ghost_parents > 0 && (
                <span style={{ color: "#ffb454" }}>
                  {" · "}{tree.counts.ghost_parents} ghost parent
                  {tree.counts.ghost_parents === 1 ? "" : "s"} (never
                  observed — a visibility gap, not an absent process)
                </span>)}
            </div>)}
          <div style={{
            marginBottom: 10, fontSize: 10.5, letterSpacing: ".3px",
            color: "var(--faint)", textTransform: "uppercase", fontWeight: 800,
          }}>
            SSOT · <span style={{ color: "var(--cyan)" }}>{tree.source}</span>
          </div>
          <div className="panel" style={{ padding: "12px 8px" }}
               data-testid="edr-processtree-panel">
            {flattenTree(tree.roots, byId).map((row) => (
              <TreeRow key={row.node.entity_id || row.node.process_iid}
                       row={row} ctx={ctx} />
            ))}
          </div>
        </>
      )}
    </NivXForgeConsole>
  );
}

/** Iterative depth-first walk → flat list of {node, depth}.  Avoids
 *  recursive JSX which trips the emergent visual-edits Babel plugin. */
function flattenTree(roots, byId) {
  const out = [];
  const stack = [];
  (roots || []).slice().reverse().forEach((id) => stack.push({ id, depth: 0 }));
  const seen = new Set();
  while (stack.length) {
    const { id, depth } = stack.pop();
    if (seen.has(id)) continue;
    seen.add(id);
    const node = byId.get(id);
    if (!node) continue;
    out.push({ node, depth });
    (node.child_ids || []).slice().reverse().forEach((cid) =>
      stack.push({ id: cid, depth: depth + 1 })
    );
  }
  return out;
}

function TreeRow({ row, ctx }) {
  const { node, depth } = row;
  // The endpoint projection keys on the canonical process identity; the
  // case projection keys on the inventory entity. One row renders both.
  const nodeId = node.entity_id || node.process_iid;
  const ghost = node.observed === false;
  const hasKids = (node.child_ids || []).length > 0;

  const trajLink = (() => {
    const p = new URLSearchParams();
    if (ctx.incident_id) p.set("incident_id", ctx.incident_id);
    if (ctx.device)      p.set("device", ctx.device);
    if (ctx.tenant)      p.set("tenant", ctx.tenant);
    p.set("entity_id", nodeId);
    return `/edr/trajectory?${p.toString()}`;
  })();
  const cmdLink = node.command_line
    ? `/analyze?incident_id=${encodeURIComponent(ctx.incident_id || "")}`
      + `&entity_id=${encodeURIComponent(nodeId)}`
    : null;

  return (
    <div style={{ paddingLeft: depth * 22 }}
         data-testid={`edr-processtree-node-${nodeId}`}>
      <div style={{
        display: "flex", alignItems: "center", gap: 8,
        padding: "6px 10px", borderRadius: 4,
      }}>
        <ChevronRight size={12} style={{
          opacity: hasKids ? 1 : 0.2,
          color: hasKids ? "var(--mint)" : "var(--faint)",
        }} />
        <GitBranch size={12} style={{ color: hasKids ? "var(--mint)" : "var(--faint)" }} />
        <span style={{ fontWeight: 700, color: "var(--text)" }}>{node.process}</span>
        {node.user && <span className="mono" style={{ color: "var(--muted)", fontSize: 11 }}>· {node.user}</span>}
        {node.host && <span className="mono" style={{ color: "var(--muted)", fontSize: 11 }}>· {node.host}</span>}
        <div style={{ flex: 1 }} />
        {ghost && (
          <span className="nx-ep" data-ep="no_evidence" data-known="true"
                data-testid={`edr-processtree-ghost-${nodeId}`}
                style={{ fontSize: 8.5 }}
                title={node.note || "Referenced as a parent but never observed"}>
            ◇ GHOST PARENT · NEVER OBSERVED
          </span>)}
        {node.pid && (
          <span className="mono" style={{ color: "var(--faint)",
                                          fontSize: 10 }}>
            pid {node.pid}{node.ppid ? ` · ppid ${node.ppid}` : ""}
          </span>)}
        {node.command_line && (
          <span className="mono" style={{
            color: "var(--text-dim)", fontSize: 11,
            maxWidth: 380, overflow: "hidden",
            textOverflow: "ellipsis", whiteSpace: "nowrap",
          }} title={node.command_line}>{node.command_line}</span>
        )}
        <Link
          to={trajLink}
          className="btn"
          style={{ textDecoration: "none", padding: "3px 8px" }}
          data-testid={`edr-processtree-pivot-trajectory-${nodeId}`}
          title="Open Device Trajectory pinned to this entity"
        >
          <Radar size={10} /> Trajectory
        </Link>
        {cmdLink && (
          <a
            href={cmdLink}
            target="_blank"
            rel="noopener noreferrer"
            className="btn mint"
            style={{ textDecoration: "none", padding: "3px 8px" }}
            data-testid={`edr-processtree-pivot-cmd-${nodeId}`}
            title="Analyze command line with Command Intelligence (opens in new tab)"
          >
            <Terminal size={10} /> Cmd Intel
          </a>
        )}
      </div>
    </div>
  );
}
