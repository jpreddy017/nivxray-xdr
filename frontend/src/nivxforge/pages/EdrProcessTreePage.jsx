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

import NivXForgeConsole, { useIncidentContext } from "@/nivxforge/NivXForgeConsole";
import { getEdrProcessTree } from "@/nivxforge/edrApi";

function useTree(incidentId) {
  const [state, setState] = useState({
    loading: !!incidentId, error: null, tree: null,
  });
  useEffect(() => {
    if (!incidentId) { setState({ loading: false, error: null, tree: null }); return; }
    let cancelled = false;
    (async () => {
      setState({ loading: true, error: null, tree: null });
      try {
        const data = await getEdrProcessTree(incidentId);
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
  }, [incidentId]);
  return state;
}

export default function EdrProcessTreePage() {
  const ctx = useIncidentContext();
  const { loading, error, tree } = useTree(ctx.incident_id);

  const byId = useMemo(() => {
    const m = new Map();
    (tree?.nodes || []).forEach((n) => m.set(n.entity_id, n));
    return m;
  }, [tree]);

  return (
    <NivXForgeConsole activeTab="process-tree">
      <h1 className="page-h1" data-testid="edr-processtree-heading">Process Tree</h1>
      <div className="page-sub">
        Reuses the canonical Activity Inventory (parent → child process relationships).
        No parallel correlation engine.
      </div>

      {!ctx.incident_id && (
        <div className="x-empty" data-testid="edr-processtree-noctx">
          Process Tree is scoped to an incident.
          Open this page from an incident's <b>NivXForge EDR</b> launcher.
        </div>
      )}
      {ctx.incident_id && loading && (
        <div className="x-empty" data-testid="edr-processtree-loading">
          <Loader2 size={13} className="spin" style={{ verticalAlign: "middle", marginRight: 6 }} />
          Loading process tree …
        </div>
      )}
      {ctx.incident_id && !loading && error && (
        <div className="x-empty" style={{ color: "#ff9494" }}
             data-testid="edr-processtree-error">
          {String(error)}
        </div>
      )}
      {ctx.incident_id && !loading && !error && tree
        && tree.reason === "no_matching_evidence" && (
        <div className="x-empty" data-testid="edr-processtree-empty">
          <b>NO MATCHING EVIDENCE</b>
          <div style={{ marginTop: 4 }}>
            {tree.note || "No canonical timeline attached to this incident."}
          </div>
        </div>
      )}
      {ctx.incident_id && !loading && !error && tree
        && tree.reason === "ok" && (
        <>
          <div style={{
            marginBottom: 10, fontSize: 10.5, letterSpacing: ".3px",
            color: "var(--faint)", textTransform: "uppercase", fontWeight: 800,
          }}>
            SSOT · <span style={{ color: "var(--cyan)" }}>{tree.source}</span>
          </div>
          <div className="panel" style={{ padding: "12px 8px" }}
               data-testid="edr-processtree-panel">
            {(tree.roots || []).map((rid) => (
              <TreeNode key={rid} node={byId.get(rid)} byId={byId} depth={0} ctx={ctx} />
            ))}
          </div>
        </>
      )}
    </NivXForgeConsole>
  );
}

function TreeNode({ node, byId, depth, ctx }) {
  if (!node) return null;
  const [open, setOpen] = useState(true);
  const kids = (node.child_ids || []).map((id) => byId.get(id)).filter(Boolean);
  const hasKids = kids.length > 0;

  const trajLink = (() => {
    const p = new URLSearchParams();
    if (ctx.incident_id) p.set("incident_id", ctx.incident_id);
    if (ctx.device)      p.set("device", ctx.device);
    if (ctx.tenant)      p.set("tenant", ctx.tenant);
    p.set("entity_id", node.entity_id);
    return `/edr/trajectory?${p.toString()}`;
  })();

  const cmdLink = node.command_line
    ? `/analyze?incident_id=${encodeURIComponent(ctx.incident_id || "")}`
      + `&entity_id=${encodeURIComponent(node.entity_id)}`
    : null;

  return (
    <div style={{ paddingLeft: depth * 22 }}
         data-testid={`edr-processtree-node-${node.entity_id}`}>
      <div style={{
        display: "flex", alignItems: "center", gap: 8,
        padding: "6px 10px", borderRadius: 4,
      }}>
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          disabled={!hasKids}
          className="btn ghost"
          style={{ padding: "0 4px", border: "none",
                     opacity: hasKids ? 1 : 0.2, background: "transparent" }}
          data-testid={`edr-processtree-toggle-${node.entity_id}`}
        >
          <ChevronRight size={12} style={{
            transform: open ? "rotate(90deg)" : "rotate(0deg)",
            transition: "transform 140ms ease",
          }} />
        </button>
        <GitBranch size={12} style={{ color: hasKids ? "var(--mint)" : "var(--faint)" }} />
        <span style={{ fontWeight: 700, color: "var(--text)" }}>{node.process}</span>
        {node.user && <span className="mono" style={{ color: "var(--muted)", fontSize: 11 }}>· {node.user}</span>}
        {node.host && <span className="mono" style={{ color: "var(--muted)", fontSize: 11 }}>· {node.host}</span>}
        <div style={{ flex: 1 }} />
        {node.command_line && (
          <span className="mono" style={{
            color: "var(--text-dim)", fontSize: 11,
            maxWidth: 380, overflow: "hidden",
            textOverflow: "ellipsis", whiteSpace: "nowrap",
          }} title={node.command_line}>
            {node.command_line}
          </span>
        )}
        <Link
          to={trajLink}
          className="btn"
          style={{ textDecoration: "none", padding: "3px 8px" }}
          data-testid={`edr-processtree-pivot-trajectory-${node.entity_id}`}
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
            data-testid={`edr-processtree-pivot-cmd-${node.entity_id}`}
            title="Analyze command line with Command Intelligence (opens in new tab)"
          >
            <Terminal size={10} /> Cmd Intel
          </a>
        )}
      </div>
      {open && kids.map((k) => (
        <TreeNode key={k.entity_id} node={k} byId={byId} depth={depth + 1} ctx={ctx} />
      ))}
    </div>
  );
}
