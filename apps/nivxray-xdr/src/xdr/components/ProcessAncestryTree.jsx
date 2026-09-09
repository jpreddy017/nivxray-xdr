/**
 * ProcessAncestryTree · P1.2 · lineage DAG surface.
 *
 * Renders the projection from lib/processAncestry.js as an indented
 * layered tree with epistemic node states and a provenance side-sheet.
 *
 * Every rendered value is copied from a persisted observation or
 * replaced by an explicit epistemic token.  Nothing is inferred into
 * existence.
 */
import React, { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { CornerDownRight, GitBranch, ShieldQuestion, X } from "lucide-react";

import { buildProcessAncestryDAG, layoutDAG, EP } from "@/xdr/lib/processAncestry";

const NOT_CAPTURED = "◇ NOT CAPTURED IN OBSERVATION";

function Row({ k, v, mono = true }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "120px 1fr", gap: 8,
                    alignItems: "baseline", marginBottom: 5 }}>
      <div style={{ color: "var(--faint)", fontSize: 9.5, fontWeight: 800,
                      textTransform: "uppercase", letterSpacing: ".3px" }}>{k}</div>
      <div className={mono ? "mono" : undefined}
            style={{ color: "var(--text-dim)", fontSize: 10.5,
                      wordBreak: "break-all" }}>{v}</div>
    </div>
  );
}

function Missing({ label = NOT_CAPTURED }) {
  return <span className="nx-ep" data-ep="no_evidence" data-known="true">{label}</span>;
}

export default function ProcessAncestryTree({ events }) {
  const [selected, setSelected] = useState(null);
  const [decoded, setDecoded] = useState(false);

  const graph = useMemo(() => buildProcessAncestryDAG(events), [events]);
  const { order, depth, childrenOf, rootCount } = useMemo(
    () => layoutDAG(graph), [graph]);

  const observedCount = graph.nodes.filter((n) => !n.isSyntheticRoot).length;
  const directEdges = graph.edges.filter((e) => e.relationType === "DIRECT_IID").length;
  const node = selected ? graph.nodes.find((n) => n.id === selected) : null;

  if (observedCount === 0) {
    return (
      <section className="panel" style={{ padding: 0 }}
                data-testid="edr-process-ancestry">
        <div className="x-empty" data-testid="edr-ancestry-empty">
          <b>◇ NO PROCESS ACTIVITY</b>
          <div style={{ marginTop: 4 }}>
            No <span className="mono">process_create</span> observations are
            persisted for this endpoint in the selected window.
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="panel" style={{ padding: 0 }}
              data-testid="edr-process-ancestry">
      <div style={{ display: "flex", alignItems: "center", gap: 10,
                      padding: "8px 10px",
                      borderBottom: "1px solid var(--border)" }}>
        <GitBranch size={12} style={{ color: "var(--mint)" }} />
        <span className="mono" style={{ fontSize: 10.5, color: "var(--text-dim)" }}
                data-testid="edr-ancestry-stats">
          {observedCount} observed process{observedCount === 1 ? "" : "es"} ·{" "}
          {directEdges} resolved lineage edge{directEdges === 1 ? "" : "s"} ·{" "}
          {rootCount} root{rootCount === 1 ? "" : "s"}
        </span>
      </div>

      {/* Substrate honesty banner — this is the real reason the tree is
            flat today, and the analyst must be told. */}
      {directEdges === 0 && (
        <div style={{ padding: "8px 10px", background: "var(--panel2)",
                        borderBottom: "1px solid var(--border)",
                        fontSize: 10.5, color: "var(--text-dim)",
                        lineHeight: 1.6 }}
              data-testid="edr-ancestry-substrate-notice">
          <span className="nx-ep" data-ep="unknown" data-known="false">
            ? NO LINEAGE RESOLVABLE
          </span>{" "}
          Every observed process declares a{" "}
          <span className="mono">parent_iid</span> that was never itself
          observed, and this substrate captures no{" "}
          <span className="mono">pid</span>/<span className="mono">ppid</span>.
          Each process therefore anchors to its own
          {" "}<span className="mono">[ROOT / PARENT NOT OBSERVED]</span>.
          No ancestor is synthesised to make the tree look deeper.
        </div>
      )}

      <div style={{ display: "grid",
                      gridTemplateColumns: node ? "1fr 340px" : "1fr" }}>
        <div style={{ padding: 8, overflow: "auto", maxHeight: 460 }}>
          {order.map((n) => {
            const d = depth.get(n.id) || 0;
            const kids = (childrenOf.get(n.id) || []).length;
            const isSel = selected === n.id;
            const root = n.isSyntheticRoot;
            const uncertain = n.epistemicState === EP.UNCERTAIN;
            return (
              <div key={n.id}
                    onClick={() => { setSelected(n.id); setDecoded(false); }}
                    style={{
                      marginLeft: d * 26,
                      marginBottom: 4,
                      padding: "6px 9px",
                      cursor: root ? "default" : "pointer",
                      border: root ? "1px dashed #2A364F"
                                    : `1px solid ${isSel ? "var(--mint)" : "var(--border)"}`,
                      borderStyle: uncertain ? "dotted" : undefined,
                      borderRadius: 4,
                      background: root ? "transparent" : "var(--panel2)",
                      display: "flex", alignItems: "center", gap: 8,
                    }}
                    data-testid={`edr-ancestry-node-${n.id}`}>
                {d > 0 && <CornerDownRight size={11} style={{ color: "var(--faint)" }} />}
                <span className="mono"
                        style={{ fontSize: 11,
                                  fontWeight: root ? 600 : 800,
                                  color: root ? "#6b7686" : "var(--text)" }}>
                  {n.label}
                </span>
                {root ? (
                  <span className="nx-ep" data-ep="unknown" data-known="true"
                          title="A parent identity was recorded by the child, but no observation of that parent exists.">
                    PARENT NOT OBSERVED
                  </span>
                ) : (
                  <>
                    <span className="nx-ep" data-ep="evidence_present" data-known="true">
                      ◆ OBSERVED
                    </span>
                    {uncertain && (
                      <span className="nx-ep" data-ep="unknown" data-known="false">
                        <ShieldQuestion size={9} /> ? UNCERTAIN
                      </span>
                    )}
                    <span className="mono" style={{ fontSize: 9.5, color: "var(--faint)" }}>
                      {n.pid === null ? "PID ◇" : `PID ${n.pid}`}
                    </span>
                    {/-enc|-EncodedCommand|-e /i.test(n.commandLine || "") && (
                      <span className="nx-ep" data-ep="evidence_present" data-known="true"
                              style={{ color: "#f5a623" }}
                              title="Encoded-command switch observed in the persisted command line">
                        ! -enc DETECTED
                      </span>
                    )}
                    {kids > 0 && (
                      <span className="mono" style={{ fontSize: 9.5,
                                                          color: "var(--cyan)" }}>
                        {kids} child{kids === 1 ? "" : "ren"}
                      </span>
                    )}
                  </>
                )}
                {root && n.claimedParentName && (
                  <span className="mono" style={{ fontSize: 9.5, color: "var(--faint)" }}
                          title="Name claimed by the child record — not an independent observation of the parent.">
                    claimed “{n.claimedParentName}” ◇ INFERRED FROM CHILD RECORD
                  </span>
                )}
              </div>
            );
          })}
        </div>

        {node && (
          <aside style={{ borderLeft: "1px solid var(--border)", padding: 10,
                            overflow: "auto", maxHeight: 460 }}
                  data-testid="edr-ancestry-sidesheet">
            <div style={{ display: "flex", alignItems: "center", gap: 8,
                            marginBottom: 10 }}>
              <div className="section-title" style={{ flex: 1 }}>
                Process Inspector
              </div>
              <button className="btn" style={{ padding: "2px 6px" }}
                        onClick={() => setSelected(null)}
                        data-testid="edr-ancestry-sidesheet-close">
                <X size={11} />
              </button>
            </div>

            <Row k="Process" v={node.label} />
            <Row k="PID / PPID"
                  v={node.pid === null && node.ppid === null
                      ? <Missing label="◇ PID/PPID NOT CAPTURED IN OBSERVATION" />
                      : `${node.pid ?? "◇"} / ${node.ppid ?? "◇"}`} />
            <Row k="Start Time" v={node.timestamp || <Missing />} />
            <Row k="User" v={node.user || <Missing />} />
            <Row k="Executable" v={node.executablePath || <Missing />} />
            <Row k="Command Line"
                  v={node.commandLine
                      ? <>
                          <span style={{ display: "block" }}>{node.commandLine}</span>
                          <button className="btn"
                                    style={{ padding: "2px 6px", marginTop: 4,
                                              fontSize: 9.5 }}
                                    onClick={() => setDecoded((v) => !v)}
                                    data-testid="edr-ancestry-decode-toggle">
                            {decoded ? "Hide decoded payload" : "Decode (59 static decoders)"}
                          </button>
                          {decoded && (
                            <div style={{ marginTop: 5 }}
                                  data-testid="edr-ancestry-decoded">
                              <span className="nx-ep" data-ep="capability_unavailable"
                                      data-known="true">
                                ⊘ INLINE DECODE NOT WIRED
                              </span>
                              <div style={{ marginTop: 4, color: "var(--faint)",
                                              fontSize: 9.5, lineHeight: 1.6 }}>
                                The 59-decoder runtime is operational but has no
                                per-process decode endpoint yet. Decoded payloads
                                for this case are reachable from the investigation
                                record. No placeholder plaintext is shown here.
                              </div>
                            </div>
                          )}
                        </>
                      : <Missing label="◇ COMMAND LINE NOT CAPTURED IN OBSERVATION" />} />
            <Row k="SHA-256" v={node.sha256 || <Missing />} />
            {node.mitre?.length > 0 && (
              <Row k="ATT&CK" v={node.mitre.join(", ")} />
            )}

            <div style={{ height: 8 }} />
            <div className="section-title" style={{ marginBottom: 6 }}>Provenance</div>
            <Row k="Substrate" v="v2_shadow_observations" />
            <Row k="Observation" v={node.observationIid || <Missing />} />
            <Row k="Process IID" v={node.isSyntheticRoot ? <Missing /> : node.id} />
            <Row k="Parent IID" v={node.parentIid || <Missing />} />
            <Row k="Device" v={node.deviceIid || <Missing />} />
            <Row k="Source Cases"
                  v={node.sourceCases?.length
                      ? node.sourceCases.map((c) => (
                          <Link key={c} to={`/xdr/incidents/${c}`}
                                  style={{ color: "var(--cyan)", display: "block" }}
                                  data-testid={`edr-ancestry-case-${c}`}>
                            {c}
                          </Link>))
                      : <Missing />} />
          </aside>
        )}
      </div>
    </section>
  );
}
