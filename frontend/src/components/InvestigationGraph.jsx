import React, { useMemo, useState, useCallback } from "react";

/**
 * InvestigationGraph — SVG kill-chain visualization for a single decode.
 *
 * Rendering: pure SVG (no external graph library). Two zones:
 *   1. VERTICAL SPINE      — the raw-input → decode-chain nodes (top → bottom)
 *   2. TERMINAL FAN-OUT    — from the last decode node, branches emit
 *      into IOC / MITRE / TI-HIT / LOLBIN categories, each expanding to
 *      individual items.
 *
 * Node color-code (per SOC-analyst spec):
 *   🔵 blue    — raw input / file format
 *   🟢 green   — decoding operation
 *   🟡 yellow  — extracted IOC
 *   🟠 orange  — MITRE ATT&CK technique
 *   🔴 red     — high-risk indicator (shellcode / C2 / AMSI / LOLBin)
 *   🟣 purple  — threat-intel hit
 *
 * Interactions:
 *   • Click any node → right-side drawer opens with details + actions
 *   • ⛶ fullscreen toggle
 *   • ▸ "Re-run from this node" (chain nodes) — pushes that layer's output
 *     back into the workspace for further recipe editing
 *   • Copy / Export JSON on every node
 */

const COLOURS = {
  input:    { fill: "#152b3d", stroke: "#5aa2ff", label: "#8ec2ff" },  // blue
  op:       { fill: "#123020", stroke: "#4aa890", label: "#7dd6bf" },  // green
  ioc:      { fill: "#332b0f", stroke: "#e6c34a", label: "#f0d878" },  // yellow
  mitre:    { fill: "#3a220f", stroke: "#e27e5d", label: "#f2a889" },  // orange
  highrisk: { fill: "#3a1414", stroke: "#d96c6c", label: "#f2a1a1" },  // red
  ti:       { fill: "#2a1a3a", stroke: "#a06cd6", label: "#c4a1f0" },  // purple
};

const HIGHRISK_MARKERS = /(shellcode|amsi|virtualalloc|createthread|createremotethread|writeprocessmemory|reflection.assembly|frombase64string.*iex|invoke-mimikatz|invoke-obfuscation|downloadstring.*iex|iex.*downloadstring)/i;
const LOLBIN_NAMES = new Set([
  "certutil.exe", "bitsadmin.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
  "wmic.exe", "installutil.exe", "msbuild.exe", "cmstp.exe", "regasm.exe",
  "regsvcs.exe", "csc.exe", "msiexec.exe", "wscript.exe", "cscript.exe",
]);

function classifyIocKind(kind) {
  if (kind === "urls") return { icon: "🔗", label: "URL" };
  if (kind === "ips") return { icon: "🌐", label: "IPv4" };
  if (kind === "domains") return { icon: "🌍", label: "DOMAIN" };
  if (kind === "md5" || kind === "sha1" || kind === "sha256") return { icon: "#", label: kind.toUpperCase() };
  if (kind === "emails") return { icon: "✉", label: "EMAIL" };
  if (kind === "bitcoin_addresses") return { icon: "₿", label: "BTC" };
  return { icon: "·", label: kind.toUpperCase() };
}

export default function InvestigationGraph({
  input, output, trace, iocs, mitre, lolbas, ti_hits, verdict,
  engine, confidence, reachedShellcode,
  onRerunFromNode,          // (layerIndex) → main workspace re-hydrates output
}) {
  const [fullscreen, setFullscreen] = useState(false);
  const [selected, setSelected] = useState(null);   // {kind, id, data}

  // Build node list
  const nodes = useMemo(() => {
    const arr = [];
    // 0) raw input (blue)
    arr.push({
      id: "input", kind: "input",
      label: "RAW INPUT",
      sub: `${(input || "").length.toLocaleString()} chars`,
      data: { text: (input || "").slice(0, 4000) },
    });
    // 1) decoding chain (green)
    (trace || []).forEach((t, i) => {
      const dangerous = HIGHRISK_MARKERS.test(t.output_preview || "");
      arr.push({
        id: `op-${i}`,
        kind: dangerous ? "highrisk" : "op",
        label: t.op.toUpperCase(),
        sub: t.reason || "",
        data: {
          op: t.op, args: t.args || {}, reason: t.reason,
          output_preview: t.output_preview,
          output_length: t.output_length,
          error: t.error,
          layer_index: i,
        },
      });
    });
    // shellcode terminal marker
    if (reachedShellcode) {
      arr.push({
        id: "shellcode-terminal", kind: "highrisk",
        label: "▲ SHELLCODE",
        sub: "known x86/x64 prologue detected",
        data: { output: (output || "").slice(0, 200), reason: "terminal shellcode state" },
      });
    }
    return arr;
  }, [input, trace, output, reachedShellcode]);

  // Terminal branches
  const iocBranches = useMemo(() => {
    const out = [];
    for (const [kind, values] of Object.entries(iocs || {})) {
      if (!Array.isArray(values) || !values.length) continue;
      for (const v of values.slice(0, 8)) {
        const meta = classifyIocKind(kind);
        out.push({
          id: `ioc-${kind}-${v}`, kind: "ioc",
          label: `${meta.icon} ${v}`, sub: meta.label,
          data: { value: v, ioc_kind: kind, meta },
        });
      }
    }
    return out;
  }, [iocs]);

  const mitreBranches = useMemo(() =>
    (mitre || []).slice(0, 10).map((m) => ({
      id: `mitre-${m.id}`, kind: "mitre",
      label: m.id, sub: m.technique || "",
      data: {
        id: m.id, technique: m.technique, tactic: m.tactic,
        evidence: m.evidence, source: m.source || "heuristic",
        url: `https://attack.mitre.org/techniques/${(m.id || "").replace(".", "/")}/`,
      },
    })), [mitre]);

  const tiBranches = useMemo(() =>
    (ti_hits || []).slice(0, 8).map((h, i) => ({
      id: `ti-${i}`, kind: "ti",
      label: h.value || `TI hit ${i + 1}`, sub: (h.severity || "unknown").toUpperCase(),
      data: h,
    })), [ti_hits]);

  const lolbinBranches = useMemo(() =>
    (lolbas || []).slice(0, 8).map((l, i) => ({
      id: `lolb-${i}`,
      kind: LOLBIN_NAMES.has((l.binary || "").toLowerCase()) ? "highrisk" : "mitre",
      label: l.binary || `lolbas ${i + 1}`,
      sub: (l.purposes || []).join(", "),
      data: l,
    })), [lolbas]);

  // Layout
  const SPINE_X = 180;
  const SPINE_Y0 = 40;
  const SPINE_DY = 90;
  const NODE_W = 240;
  const NODE_H = 52;
  const spineY = (i) => SPINE_Y0 + i * SPINE_DY;
  const spineHeight = SPINE_Y0 + Math.max(1, nodes.length) * SPINE_DY + 60;

  // Terminal fan-out — 4 columns
  const fanCols = [
    { title: "URLs / IPs / DOMAINS / HASHES", items: iocBranches, x: 460 },
    { title: "MITRE ATT&CK", items: mitreBranches, x: 720 },
    { title: "LOLBINS", items: lolbinBranches, x: 980 },
    { title: "THREAT INTEL", items: tiBranches, x: 1240 },
  ];
  const terminalNodeY = spineY(nodes.length - 1) + NODE_H / 2;
  const branchStartY = 40;
  const branchDy = 60;
  const maxBranchLen = Math.max(1, ...fanCols.map((c) => c.items.length));
  const svgHeight = Math.max(spineHeight, branchStartY + maxBranchLen * branchDy + 80);
  const svgWidth = 1500;

  const nodeStyle = (kind) => {
    const c = COLOURS[kind] || COLOURS.op;
    return { fill: c.fill, stroke: c.stroke, label: c.label };
  };

  const openDetails = (n) => setSelected(n);
  const closeDetails = useCallback(() => setSelected(null), []);

  const copyToClipboard = (text) => {
    try { navigator.clipboard.writeText(text || ""); } catch { /* noop */ }
  };
  const exportJson = (label, obj) => {
    const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `nivxray_${label}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const containerStyle = fullscreen
    ? { position: "fixed", inset: 0, zIndex: 9999, background: "var(--bg)" }
    : { position: "relative", background: "var(--inset)" };

  return (
    <div className="inv-graph" style={containerStyle} data-testid="investigation-graph">
      <style>{`
        .inv-graph .hdr {
          display:flex; align-items:center; gap:12px;
          padding:8px 14px; border-bottom:1px solid var(--br);
          background: var(--sf); font-family:'JetBrains Mono',monospace;
          font-size:11px; letter-spacing:0.14em;
        }
        .inv-graph .hdr .title { color: var(--ac); font-weight:700; }
        .inv-graph .hdr .badge { padding:2px 8px; border:1px solid var(--br); font-size:10px; }
        .inv-graph .hdr .badge.conf { color: var(--tx); }
        .inv-graph .hdr .badge.shellcode { color: var(--hi); border-color: var(--hi); background: rgba(217,108,108,0.12); }
        .inv-graph .hdr .btn-fs {
          margin-left:auto; padding:4px 10px; border:1px solid var(--br); background:transparent;
          color:var(--dim); cursor:pointer; font-family:'JetBrains Mono',monospace; font-size:10px;
          letter-spacing:0.14em; transition: all .12s;
        }
        .inv-graph .hdr .btn-fs:hover { border-color: var(--ac); color: var(--ac); }
        .inv-graph .scroller {
          overflow:auto; ${fullscreen ? "height: calc(100vh - 42px);" : "max-height: 620px;"}
          background: repeating-linear-gradient(0deg, transparent 0 39px, rgba(255,255,255,0.02) 39px 40px);
        }
        .inv-graph svg text { font-family:'JetBrains Mono',monospace; }
        .inv-graph .node-rect { cursor:pointer; transition: filter .12s; }
        .inv-graph .node-rect:hover { filter: brightness(1.3); }
        .inv-graph .colhead {
          fill: var(--dim); font-size:9px; letter-spacing:0.22em; font-weight:700;
        }
        .inv-graph .legend {
          display:flex; gap:16px; padding:6px 14px; border-top:1px solid var(--br);
          background:var(--sf); font-family:'JetBrains Mono',monospace; font-size:10px;
          color:var(--dim); flex-wrap: wrap;
        }
        .inv-graph .legend .swatch {
          display:inline-block; width:10px; height:10px; margin-right:6px; vertical-align:middle;
          border-radius:2px;
        }
        .inv-graph .drawer {
          position:absolute; top:42px; right:0; ${fullscreen ? "height: calc(100vh - 42px);" : "height: 620px;"}
          width:420px; background:var(--sf); border-left:1px solid var(--br);
          font-family:'JetBrains Mono',monospace; font-size:11px; display:flex;
          flex-direction:column; z-index:10;
        }
        .inv-graph .drawer .dhdr {
          display:flex; gap:8px; align-items:center; padding:10px 14px;
          border-bottom:1px solid var(--br); background:var(--inset);
        }
        .inv-graph .drawer .dhdr .close {
          margin-left:auto; padding:2px 8px; border:1px solid var(--br); background:transparent;
          color:var(--dim); cursor:pointer; font-family:'JetBrains Mono',monospace; font-size:10px;
        }
        .inv-graph .drawer .dbody { padding:14px; overflow:auto; flex:1; }
        .inv-graph .drawer .field { margin-bottom:12px; }
        .inv-graph .drawer .field .k {
          color: var(--dim); text-transform: uppercase; letter-spacing: 0.14em; font-size: 9px; margin-bottom: 4px;
        }
        .inv-graph .drawer .field .v {
          background:var(--inset); border:1px solid var(--br); padding:8px 10px; word-break:break-all;
          white-space:pre-wrap; color: var(--tx);
        }
        .inv-graph .drawer .actions {
          display:flex; gap:8px; padding:10px 14px; border-top:1px solid var(--br); flex-wrap:wrap;
        }
        .inv-graph .drawer .actions button {
          padding:5px 10px; border:1px solid var(--br); background:transparent; color:var(--tx);
          cursor:pointer; font-family:'JetBrains Mono',monospace; font-size:10px; letter-spacing:0.12em;
        }
        .inv-graph .drawer .actions button:hover { border-color: var(--ac); color: var(--ac); }
        .inv-graph .drawer .actions button.danger { color:var(--warn); border-color:var(--warn); }
        .inv-graph .drawer .actions button.danger:hover { background: rgba(226,126,93,0.1); }
      `}</style>

      <div className="hdr" data-testid="inv-graph-header">
        <span className="title">⬢ INVESTIGATION GRAPH</span>
        {engine && <span className="badge" data-testid="inv-graph-engine">{engine.toUpperCase()}</span>}
        {typeof confidence === "number" && (
          <span className="badge conf" data-testid="inv-graph-confidence">{confidence}% CONFIDENCE</span>
        )}
        {reachedShellcode && <span className="badge shellcode">▲ SHELLCODE TERMINAL</span>}
        <button
          className="btn-fs"
          onClick={() => setFullscreen(!fullscreen)}
          data-testid="inv-graph-fullscreen"
        >
          {fullscreen ? "⤡ EXIT FULLSCREEN" : "⛶ EXPAND"}
        </button>
      </div>

      <div className="scroller">
        <svg width={svgWidth} height={svgHeight} data-testid="inv-graph-svg">
          {/* --- SPINE EDGES --- */}
          {nodes.slice(1).map((_, idx) => (
            <line
              key={`spine-edge-${idx}`}
              x1={SPINE_X + NODE_W / 2} y1={spineY(idx) + NODE_H}
              x2={SPINE_X + NODE_W / 2} y2={spineY(idx + 1)}
              stroke="#4aa890" strokeWidth="1.5" strokeDasharray="4 3" opacity="0.7"
            />
          ))}

          {/* --- SPINE NODES --- */}
          {nodes.map((n, idx) => {
            const st = nodeStyle(n.kind);
            return (
              <g key={n.id} onClick={() => openDetails(n)} data-testid={`inv-node-${n.id}`}>
                <rect
                  className="node-rect"
                  x={SPINE_X} y={spineY(idx)} width={NODE_W} height={NODE_H} rx="6"
                  fill={st.fill} stroke={st.stroke} strokeWidth="1.5"
                />
                <text x={SPINE_X + 14} y={spineY(idx) + 20}
                      fill={st.label} fontSize="11" fontWeight="700" letterSpacing="0.08em">
                  {n.label.slice(0, 26)}
                </text>
                <text x={SPINE_X + 14} y={spineY(idx) + 38}
                      fill="#8b949e" fontSize="9" letterSpacing="0.06em">
                  {(n.sub || "").slice(0, 34)}
                </text>
                <text x={SPINE_X - 22} y={spineY(idx) + 32}
                      fill="#8b949e" fontSize="10" fontWeight="700">
                  {idx + 1}
                </text>
              </g>
            );
          })}

          {/* --- FAN-OUT COLUMN HEADERS + BRANCH EDGES + NODES --- */}
          {fanCols.map((col, ci) => (
            <g key={`col-${ci}`}>
              <text x={col.x} y={20} className="colhead">{col.title}</text>
              {col.items.map((it, i) => {
                const y = branchStartY + i * branchDy;
                const st = nodeStyle(it.kind);
                return (
                  <g key={it.id}>
                    <path
                      d={`M ${SPINE_X + NODE_W} ${terminalNodeY} C ${(SPINE_X + NODE_W + col.x) / 2} ${terminalNodeY}, ${(SPINE_X + NODE_W + col.x) / 2} ${y + 22}, ${col.x} ${y + 22}`}
                      stroke={st.stroke} strokeWidth="1" fill="none" opacity="0.5"
                    />
                    <g onClick={() => openDetails(it)} data-testid={`inv-node-${it.id}`}>
                      <rect
                        className="node-rect"
                        x={col.x} y={y} width={220} height={44} rx="6"
                        fill={st.fill} stroke={st.stroke} strokeWidth="1.2"
                      />
                      <text x={col.x + 10} y={y + 18}
                            fill={st.label} fontSize="10.5" fontWeight="600">
                        {(it.label || "").slice(0, 30)}
                      </text>
                      <text x={col.x + 10} y={y + 33}
                            fill="#8b949e" fontSize="9" letterSpacing="0.06em">
                        {(it.sub || "").slice(0, 32)}
                      </text>
                    </g>
                  </g>
                );
              })}
              {col.items.length === 0 && (
                <text x={col.x + 6} y={62} fill="#4a4d51" fontSize="10">(none)</text>
              )}
            </g>
          ))}
        </svg>
      </div>

      <div className="legend">
        <span><span className="swatch" style={{ background: COLOURS.input.stroke }} />RAW INPUT</span>
        <span><span className="swatch" style={{ background: COLOURS.op.stroke }} />DECODE OP</span>
        <span><span className="swatch" style={{ background: COLOURS.ioc.stroke }} />IOC</span>
        <span><span className="swatch" style={{ background: COLOURS.mitre.stroke }} />MITRE / LOLBIN</span>
        <span><span className="swatch" style={{ background: COLOURS.highrisk.stroke }} />HIGH-RISK</span>
        <span><span className="swatch" style={{ background: COLOURS.ti.stroke }} />TI HIT</span>
      </div>

      {/* DRAWER */}
      {selected && (
        <NodeDetailsDrawer
          node={selected}
          onClose={closeDetails}
          onCopy={copyToClipboard}
          onExport={exportJson}
          onRerunFromNode={onRerunFromNode}
        />
      )}
    </div>
  );
}


function NodeDetailsDrawer({ node, onClose, onCopy, onExport, onRerunFromNode }) {
  const d = node.data || {};
  const isOp = node.kind === "op" || (node.kind === "highrisk" && d.op);
  const isMitre = node.kind === "mitre";
  const isIoc = node.kind === "ioc";
  const isTi = node.kind === "ti";
  const isInput = node.kind === "input";

  return (
    <div className="drawer" data-testid="inv-graph-drawer">
      <div className="dhdr">
        <span style={{ color: "var(--ac)", fontWeight: 700, letterSpacing: "0.14em" }}>
          {node.label.slice(0, 32)}
        </span>
        <button className="close" onClick={onClose} data-testid="inv-drawer-close">✕</button>
      </div>
      <div className="dbody">
        {isInput && (
          <>
            <div className="field">
              <div className="k">Raw input preview</div>
              <div className="v" style={{ maxHeight: 260, overflow: "auto" }}>
                {(d.text || "").slice(0, 3000) || "(empty)"}
              </div>
            </div>
          </>
        )}
        {isOp && (
          <>
            <div className="field"><div className="k">Operation</div><div className="v">{d.op}</div></div>
            {d.reason && <div className="field"><div className="k">Reason</div><div className="v">{d.reason}</div></div>}
            {d.args && Object.keys(d.args).length > 0 && (
              <div className="field"><div className="k">Args</div>
                <div className="v">{JSON.stringify(d.args, null, 2)}</div>
              </div>
            )}
            {d.error ? (
              <div className="field"><div className="k">Error</div>
                <div className="v" style={{ color: "var(--hi)" }}>{d.error}</div>
              </div>
            ) : (
              <>
                <div className="field"><div className="k">Output preview</div>
                  <div className="v" style={{ maxHeight: 200, overflow: "auto" }}>{d.output_preview || "(empty)"}</div>
                </div>
                {d.output_length != null && (
                  <div className="field"><div className="k">Output length</div>
                    <div className="v">{d.output_length.toLocaleString()} chars</div></div>
                )}
              </>
            )}
          </>
        )}
        {isMitre && (
          <>
            <div className="field"><div className="k">Technique ID</div>
              <div className="v"><a href={d.url} target="_blank" rel="noopener noreferrer"
                                     style={{ color: "var(--ac)" }}>{d.id}</a></div></div>
            {d.technique && <div className="field"><div className="k">Name</div><div className="v">{d.technique}</div></div>}
            {d.tactic && <div className="field"><div className="k">Tactic</div><div className="v">{d.tactic}</div></div>}
            {d.evidence && <div className="field"><div className="k">Evidence</div><div className="v">{d.evidence}</div></div>}
            {d.source && <div className="field"><div className="k">Source</div><div className="v">{d.source}</div></div>}
          </>
        )}
        {isIoc && (
          <>
            <div className="field"><div className="k">Kind</div><div className="v">{d.meta?.label}</div></div>
            <div className="field"><div className="k">Value</div><div className="v">{d.value}</div></div>
            {d.ioc_kind === "urls" || d.ioc_kind === "ips" || d.ioc_kind === "domains" ? (
              <>
                <div className="field"><div className="k">VirusTotal</div>
                  <div className="v"><a href={`https://www.virustotal.com/gui/search/${encodeURIComponent(d.value)}`}
                                          target="_blank" rel="noopener noreferrer"
                                          style={{ color: "var(--ac)" }}>Search on VT ↗</a></div></div>
                <div className="field"><div className="k">urlscan.io</div>
                  <div className="v"><a href={`https://urlscan.io/search/#${encodeURIComponent(d.value)}`}
                                          target="_blank" rel="noopener noreferrer"
                                          style={{ color: "var(--ac)" }}>Search on urlscan ↗</a></div></div>
              </>
            ) : null}
            {(d.ioc_kind === "md5" || d.ioc_kind === "sha1" || d.ioc_kind === "sha256") && (
              <div className="field"><div className="k">VirusTotal (hash)</div>
                <div className="v"><a href={`https://www.virustotal.com/gui/file/${d.value}`}
                                        target="_blank" rel="noopener noreferrer"
                                        style={{ color: "var(--ac)" }}>Search on VT ↗</a></div></div>
            )}
          </>
        )}
        {isTi && (
          <>
            <div className="field"><div className="k">Kind</div><div className="v">{d.kind || "?"}</div></div>
            <div className="field"><div className="k">Value</div><div className="v">{d.value}</div></div>
            {d.severity && <div className="field"><div className="k">Severity</div><div className="v">{d.severity}</div></div>}
            {d.source && <div className="field"><div className="k">Source</div><div className="v">{d.source}</div></div>}
            {d.tags?.length ? <div className="field"><div className="k">Tags</div><div className="v">{d.tags.join(", ")}</div></div> : null}
          </>
        )}
      </div>
      <div className="actions">
        <button onClick={() => onCopy(JSON.stringify(d))} data-testid="inv-drawer-copy">
          ⧉ COPY JSON
        </button>
        <button onClick={() => onExport(`node_${node.id}`, { ...node, data: d })}
                data-testid="inv-drawer-export">
          ⇩ EXPORT
        </button>
        {isOp && typeof d.layer_index === "number" && onRerunFromNode && !d.error && (
          <button className="danger"
                  onClick={() => { onRerunFromNode(d.layer_index); onClose(); }}
                  data-testid="inv-drawer-rerun">
            ▸ RE-RUN FROM HERE
          </button>
        )}
      </div>
    </div>
  );
}
