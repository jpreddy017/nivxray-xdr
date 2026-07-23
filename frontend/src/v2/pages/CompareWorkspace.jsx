/*
 * CompareWorkspace — side-by-side Device Trajectory panes.
 *
 * Two independent workspaces rendered as iframes so each keeps its full
 * viewport / selection / playback state. Ideal for red-team-vs-blue-team
 * or before/after comparison of two cases.
 *
 * Route: /v2/compare/:caseA/:caseB   (fallback: same case on both sides)
 */
import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { T } from "../theme";

export default function CompareWorkspace() {
  const navigate = useNavigate();
  const { caseA = "case_dfir_bumblebee_akira_2026",
          caseB = "case_dfir_bumblebee_akira_2026" } = useParams() || {};
  const [a, setA] = useState(caseA);
  const [b, setB] = useState(caseB);
  const swap = () => { const t = a; setA(b); setB(t); };
  const apply = () => navigate(`/v2/compare/${encodeURIComponent(a)}/${encodeURIComponent(b)}`);

  return (
    <div className="w-screen h-screen flex flex-col"
         style={{ background: T.bg, color: T.ink }}
         data-testid="compare-workspace">
      {/* Header bar — case pickers */}
      <div className="flex items-center gap-3 px-4 py-2 flex-shrink-0"
           style={{ background: T.cardGradient,
                    borderBottom: `1px solid ${T.line}`,
                    boxShadow: "inset 0 1px 0 rgba(255,255,255,0.03)" }}>
        <div className="text-[12px] font-bold" style={{ color: T.ink }}>
          Compare Investigations
        </div>
        <div className="text-[10px]" style={{ color: T.inkMute }}>
          Two independent Device Trajectory workspaces
        </div>
        <div className="flex-1" />
        <label className="text-[10px] font-mono flex items-center gap-1.5"
               style={{ color: T.inkDim }}>
          A
          <input type="text" value={a} onChange={(e) => setA(e.target.value)}
                 data-testid="compare-input-a"
                 className="px-2 py-1 rounded text-[11px] font-mono outline-none"
                 style={{ background: T.paper2, border: `1px solid ${T.line}`, color: T.ink, minWidth: 260 }} />
        </label>
        <button onClick={swap}
                data-testid="compare-swap"
                className="text-[11px] font-mono px-2 py-1 rounded"
                style={{ background: T.paper2, border: `1px solid ${T.line}`, color: T.inkDim }}
                title="Swap A ↔ B">
          ⇆
        </button>
        <label className="text-[10px] font-mono flex items-center gap-1.5"
               style={{ color: T.inkDim }}>
          B
          <input type="text" value={b} onChange={(e) => setB(e.target.value)}
                 data-testid="compare-input-b"
                 className="px-2 py-1 rounded text-[11px] font-mono outline-none"
                 style={{ background: T.paper2, border: `1px solid ${T.line}`, color: T.ink, minWidth: 260 }} />
        </label>
        <button onClick={apply}
                data-testid="compare-apply"
                className="text-[11px] font-semibold px-3 py-1 rounded"
                style={{ background: T.amber, color: "#05080F", border: `1px solid ${T.amber}` }}>
          Apply
        </button>
        <button onClick={() => navigate("/")}
                data-testid="compare-close"
                className="w-7 h-7 rounded flex items-center justify-center"
                style={{ border: `1px solid ${T.line}`, color: T.inkDim }}
                title="Close">✕</button>
      </div>

      {/* Split content */}
      <div className="flex-1 grid min-h-0" style={{ gridTemplateColumns: "1fr 1fr", gap: 2 }}>
        <Pane label="A" caseId={caseA} />
        <Pane label="B" caseId={caseB} />
      </div>
    </div>
  );
}

function Pane({ label, caseId }) {
  return (
    <div className="relative min-h-0"
         data-testid={`compare-pane-${label.toLowerCase()}`}
         style={{ borderRight: label === "A" ? `1px solid ${T.line}` : "none" }}>
      <div className="absolute top-2 left-2 text-[10px] font-mono px-1.5 py-0.5 rounded z-10"
           style={{
             background: T.amber, color: "#05080F", fontWeight: 700,
             boxShadow: "0 4px 12px -2px rgba(0,0,0,0.5)",
           }}>
        {label}
      </div>
      <iframe title={`Trajectory ${label}`}
              src={`/v2/trajectory/${encodeURIComponent(caseId)}`}
              className="w-full h-full"
              style={{ border: "none", background: T.bg }}
              data-testid={`compare-iframe-${label.toLowerCase()}`} />
    </div>
  );
}
