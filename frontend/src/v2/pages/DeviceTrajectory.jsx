/**
 * Device Trajectory · Phase 3e · DetectFlow swimlane view.
 *
 * Renders GET /api/v2/cases/{caseId}/trajectory/device as five
 * horizontal lanes (system · process · file · network · registry)
 * with entity-aware event nodes plotted along a shared time axis.
 *
 * • Cyan-teal accent (#22D3EE) with subtle glow
 * • Chivo 900 headers · JetBrains Mono details · glass panels
 * • Right-side Activity drawer, cursor-synced
 * • Zoom scrubber (Fit / 1h / 24h / 7d / 30d)
 * • Keyboard nav (← / → to move selection)
 *
 * Feature-flag gated on TRAJECTORY_ENGINE. No RC5 imports.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { isObservable } from "../flags";
import api from "@/lib/api";

const LANE_META = {
  system:   { label: "SYSTEM",   color: "#a78bfa" },
  process:  { label: "PROCESS",  color: "#22d3ee" },
  file:     { label: "FILES",    color: "#67e8f9" },
  network:  { label: "NETWORK",  color: "#fcd34d" },
  registry: { label: "REGISTRY", color: "#f472b6" },
};
const LANE_ORDER = ["system", "process", "file", "network", "registry"];
const LANE_HEIGHT = 92;
const HEADER_H = 44;
const LEFT_W = 132;

export default function DeviceTrajectory() {
  const { caseId = "case_dfir_bumblebee_akira_2026" } = useParams() || {};
  const [data, setData]       = useState(null);
  const [err, setErr]         = useState(null);
  const [selected, setSelectd]= useState(null);
  const [zoom, setZoom]       = useState("Fit");
  const [query, setQuery]     = useState("");
  const canvasRef             = useRef(null);
  const enabled               = isObservable("TRAJECTORY_ENGINE") || isObservable("CASE_ENGINE");

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    (async () => {
      try {
        const r = await api.get(`/v2/cases/${encodeURIComponent(caseId)}/trajectory/device?limit=1000`);
        if (!cancelled) setData(r.data);
      } catch (e) {
        if (!cancelled) setErr(e?.response?.data?.detail || e.message);
      }
    })();
    return () => { cancelled = true; };
  }, [caseId, enabled]);

  const frames = useMemo(() => {
    if (!data?.frames) return [];
    if (!query) return data.frames;
    const q = query.toLowerCase();
    return data.frames.filter(f =>
      (f.label || "").toLowerCase().includes(q) ||
      (f.action || "").toLowerCase().includes(q) ||
      (f.mitre || []).some(t => t.toLowerCase().includes(q)),
    );
  }, [data, query]);

  const { xForFrame, minTs, maxTs } = useMemo(() => {
    if (!frames.length) return { xForFrame: () => 0, minTs: 0, maxTs: 1 };
    const times = frames.map(f => new Date(f.ts).getTime());
    let lo = Math.min(...times), hi = Math.max(...times);
    if (hi === lo) hi = lo + 1000;
    return {
      xForFrame: (f) => (new Date(f.ts).getTime() - lo) / (hi - lo),
      minTs: lo,
      maxTs: hi,
    };
  }, [frames]);

  // Keyboard nav.
  useEffect(() => {
    if (!enabled) return;
    const handler = (e) => {
      if (!frames.length) return;
      if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
      const idx = selected ? frames.findIndex(f => f.frame_iid === selected.frame_iid) : -1;
      const nextIdx = e.key === "ArrowRight" ? Math.min(idx + 1, frames.length - 1) : Math.max(idx - 1, 0);
      setSelectd(frames[nextIdx]);
      e.preventDefault();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [enabled, frames, selected]);

  if (!enabled) {
    return (
      <div data-testid="v2-trajectory-disabled" style={pageStyle}>
        <div style={{ padding: 24, color: "var(--text-mute)", fontFamily: "JetBrains Mono, monospace", fontSize: 12 }}>
          Device Trajectory is disabled. Set{" "}
          <code>REACT_APP_NIVX_FLAG_TRAJECTORY_ENGINE=shadow</code>{" "}or{" "}
          <code>REACT_APP_NIVX_FLAG_CASE_ENGINE=shadow</code> to enable.
        </div>
      </div>
    );
  }

  return (
    <div data-testid="v2-device-trajectory" style={pageStyle}>
      {/* HEADER */}
      <div style={headerStyle}>
        <div>
          <div style={{ fontSize: 9, letterSpacing: "0.24em", color: "var(--text-mute)" }}>
            NIVXRAY · V2 · SHADOW
          </div>
          <h1 style={h1Style}>Device Trajectory</h1>
          <div style={{ color: "var(--text-dim)", fontSize: 11, fontFamily: "JetBrains Mono, monospace", marginTop: 3 }}>
            case = <code style={{ color: "#22d3ee" }}>{caseId}</code>
            {" · "}events = <span style={{ color: "#e2e8f0" }}>{data?.count ?? "—"}</span>
          </div>
        </div>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <input
            data-testid="trajectory-search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="search / filter…"
            style={searchStyle}
          />
          <div style={{ display: "flex", gap: 4 }} role="tablist" aria-label="zoom">
            {["Fit", "1h", "24h", "7d", "30d"].map(z => (
              <button key={z}
                data-testid={`zoom-${z}`}
                onClick={() => setZoom(z)}
                style={{
                  ...zoomBtnStyle,
                  ...(zoom === z ? { color: "#22d3ee", borderColor: "rgba(34,211,238,0.45)", background: "rgba(34,211,238,0.08)" } : {}),
                }}
              >{z}</button>
            ))}
          </div>
        </div>
      </div>

      {err && (
        <div style={{ padding: 16, color: "#f87171", fontFamily: "JetBrains Mono, monospace", fontSize: 12 }}>
          {String(err)}
        </div>
      )}

      {/* MAIN */}
      <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
        {/* Timeline canvas */}
        <div style={canvasWrap} ref={canvasRef}>
          <svg width="100%" height={HEADER_H + LANE_ORDER.length * LANE_HEIGHT} preserveAspectRatio="none">
            {/* lane backdrops + labels */}
            {LANE_ORDER.map((lane, i) => {
              const y = HEADER_H + i * LANE_HEIGHT;
              const meta = LANE_META[lane];
              return (
                <g key={lane}>
                  <rect x={0} y={y} width="100%" height={LANE_HEIGHT}
                    fill={i % 2 === 0 ? "rgba(15,23,42,0.35)" : "rgba(2,6,23,0.35)"}
                  />
                  <line x1={LEFT_W} y1={y + LANE_HEIGHT - 0.5} x2="100%" y2={y + LANE_HEIGHT - 0.5}
                    stroke="rgba(148,163,184,0.12)" strokeWidth="0.5" />
                  <text x={16} y={y + 26}
                    fill={meta.color} fontFamily="Chivo, sans-serif"
                    fontWeight="900" fontSize="11" letterSpacing="0.16em">
                    {meta.label}
                  </text>
                  <line x1={LEFT_W - 0.5} y1={y} x2={LEFT_W - 0.5} y2={y + LANE_HEIGHT}
                    stroke={meta.color} strokeOpacity="0.35" strokeWidth="1" />
                </g>
              );
            })}
            {/* cyan spine (time axis) */}
            <line x1={LEFT_W} y1={HEADER_H - 4} x2="100%" y2={HEADER_H - 4}
              stroke="#22d3ee" strokeOpacity="0.55" strokeWidth="1" filter="url(#glow)" />
            <defs>
              <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur stdDeviation="1.4" result="b" />
                <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
              </filter>
            </defs>
            {/* event nodes */}
            {frames.map((f, i) => {
              const laneIdx = Math.max(0, LANE_ORDER.indexOf(f.lane));
              const y = HEADER_H + laneIdx * LANE_HEIGHT + LANE_HEIGHT / 2;
              const xFrac = xForFrame(f);
              const x = LEFT_W + 12 + xFrac * (canvasRef.current ? canvasRef.current.clientWidth - LEFT_W - 24 : 800);
              const isSel = selected?.frame_iid === f.frame_iid;
              const color = LANE_META[f.lane]?.color || "#22d3ee";
              return (
                <g key={f.frame_iid} onClick={() => setSelectd(f)}
                   style={{ cursor: "pointer" }} data-testid={`event-${f.frame_iid}`}>
                  <circle cx={x} cy={y} r={isSel ? 8 : 5}
                    fill={color} fillOpacity={isSel ? 1 : 0.85}
                    stroke={isSel ? "#e2e8f0" : "rgba(2,6,23,0.85)"}
                    strokeWidth={isSel ? 1.4 : 0.8}
                    filter="url(#glow)" />
                  {isSel && (
                    <text x={x + 12} y={y + 4}
                      fill="#e2e8f0" fontFamily="JetBrains Mono, monospace" fontSize="10">
                      {(f.label || f.action).slice(0, 60)}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>
          {!frames.length && !err && (
            <div style={{ padding: 24, color: "var(--text-mute)", fontFamily: "JetBrains Mono, monospace", fontSize: 12 }}>
              No trajectory frames yet — seed observations via <code>POST /api/v2/cases/{caseId}/observations</code>.
            </div>
          )}
          {frames.length > 0 && (
            <div style={{
              padding: "6px 16px", fontFamily: "JetBrains Mono, monospace",
              fontSize: 9, color: "rgba(148,163,184,0.7)", letterSpacing: "0.18em",
              display: "flex", justifyContent: "space-between", borderTop: "1px solid rgba(148,163,184,0.14)",
            }}>
              <span>t = {new Date(minTs).toISOString()}</span>
              <span>window = {zoom}</span>
              <span>t = {new Date(maxTs).toISOString()}</span>
            </div>
          )}
        </div>

        {/* Activity drawer */}
        <aside style={drawerStyle}>
          <div style={{ fontSize: 9, letterSpacing: "0.22em", color: "var(--text-mute)", marginBottom: 6 }}>
            ACTIVITY
          </div>
          {selected ? (
            <div>
              <div style={{ fontSize: 10, color: "#22d3ee", fontFamily: "JetBrains Mono, monospace",
                            letterSpacing: "0.14em", fontWeight: 700, marginBottom: 4 }}>
                {(LANE_META[selected.lane]?.label) || selected.lane} · {selected.action}
              </div>
              <div style={{ color: "#e2e8f0", fontSize: 12, lineHeight: 1.5,
                            fontFamily: "JetBrains Mono, monospace", wordBreak: "break-word" }}>
                {selected.label}
              </div>
              <div style={{ marginTop: 10, fontSize: 10, color: "var(--text-mute)",
                            fontFamily: "JetBrains Mono, monospace", lineHeight: 1.6 }}>
                <div>ts       · <span style={{ color: "#cbd5e1" }}>{selected.ts}</span></div>
                <div>device   · <code style={{ color: "#67e8f9" }}>{selected.device?.iid}</code></div>
                {selected.process && <div>process  · <code style={{ color: "#22d3ee" }}>{selected.process.iid}</code></div>}
                {selected.parent  && <div>parent   · <code style={{ color: "#a78bfa" }}>{selected.parent.iid}</code></div>}
                {selected.file    && <div>file     · <code style={{ color: "#67e8f9" }}>{selected.file.iid}</code></div>}
                {selected.network && <div>net_conn · <code style={{ color: "#fcd34d" }}>{selected.network.iid}</code></div>}
                {selected.registry&& <div>registry · <code style={{ color: "#f472b6" }}>{selected.registry.iid}</code></div>}
                {selected.user    && <div>user     · <code style={{ color: "#e2e8f0" }}>{selected.user.iid}</code></div>}
                {selected.mitre?.length > 0 && (
                  <div>mitre    · <span style={{ color: "#f87171" }}>{selected.mitre.join(", ")}</span></div>
                )}
              </div>
            </div>
          ) : (
            <div style={{ fontSize: 11, color: "var(--text-mute)",
                          fontFamily: "JetBrains Mono, monospace", lineHeight: 1.6 }}>
              Select an event to inspect its entity refs. Use ← / → to step through frames.
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}

/* ── inline styles ── */
const pageStyle = {
  minHeight: "100vh",
  background: "linear-gradient(180deg, #020617 0%, #0b1220 100%)",
  color: "var(--text)",
  display: "flex", flexDirection: "column",
};
const headerStyle = {
  padding: "18px 24px 14px",
  borderBottom: "1px solid rgba(148,163,184,0.14)",
  display: "flex", justifyContent: "space-between", alignItems: "flex-end",
  background: "rgba(2,6,23,0.65)", backdropFilter: "blur(18px)",
};
const h1Style = {
  fontFamily: "Chivo, sans-serif", fontWeight: 900, letterSpacing: "-0.02em",
  fontSize: 30, margin: 0, color: "#e2e8f0",
};
const searchStyle = {
  padding: "6px 10px", background: "rgba(15,23,42,0.7)",
  border: "1px solid rgba(148,163,184,0.22)", borderRadius: 6,
  color: "#e2e8f0", fontFamily: "JetBrains Mono, monospace",
  fontSize: 11, outline: "none", minWidth: 200,
};
const zoomBtnStyle = {
  padding: "5px 10px", fontSize: 10, letterSpacing: "0.14em",
  fontFamily: "JetBrains Mono, monospace", fontWeight: 700,
  background: "rgba(15,23,42,0.5)", border: "1px solid rgba(148,163,184,0.22)",
  borderRadius: 4, color: "var(--text-mute)", cursor: "pointer",
};
const canvasWrap = {
  flex: 1, minWidth: 0, position: "relative",
  background: "rgba(2,6,23,0.55)", overflow: "auto",
};
const drawerStyle = {
  width: 340, flexShrink: 0,
  padding: "18px 20px",
  background: "linear-gradient(160deg, rgba(15,23,42,0.98), rgba(2,6,23,0.92))",
  borderLeft: "1px solid rgba(148,163,184,0.14)",
  backdropFilter: "blur(18px) saturate(160%)",
};
