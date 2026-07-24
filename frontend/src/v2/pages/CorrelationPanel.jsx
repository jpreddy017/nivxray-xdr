/**
 * CorrelationPanel — Verdict Engine v3.1 · Multi-event Correlation UI.
 *
 * Renders the layered aggregation returned by
 *   GET /api/v2/cases/{case_id}/verdicts/aggregate
 *
 * Hierarchy:
 *   Incident → Device → Chain(s) → Process(es)
 *
 * Every layer shows: score · band · confidence · top signals ·
 * correlation bonuses that fired. No LLM, no name reputation — pure
 * evidence breakdown from the deterministic engine.
 *
 * Gated at the caller by `isObservable("VERDICT_ENGINE_V3")` — this
 * component simply renders whatever data it is handed.
 */
import { useEffect, useMemo, useState } from "react";
import { T } from "../theme";
import api from "@/lib/api";

const BAND_TONES = {
  benign:        { bg: "#0F2418", fg: "#4ADE80", label: "BENIGN"        },
  informational: { bg: "#0E1E2A", fg: "#7DB1D6", label: "INFO"          },
  low:           { bg: "#1E1E14", fg: "#D4C069", label: "LOW"           },
  suspicious:    { bg: "#2A1E10", fg: "#F5A34C", label: "SUSPICIOUS"    },
  malicious:     { bg: "#2A1114", fg: "#F87171", label: "MALICIOUS"     },
  critical:      { bg: "#3A0F16", fg: "#FCA5A5", label: "CRITICAL"      },
};

function Ring({ score, band, size = 46 }) {
  const tone = BAND_TONES[band] || BAND_TONES.benign;
  const stroke = 4;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const dash = Math.max(0, Math.min(1, score / 100)) * c;
  return (
    <div className="relative inline-flex items-center justify-center"
         style={{ width: size, height: size }}
         data-testid="corr-ring">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={size/2} cy={size/2} r={r}
                fill="transparent" stroke={T.line} strokeWidth={stroke} />
        <circle cx={size/2} cy={size/2} r={r}
                fill="transparent" stroke={tone.fg} strokeWidth={stroke}
                strokeDasharray={`${dash} ${c}`}
                transform={`rotate(-90 ${size/2} ${size/2})`}
                strokeLinecap="round" />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center
                      text-[13px] font-bold font-mono"
           style={{ color: tone.fg }}>
        {score}
      </div>
    </div>
  );
}

function BandPill({ band }) {
  const tone = BAND_TONES[band] || BAND_TONES.benign;
  return (
    <span className="text-[9px] tracking-[1.2px] font-bold px-1.5 py-0.5 rounded"
          style={{ background: tone.bg, color: tone.fg }}>
      {tone.label}
    </span>
  );
}

function LayerCard({ verdict, testid, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  if (!verdict) return null;
  const { score, band, confidence, explanation, signals = [],
          correlation_bonuses = [], contributing_events = [],
          contributing_processes = [], evidence_breakdown = [],
          families = [], mitre_tactics = [] } = verdict;

  return (
    <div data-testid={testid}
         className="rounded-md"
         style={{ background: T.paper2, border: `1px solid ${T.line}` }}>
      <button className="w-full flex items-center gap-3 px-2.5 py-2"
              onClick={() => setOpen(o => !o)}>
        <Ring score={score} band={band} />
        <div className="flex-1 text-left min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[11px] font-bold uppercase tracking-[0.9px]"
                  style={{ color: T.ink }}>{verdict.layer}</span>
            <BandPill band={band} />
            <span className="text-[10px] font-mono" style={{ color: T.inkMute }}>
              conf {confidence}%
            </span>
          </div>
          <div className="text-[10px] mt-0.5 truncate font-mono" style={{ color: T.inkDim }}>
            {verdict.label}
          </div>
        </div>
        <span className="text-[10px]" style={{ color: T.inkFaint }}>
          {open ? "▾" : "▸"}
        </span>
      </button>

      {open && (
        <div className="px-2.5 pb-2.5 pt-1 border-t space-y-2"
             style={{ borderColor: T.line }}>
          <div className="text-[10px]" style={{ color: T.inkDim }}>
            {explanation}
          </div>

          {correlation_bonuses.length > 0 && (
            <div>
              <div className="text-[9px] tracking-[1.3px] font-bold mb-1"
                   style={{ color: T.inkMute }}>CORRELATION BONUSES</div>
              <div className="flex flex-wrap gap-1">
                {correlation_bonuses.map(b => (
                  <span key={b.signal}
                        className="text-[9px] px-1.5 py-0.5 rounded font-mono font-semibold"
                        style={{ background: "#0F1D2C", color: "#7DB1D6", border: `1px solid ${T.line}` }}
                        title={b.reason}>
                    +{b.weight} {b.signal}
                  </span>
                ))}
              </div>
            </div>
          )}

          {evidence_breakdown.length > 0 && (
            <div>
              <div className="text-[9px] tracking-[1.3px] font-bold mb-1"
                   style={{ color: T.inkMute }}>EVIDENCE</div>
              <div className="space-y-0.5 max-h-40 overflow-y-auto pr-1">
                {evidence_breakdown
                  .slice()
                  .sort((a, b) => (b.effective_weight || 0) - (a.effective_weight || 0))
                  .slice(0, 8)
                  .map((b, i) => (
                    <div key={i}
                         className="flex items-baseline gap-2 text-[10px]"
                         style={{ color: T.inkDim }}>
                      <span className="font-mono font-bold"
                            style={{ color: b.effective_weight > 0 ? "#F5A34C" : T.inkMute, minWidth: 32 }}>
                        {b.effective_weight > 0 ? `+${b.effective_weight}` : b.effective_weight}
                      </span>
                      <span className="font-mono text-[10px]" style={{ color: T.ink }}>
                        {b.signal}
                      </span>
                      <span className="text-[9px] truncate flex-1" title={b.reason}>
                        {b.reason}
                      </span>
                    </div>
                  ))}
                {evidence_breakdown.length > 8 && (
                  <div className="text-[9px]" style={{ color: T.inkFaint }}>
                    +{evidence_breakdown.length - 8} more signals
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="flex flex-wrap gap-x-3 gap-y-1 text-[9px] font-mono"
               style={{ color: T.inkMute }}>
            {mitre_tactics.length > 0 && (
              <span title="MITRE tactics observed">
                tactics: <b style={{ color: T.ink }}>{mitre_tactics.length}</b>
              </span>
            )}
            {families.length > 0 && (
              <span title="Distinct signal families">
                families: <b style={{ color: T.ink }}>{families.length}</b>
              </span>
            )}
            {contributing_processes.length > 0 && (
              <span title="Contributing processes">
                processes: <b style={{ color: T.ink }}>{contributing_processes.length}</b>
              </span>
            )}
            {contributing_events.length > 0 && (
              <span title="Contributing events">
                events: <b style={{ color: T.ink }}>{contributing_events.length}</b>
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function CorrelationPanel({ caseId }) {
  const [data, setData] = useState(null);
  const [err,  setErr]  = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!caseId) return;
    let cancelled = false;
    setLoading(true);
    api.get(`/v2/cases/${encodeURIComponent(caseId)}/verdicts/aggregate?limit=500`)
      .then(r => { if (!cancelled) setData(r.data); })
      .catch(e => { if (!cancelled) setErr(e?.response?.data?.detail || e.message); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [caseId]);

  const topChains = useMemo(() => {
    if (!data?.chains) return [];
    return Object.values(data.chains)
      .sort((a, b) => b.score - a.score)
      .slice(0, 5);
  }, [data]);

  const topProcesses = useMemo(() => {
    if (!data?.processes) return [];
    return Object.values(data.processes)
      .filter(p => p.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 8);
  }, [data]);

  if (loading) {
    return <div className="text-[10px]" style={{ color: T.inkFaint }} data-testid="corr-loading">
      Loading correlation…
    </div>;
  }
  if (err) {
    return <div className="text-[10px]" style={{ color: T.red }} data-testid="corr-error">
      Correlation unavailable: {err}
    </div>;
  }
  if (!data || !data.device) {
    return <div className="text-[10px]" style={{ color: T.inkFaint }} data-testid="corr-empty">
      No correlation data.
    </div>;
  }

  return (
    <div className="space-y-2" data-testid="correlation-panel">
      <LayerCard verdict={data.incident} testid="corr-incident" defaultOpen />
      <LayerCard verdict={data.device}   testid="corr-device"   defaultOpen />

      {topChains.length > 0 && (
        <div>
          <div className="text-[9px] tracking-[1.5px] font-bold mb-1.5"
               style={{ color: T.inkMute }}>TOP CHAINS</div>
          <div className="space-y-1.5">
            {topChains.map(c => (
              <LayerCard key={c.id} verdict={c} testid={`corr-chain-${c.id}`} />
            ))}
          </div>
        </div>
      )}

      {topProcesses.length > 0 && (
        <div>
          <div className="text-[9px] tracking-[1.5px] font-bold mb-1.5"
               style={{ color: T.inkMute }}>TOP PROCESSES</div>
          <div className="space-y-1.5">
            {topProcesses.map(p => (
              <LayerCard key={p.id} verdict={p} testid={`corr-process-${p.id}`} />
            ))}
          </div>
        </div>
      )}

      <div className="text-[9px] font-mono pt-1" style={{ color: T.inkFaint }}>
        engine {data.engine} · shadow mode · deterministic
      </div>
    </div>
  );
}
