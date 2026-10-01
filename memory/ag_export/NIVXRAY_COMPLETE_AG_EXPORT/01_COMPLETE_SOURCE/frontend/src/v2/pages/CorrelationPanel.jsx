/**
 * CorrelationPanel — Verdict Engine v3.1 · Multi-event Correlation UI.
 *
 * Renders the layered aggregation returned by
 *   GET /api/v2/cases/{case_id}/verdicts/aggregate?profile={profileId}
 *
 * Includes:
 *   • Profile selector (SOC Balanced / Threat Hunting / DFIR / High Security /
 *     Cloud Workload / OT-ICS)
 *   • Legacy vs v3.1 verdict comparison
 *   • Score-escalation ladder ("why did this score change?")
 *   • ATT&CK tactic coverage wheel
 *   • Attack progression badges (kill-chain matches)
 *   • Per-layer drill-down (Incident → Device → Chain → Process)
 *
 * All content is deterministic — no LLM, no name reputation.
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

const TACTIC_LABELS = {
  initial_access:      "Initial Access",
  execution:           "Execution",
  persistence:         "Persistence",
  privilege_escalation:"Priv Escalation",
  defense_evasion:     "Defense Evasion",
  credential_access:   "Credential Access",
  discovery:           "Discovery",
  lateral_movement:    "Lateral Movement",
  collection:          "Collection",
  command_and_control: "Command & Control",
  exfiltration:        "Exfiltration",
  impact:              "Impact",
};

const TACTIC_ORDER = [
  "initial_access", "execution", "persistence", "privilege_escalation",
  "defense_evasion", "credential_access", "discovery", "lateral_movement",
  "collection", "command_and_control", "exfiltration", "impact",
];

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

// ═════════════════════════════════════════════════════════════════════
// Profile Selector
// ═════════════════════════════════════════════════════════════════════
function ProfileSelector({ profiles, current, onChange }) {
  return (
    <div data-testid="profile-selector">
      <div className="text-[9px] tracking-[1.5px] font-bold mb-1.5"
           style={{ color: T.inkMute }}>WEIGHT PROFILE</div>
      <select value={current}
              onChange={(e) => onChange(e.target.value)}
              data-testid="profile-select"
              className="w-full text-[11px] font-mono px-2 py-1.5 rounded"
              style={{ background: T.paper2, border: `1px solid ${T.line}`,
                       color: T.ink }}>
        {profiles.map(p => (
          <option key={p.id} value={p.id}>
            {p.label}{p.is_default ? " · default" : ""}
          </option>
        ))}
      </select>
      {profiles.find(p => p.id === current)?.description && (
        <div className="text-[9px] mt-1" style={{ color: T.inkFaint }}>
          {profiles.find(p => p.id === current).description}
        </div>
      )}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════
// Legacy vs v3.1 side-by-side
// ═════════════════════════════════════════════════════════════════════
function VerdictComparison({ legacyMalicious, legacyMalCount, v31 }) {
  const legacyBand = legacyMalCount > 0 ? "malicious" : "benign";
  const legacy = BAND_TONES[legacyBand];
  const modern = BAND_TONES[v31.band] || BAND_TONES.benign;
  return (
    <div data-testid="verdict-comparison"
         className="grid grid-cols-2 gap-2">
      <div className="rounded p-2"
           style={{ background: T.paper2, border: `1px solid ${T.line}` }}>
        <div className="text-[9px] tracking-[1.4px] font-bold mb-1"
             style={{ color: T.inkMute }}>LEGACY</div>
        <div className="flex items-center gap-2">
          <div className="text-[15px] font-bold font-mono"
               style={{ color: legacy.fg }}>
            {legacyMalCount}
          </div>
          <BandPill band={legacyBand} />
        </div>
        <div className="text-[9px] mt-1" style={{ color: T.inkFaint }}>
          malicious events (rule-based)
        </div>
      </div>
      <div className="rounded p-2"
           style={{ background: T.paper2, border: `1px solid ${modern.fg}` }}>
        <div className="text-[9px] tracking-[1.4px] font-bold mb-1"
             style={{ color: modern.fg }}>VERDICT v3.1</div>
        <div className="flex items-center gap-2">
          <div className="text-[15px] font-bold font-mono"
               style={{ color: modern.fg }}>
            {v31.score}
          </div>
          <BandPill band={v31.band} />
          <span className="text-[9px] font-mono" style={{ color: T.inkMute }}>
            conf {v31.confidence}%
          </span>
        </div>
        <div className="text-[9px] mt-1 truncate" style={{ color: T.inkDim }}
             title={v31.explanation}>
          {v31.explanation}
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════
// Score-escalation ladder
// ═════════════════════════════════════════════════════════════════════
function ScoreEscalation({ ladder }) {
  if (!ladder || ladder.length <= 1) return null;
  return (
    <div data-testid="score-escalation">
      <div className="text-[9px] tracking-[1.4px] font-bold mb-1.5"
           style={{ color: T.inkMute }}>WHY DID THE SCORE ESCALATE?</div>
      <div className="space-y-0.5">
        {ladder.map((step, i) => {
          const isBase = i === 0;
          const isCap = step.layer === "corroboration_cap";
          const deltaColor = step.delta > 0 ? "#F5A34C" : (step.delta < 0 ? "#F87171" : T.inkMute);
          return (
            <div key={i}
                 data-testid={`escalation-step-${i}`}
                 className="flex items-baseline gap-2 text-[10px]"
                 style={{ color: T.inkDim }}>
              <span className="font-mono font-bold"
                    style={{ color: deltaColor, minWidth: 36, textAlign: "right" }}>
                {isBase ? `= ${step.score}`
                        : (step.delta > 0 ? `+${step.delta}` : `${step.delta}`)}
              </span>
              <span className="font-mono text-[10px]"
                    style={{ color: isBase ? T.inkMute : T.ink, minWidth: 90 }}>
                {step.signal || step.layer}
              </span>
              <span className="text-[9px] truncate flex-1"
                    title={step.reason}
                    style={{ color: isCap ? "#F87171" : T.inkFaint }}>
                {step.reason}
              </span>
              <span className="font-mono text-[10px] font-bold"
                    style={{ color: T.ink }}>
                → {step.score}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════
// ATT&CK Coverage Wheel (horizontal bar variant — reads well in the drawer)
// ═════════════════════════════════════════════════════════════════════
function TacticCoverage({ coverage }) {
  const entries = TACTIC_ORDER
    .map(t => [t, coverage?.[t]])
    .filter(([_, v]) => v);
  if (entries.length === 0) return null;
  const maxCount = Math.max(...entries.map(([_, v]) => v.count));
  return (
    <div data-testid="tactic-coverage">
      <div className="text-[9px] tracking-[1.4px] font-bold mb-1.5"
           style={{ color: T.inkMute }}>ATT&amp;CK TACTIC COVERAGE</div>
      <div className="space-y-1">
        {entries.map(([tac, v]) => {
          const pct = Math.max(0.1, v.count / maxCount);
          const barColor = v.level >= 3 ? "#F87171"
                         : v.level === 2 ? "#F5A34C" : "#7DB1D6";
          return (
            <div key={tac}
                 data-testid={`tactic-row-${tac}`}
                 className="flex items-center gap-2 text-[10px]"
                 title={v.techniques.join(", ")}>
              <span className="font-mono" style={{ color: T.inkDim, minWidth: 108 }}>
                {TACTIC_LABELS[tac] || tac}
              </span>
              <div className="flex-1 h-2 rounded overflow-hidden"
                   style={{ background: T.paper2 }}>
                <div style={{
                  width: `${pct * 100}%`, height: "100%",
                  background: `linear-gradient(90deg, ${barColor}44, ${barColor})`,
                }} />
              </div>
              <span className="font-mono font-semibold"
                    style={{ color: T.ink, minWidth: 20, textAlign: "right" }}>
                {v.count}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════
// Progression badges
// ═════════════════════════════════════════════════════════════════════
function ProgressionBadges({ progressions }) {
  if (!progressions || progressions.length === 0) return null;
  return (
    <div data-testid="progressions">
      <div className="text-[9px] tracking-[1.4px] font-bold mb-1.5"
           style={{ color: T.inkMute }}>ATTACK PROGRESSIONS DETECTED</div>
      <div className="space-y-1.5">
        {progressions.map(p => (
          <div key={p.id}
               data-testid={`progression-${p.id}`}
               className="rounded p-2"
               style={{ background: "#2A1114",
                        border: `1px solid ${p.full ? "#F87171" : "#F5A34C"}` }}>
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] font-bold" style={{ color: T.ink }}>
                {p.label}
              </span>
              <span className="text-[9px] font-mono font-bold"
                    style={{ color: p.full ? "#FCA5A5" : "#F5A34C" }}>
                +{p.effective_weight || p.weight} · {p.stages_matched.length}/{p.stages_total}
              </span>
            </div>
            <div className="flex flex-wrap gap-1">
              {p.stages_matched.map(s => (
                <span key={s}
                      className="text-[9px] px-1.5 py-0.5 rounded font-mono"
                      style={{ background: T.paper2, color: T.inkDim,
                               border: `1px solid ${T.line}` }}>
                  {s}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════
// Layer card (Incident / Device / Chain / Process drill-down)
// ═════════════════════════════════════════════════════════════════════
function LayerCard({ verdict, testid, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  if (!verdict) return null;
  const { score, band, confidence, explanation, correlation_bonuses = [],
          contributing_events = [], contributing_processes = [],
          evidence_breakdown = [], families = [], mitre_tactics = [] } = verdict;

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
                        style={{ background: "#0F1D2C", color: "#7DB1D6",
                                 border: `1px solid ${T.line}` }}
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
                    <div key={i} className="flex items-baseline gap-2 text-[10px]"
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

// ═════════════════════════════════════════════════════════════════════
// Main panel
// ═════════════════════════════════════════════════════════════════════
export default function CorrelationPanel({ caseId, legacyMaliciousCount = 0 }) {
  const [data, setData] = useState(null);
  const [err,  setErr]  = useState(null);
  const [loading, setLoading] = useState(false);
  const [profileId, setProfileId] = useState("soc_balanced");
  const [profiles, setProfiles]   = useState([]);

  // Load profiles once.
  useEffect(() => {
    api.get("/v2/verdict/profiles").then(r => {
      setProfiles(r.data?.profiles || []);
    }).catch(() => {});
  }, []);

  // Refetch on caseId / profile change.
  useEffect(() => {
    if (!caseId) return;
    let cancelled = false;
    setLoading(true);
    api.get(`/v2/cases/${encodeURIComponent(caseId)}/verdicts/aggregate?limit=500&profile=${profileId}`)
      .then(r => { if (!cancelled) setData(r.data); })
      .catch(e => { if (!cancelled) setErr(e?.response?.data?.detail || e.message); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [caseId, profileId]);

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

  if (loading && !data) {
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
    <div className="space-y-3" data-testid="correlation-panel">
      {profiles.length > 0 && (
        <ProfileSelector profiles={profiles}
                         current={profileId}
                         onChange={setProfileId} />
      )}

      <VerdictComparison legacyMalCount={legacyMaliciousCount}
                         v31={data.device} />

      <ScoreEscalation ladder={data.device.score_escalation} />

      <TacticCoverage coverage={data.device.tactic_coverage} />

      <ProgressionBadges progressions={data.device.progressions} />

      <LayerCard verdict={data.incident} testid="corr-incident" defaultOpen />
      <LayerCard verdict={data.device}   testid="corr-device"   />

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
        engine {data.engine} · profile {data.profile} · shadow mode · deterministic
      </div>
    </div>
  );
}
