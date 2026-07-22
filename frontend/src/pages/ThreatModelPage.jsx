// ThreatModelPage — Feb 2026
// New route /threat-model — paste a Mermaid architecture diagram and get a
// deterministic threat-model report (attack paths + MITRE + STRIDE +
// detection recommendations). AI enrichment via the MoE panel is optional.
//
// Discipline (matches the rest of NivXRay):
//   * The deterministic report is the source of truth. AI is ADDITIVE.
//   * Every finding surfaced on this page is evidence-grounded (component
//     kind inference, trust-zone crossings, or attack-path enumeration).
import React, { useState } from "react";
import axios from "axios";
import Header from "@/components/Header";
import PageHeader from "@/components/PageHeader";
import MoEPanel from "@/components/MoEPanel";
import CorrectionRefineModal from "@/components/CorrectionRefineModal";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const SEV_COLOR = {
  critical: { bg: "#7f1d1d", fg: "#fecaca" },
  high:     { bg: "#7c2d12", fg: "#fed7aa" },
  medium:   { bg: "#78350f", fg: "#fde68a" },
  low:      { bg: "#134e4a", fg: "#a5f3fc" },
  info:     { bg: "#1e293b", fg: "#cbd5e1" },
};

const ZONE_COLOR = {
  EXT:  "#f43f5e",  // rose — external / hostile
  DMZ:  "#f59e0b",  // amber — perimeter
  INT:  "#22d3ee",  // cyan — internal / trusted
  DATA: "#a855f7",  // violet — crown jewels
};

const DEFAULT_EXAMPLE = `flowchart TD
  User[[EXT]] -->|HTTPS| WAF[[DMZ]]
  WAF --> LB[[DMZ]]
  LB --> API[[INT]]
  API -->|OAuth| Auth[[INT]]
  API --> Cache[[INT]]
  API --> DB[[DATA]]
  API --> Secrets[[DATA]]
  API --> LLM[[EXT]]
  Worker[[INT]] --> Queue[[INT]]
  Queue --> API`;

function SevBadge({ sev }) {
  const c = SEV_COLOR[sev] || SEV_COLOR.info;
  return (
    <span
      style={{
        padding: "1px 8px",
        borderRadius: 4,
        background: c.bg,
        color: c.fg,
        fontSize: 10,
        fontWeight: 700,
        textTransform: "uppercase",
        letterSpacing: 0.5,
      }}
    >
      {sev}
    </span>
  );
}

function ZoneBadge({ zone }) {
  if (!zone) return null;
  return (
    <span
      style={{
        padding: "1px 6px",
        borderRadius: 3,
        background: "#0f172a",
        color: ZONE_COLOR[zone] || "#94a3b8",
        border: `1px solid ${ZONE_COLOR[zone] || "#334155"}`,
        fontSize: 9,
        fontWeight: 700,
      }}
    >
      {zone}
    </span>
  );
}

function AttackPathCard({ path, idx }) {
  return (
    <div
      data-testid={`threat-attack-path-${idx}`}
      style={{
        padding: 10,
        marginBottom: 8,
        background: "#0b1220",
        border: `1px solid ${SEV_COLOR[path.severity]?.bg || "#334155"}`,
        borderRadius: 6,
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
        <span style={{ color: "#cbd5e1", fontSize: 12, fontWeight: 700 }}>
          PATH #{idx + 1} · {path.hops} hop(s) · {path.trust_crossings} zone crossing(s)
        </span>
        <SevBadge sev={path.severity} />
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 4 }}>
        {path.nodes.map((n, i) => (
          <React.Fragment key={n.id}>
            <div
              style={{
                padding: "2px 8px",
                borderRadius: 4,
                background: "#0f172a",
                border: `1px solid ${ZONE_COLOR[n.zone] || "#334155"}`,
                fontSize: 11,
                color: "#e2e8f0",
              }}
            >
              {n.label} <ZoneBadge zone={n.zone} />
            </div>
            {i < path.nodes.length - 1 && (
              <span style={{ color: "#64748b" }}>→</span>
            )}
          </React.Fragment>
        ))}
      </div>
      {path.stride?.length > 0 && (
        <div style={{ marginTop: 6 }}>
          <span style={{ fontSize: 9, color: "#64748b", marginRight: 4 }}>STRIDE:</span>
          {path.stride.map((s) => (
            <span
              key={s}
              style={{
                fontSize: 9,
                padding: "1px 5px",
                marginRight: 3,
                borderRadius: 3,
                background: "#1e293b",
                color: "#fbbf24",
                border: "1px solid #78350f",
              }}
            >
              {s}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function FindingCard({ finding, idx, onRefine }) {
  return (
    <div
      data-testid={`threat-finding-${idx}`}
      style={{
        padding: "8px 10px",
        marginBottom: 6,
        background: "#0b1220",
        border: `1px solid ${SEV_COLOR[finding.severity]?.bg || "#334155"}`,
        borderRadius: 5,
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "start", gap: 8 }}>
        <div style={{ flex: 1, fontSize: 12, fontWeight: 600, color: "#e2e8f0" }}>
          {finding.title}
        </div>
        <SevBadge sev={finding.severity} />
      </div>
      <div style={{ fontSize: 11, color: "#94a3b8", marginTop: 4, lineHeight: 1.45 }}>
        {finding.description}
      </div>
      {finding.mitre?.length > 0 && (
        <div style={{ marginTop: 4, display: "flex", flexWrap: "wrap", gap: 3, alignItems: "center" }}>
          {finding.mitre.map((m) => (
            <span
              key={m}
              style={{
                fontSize: 9, padding: "1px 5px", borderRadius: 3,
                background: "#0f172a", color: "#a5f3fc",
                border: "1px solid #14b8a6",
                display: "inline-flex", alignItems: "center", gap: 3,
              }}
            >
              {m}
              <button
                onClick={() => onRefine?.({ kind: "mitre", value: m })}
                data-testid={`refine-mitre-${idx}-${m}`}
                title={`Refine — mark ${m} as wrong and teach NivXRay the correct mapping`}
                style={{
                  background: "rgba(245,158,11,0.20)",
                  border: "1px solid #f59e0b", padding: "1px 5px",
                  cursor: "pointer", color: "#fbbf24", fontSize: 10,
                  fontWeight: 800, borderRadius: 3, lineHeight: 1,
                }}
              >✎ REFINE</button>
            </span>
          ))}
        </div>
      )}
      {finding.detections?.length > 0 && (
        <details style={{ marginTop: 6 }}>
          <summary style={{ fontSize: 10, color: "#22d3ee", cursor: "pointer" }}>
            ▸ {finding.detections.length} detection idea(s)
          </summary>
          {finding.detections.map((d, i) => (
            <div
              key={i}
              style={{
                fontSize: 10,
                fontFamily: "ui-monospace,monospace",
                color: "#cbd5e1",
                background: "#0f172a",
                border: "1px solid #1e293b",
                padding: "3px 6px",
                marginTop: 3,
                borderRadius: 3,
              }}
            >
              {d}
            </div>
          ))}
        </details>
      )}
    </div>
  );
}

function RiskGauge({ risk }) {
  const pct = risk?.score || 0;
  const c = SEV_COLOR[risk?.level] || SEV_COLOR.info;
  return (
    <div
      data-testid="threat-risk-gauge"
      style={{
        padding: 14,
        borderRadius: 8,
        background: "linear-gradient(180deg, #0f172a 0%, #0b1220 100%)",
        border: `1px solid ${c.bg}`,
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
        <span style={{ fontSize: 12, fontWeight: 700, color: "#a5b4fc", letterSpacing: 0.5 }}>
          ▣ THREAT RISK
        </span>
        <SevBadge sev={risk?.level} />
      </div>
      <div style={{ position: "relative", height: 8, background: "#1e293b", borderRadius: 4 }}>
        <div
          style={{
            position: "absolute", left: 0, top: 0, bottom: 0,
            width: `${pct}%`, background: c.bg, borderRadius: 4,
            transition: "width 0.4s ease",
          }}
        />
      </div>
      <div style={{ marginTop: 4, fontSize: 20, fontWeight: 700, color: c.fg }}>
        {pct} <span style={{ fontSize: 11, color: "#64748b" }}>/ 100</span>
      </div>
    </div>
  );
}

export default function ThreatModelPage() {
  const [mermaid, setMermaid] = useState(DEFAULT_EXAMPLE);
  const [state, setState] = useState({ status: "idle", report: null, error: null });
  // Feb-2026: analyst-corrections modal state.
  const [refineOpen, setRefineOpen] = useState(false);
  const [refineWrong, setRefineWrong] = useState(null);

  const openRefine = (wrong) => { setRefineWrong(wrong); setRefineOpen(true); };
  const closeRefine = () => setRefineOpen(false);

  const runAnalysis = async () => {
    setState({ status: "loading", report: null, error: null });
    try {
      const token = localStorage.getItem("nvx_token");
      const r = await axios.post(
        `${API}/threat-model/analyze`,
        { mermaid },
        { headers: token ? { Authorization: `Bearer ${token}` } : undefined, timeout: 30000 },
      );
      setState({ status: "done", report: r.data, error: null });
    } catch (e) {
      setState({ status: "error", report: null, error: e?.response?.data?.detail || e.message });
    }
  };

  const loadExample = async () => {
    setMermaid(DEFAULT_EXAMPLE);
    setState({ status: "idle", report: null, error: null });
  };

  const report = state.report;

  return (
    <>
      <Header />
      <div style={{ padding: 16, minHeight: "calc(100vh - 60px)", background: "#0a0f1c" }}>
        <div style={{ maxWidth: 1400, margin: "0 auto" }}>
          <PageHeader
            testId="threat-model-hero"
            eyebrow="Architecture Threat Modelling · Deterministic-First"
            title="Threat-Model Assessor"
            subtitle="Paste a Mermaid architecture diagram — tag components with [[EXT]] [[DMZ]] [[INT]] [[DATA]] to declare trust zones. Every finding is evidence-grounded: attack paths, MITRE mapping, STRIDE per trust-boundary edge, and detection recommendations. AI enrichment is optional and never overrides the deterministic verdict."
            tone="violet"
          />

          {/* NEW FEATURE BANNER — Feb-2026: Teach NivXRay */}
          <div
            data-testid="tm-refine-feature-banner"
            style={{
              margin: "0 0 16px 0",
              padding: "12px 16px",
              background: "linear-gradient(90deg, rgba(124,58,237,0.15), rgba(34,211,238,0.10))",
              border: "1.5px solid #7c3aed",
              borderRadius: 6,
              display: "flex",
              alignItems: "center",
              gap: 12,
              flexWrap: "wrap",
            }}
          >
            <div style={{
              fontSize: 11, fontWeight: 800, letterSpacing: "0.20em",
              color: "#c4b5fd", padding: "3px 8px",
              background: "rgba(124,58,237,0.30)", borderRadius: 3,
            }}>
              ✎ NEW
            </div>
            <div style={{ flex: 1, minWidth: 300 }}>
              <div style={{ fontSize: 13, color: "#e2e8f0", fontWeight: 600 }}>
                Teach NivXRay when a finding is wrong.
              </div>
              <div style={{ fontSize: 11, color: "#94a3b8", marginTop: 2 }}>
                After you analyze, click the small <span style={{ color: "#f59e0b" }}>✎</span> next to any
                MITRE tag — or use the Refine buttons below — to submit a Correct / Incorrect /
                Partial / Suggest verdict. Your correction re-runs the analysis automatically.
              </div>
            </div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {[
                ["mitre",      "MITRE"],
                ["family",     "FAMILY"],
                ["risk",       "RISK"],
                ["mitigation", "MITIGATION"],
                ["detection",  "DETECTION"],
              ].map(([surf, label]) => (
                <button
                  key={surf}
                  type="button"
                  data-testid={`tm-btn-refine-${surf}`}
                  onClick={() => openRefine({ kind: surf, value: "" })}
                  style={{
                    background: "rgba(124,58,237,0.20)",
                    color: "#c4b5fd",
                    border: "1px solid #7c3aed",
                    padding: "5px 10px",
                    fontSize: 10,
                    fontWeight: 700,
                    letterSpacing: "0.10em",
                    borderRadius: 3,
                    cursor: "pointer",
                  }}
                >
                  ✎ {label}
                </button>
              ))}
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            {/* Left column — input */}
            <div>
              <div style={{ marginBottom: 8, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 11, color: "#94a3b8", fontWeight: 700, letterSpacing: 0.5 }}>
                  MERMAID DIAGRAM
                </span>
                <div style={{ display: "flex", gap: 6 }}>
                  <button
                    data-testid="threat-load-example-btn"
                    onClick={loadExample}
                    style={{
                      background: "#1e293b", color: "#cbd5e1", border: "1px solid #334155",
                      padding: "4px 10px", fontSize: 10, fontWeight: 700, borderRadius: 4, cursor: "pointer",
                    }}
                  >
                    ⟳ EXAMPLE
                  </button>
                  <button
                    data-testid="threat-analyze-btn"
                    onClick={runAnalysis}
                    disabled={state.status === "loading" || !mermaid.trim()}
                    style={{
                      background: state.status === "loading" ? "#334155" : "#4f46e5",
                      color: "#e2e8f0", border: "1px solid #6366f1",
                      padding: "4px 14px", fontSize: 11, fontWeight: 700, letterSpacing: 0.5,
                      borderRadius: 4, cursor: state.status === "loading" ? "wait" : "pointer",
                    }}
                  >
                    {state.status === "loading" ? "◐ ANALYSING…" : "▶ ANALYSE THREAT MODEL"}
                  </button>
                </div>
              </div>
              <textarea
                data-testid="threat-mermaid-input"
                value={mermaid}
                onChange={(e) => setMermaid(e.target.value)}
                spellCheck={false}
                style={{
                  width: "100%", minHeight: 420, padding: 10,
                  background: "#0b1220", color: "#a5f3fc",
                  border: "1px solid #334155", borderRadius: 6,
                  fontFamily: "ui-monospace,SFMono-Regular,monospace",
                  fontSize: 12, lineHeight: 1.5, resize: "vertical",
                }}
              />
              {state.error && (
                <div
                  data-testid="threat-error"
                  style={{
                    marginTop: 8, padding: 10, fontSize: 11, color: "#fecaca",
                    background: "#7f1d1d20", border: "1px solid #7f1d1d", borderRadius: 6,
                  }}
                >
                  ⚠ {state.error}
                </div>
              )}
            </div>

            {/* Right column — report */}
            <div>
              {!report && state.status !== "loading" && (
                <div
                  style={{
                    padding: 24, textAlign: "center",
                    color: "#64748b", fontSize: 12, fontStyle: "italic",
                    border: "1px dashed #334155", borderRadius: 6, background: "#0b1220",
                  }}
                >
                  Deterministic report will appear here after analysis.
                  <br />
                  <br />
                  Every finding is evidence-grounded — component-kind inference, MITRE mapping, STRIDE per trust-boundary edge, and attack-path enumeration are all rule-based.
                  <br />
                  <br />
                  <span style={{ color: "#22d3ee" }}>AI is optional</span> and never overrides the deterministic verdict.
                </div>
              )}

              {state.status === "loading" && (
                <div style={{ padding: 24, textAlign: "center", color: "#cbd5e1", fontSize: 12 }}>
                  Enumerating attack paths…
                </div>
              )}

              {report && (
                <>
                  <RiskGauge risk={report.risk} />

                  {report.corrections_available?.length > 0 && (
                    <div
                      data-testid="corrections-applied-banner"
                      style={{
                        marginTop: 10, padding: "8px 10px",
                        border: "1px solid #7c3aed", borderRadius: 4,
                        background: "rgba(124,58,237,0.10)", fontSize: 11,
                        color: "#c4b5fd",
                      }}
                    >
                      <div style={{ letterSpacing: "0.14em", fontWeight: 700, marginBottom: 4 }}>
                        ✎ ANALYST CORRECTIONS APPLIED ({report.corrections_available.length})
                      </div>
                      {report.corrections_available.slice(0, 5).map((c) => (
                        <div key={c.id} style={{ marginTop: 3, fontSize: 10 }}>
                          <span style={{ color: "#a78bfa" }}>{c.id}</span>
                          <span style={{ color: "#94a3b8" }}> · v{c.version} · conf {c.confidence} · </span>
                          <span style={{ color: c.apply_mode === "override" ? "#f472b6" : "#94a3b8" }}>
                            {c.apply_mode?.toUpperCase()}
                          </span>
                          <span style={{ color: "#cbd5e1" }}> — {c.correct_prompt?.slice(0, 100)}…</span>
                        </div>
                      ))}
                    </div>
                  )}

                  <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8, marginTop: 12 }}>
                    {[
                      ["nodes", report.counts.nodes],
                      ["edges", report.counts.edges],
                      ["trust-boundary", report.counts.trust_boundary_edges],
                      ["attack paths", report.counts.attack_paths],
                    ].map(([k, v]) => (
                      <div
                        key={k}
                        data-testid={`threat-count-${k.replace(/\s/g, "-")}`}
                        style={{
                          padding: 8, background: "#0b1220",
                          border: "1px solid #334155", borderRadius: 4, textAlign: "center",
                        }}
                      >
                        <div style={{ fontSize: 18, fontWeight: 700, color: "#e2e8f0" }}>{v}</div>
                        <div style={{ fontSize: 9, color: "#64748b", textTransform: "uppercase" }}>{k}</div>
                      </div>
                    ))}
                  </div>

                  {report.attack_paths?.length > 0 && (
                    <div style={{ marginTop: 14 }}>
                      <div style={{ fontSize: 11, color: "#a5b4fc", fontWeight: 700, marginBottom: 6, letterSpacing: 0.5 }}>
                        ▸ ATTACK PATHS ({report.attack_paths.length})
                      </div>
                      {report.attack_paths.slice(0, 8).map((p, i) => (
                        <AttackPathCard key={i} path={p} idx={i} />
                      ))}
                    </div>
                  )}

                  {report.findings?.length > 0 && (
                    <div style={{ marginTop: 14 }}>
                      <div style={{ fontSize: 11, color: "#a5b4fc", fontWeight: 700, marginBottom: 6, letterSpacing: 0.5 }}>
                        ▸ FINDINGS ({report.findings.length})
                      </div>
                      {report.findings.map((f, i) => (
                        <FindingCard key={i} finding={f} idx={i} onRefine={openRefine} />
                      ))}
                    </div>
                  )}

                  {report.mitre_summary?.length > 0 && (
                    <div style={{ marginTop: 14, padding: 10, background: "#0b1220", border: "1px solid #334155", borderRadius: 6 }}>
                      <div style={{ fontSize: 11, color: "#a5b4fc", fontWeight: 700, marginBottom: 6, letterSpacing: 0.5 }}>
                        ▸ MITRE COVERAGE
                      </div>
                      {report.mitre_summary.map((m) => (
                        <span
                          key={m}
                          style={{
                            display: "inline-block", padding: "2px 8px", margin: "2px 3px",
                            borderRadius: 4, background: "#0f172a",
                            border: "1px solid #14b8a6", color: "#a5f3fc",
                            fontSize: 10, fontWeight: 600,
                          }}
                        >
                          {m}
                        </span>
                      ))}
                    </div>
                  )}
                </>
              )}
            </div>
          </div>

          {/* Optional MoE enrichment — always additive */}
          {report && (
            <div style={{ marginTop: 20 }}>
              <div
                style={{
                  fontSize: 11, color: "#94a3b8", fontWeight: 700,
                  letterSpacing: 0.5, marginBottom: 8, textTransform: "uppercase",
                }}
              >
                Optional · AI enrichment (additive — never overrides)
              </div>
              <MoEPanel
                input={mermaid}
                testidPrefix="threat-moe-panel"
              />
            </div>
          )}
        </div>
      </div>

      {/* Analyst-corrections modal (Feb-2026 · teach-the-model feature) */}
      <CorrectionRefineModal
        open={refineOpen}
        onClose={closeRefine}
        surface="threat_model"
        wrongFinding={refineWrong || {}}
        inputText={mermaid}
        defaultTags={[]}
        onRerun={runAnalysis}
      />
    </>
  );
}
