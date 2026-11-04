// MoEPanel — Mixture-of-Experts Analyst Panel (Feb-2026)
//
// Renders a 3-critic + synthesiser view of a decoded payload:
//   * Malware Analyst  — behavioural, IOC, MITRE
//   * Red Team Reviewer — offensive tradecraft, LOLBAS abuse, evasion
//   * Defensive Reviewer — Sigma / hunting queries / containment
//   * Synthesiser panel — consensus, disagreements, final verdict
//
// Analyst discipline:
//   * Every finding chip shows its evidence_refs → hover to see them
//   * Findings without evidence never reach this UI (server-side guardrail)
//   * Panel renders even without an LLM key (deterministic fallback path)
import React, { useMemo, useState } from "react";
import axios from "axios";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const SEV_COLOR = {
  critical: { bg: "#7f1d1d", fg: "#fecaca", border: "#b91c1c" },
  high:     { bg: "#7c2d12", fg: "#fed7aa", border: "#c2410c" },
  medium:   { bg: "#78350f", fg: "#fde68a", border: "#b45309" },
  low:      { bg: "#134e4a", fg: "#a5f3fc", border: "#0d9488" },
  info:     { bg: "#1e293b", fg: "#cbd5e1", border: "#334155" },
};

const REVIEWER_META = {
  malware_analyst: { label: "MALWARE ANALYST", accent: "#f59e0b", icon: "◈" },
  red_team:        { label: "RED TEAM REVIEWER", accent: "#f43f5e", icon: "⚔" },
  defensive:       { label: "DEFENSIVE REVIEWER", accent: "#22d3ee", icon: "▲" },
};

const VERDICT_COLOR = {
  malicious:         { bg: "#7f1d1d", fg: "#fecaca" },
  suspicious:        { bg: "#78350f", fg: "#fde68a" },
  "benign-candidate":{ bg: "#134e4a", fg: "#a5f3fc" },
  unknown:           { bg: "#1e293b", fg: "#cbd5e1" },
};

function EvidenceChip({ ref: r }) {
  return (
    <span
      title={`${r.type}: ${r.value}`}
      style={{
        display: "inline-block",
        padding: "1px 6px",
        marginRight: 4,
        marginTop: 2,
        borderRadius: 4,
        fontSize: 10,
        fontFamily: "ui-monospace,SFMono-Regular,monospace",
        background: "#0f172a",
        border: "1px solid #334155",
        color: "#a5f3fc",
      }}
    >
      {r.type}·{r.value.length > 40 ? r.value.slice(0, 40) + "…" : r.value}
    </span>
  );
}

function FindingCard({ finding, testidPrefix, idx }) {
  const sev = SEV_COLOR[finding.severity] || SEV_COLOR.info;
  return (
    <div
      data-testid={`${testidPrefix}-finding-${idx}`}
      style={{
        padding: "8px 10px",
        marginBottom: 8,
        borderRadius: 6,
        border: `1px solid ${sev.border}`,
        background: "#0b1220",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "start", gap: 8 }}>
        <div style={{ flex: 1, fontSize: 13, fontWeight: 600, color: "#e2e8f0" }}>
          {finding.title}
        </div>
        <span
          style={{
            fontSize: 10,
            padding: "1px 6px",
            borderRadius: 3,
            background: sev.bg,
            color: sev.fg,
            fontWeight: 700,
            textTransform: "uppercase",
          }}
        >
          {finding.severity} · {(finding.confidence * 100).toFixed(0)}%
        </span>
      </div>
      <div style={{ fontSize: 11, color: "#94a3b8", marginTop: 4, lineHeight: 1.45 }}>
        {finding.description}
      </div>
      {finding.evidence_refs && finding.evidence_refs.length > 0 && (
        <div style={{ marginTop: 6 }}>
          <span style={{ fontSize: 9, color: "#64748b", marginRight: 4 }}>EVIDENCE:</span>
          {finding.evidence_refs.map((r, i) => (
            <EvidenceChip key={i} ref={r} />
          ))}
        </div>
      )}
      {finding.tags && finding.tags.length > 0 && (
        <div style={{ marginTop: 4 }}>
          {finding.tags.map((t, i) => (
            <span
              key={i}
              style={{
                fontSize: 9,
                padding: "1px 5px",
                marginRight: 4,
                borderRadius: 3,
                background: "#1e293b",
                color: "#94a3b8",
                border: "1px solid #334155",
              }}
            >
              {t}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function ReviewerColumn({ role, report, testidPrefix }) {
  const meta = REVIEWER_META[role] || { label: role.toUpperCase(), accent: "#94a3b8", icon: "◉" };
  return (
    <div
      data-testid={`${testidPrefix}-reviewer-${role}`}
      style={{
        borderRadius: 8,
        border: `1px solid ${meta.accent}30`,
        background: "linear-gradient(180deg, #0b1220 0%, #0a0f1c 100%)",
        padding: 10,
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ color: meta.accent, fontSize: 16 }}>{meta.icon}</span>
          <span style={{ fontSize: 11, fontWeight: 700, color: meta.accent, letterSpacing: 0.5 }}>
            {meta.label}
          </span>
        </div>
        <span style={{ fontSize: 9, color: "#64748b" }}>
          {report.provider} · {report.duration_ms}ms
        </span>
      </div>
      {report.summary && (
        <div
          style={{
            fontSize: 11,
            color: "#cbd5e1",
            marginBottom: 8,
            padding: 6,
            borderLeft: `2px solid ${meta.accent}`,
            background: "#0f172a",
            lineHeight: 1.5,
          }}
        >
          {report.summary}
        </div>
      )}
      <div>
        {report.findings.length === 0 ? (
          <div style={{ fontSize: 11, color: "#64748b", fontStyle: "italic", padding: 8 }}>
            No evidence-grounded findings from this reviewer.
          </div>
        ) : (
          report.findings.map((f, i) => (
            <FindingCard
              key={i}
              finding={f}
              idx={i}
              testidPrefix={`${testidPrefix}-${role}`}
            />
          ))
        )}
      </div>
      {report.extras && (
        <ReviewerExtras extras={report.extras} accent={meta.accent} testidPrefix={`${testidPrefix}-${role}`} />
      )}
      {report.error && (
        <div style={{ fontSize: 10, color: "#f87171", marginTop: 6 }}>
          ⚠ {report.error}
        </div>
      )}
    </div>
  );
}

function ReviewerExtras({ extras, accent, testidPrefix }) {
  const blocks = [];
  if (Array.isArray(extras.techniques) && extras.techniques.length) {
    blocks.push({ label: "TECHNIQUES", items: extras.techniques });
  }
  if (Array.isArray(extras.sigma_rules) && extras.sigma_rules.length) {
    blocks.push({
      label: "SIGMA IDEAS",
      items: extras.sigma_rules.map((s) =>
        typeof s === "string" ? s : `${s.title || ""} — ${s.detection || ""}`,
      ),
    });
  }
  if (Array.isArray(extras.hunting_queries) && extras.hunting_queries.length) {
    blocks.push({ label: "HUNTING", items: extras.hunting_queries });
  }
  if (Array.isArray(extras.yara_rules) && extras.yara_rules.length) {
    blocks.push({ label: "YARA IDEAS", items: extras.yara_rules });
  }
  if (!blocks.length) return null;
  return (
    <div style={{ marginTop: 8 }} data-testid={`${testidPrefix}-extras`}>
      {blocks.map((b, i) => (
        <div key={i} style={{ marginTop: 6 }}>
          <div style={{ fontSize: 9, color: accent, fontWeight: 700 }}>{b.label}</div>
          {b.items.slice(0, 4).map((s, j) => (
            <div
              key={j}
              style={{
                fontSize: 10,
                fontFamily: "ui-monospace,SFMono-Regular,monospace",
                color: "#cbd5e1",
                background: "#0f172a",
                border: "1px solid #1e293b",
                padding: "3px 6px",
                marginTop: 3,
                borderRadius: 3,
                overflowX: "auto",
                whiteSpace: "nowrap",
              }}
            >
              {s}
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

function SynthesisCard({ synthesis, testidPrefix }) {
  const verdict = synthesis.verdict || {};
  const vc = VERDICT_COLOR[verdict.label] || VERDICT_COLOR.unknown;
  return (
    <div
      data-testid={`${testidPrefix}-synthesis`}
      style={{
        marginTop: 12,
        padding: 12,
        borderRadius: 8,
        border: "1px solid #6366f1",
        background: "linear-gradient(180deg, #0f172a 0%, #0b1220 100%)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: "#a5b4fc", letterSpacing: 0.5 }}>
          ▣ SYNTHESISER · CONSENSUS + DISAGREEMENTS
        </div>
        <div
          data-testid={`${testidPrefix}-verdict`}
          style={{
            padding: "3px 10px",
            borderRadius: 4,
            background: vc.bg,
            color: vc.fg,
            fontSize: 11,
            fontWeight: 700,
            textTransform: "uppercase",
          }}
        >
          {verdict.label} · {((verdict.confidence || 0) * 100).toFixed(0)}%
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <div>
          <div style={{ fontSize: 10, color: "#a5b4fc", fontWeight: 700, marginBottom: 4 }}>
            ✓ CONSENSUS ({synthesis.consensus?.length || 0})
          </div>
          {(synthesis.consensus || []).length === 0 ? (
            <div style={{ fontSize: 10, color: "#64748b", fontStyle: "italic" }}>
              No cross-reviewer consensus yet.
            </div>
          ) : (
            (synthesis.consensus || []).map((c, i) => (
              <div
                key={i}
                style={{
                  fontSize: 11,
                  padding: 6,
                  marginBottom: 4,
                  background: "#0b1220",
                  border: "1px solid #14532d",
                  borderRadius: 4,
                  color: "#a7f3d0",
                }}
              >
                <div style={{ fontWeight: 600 }}>{c.title}</div>
                <div style={{ fontSize: 9, color: "#94a3b8", marginTop: 2 }}>
                  ↳ {c.reviewers.join(" + ")} · {c.severity} · {(c.confidence * 100).toFixed(0)}%
                </div>
              </div>
            ))
          )}
        </div>

        <div>
          <div style={{ fontSize: 10, color: "#f87171", fontWeight: 700, marginBottom: 4 }}>
            ⚠ DISAGREEMENTS ({synthesis.disagreements?.length || 0})
          </div>
          {(synthesis.disagreements || []).length === 0 ? (
            <div style={{ fontSize: 10, color: "#64748b", fontStyle: "italic" }}>
              All reviewers align on severity.
            </div>
          ) : (
            (synthesis.disagreements || []).map((d, i) => (
              <div
                key={i}
                style={{
                  fontSize: 11,
                  padding: 6,
                  marginBottom: 4,
                  background: "#0b1220",
                  border: "1px solid #7f1d1d",
                  borderRadius: 4,
                  color: "#fecaca",
                }}
              >
                <div style={{ fontWeight: 600 }}>{d.title}</div>
                <div style={{ fontSize: 9, color: "#94a3b8", marginTop: 2 }}>
                  {Object.entries(d.severity_by_reviewer || {})
                    .map(([sev, revs]) => `${sev}: ${revs.join(",")}`)
                    .join(" · ")}
                </div>
                <div style={{ fontSize: 9, color: "#fbbf24", marginTop: 2 }}>
                  → escalated to {d.escalated_severity}
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {(synthesis.recommended_actions || []).length > 0 && (
        <div style={{ marginTop: 10, padding: 8, background: "#0b1220", borderRadius: 4, border: "1px solid #1e293b" }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: "#22d3ee", marginBottom: 4 }}>
            ▸ RECOMMENDED ACTIONS
          </div>
          {synthesis.recommended_actions.map((a, i) => (
            <div
              key={i}
              style={{ fontSize: 11, color: "#cbd5e1", padding: "2px 0", lineHeight: 1.5 }}
            >
              {i + 1}. {a}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * MoEPanel
 *
 * Props:
 *   input           — raw payload (if `evidence` not supplied, server decodes it)
 *   evidence        — pre-built evidence bundle (skip re-decode)
 *   testidPrefix    — data-testid namespace root
 */
export default function MoEPanel({ input, evidence, testidPrefix = "moe-panel" }) {
  const [state, setState] = useState({ status: "idle", data: null, error: null });

  const canRun = useMemo(() => {
    if (evidence) return true;
    return typeof input === "string" && input.trim().length > 0;
  }, [input, evidence]);

  const runPanel = async () => {
    if (!canRun) return;
    setState({ status: "running", data: null, error: null });
    try {
      const token = localStorage.getItem("nvx_token");
      const body = evidence ? { evidence } : { input };
      const r = await axios.post(`${API}/moe/analyze`, body, {
        headers: token ? { Authorization: `Bearer ${token}` } : undefined,
        timeout: 90000,
      });
      setState({ status: "done", data: r.data, error: null });
    } catch (e) {
      const detail = e?.response?.data?.detail || e.message || "Unknown error";
      setState({ status: "error", data: null, error: detail });
    }
  };

  const data = state.data;

  return (
    <div
      data-testid={testidPrefix}
      style={{
        borderRadius: 10,
        border: "1px solid #334155",
        background: "linear-gradient(180deg, #0a0f1c 0%, #0b1220 100%)",
        padding: 12,
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: 10,
        }}
      >
        <div style={{ fontSize: 13, fontWeight: 700, color: "#a5b4fc", letterSpacing: 0.5 }}>
          ▣ ANALYST PANEL · MIXTURE-OF-EXPERTS
        </div>
        <button
          data-testid={`${testidPrefix}-run`}
          onClick={runPanel}
          disabled={!canRun || state.status === "running"}
          className="nvx-btn sm"
          style={{
            background: state.status === "running" ? "#334155" : "#4f46e5",
            color: "#e2e8f0",
            border: "1px solid #6366f1",
            padding: "4px 12px",
            fontSize: 11,
            fontWeight: 700,
            letterSpacing: 0.5,
            cursor: canRun && state.status !== "running" ? "pointer" : "not-allowed",
          }}
        >
          {state.status === "running" ? "◐ REVIEWERS WORKING…" : "▶ RUN 3-CRITIC PANEL"}
        </button>
      </div>

      {state.status === "idle" && (
        <div
          style={{
            fontSize: 11,
            color: "#94a3b8",
            padding: 10,
            background: "#0f172a",
            borderRadius: 6,
            border: "1px dashed #1e293b",
            lineHeight: 1.55,
          }}
        >
          Runs 3 specialist critics in parallel — Malware Analyst, Red Team Reviewer,
          Defensive Reviewer — followed by a Synthesiser that surfaces consensus, flags
          disagreements, and issues a confidence-scored verdict. Every finding is
          <b style={{ color: "#a5f3fc" }}> evidence-grounded</b> — no chain-step, IOC, or
          MITRE ID that isn&#39;t in the decoded artefacts can appear in a finding.
        </div>
      )}

      {state.status === "error" && (
        <div
          style={{
            fontSize: 11,
            color: "#fecaca",
            padding: 10,
            background: "#7f1d1d20",
            borderRadius: 6,
            border: "1px solid #7f1d1d",
          }}
        >
          ⚠ {state.error}
        </div>
      )}

      {state.status === "running" && (
        <div
          style={{
            fontSize: 11,
            color: "#cbd5e1",
            padding: 12,
            background: "#0f172a",
            borderRadius: 6,
            border: "1px solid #1e293b",
            textAlign: "center",
          }}
        >
          Reviewers analysing decoded artefacts in parallel…
        </div>
      )}

      {data && (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
            {["malware_analyst", "red_team", "defensive"].map((role) => {
              const rep = data.reviewers[role];
              if (!rep) return null;
              return <ReviewerColumn key={role} role={role} report={rep} testidPrefix={testidPrefix} />;
            })}
          </div>
          <SynthesisCard synthesis={data.synthesis} testidPrefix={testidPrefix} />
          <div style={{ marginTop: 8, fontSize: 9, color: "#64748b", textAlign: "right" }}>
            provider={data.provider} · total {data.durations_ms?.total || 0}ms
          </div>
        </>
      )}
    </div>
  );
}
