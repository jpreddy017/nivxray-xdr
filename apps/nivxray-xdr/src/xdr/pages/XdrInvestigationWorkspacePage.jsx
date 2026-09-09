/**
 * XdrInvestigationWorkspacePage · `/xdr/investigations/:caseId`
 *
 * The Flagship Causal Investigation Surface of NivXRay XDR.
 * Renders the full 7-stage causal pipeline:
 * Evidence → Causality → Security State → Verdict → Impact → Intervention → Verification
 *
 * Consumes:
 *   GET /api/v2/cases/:caseId/investigation?profile=:profile
 * with fallback to /api/incidents/:caseId.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useParams, useSearchParams, useNavigate } from "react-router-dom";
import {
  FolderSearch, ChevronLeft, RefreshCw, GitBranch, AlertOctagon,
  ShieldAlert, Activity, Layers, FileText, Database, Shield, Zap,
  Terminal, Wifi, Lock, HelpCircle, CheckCircle2, ChevronDown, ChevronUp
} from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import api from "@/lib/api";

const BAND_COLORS = {
  critical:      { fg: "var(--nx-critical)", bg: "rgba(239, 68, 68, 0.15)",  border: "rgba(239, 68, 68, 0.35)" },
  malicious:     { fg: "var(--nx-critical)", bg: "rgba(248, 113, 113, 0.15)", border: "rgba(248, 113, 113, 0.35)" },
  suspicious:    { fg: "var(--nx-medium)", bg: "rgba(245, 158, 11, 0.15)",  border: "rgba(245, 158, 11, 0.35)" },
  low:           { fg: "var(--nx-medium)", bg: "rgba(212, 192, 105, 0.15)", border: "rgba(212, 192, 105, 0.35)" },
  informational: { fg: "var(--nx-info)", bg: "rgba(56, 189, 248, 0.15)",  border: "rgba(56, 189, 248, 0.35)" },
  benign:        { fg: "var(--nx-benign)", bg: "rgba(74, 222, 128, 0.15)",  border: "rgba(74, 222, 128, 0.35)" },
};

const PROFILES = [
  { id: "soc_balanced", label: "SOC Balanced", isDefault: true },
  { id: "aggressive", label: "Aggressive (High Recall)" },
  { id: "conservative", label: "Conservative (High Precision)" },
];

export default function XdrInvestigationWorkspacePage() {
  const { caseId } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  const activeTab = searchParams.get("tab") || "story";
  const profile = searchParams.get("profile") || "soc_balanced";
  const trajView = searchParams.get("traj_view") || "timeline";

  const [inv, setInv] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [explainOpen, setExplainOpen] = useState(false);
  const [explainQuestion, setExplainQuestion] = useState("positive");
  const [negativeExplanations, setNegativeExplanations] = useState({});

  const [trajectoryData, setTrajectoryData] = useState(null);
  const [trajectoryLoading, setTrajectoryLoading] = useState(false);
  const [processTreeData, setProcessTreeData] = useState(null);
  const [processTreeLoading, setProcessTreeLoading] = useState(false);
  const [caseArtifacts, setCaseArtifacts] = useState([]);
  const [artifactsLoading, setArtifactsLoading] = useState(false);
  const [securityStateData, setSecurityStateData] = useState(null);
  const [securityStateLoading, setSecurityStateLoading] = useState(false);

  const setTab = useCallback((key) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", key);
    setSearchParams(next, { replace: false });
  }, [searchParams, setSearchParams]);

  const setProfile = useCallback((prof) => {
    const next = new URLSearchParams(searchParams);
    next.set("profile", prof);
    setSearchParams(next, { replace: true });
  }, [searchParams, setSearchParams]);

  const setTrajView = useCallback((v) => {
    const next = new URLSearchParams(searchParams);
    next.set("traj_view", v);
    setSearchParams(next, { replace: true });
  }, [searchParams, setSearchParams]);

  const loadInvestigation = useCallback(async () => {
    if (!caseId) return;
    setLoading(true);
    setError(null);
    try {
      let data = null;
      try {
        const res = await api.get(`/v2/cases/${encodeURIComponent(caseId)}/investigation?limit=500&profile=${profile}`);
        data = res.data;
      } catch {
        // Fallback to incident endpoint if v2 case fails
        try {
          const resInc = await api.get(`/incidents/${encodeURIComponent(caseId)}`);
          const inc = resInc.data;
          data = {
            case_id: inc.id || caseId,
            header: {
              verdict_band: inc.verdict_stage2?.label || inc.verdict || "benign",
              device_score: inc.device_score ?? inc.verdict_stage2?.risk_score ?? 0,
              incident_score: inc.incident_score ?? inc.verdict_stage2?.risk_score ?? 0,
              confidence: inc.confidence ?? inc.verdict_stage2?.confidence ?? 0,
              event_count: inc.evidence_count || (Array.isArray(inc.evidence) ? inc.evidence.length : 0),
              process_count: inc.process_count || 0,
              chain_count: inc.chain_count || 0,
            },
            ikg: {
              stats: {
                nodes: inc.ikg_nodes || (Array.isArray(inc.nodes) ? inc.nodes.length : 0),
                edges: inc.ikg_edges || (Array.isArray(inc.edges) ? inc.edges.length : 0),
              },
              nodes: inc.nodes || [],
              edges: inc.edges || [],
            },
            story: {
              narrative: inc.attack_story?.narrative || inc.description || "No causal narrative available for this incident.",
              steps: inc.attack_story?.steps || [],
            },
            explainability: {
              positive: {
                reasons: inc.explainability?.positive?.reasons || [],
              },
              negative_patterns: inc.explainability?.negative_patterns || [],
            },
            engine_version: inc.engine_version || { verdict: "3.1b" },
            patient_zero: inc.patient_zero || inc.host || null,
            root_process: inc.root_process || null,
            target_identity: inc.target_identity || inc.user || null,
            c2_endpoints: inc.c2_endpoints || null,
            containment: inc.containment || inc.recommendations || null,
            security_state: inc.security_state || null,
            mitre_techniques: inc.mitre_techniques || inc.techniques || [],
          };
        } catch (inner) {
          throw new Error("Investigation could not be loaded from either case engine or incident registry.");
        }
      }
      setInv(data);
    } catch (err) {
      setError(err?.message || "Failed to load investigation workspace.");
    } finally {
      setLoading(false);
    }

    // Parallel dynamic sub-fetches for Tabs 2, 3, 6
    setTrajectoryLoading(true);
    api.get(`/v2/cases/${encodeURIComponent(caseId)}/trajectory/device?limit=500`)
      .then((res) => {
        setTrajectoryData(res.data);
      })
      .catch(() => {
        // P0-2C · PIVOT DEFECT REMOVED. This fallback called
        // `/edr/device-trajectory?device=<CASE ID>` — a case id is never
        // an endpoint identifier, so the request could only ever return
        // an empty canvas that read as "this case has no activity".
        // There is no endpoint identity in scope here to substitute, and
        // inventing one would be worse, so the tab now reports the
        // absence instead of querying an unsupported identifier.
        setTrajectoryData(null);
      })
      .finally(() => setTrajectoryLoading(false));

    setProcessTreeLoading(true);
    api.get(`/edr/process-tree?incident_id=${encodeURIComponent(caseId)}`)
      .then((res) => {
        setProcessTreeData(res.data);
      })
      .catch(() => setProcessTreeData(null))
      .finally(() => setProcessTreeLoading(false));

    setArtifactsLoading(true);
    api.get(`/v2/cases/${encodeURIComponent(caseId)}/artifacts?limit=500`)
      .then((res) => {
        setCaseArtifacts(res.data?.artifacts || []);
      })
      .catch(() => setCaseArtifacts([]))
      .finally(() => setArtifactsLoading(false));

    setSecurityStateLoading(true);
    api.get(`/v2/security-state/${encodeURIComponent(caseId)}?tenant_id=default`)
      .then((res) => {
        const states = res.data?.states || [];
        setSecurityStateData(states[0] || res.data);
      })
      .catch(() => setSecurityStateData(null))
      .finally(() => setSecurityStateLoading(false));
  }, [caseId, profile]);

  useEffect(() => {
    loadInvestigation();
  }, [loadInvestigation]);

  const h = inv?.header || {};
  const band = String(h.verdict_band || "benign").toLowerCase();
  const c = BAND_COLORS[band] || BAND_COLORS.suspicious;

  const laneBreakdown = useMemo(() => {
    const counts = { process: 0, network: 0, file: 0, registry: 0, system: 0 };
    if (trajectoryData?.frames && Array.isArray(trajectoryData.frames)) {
      for (const f of trajectoryData.frames) {
        const k = (f.lane || f.category || "system").toLowerCase();
        if (counts[k] !== undefined) counts[k]++;
        else counts.system++;
      }
    } else if (trajectoryData?.lane_counts) {
      Object.assign(counts, trajectoryData.lane_counts);
    }
    return counts;
  }, [trajectoryData]);

  // Authoritative Security State only — NEVER inferred or manufactured from verdict_band
  const authoritativeSecurityState = useMemo(() => {
    if (inv?.security_state) return inv.security_state;
    if (securityStateData?.state) return securityStateData.state;
    if (securityStateData?.attack_state) return securityStateData.attack_state;
    if (securityStateData?.current_state) return securityStateData.current_state;
    return null;
  }, [inv?.security_state, securityStateData]);

  // Authoritative Verdict Weights — only when real numeric weights exist
  const authoritativeWeights = useMemo(() => {
    const reasons = inv?.explainability?.positive?.reasons || [];
    const rows = inv?.verdict_stage2?.evidence_rows || [];
    let totalPositive = 0;
    let hasPositive = false;
    let totalNegative = 0;
    let hasNegative = false;

    for (const r of reasons) {
      if (typeof r.weight === "number" && r.weight !== 0) {
        if (r.weight > 0) {
          totalPositive += r.weight;
          hasPositive = true;
        } else {
          totalNegative += r.weight;
          hasNegative = true;
        }
      }
    }
    for (const row of rows) {
      if (typeof row.weight_contribution === "number" && row.weight_contribution !== 0) {
        if (row.weight_contribution > 0) {
          totalPositive += row.weight_contribution;
          hasPositive = true;
        } else {
          totalNegative += row.weight_contribution;
          hasNegative = true;
        }
      }
    }
    return {
      hasWeights: hasPositive || hasNegative,
      totalPositive,
      totalNegative,
    };
  }, [inv?.explainability?.positive?.reasons, inv?.verdict_stage2?.evidence_rows]);

  const mitreList = useMemo(() => {
    if (Array.isArray(inv?.mitre_techniques) && inv.mitre_techniques.length > 0) {
      return inv.mitre_techniques;
    }
    const list = [];
    const seen = new Set();
    (inv?.story?.steps || []).forEach((s) => {
      if (s.technique && !seen.has(s.technique)) {
        seen.add(s.technique);
        list.push({ tactic: s.stage || "Execution", tech: s.technique, name: s.summary || s.stage });
      }
    });
    return list;
  }, [inv?.mitre_techniques, inv?.story?.steps]);

  return (
    <XdrShell>
      <div
        data-testid="xdr-investigation-workspace-page"
        style={{
          display: "flex",
          flexDirection: "column",
          minHeight: "calc(100vh - 56px)",
          background: "var(--nx-surf-canvas)",
          color: "var(--nx-text)",
        }}
      >
        {/* Top Breadcrumb & Actions Bar */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "10px 24px",
            background: "var(--nx-surf-canvas)",
            borderBottom: "1px solid var(--nx-surf-inset)",
            fontSize: 12,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <Link
              to="/xdr/investigations"
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 4,
                color: "var(--nx-benign)",
                textDecoration: "none",
                fontWeight: 600,
              }}
            >
              <ChevronLeft size={14} /> All Investigations
            </Link>
            <span style={{ color: "var(--nx-bd-strong)" }}>/</span>
            <span style={{ fontFamily: "var(--mono, monospace)", fontWeight: 700, color: "var(--nx-text)" }}>
              {caseId}
            </span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, color: "var(--nx-muted)" }}>
              <span style={{ fontWeight: 700, letterSpacing: "0.05em" }}>PROFILE:</span>
              <select
                value={profile}
                onChange={(e) => setProfile(e.target.value)}
                style={{
                  background: "var(--nx-surf-primary)",
                  border: "1px solid var(--nx-bd-quiet)",
                  color: "var(--nx-text)",
                  fontSize: 11,
                  padding: "3px 8px",
                  borderRadius: 4,
                  outline: "none",
                }}
              >
                {PROFILES.map((p) => (
                  <option key={p.id} value={p.id}>{p.label}</option>
                ))}
              </select>
            </label>

            <button
              onClick={loadInvestigation}
              disabled={loading}
              title="Reload investigation graph"
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 5,
                padding: "4px 10px",
                borderRadius: 4,
                background: "var(--nx-surf-primary)",
                border: "1px solid var(--nx-bd-quiet)",
                color: "var(--nx-text)",
                fontSize: 11,
                cursor: "pointer",
              }}
            >
              <RefreshCw size={11} className={loading ? "spin" : ""} /> Refresh
            </button>
          </div>
        </div>

        {/* Persistent Causal Header */}
        <div
          style={{
            padding: "16px 24px",
            background: "var(--nx-surf-canvas)",
            borderBottom: "1px solid var(--nx-bd-quiet)",
            display: "flex",
            alignItems: "center",
            gap: 20,
            flexWrap: "wrap",
          }}
        >
          <div>
            <div style={{ fontSize: 10, fontWeight: 700, color: "var(--nx-muted)", letterSpacing: "0.08em" }}>CASE ID</div>
            <div style={{ fontSize: 16, fontWeight: 700, fontFamily: "var(--mono, monospace)", color: "var(--nx-text)" }}>
              {caseId}
            </div>
          </div>

          <div style={{ width: 1, height: 32, background: "var(--nx-bd-quiet)" }} />

          <div>
            <div style={{ fontSize: 10, fontWeight: 700, color: "var(--nx-muted)", letterSpacing: "0.08em" }}>VERDICT BAND</div>
            <div style={{ marginTop: 2 }}>
              <span
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  padding: "3px 8px",
                  borderRadius: 4,
                  fontSize: 11,
                  fontWeight: 700,
                  fontFamily: "var(--mono, monospace)",
                  color: c.fg,
                  background: c.bg,
                  border: `1px solid ${c.border}`,
                }}
              >
                <span style={{ width: 6, height: 6, borderRadius: "50%", background: c.fg }} />
                {band.toUpperCase()}
              </span>
            </div>
          </div>

          <div style={{ width: 1, height: 32, background: "var(--nx-bd-quiet)" }} />

          <div>
            <div style={{ fontSize: 10, fontWeight: 700, color: "var(--nx-muted)", letterSpacing: "0.08em" }}>DEVICE RISK</div>
            <div style={{ fontSize: 14, fontWeight: 700, fontFamily: "var(--mono, monospace)", color: "var(--nx-critical)" }}>
              {h.device_score ?? "—"} / 100
            </div>
          </div>

          <div>
            <div style={{ fontSize: 10, fontWeight: 700, color: "var(--nx-muted)", letterSpacing: "0.08em" }}>INCIDENT RISK</div>
            <div style={{ fontSize: 14, fontWeight: 700, fontFamily: "var(--mono, monospace)", color: "var(--nx-medium)" }}>
              {h.incident_score ?? "—"} / 100
            </div>
          </div>

          <div>
            <div style={{ fontSize: 10, fontWeight: 700, color: "var(--nx-muted)", letterSpacing: "0.08em" }}>CONFIDENCE</div>
            <div style={{ fontSize: 14, fontWeight: 700, fontFamily: "var(--mono, monospace)", color: "var(--nx-info)" }}>
              {h.confidence != null ? `${h.confidence}%` : "—"}
            </div>
          </div>

          <div style={{ width: 1, height: 32, background: "var(--nx-bd-quiet)" }} />

          <div>
            <div style={{ fontSize: 10, fontWeight: 700, color: "var(--nx-muted)", letterSpacing: "0.08em" }}>TELEMETRY</div>
            <div style={{ fontSize: 12, fontFamily: "var(--mono, monospace)", color: "var(--nx-text)" }}>
              <b>{h.event_count ?? 0}</b> events · <b>{h.process_count ?? 0}</b> procs
            </div>
          </div>

          <div>
            <div style={{ fontSize: 10, fontWeight: 700, color: "var(--nx-muted)", letterSpacing: "0.08em" }}>IKG GRAPH SIZE</div>
            <div style={{ fontSize: 12, fontFamily: "var(--mono, monospace)", color: "var(--nx-benign)" }}>
              <b>{inv?.ikg?.stats?.nodes ?? 0}</b> nodes · <b>{inv?.ikg?.stats?.edges ?? 0}</b> edges
            </div>
          </div>

          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
            <span
              style={{
                fontSize: 10,
                fontFamily: "var(--mono, monospace)",
                padding: "3px 8px",
                borderRadius: 4,
                background: "var(--nx-surf-primary)",
                border: "1px solid var(--nx-bd-quiet)",
                color: "var(--nx-muted)",
              }}
            >
              Verdict Engine v{inv?.engine_version?.verdict || "3.1b"}
            </span>
          </div>
        </div>

        {/* 8 Causal Investigation Tabs Strip */}
        <div
          data-testid="investigation-tab-strip"
          style={{
            display: "flex",
            alignItems: "center",
            padding: "0 20px",
            background: "var(--nx-surf-canvas)",
            borderBottom: "1px solid var(--nx-bd-quiet)",
            gap: 4,
            overflowX: "auto",
          }}
        >
          {[
            { key: "story",          label: "Attack Story",               icon: FileText },
            { key: "trajectory",     label: "Device Trajectory",          icon: Activity },
            { key: "process",        label: "Process Ancestry",           icon: GitBranch },
            { key: "graph",          label: "Evidence Graph (IKG)",       icon: Layers },
            { key: "security_state", label: "Security State & Causal FSM", icon: Shield },
            { key: "evidence",       label: "Extracted Artifacts & Hashes", icon: Database },
            { key: "verdict",        label: "Deterministic Verdict",      icon: CheckCircle2 },
            { key: "attack",         label: "MITRE ATT&CK",               icon: ShieldAlert },
          ].map((t) => {
            const active = activeTab === t.key;
            const Icon = t.icon;
            return (
              <button
                key={t.key}
                onClick={() => setTab(t.key)}
                data-testid={`tab-${t.key}`}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 6,
                  padding: "10px 14px",
                  background: active ? "var(--nx-surf-primary)" : "transparent",
                  color: active ? "var(--nx-benign)" : "var(--nx-muted)",
                  border: "none",
                  borderBottom: `2px solid ${active ? "var(--nx-benign)" : "transparent"}`,
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: "pointer",
                  whiteSpace: "nowrap",
                  transition: "all 0.15s",
                }}
              >
                <Icon size={13} color={active ? "var(--nx-benign)" : "var(--nx-muted)"} />
                {t.label}
              </button>
            );
          })}
        </div>

        {/* Tab Content Canvas */}
        <div style={{ flex: 1, padding: "20px 24px", overflowY: "auto" }}>
          {loading ? (
            <div style={{ padding: 60, textAlign: "center", color: "var(--nx-muted)" }}>
              <RefreshCw size={24} className="spin" style={{ margin: "0 auto 12px" }} />
              Reconstructing causal attack graph from IKG...
            </div>
          ) : error ? (
            <div style={{ padding: 40, textAlign: "center", color: "var(--nx-critical)" }}>
              <ShieldAlert size={24} style={{ margin: "0 auto 8px" }} />
              {error}
            </div>
          ) : (
            <>
              {/* TAB 1: ATTACK STORY */}
              {activeTab === "story" && (
                <div data-testid="tab-story-content" style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 20 }}>
                  <div style={{ background: "var(--nx-surf-canvas)", borderRadius: 6, border: "1px solid var(--nx-bd-quiet)", padding: 20 }}>
                    <h3 style={{ fontSize: 14, fontWeight: 700, margin: "0 0 12px", color: "var(--nx-benign)" }}>
                      Reconstructed Attack Progression Narrative
                    </h3>
                    <p style={{ fontSize: 13, lineHeight: 1.7, color: "var(--nx-text)", margin: "0 0 20px" }}>
                      {inv?.story?.narrative || "No causal attack narrative recorded for this incident."}
                    </p>

                    <h4 style={{ fontSize: 12, fontWeight: 700, color: "var(--nx-muted)", letterSpacing: "0.05em", textTransform: "uppercase", marginBottom: 12 }}>
                      Sequential Attack Milestones
                    </h4>
                    {(inv?.story?.steps || []).length > 0 ? (
                      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                        {inv.story.steps.map((step, idx) => (
                          <div
                            key={idx}
                            style={{
                              display: "flex",
                              gap: 14,
                              padding: "10px 14px",
                              borderRadius: 4,
                              background: "var(--nx-surf-primary)",
                              border: "1px solid var(--nx-bd-quiet)",
                            }}
                          >
                            <div style={{ width: 22, height: 22, borderRadius: "50%", background: "rgba(92,192,165,0.2)", color: "var(--nx-benign)", fontWeight: 700, fontSize: 11, display: "flex", alignItems: "center", justifyContent: "center" }}>
                              {idx + 1}
                            </div>
                            <div style={{ flex: 1 }}>
                              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                <span style={{ fontWeight: 700, fontSize: 12, color: "var(--nx-text)" }}>{step.stage}</span>
                                <span style={{ fontSize: 10.5, fontFamily: "var(--mono, monospace)", color: "var(--nx-info)" }}>{step.technique}</span>
                              </div>
                              <div style={{ fontSize: 12, color: "var(--nx-muted)", marginTop: 2 }}>{step.summary}</div>
                              {step.time && <div style={{ fontSize: 10, color: "var(--nx-faint)", marginTop: 4, fontFamily: "var(--mono, monospace)" }}>{step.time}</div>}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div data-testid="no-story-steps" style={{ padding: 24, textAlign: "center", color: "var(--nx-muted)", background: "var(--nx-surf-primary)", borderRadius: 4, border: "1px solid var(--nx-bd-quiet)", fontSize: 12 }}>
                        NO SEQUENTIAL ATTACK MILESTONES RECORDED FOR THIS INCIDENT
                      </div>
                    )}
                  </div>

                  <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                    <div style={{ background: "var(--nx-surf-canvas)", borderRadius: 6, border: "1px solid var(--nx-bd-quiet)", padding: 18 }}>
                      <h4 style={{ fontSize: 12, fontWeight: 700, color: "var(--nx-muted)", textTransform: "uppercase", margin: "0 0 10px" }}>
                        Causal Anchor Entities
                      </h4>
                      <div style={{ fontSize: 12, display: "flex", flexDirection: "column", gap: 8 }}>
                        <div style={{ display: "flex", justifyContent: "space-between" }}>
                          <span style={{ color: "var(--nx-muted)" }}>Patient Zero Host:</span>
                          <span style={{ fontFamily: "var(--mono, monospace)", fontWeight: 600 }}>
                            {inv?.patient_zero || inv?.header?.host || (inv?.ikg?.nodes?.find(n => n.type === 'host')?.label) || "None recorded"}
                          </span>
                        </div>
                        <div style={{ display: "flex", justifyContent: "space-between" }}>
                          <span style={{ color: "var(--nx-muted)" }}>Root Process:</span>
                          <span style={{ fontFamily: "var(--mono, monospace)", fontWeight: 600 }}>
                            {inv?.root_process || (inv?.ikg?.nodes?.find(n => n.type === 'process')?.label) || "None recorded"}
                          </span>
                        </div>
                        <div style={{ display: "flex", justifyContent: "space-between" }}>
                          <span style={{ color: "var(--nx-muted)" }}>Target Identity:</span>
                          <span style={{ fontFamily: "var(--mono, monospace)", fontWeight: 600 }}>
                            {inv?.target_identity || (inv?.ikg?.nodes?.find(n => n.type === 'user')?.label) || "None recorded"}
                          </span>
                        </div>
                        <div style={{ display: "flex", justifyContent: "space-between" }}>
                          <span style={{ color: "var(--nx-muted)" }}>Primary External C2:</span>
                          <span style={{ fontFamily: "var(--mono, monospace)", fontWeight: 600, color: "var(--nx-critical)" }}>
                            {inv?.c2_endpoints || (inv?.ikg?.nodes?.find(n => n.type === 'socket' || n.type === 'ip')?.label) || "None recorded"}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div style={{ background: "var(--nx-surf-canvas)", borderRadius: 6, border: "1px solid var(--nx-bd-quiet)", padding: 18 }}>
                      <h4 style={{ fontSize: 12, fontWeight: 700, color: "var(--nx-muted)", textTransform: "uppercase", margin: "0 0 10px" }}>
                        Active Containment Recommendations
                      </h4>
                      {inv?.containment ? (
                        <div style={{ padding: "10px 12px", borderRadius: 4, background: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.25)", fontSize: 12, color: "var(--nx-critical)" }}>
                          <b>Minimal Effective Containment:</b> {typeof inv.containment === "string" ? inv.containment : JSON.stringify(inv.containment)}
                        </div>
                      ) : (
                        <div style={{ padding: "12px 14px", borderRadius: 4, background: "var(--nx-surf-primary)", border: "1px solid var(--nx-bd-quiet)", fontSize: 12, color: "var(--nx-muted)" }}>
                          No automated containment recommendations generated for this incident.
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 2: DEVICE TRAJECTORY */}
              {activeTab === "trajectory" && (
                <div data-testid="tab-trajectory-content" style={{ background: "var(--nx-surf-canvas)", borderRadius: 6, border: "1px solid var(--nx-bd-quiet)", padding: 20 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
                    <div>
                      <h3 style={{ fontSize: 14, fontWeight: 700, margin: 0 }}>Device Chronological Trajectory</h3>
                      <p style={{ fontSize: 12, color: "var(--nx-muted)", margin: "4px 0 0" }}>
                        Replays endpoint event streams across 5 telemetry lanes (System, Process, File, Network, Registry).
                      </p>
                    </div>
                    <div style={{ display: "flex", gap: 6 }}>
                      {["timeline", "attack_path"].map((m) => (
                        <button
                          key={m}
                          onClick={() => setTrajView(m)}
                          style={{
                            padding: "4px 10px",
                            borderRadius: 4,
                            fontSize: 11,
                            fontWeight: 700,
                            cursor: "pointer",
                            background: trajView === m ? "var(--nx-benign)" : "var(--nx-surf-primary)",
                            color: trajView === m ? "var(--nx-surf-canvas)" : "var(--nx-muted)",
                            border: "1px solid var(--nx-bd-quiet)",
                            textTransform: "capitalize",
                          }}
                        >
                          {m === "timeline" ? "Chronological Timeline" : "Causal Attack Path"}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div style={{ display: "grid", gridTemplateColumns: "240px 1fr", gap: 16, minHeight: 340 }}>
                    <div style={{ background: "var(--nx-surf-primary)", borderRadius: 4, padding: 14, border: "1px solid var(--nx-bd-quiet)" }}>
                      <div style={{ fontSize: 11, fontWeight: 700, color: "var(--nx-muted)", textTransform: "uppercase", marginBottom: 8 }}>
                        Event Lane Breakdown
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 8, fontSize: 12 }}>
                        {[
                          { lane: "Process", count: laneBreakdown.process, icon: GitBranch, color: "var(--nx-benign)" },
                          { lane: "Network", count: laneBreakdown.network, icon: Wifi, color: "var(--nx-info)" },
                          { lane: "File", count: laneBreakdown.file, icon: FileText, color: "var(--nx-medium)" },
                          { lane: "Registry", count: laneBreakdown.registry, icon: Terminal, color: "var(--nx-purple)" },
                          { lane: "System", count: laneBreakdown.system, icon: Layers, color: "var(--nx-muted)" },
                        ].map((l) => (
                          <div key={l.lane} style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                            <span style={{ display: "flex", alignItems: "center", gap: 6, color: "var(--nx-text)" }}>
                              <l.icon size={12} color={l.color} /> {l.lane}
                            </span>
                            <b style={{ fontFamily: "var(--mono, monospace)", color: l.color }}>{l.count}</b>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div style={{ background: "var(--nx-surf-primary)", borderRadius: 4, padding: 16, border: "1px solid var(--nx-bd-quiet)", display: "flex", flexDirection: "column", gap: 10 }}>
                      <div style={{ fontSize: 11, fontWeight: 700, color: "var(--nx-muted)", textTransform: "uppercase" }}>
                        Timeline Sequence (Sorted by Timestamp)
                      </div>
                      {trajectoryLoading ? (
                        <div style={{ padding: 40, textAlign: "center", color: "var(--nx-muted)" }}>
                          <RefreshCw size={18} className="spin" style={{ margin: "0 auto 8px" }} />
                          Loading device trajectory events...
                        </div>
                      ) : (trajectoryData?.frames && trajectoryData.frames.length > 0) ? (
                        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                          {trajectoryData.frames.map((ev, i) => (
                            <div key={i} style={{ padding: "8px 12px", borderRadius: 4, background: "var(--nx-surf-canvas)", border: "1px solid var(--nx-bd-quiet)", fontSize: 12, display: "flex", gap: 12 }}>
                              <span style={{ fontFamily: "var(--mono, monospace)", color: "var(--nx-muted)", fontSize: 11 }}>
                                {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : (ev.time || "—")}
                              </span>
                              <span style={{ fontFamily: "var(--mono, monospace)", textTransform: "uppercase", fontSize: 10, fontWeight: 700, color: "var(--nx-benign)" }}>
                                [{ev.lane || ev.category || "event"}]
                              </span>
                              <span style={{ color: "var(--nx-text)" }}>
                                {ev.summary || ev.action || ev.event || ev.name || JSON.stringify(ev)}
                              </span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div data-testid="no-matching-trajectory" style={{ padding: 40, textAlign: "center", color: "var(--nx-muted)" }}>
                          <Activity size={24} style={{ margin: "0 auto 8px", opacity: 0.5 }} />
                          <div style={{ fontWeight: 700, fontSize: 13, color: "var(--nx-text)" }}>NO MATCHING TRAJECTORY EVIDENCE</div>
                          <div style={{ fontSize: 11.5, marginTop: 4 }}>No chronological device telemetry frames recorded for this case.</div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 3: PROCESS ANCESTRY */}
              {activeTab === "process" && (
                <div data-testid="tab-process-content" style={{ background: "var(--nx-surf-canvas)", borderRadius: 6, border: "1px solid var(--nx-bd-quiet)", padding: 20 }}>
                  <h3 style={{ fontSize: 14, fontWeight: 700, margin: "0 0 12px" }}>Process Execution Hierarchy</h3>
                  {processTreeLoading ? (
                    <div style={{ padding: 40, textAlign: "center", color: "var(--nx-muted)" }}>
                      <RefreshCw size={18} className="spin" style={{ margin: "0 auto 8px" }} />
                      Building process ancestry tree...
                    </div>
                  ) : (processTreeData?.nodes && processTreeData.nodes.length > 0) ? (
                    <div style={{ fontFamily: "var(--mono, monospace)", fontSize: 12, lineHeight: 1.8, background: "var(--nx-surf-primary)", padding: 18, borderRadius: 4, border: "1px solid var(--nx-bd-quiet)" }}>
                      {processTreeData.nodes.map((node, i) => (
                        <div key={node.entity_id || i} style={{ marginLeft: (node.parent_id ? 24 : 0), color: node.command_line ? "var(--nx-medium)" : "var(--nx-text)", display: "flex", gap: 8, alignItems: "center" }}>
                          <span>{node.parent_id ? "└─" : "●"}</span>
                          <span style={{ fontWeight: 700 }}>{node.process || node.name || "process"}</span>
                          <span style={{ color: "var(--nx-muted)" }}>(PID {node.pid || node.entity_id})</span>
                          {node.command_line && <span style={{ color: "var(--nx-benign)" }}>[{node.command_line}]</span>}
                          {node.user && <span style={{ color: "var(--nx-muted)", fontSize: 11 }}>— {node.user}</span>}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div data-testid="no-matching-process-tree" style={{ padding: 40, textAlign: "center", color: "var(--nx-muted)", background: "var(--nx-surf-primary)", borderRadius: 4, border: "1px solid var(--nx-bd-quiet)" }}>
                      <GitBranch size={24} style={{ margin: "0 auto 8px", opacity: 0.5 }} />
                      <div style={{ fontWeight: 700, fontSize: 13, color: "var(--nx-text)" }}>NO PROCESS ANCESTRY RECORDED</div>
                      <div style={{ fontSize: 11.5, marginTop: 4 }}>No process hierarchy or parent-child execution telemetry recorded for this incident.</div>
                    </div>
                  )}
                </div>
              )}

              {/* TAB 4: EVIDENCE GRAPH (IKG) */}
              {activeTab === "graph" && (
                <div data-testid="tab-graph-content" style={{ background: "var(--nx-surf-canvas)", borderRadius: 6, border: "1px solid var(--nx-bd-quiet)", padding: 20 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
                    <div>
                      <h3 style={{ fontSize: 14, fontWeight: 700, margin: 0 }}>Investigation Knowledge Graph (IKG)</h3>
                      <p style={{ fontSize: 12, color: "var(--nx-muted)", margin: "4px 0 0" }}>
                        Causal node-link representation linking host, user, process, socket, file, and MITRE technique entities.
                      </p>
                    </div>
                    <span style={{ fontSize: 11, color: "var(--nx-benign)", fontFamily: "var(--mono, monospace)" }}>
                      {inv?.ikg?.stats?.nodes || inv?.ikg?.nodes?.length || 0} Nodes · {inv?.ikg?.stats?.edges || inv?.ikg?.edges?.length || 0} Edges
                    </span>
                  </div>

                  {(inv?.ikg?.nodes && inv.ikg.nodes.length > 0) ? (
                    <div style={{ background: "var(--nx-surf-primary)", borderRadius: 4, border: "1px solid var(--nx-bd-quiet)", padding: 16 }}>
                      <div style={{ fontSize: 12, fontWeight: 700, color: "var(--nx-benign)", textTransform: "uppercase", marginBottom: 12 }}>
                        Active Knowledge Graph Entities ({inv.ikg.nodes.length})
                      </div>
                      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 10 }}>
                        {inv.ikg.nodes.map((node, i) => (
                          <div key={node.id || i} style={{ padding: "8px 12px", borderRadius: 4, background: "var(--nx-surf-canvas)", border: "1px solid var(--nx-bd-quiet)", fontSize: 12 }}>
                            <div style={{ color: "var(--nx-info)", fontWeight: 700, fontSize: 11, textTransform: "uppercase" }}>{node.type || "entity"}</div>
                            <div style={{ color: "var(--nx-text)", fontWeight: 600, marginTop: 2 }}>{node.label || node.name || node.id}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div data-testid="no-matching-ikg" style={{ height: 280, background: "var(--nx-surf-primary)", borderRadius: 4, border: "1px solid var(--nx-bd-quiet)", display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 8, color: "var(--nx-muted)" }}>
                      <Layers size={32} style={{ opacity: 0.5 }} />
                      <div style={{ fontWeight: 700, fontSize: 13, color: "var(--nx-text)" }}>NO IKG GRAPH NODES FOR THIS CASE</div>
                      <div style={{ fontSize: 11.5 }}>No graph entities or causal relationships have been generated.</div>
                    </div>
                  )}
                </div>
              )}

              {/* TAB 5: SECURITY STATE & CAUSAL FSM */}
              {activeTab === "security_state" && (
                <div data-testid="tab-security-state-content" style={{ background: "var(--nx-surf-canvas)", borderRadius: 6, border: "1px solid var(--nx-bd-quiet)", padding: 20 }}>
                  <h3 style={{ fontSize: 14, fontWeight: 700, margin: "0 0 12px" }}>Security State Computing & Causal Transition FSM</h3>
                  <p style={{ fontSize: 12.5, color: "var(--nx-muted)", margin: "0 0 20px" }}>
                    Enforces the fundamental semantic invariant: <code>AUTHORIZED → SUSPICIOUS → ABUSED → CONFIRMED_ATTACK</code>.
                    State transitions are validated against triggers and recorded in the cryptographically sealed ledger.
                  </p>

                  {securityStateLoading ? (
                    <div style={{ padding: 40, textAlign: "center", color: "var(--nx-muted)" }}>
                      <RefreshCw size={18} className="spin" style={{ margin: "0 auto 8px" }} />
                      Loading authoritative security state from causal ledger...
                    </div>
                  ) : authoritativeSecurityState ? (
                    <>
                      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 24 }}>
                        {[
                          { state: "AUTHORIZED_ADMIN", desc: "Standard administrative operation within trusted boundaries." },
                          { state: "SUSPICIOUS_UNMANAGED", desc: "Unusual parent process or off-hours execution." },
                          { state: "ABUSED_CAPABILITY", desc: "Dual-use tool repurposed for intrusion." },
                          { state: "CONFIRMED_ATTACK", desc: "C2 established and active credential access observed." },
                        ].map((s) => {
                          const isCur = s.state === authoritativeSecurityState;
                          return (
                            <div
                              key={s.state}
                              style={{
                                padding: 14,
                                borderRadius: 4,
                                background: isCur ? "rgba(248, 113, 113, 0.12)" : "var(--nx-surf-primary)",
                                border: `1px solid ${isCur ? "var(--nx-critical)" : "var(--nx-bd-quiet)"}`,
                              }}
                            >
                              <div style={{ fontSize: 11, fontWeight: 700, fontFamily: "var(--mono, monospace)", color: isCur ? "var(--nx-critical)" : "var(--nx-muted)" }}>
                                {s.state} {isCur && "● CURRENT"}
                              </div>
                              <div style={{ fontSize: 11.5, color: "var(--nx-text)", marginTop: 6 }}>{s.desc}</div>
                            </div>
                          );
                        })}
                      </div>
                      <div style={{ padding: "10px 14px", borderRadius: 4, background: "var(--nx-surf-primary)", border: "1px solid var(--nx-bd-quiet)", fontSize: 12, color: "var(--nx-muted)" }}>
                        <b>Causal State Transition Ledger:</b> Authoritative security state evaluated as <b style={{ color: "var(--nx-benign)" }}>{authoritativeSecurityState}</b>{securityStateData?.version ? ` (Version ${securityStateData.version})` : ""}.
                      </div>
                    </>
                  ) : (
                    <div data-testid="no-authoritative-security-state" style={{ padding: 48, textAlign: "center", color: "var(--nx-muted)", background: "var(--nx-surf-primary)", borderRadius: 4, border: "1px solid var(--nx-bd-quiet)" }}>
                      <Shield size={28} style={{ margin: "0 auto 10px", opacity: 0.5 }} />
                      <div style={{ fontWeight: 700, fontSize: 13, color: "var(--nx-text)" }}>NO AUTHORITATIVE SECURITY STATE RECORDED</div>
                      <div style={{ fontSize: 11.5, marginTop: 4 }}>
                        No formal Security State FSM evaluation or causal state transition has been cryptographically sealed for this incident.
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* TAB 6: EXTRACTED ARTIFACTS & EVIDENCE */}
              {activeTab === "evidence" && (
                <div data-testid="tab-evidence-content" style={{ background: "var(--nx-surf-canvas)", borderRadius: 6, border: "1px solid var(--nx-bd-quiet)", padding: 20 }}>
                  <h3 style={{ fontSize: 14, fontWeight: 700, margin: "0 0 12px" }}>Extracted Evidence & Hash Chains</h3>
                  <p style={{ fontSize: 12.5, color: "var(--nx-muted)", margin: "0 0 16px" }}>
                    Intermediate payload retention up to 64KB per decoding stage with SHA-256 verification.
                  </p>

                  {artifactsLoading ? (
                    <div style={{ padding: 40, textAlign: "center", color: "var(--nx-muted)" }}>
                      <RefreshCw size={18} className="spin" style={{ margin: "0 auto 8px" }} />
                      Loading extracted artifacts...
                    </div>
                  ) : caseArtifacts.length > 0 ? (
                    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, textAlign: "left" }}>
                      <thead>
                        <tr style={{ borderBottom: "1px solid var(--nx-bd-quiet)", color: "var(--nx-faint)", fontSize: 11, textTransform: "uppercase" }}>
                          <th style={{ padding: "8px 12px" }}>Artifact / Stage</th>
                          <th style={{ padding: "8px 12px" }}>Type</th>
                          <th style={{ padding: "8px 12px" }}>SHA-256 Hash</th>
                          <th style={{ padding: "8px 12px" }}>Decoded Output Preview</th>
                          <th style={{ padding: "8px 12px" }}>Stop Reason</th>
                        </tr>
                      </thead>
                      <tbody>
                        {caseArtifacts.map((row, i) => (
                          <tr key={i} style={{ borderBottom: "1px solid var(--nx-surf-primary)" }}>
                            <td style={{ padding: "10px 12px", fontWeight: 600, color: "var(--nx-text)" }}>{row.stage || row.name || `Artifact ${i + 1}`}</td>
                            <td style={{ padding: "10px 12px", color: "var(--nx-info)", fontFamily: "var(--mono, monospace)" }}>{row.type || row.category || "artifact"}</td>
                            <td style={{ padding: "10px 12px", color: "var(--nx-muted)", fontFamily: "var(--mono, monospace)" }}>{row.sha256 || row.hash || "—"}</td>
                            <td style={{ padding: "10px 12px", color: "var(--nx-benign)", fontFamily: "var(--mono, monospace)" }}>{row.preview || row.decoded || "—"}</td>
                            <td style={{ padding: "10px 12px", color: "var(--nx-faint)" }}>{row.stop_reason || row.stop || "verified"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <div data-testid="no-matching-artifacts" style={{ padding: 40, textAlign: "center", color: "var(--nx-muted)" }}>
                      <Database size={24} style={{ margin: "0 auto 8px", opacity: 0.5 }} />
                      <div style={{ fontWeight: 700, fontSize: 13, color: "var(--nx-text)" }}>NO EXTRACTED ARTIFACTS RECORDED</div>
                      <div style={{ fontSize: 11.5, marginTop: 4 }}>No multi-stage decode artifacts or intermediate hashes recorded for this case.</div>
                    </div>
                  )}
                </div>
              )}

              {/* TAB 7: DETERMINISTIC VERDICT */}
              {activeTab === "verdict" && (
                <div data-testid="tab-verdict-content" style={{ background: "var(--nx-surf-canvas)", borderRadius: 6, border: "1px solid var(--nx-bd-quiet)", padding: 20 }}>
                  <h3 style={{ fontSize: 14, fontWeight: 700, margin: "0 0 12px" }}>Deterministic Verdict Engine Breakdown</h3>
                  <p style={{ fontSize: 12.5, color: "var(--nx-muted)", margin: "0 0 16px" }}>
                    The verdict is computed deterministically from canonical evidence and evaluated against explainability patterns.
                  </p>
                  <div style={{ background: "var(--nx-surf-primary)", borderRadius: 4, padding: 16, border: "1px solid var(--nx-bd-quiet)", fontSize: 12.5 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                      <span style={{ color: "var(--nx-muted)" }}>Deterministic Verdict:</span>
                      <b style={{ color: c.fg }}>{band.toUpperCase()}</b>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                      <span style={{ color: "var(--nx-muted)" }}>Risk Score:</span>
                      <span style={{ fontFamily: "var(--mono, monospace)", color: "var(--nx-critical)" }}>
                        {h.incident_score ?? h.device_score != null ? `${h.incident_score ?? h.device_score} / 100` : "Not recorded"}
                      </span>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                      <span style={{ color: "var(--nx-muted)" }}>Confidence Rating:</span>
                      <span style={{ fontFamily: "var(--mono, monospace)", color: "var(--nx-info)" }}>
                        {h.confidence != null ? `${h.confidence}%` : "Not recorded"}
                      </span>
                    </div>
                    {authoritativeWeights.hasWeights ? (
                      <>
                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                          <span style={{ color: "var(--nx-muted)" }}>Authoritative Evidence Weight:</span>
                          <span style={{ fontFamily: "var(--mono, monospace)", color: "var(--nx-benign)" }}>
                            +{authoritativeWeights.totalPositive} points
                          </span>
                        </div>
                        {authoritativeWeights.totalNegative !== 0 && (
                          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                            <span style={{ color: "var(--nx-muted)" }}>Authoritative Negative Offset:</span>
                            <span style={{ fontFamily: "var(--mono, monospace)", color: "var(--nx-info)" }}>
                              {authoritativeWeights.totalNegative} points
                            </span>
                          </div>
                        )}
                      </>
                    ) : (
                      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                        <span style={{ color: "var(--nx-muted)" }}>Contributing Evidence Signals:</span>
                        <span style={{ fontFamily: "var(--mono, monospace)", color: "var(--nx-benign)" }}>
                          {(inv?.explainability?.positive?.reasons || []).length || h.event_count || 0} signals observed
                        </span>
                      </div>
                    )}
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--nx-muted)" }}>Negative Pattern Coverage:</span>
                      <span style={{ fontFamily: "var(--mono, monospace)", color: "var(--nx-info)" }}>
                        {(inv?.explainability?.negative_patterns || []).length} patterns evaluated
                      </span>
                    </div>
                  </div>

                  {(inv?.explainability?.positive?.reasons || []).length > 0 ? (
                    <div style={{ marginTop: 16 }}>
                      <h4 style={{ fontSize: 12, fontWeight: 700, color: "var(--nx-muted)", textTransform: "uppercase", marginBottom: 8 }}>
                        Authoritative Evidence Breakdown
                      </h4>
                      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                        {inv.explainability.positive.reasons.map((r, i) => (
                          <div key={i} style={{ padding: "8px 12px", borderRadius: 4, background: "var(--nx-surf-primary)", border: "1px solid var(--nx-bd-quiet)", fontSize: 12, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                            <div>
                              <span style={{ padding: "2px 6px", borderRadius: 3, background: "rgba(92, 192, 165, 0.15)", color: "var(--nx-benign)", fontSize: 10, fontWeight: 700, fontFamily: "var(--mono, monospace)", marginRight: 8 }}>
                                {(r.kind || "evidence").toUpperCase()}
                              </span>
                              <span style={{ color: "var(--nx-text)" }}>{r.text}</span>
                              {r.detail && <span style={{ color: "var(--nx-muted)", fontSize: 11, marginLeft: 6 }}>— {r.detail}</span>}
                            </div>
                            {typeof r.weight === "number" && r.weight !== 0 && (
                              <span style={{ fontFamily: "var(--mono, monospace)", fontWeight: 700, color: r.weight > 0 ? "var(--nx-benign)" : "var(--nx-info)", fontSize: 11 }}>
                                {r.weight > 0 ? `+${r.weight}` : r.weight}
                              </span>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div style={{ color: "var(--nx-muted)", marginTop: 12, fontSize: 12 }}>
                      No detailed evidence signals or explanation breakdown attached to this verdict.
                    </div>
                  )}
                </div>
              )}

              {/* TAB 8: MITRE ATT&CK */}
              {activeTab === "attack" && (
                <div data-testid="tab-attack-content" style={{ background: "var(--nx-surf-canvas)", borderRadius: 6, border: "1px solid var(--nx-bd-quiet)", padding: 20 }}>
                  <h3 style={{ fontSize: 14, fontWeight: 700, margin: "0 0 12px" }}>Observed MITRE ATT&CK Matrix Crosswalk</h3>
                  {mitreList.length > 0 ? (
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12 }}>
                      {mitreList.map((m, idx) => (
                        <div key={m.tech || idx} style={{ padding: 12, borderRadius: 4, background: "var(--nx-surf-primary)", border: "1px solid var(--nx-bd-quiet)" }}>
                          <div style={{ fontSize: 10.5, fontWeight: 700, color: "var(--nx-benign)", textTransform: "uppercase" }}>{m.tactic || "Technique"}</div>
                          <div style={{ fontSize: 12, fontWeight: 700, color: "var(--nx-text)", marginTop: 4 }}>{m.tech || m.id}</div>
                          <div style={{ fontSize: 11, color: "var(--nx-muted)", marginTop: 2 }}>{m.name || m.label || m.summary}</div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div data-testid="no-matching-mitre" style={{ padding: 40, textAlign: "center", color: "var(--nx-muted)" }}>
                      <ShieldAlert size={24} style={{ margin: "0 auto 8px", opacity: 0.5 }} />
                      <div style={{ fontWeight: 700, fontSize: 13, color: "var(--nx-text)" }}>NO OBSERVED MITRE ATT&CK TECHNIQUES</div>
                      <div style={{ fontSize: 11.5, marginTop: 4 }}>No MITRE ATT&CK techniques mapped to the events in this case.</div>
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>

        {/* Global Collapsible Explainability Bottom Rail */}
        <div
          data-testid="global-explainability-panel"
          style={{
            background: "var(--nx-surf-canvas)",
            borderTop: "1px solid var(--nx-bd-quiet)",
            marginTop: "auto",
          }}
        >
          <button
            onClick={() => setExplainOpen(!explainOpen)}
            data-testid="toggle-explainability-btn"
            style={{
              width: "100%",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              padding: "10px 24px",
              background: "transparent",
              border: "none",
              color: "var(--nx-text)",
              fontSize: 12,
              fontWeight: 700,
              cursor: "pointer",
            }}
          >
            <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <HelpCircle size={14} color="var(--nx-benign)" />
              DETERMINISTIC EXPLAINABILITY ENGINE (POSITIVE + NEGATIVE REASONING)
            </span>
            {explainOpen ? <ChevronDown size={14} /> : <ChevronUp size={14} />}
          </button>

          {explainOpen && (
            <div style={{ padding: "12px 24px 20px", borderTop: "1px solid var(--nx-surf-primary)", fontSize: 12 }}>
              <div style={{ display: "flex", gap: 8, marginBottom: 14, flexWrap: "wrap" }}>
                <button
                  onClick={() => setExplainQuestion("positive")}
                  style={{
                    padding: "4px 10px",
                    borderRadius: 4,
                    fontSize: 11,
                    fontWeight: 700,
                    cursor: "pointer",
                    background: explainQuestion === "positive" ? "var(--nx-benign)" : "var(--nx-surf-primary)",
                    color: explainQuestion === "positive" ? "var(--nx-surf-canvas)" : "var(--nx-muted)",
                    border: "1px solid var(--nx-bd-quiet)",
                  }}
                >
                  Why is this {band.toUpperCase()}?
                </button>
                {(inv?.explainability?.negative_patterns || []).map((pat) => (
                  <button
                    key={pat.id}
                    onClick={() => setExplainQuestion(pat.id)}
                    style={{
                      padding: "4px 10px",
                      borderRadius: 4,
                      fontSize: 11,
                      fontWeight: 700,
                      cursor: "pointer",
                      background: explainQuestion === pat.id ? "var(--nx-benign)" : "var(--nx-surf-primary)",
                      color: explainQuestion === pat.id ? "var(--nx-surf-canvas)" : "var(--nx-muted)",
                      border: "1px solid var(--nx-bd-quiet)",
                    }}
                  >
                    Why isn't this {pat.label}?
                  </button>
                ))}
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {(inv?.explainability?.positive?.reasons || []).length > 0 ? (
                  (inv?.explainability?.positive?.reasons || []).map((r, i) => (
                    <div key={i} style={{ display: "flex", alignItems: "baseline", gap: 10, fontSize: 12 }}>
                      <span style={{ padding: "2px 6px", borderRadius: 3, background: "rgba(74, 222, 128, 0.15)", color: "var(--nx-benign)", fontSize: 10, fontWeight: 700, fontFamily: "var(--mono, monospace)" }}>
                        {(r.kind || "reason").toUpperCase()}
                      </span>
                      <span style={{ color: "var(--nx-text)" }}>{r.text}</span>
                      {r.detail && <span style={{ color: "var(--nx-muted)", fontSize: 11 }}>— {r.detail}</span>}
                    </div>
                  ))
                ) : (
                  <div style={{ color: "var(--nx-muted)", padding: "8px 0" }}>No explainability reasons recorded for this verdict.</div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </XdrShell>
  );
}
