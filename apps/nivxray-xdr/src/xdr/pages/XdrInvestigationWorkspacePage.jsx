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
import { NxDataTable, NxState, NxTabs, NxToken } from "@/xdr/nx";
import api from "@/lib/api";
import { activeTenant } from "@/lib/tenant";

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

/**
 * B2-INV · this surface is now a CAPABILITY PROVIDER as well as a page.
 *
 * `embedded` + `capabilities` render ONLY the requested engine panels with
 * no chrome, so the unified analyst workspace (`/xdr/incidents/:id`) can
 * mount Device Trajectory under Timeline, Process Ancestry under Attack
 * Story, the IKG under Entities, artifacts under Evidence and the
 * deterministic verdict / causal FSM under Overview — without a second
 * investigation experience and without reimplementing an engine.
 */
/**
 * The investigation tab vocabulary.
 *
 * NOTE for the next wave: the owner's target set is
 * Overview | Attack Story | Timeline | Evidence | Entities | Detections |
 * MITRE | Response | Activity | Report. The tabs below are the ones this
 * build can actually populate from real case data; the missing ones are
 * tracked in the migration register rather than added as empty shells,
 * because an empty tab claims a capability the platform does not have.
 */
const WORKSPACE_TABS = [
  { key: "story",          label: "Attack Story" },
  { key: "trajectory",     label: "Device Trajectory" },
  { key: "process",        label: "Process Ancestry" },
  { key: "graph",          label: "Evidence Graph" },
  { key: "security_state", label: "Security State" },
  { key: "evidence",       label: "Evidence" },
  { key: "verdict",        label: "Verdict" },
  { key: "attack",         label: "MITRE ATT&CK" },
];

export default function XdrInvestigationWorkspacePage(
  { caseId: caseIdProp = null, capabilities = null, embedded = false } = {}) {
  const { caseId: caseIdParam } = useParams();
  const caseId = caseIdProp || caseIdParam;
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  const activeTab = searchParams.get("tab") || "story";
  /** One gate: a tab when standalone, a requested capability when embedded. */
  const show = (key) => (embedded
    ? (capabilities || []).includes(key)
    : activeTab === key);
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

    // B7 Option A · this named the literal `default`, so the panel read a
    // tenancy the operator had not selected. The tenant is now the operator's
    // ACTIVE selection and there is no fallback: with nothing selected the
    // panel reports the absence rather than querying a tenant it invented.
    const tenantId = activeTenant();
    if (!tenantId) {
      setSecurityStateData(null);
      setSecurityStateLoading(false);
    } else {
      setSecurityStateLoading(true);
      api.get(`/v2/security-state/${encodeURIComponent(caseId)}`
              + `?tenant_id=${encodeURIComponent(tenantId)}`)
        .then((res) => {
          const states = res.data?.states || [];
          setSecurityStateData(states[0] || res.data);
        })
        .catch(() => setSecurityStateData(null))
        .finally(() => setSecurityStateLoading(false));
    }
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

  const Wrapper = embedded ? React.Fragment : XdrShell;
  return (
    <Wrapper>
      <div
        data-testid={embedded
          ? `investigation-engine-${(capabilities || []).join("-")}`
          : "xdr-investigation-workspace-page"}
        style={embedded ? { color: "var(--nx-text)" } : {
          display: "flex",
          flexDirection: "column",
          minHeight: "calc(100vh - 56px)",
          background: "var(--nx-surf-canvas)",
          color: "var(--nx-text)",
        }}
      >
        {!embedded && (<>
        {/* Top Breadcrumb & Actions Bar */}
        {/* One tab rail for the whole product. The hand-rolled rail that
            used to live here carried its own colours, spacing, active
            treatment and focus behaviour — a second tab system inside
            NivXRay XDR. Tab KEYS and `data-testid`s are unchanged. */}
        <NxTabs tabs={WORKSPACE_TABS} active={activeTab} onChange={setTab}
                testid="investigation-workspace-tabs" />

        </>)}

        {/* Tab Content Canvas */}
        <div style={embedded
              ? { padding: 0 }
              : { flex: 1, padding: "20px 24px", overflowY: "auto" }}>
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
              {show("story") && (
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
              {show("trajectory") && (
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
              {show("process") && (
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
              {show("graph") && (
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
              {show("security_state") && (
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
              {show("evidence") && (
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
                  ) : (
                    <NxDataTable rows={caseArtifacts} pageSize={25}
                                 rowKey={(r, i) => r.sha256 || r.hash
                                   || `${r.stage || r.name}-${i}`}
                                 searchPlaceholder="Search artifact, hash, decoder"
                                 testid="case-artifacts-table"
                                 emptyTitle="No extracted artifact is recorded"
                                 emptyHint="No multi-stage decode artifact or
                                            intermediate hash was recorded for
                                            this case — that is a statement
                                            about this case, not a decoder
                                            failure"
                                 columns={[
                      { key: "stage", header: "Artifact / stage", width: "220px",
                        value: (r) => r.stage || r.name || "",
                        render: (r) => (
                          <strong>{r.stage || r.name || "Artifact"}</strong>) },
                      { key: "type", header: "Type", width: "150px",
                        value: (r) => r.type || r.category || "artifact",
                        render: (r) => (
                          <NxToken>{r.type || r.category || "artifact"}</NxToken>) },
                      { key: "hash", header: "SHA-256", width: "230px",
                        value: (r) => r.sha256 || r.hash || "",
                        render: (r) => ((r.sha256 || r.hash)
                          ? <span className="nx-mono">{r.sha256 || r.hash}</span>
                          : <span className="nx-absent">—</span>) },
                      { key: "decoded", header: "Decoded output",
                        value: (r) => r.preview || r.decoded || "",
                        render: (r) => ((r.preview || r.decoded)
                          ? <span className="nx-mono">
                              {r.preview || r.decoded}
                            </span>
                          : <span className="nx-absent">—</span>) },
                      { key: "stop_reason", header: "Stop reason", width: "170px",
                        value: (r) => r.stop_reason || r.stop || "",
                        render: (r) => (r.stop_reason || r.stop
                          ? <NxState value={r.stop_reason || r.stop} />
                          : <span className="nx-absent">—</span>) },
                    ]} />
                  )}
                </div>
              )}

              {/* TAB 7: DETERMINISTIC VERDICT */}
              {show("verdict") && (
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
              {show("attack") && (
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
    </Wrapper>
  );
}
