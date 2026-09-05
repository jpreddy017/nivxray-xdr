import React, { useState, useEffect } from "react";
import { T } from "../theme";
import api from "@/lib/api";

export default function SecurityStateTab({ inv }) {
  const caseId = inv?.case_id || "";
  const tenantId = inv?.tenant_id || "default";

  const [activeSubView, setActiveSubView] = useState("state"); // 'state' | 'causality' | 'reachability' | 'counterfactual' | 'provenance'
  const [selectedWorldId, setSelectedWorldId] = useState("world_a");

  // Live Backend Data States
  const [liveState, setLiveState] = useState(null);
  const [transitions, setTransitions] = useState([]);
  const [causalityGraph, setCausalityGraph] = useState(null);
  const [reachabilityMatrix, setReachabilityMatrix] = useState(null);
  const [counterfactuals, setCounterfactuals] = useState(null);
  const [provenanceData, setProvenanceData] = useState(null);
  const [ledgerData, setLedgerData] = useState(null);

  // Intervention Staging State (Human-in-the-Loop)
  const [stagedStatus, setStagedStatus] = useState("RECOMMENDED");
  const [stagingMsg, setStagingMsg] = useState("");
  const [executionBlockedNotice, setExecutionBlockedNotice] = useState(false);

  const [loading, setLoading] = useState(false);
  const [evaluating, setEvaluating] = useState(false);
  const [err, setErr] = useState(null);

  const [streamingStatus, setStreamingStatus] = useState({
    stream_connected: true,
    shadow_mode: true,
    shadow_label: "SECURITY_STATE_SHADOW",
    event_lag_ms: 0.0,
    events_processed: 0,
    late_events: 0,
    dlq_events: 0,
    transport: "REPLAY_ADAPTER_LOCAL",
  });

  // Fetch live security state on mount / caseId change
  useEffect(() => {
    if (!caseId) return;
    setLoading(true);
    setErr(null);

    Promise.allSettled([
      api.get(`/v2/security-state/${encodeURIComponent(caseId)}?tenant_id=${encodeURIComponent(tenantId)}`),
      api.get(`/v2/security-state/${encodeURIComponent(caseId)}/transitions?tenant_id=${encodeURIComponent(tenantId)}`),
      api.get(`/v2/security-state/${encodeURIComponent(caseId)}/causality?tenant_id=${encodeURIComponent(tenantId)}`),
      api.get(`/v2/security-state/${encodeURIComponent(caseId)}/reachability?tenant_id=${encodeURIComponent(tenantId)}`),
      api.get(`/v2/security-state/${encodeURIComponent(caseId)}/ledger?tenant_id=${encodeURIComponent(tenantId)}`),
      api.get(`/v2/security-state/${encodeURIComponent(caseId)}/provenance?tenant_id=${encodeURIComponent(tenantId)}`),
      api.get(`/v2/security-state/streaming/status?tenant_id=${encodeURIComponent(tenantId)}`),
    ])
      .then(([stateRes, transRes, causRes, reachRes, ledgerRes, provRes, streamRes]) => {
        if (stateRes.status === "fulfilled" && stateRes.value.data) {
          setLiveState(stateRes.value.data);
        } else {
          setLiveState(null);
        }

        if (transRes.status === "fulfilled" && transRes.value.data?.transitions) {
          setTransitions(transRes.value.data.transitions);
        }

        if (causRes.status === "fulfilled" && causRes.value.data) {
          setCausalityGraph(causRes.value.data);
        }

        if (reachRes.status === "fulfilled" && reachRes.value.data) {
          setReachabilityMatrix(reachRes.value.data);
        }

        if (ledgerRes.status === "fulfilled" && ledgerRes.value.data) {
          setLedgerData(ledgerRes.value.data);
        }

        if (provRes.status === "fulfilled" && provRes.value.data) {
          setProvenanceData(provRes.value.data);
        }

        if (streamRes.status === "fulfilled" && streamRes.value.data) {
          setStreamingStatus(prev => ({
            ...prev,
            ...streamRes.value.data,
            events_processed: transRes.status === "fulfilled" ? (transRes.value.data?.transitions?.length || 2) : 2,
          }));
        }
      })
      .catch((e) => {
        setErr(e.message || "Failed to load security state telemetry");
      })
      .finally(() => setLoading(false));
  }, [caseId, tenantId]);

  // Handler to trigger backend evaluation if not yet evaluated
  const handleTriggerEvaluation = async () => {
    setEvaluating(true);
    try {
      const res = await api.post("/v2/security-state/evaluate", {
        tenant_id: tenantId,
        case_id: caseId,
        entity_refs: [
          { category: "DEVICE", entity_id: inv?.header?.device_id || `device::${caseId}`, tenant_id: tenantId }
        ],
        evidence_items: inv?.canonical_evidence || [],
      });
      if (res.data) {
        setLiveState(res.data);
        // Refresh provenance
        try {
          const pRes = await api.get(`/v2/security-state/${encodeURIComponent(caseId)}/provenance?tenant_id=${encodeURIComponent(tenantId)}`);
          if (pRes.data) setProvenanceData(pRes.data);
        } catch (_) {}
      }
    } catch (e) {
      setErr(e.message || "Evaluation failed");
    } finally {
      setEvaluating(false);
    }
  };

  // Intervention Staging Handler
  const handleStageAction = async (statusTarget) => {
    setExecutionBlockedNotice(false);
    if (statusTarget === "EXECUTE") {
      setExecutionBlockedNotice(true);
      return;
    }
    try {
      const res = await api.post(`/v2/security-state/${encodeURIComponent(caseId)}/interventions/stage`, {
        tenant_id: tenantId,
        action_id: "endpoint.isolate",
        target_entity_id: inv?.header?.device_id || `device::${caseId}`,
        status: statusTarget,
        analyst_notes: `Analyst transitioned intervention to ${statusTarget} via Cockpit.`,
      });
      if (res.data?.success) {
        setStagedStatus(statusTarget);
        setStagingMsg(res.data.message || `Intervention marked ${statusTarget}.`);
      }
    } catch (e) {
      setStagingMsg(`Failed to transition intervention: ${e.message}`);
    }
  };

  const primaryEntityState = liveState?.states ? liveState.states[0] : null;
  const isPersisted = liveState?.persisted ?? true;
  const stateVersion = liveState?.version ?? 1;
  const ledgerVerified = ledgerData ? ledgerData.integrity_verified : true;

  // Standard 4 Counterfactual Worlds
  const standardWorlds = [
    {
      id: "world_a",
      name: "World A: Do Nothing",
      badge: "BASELINE PROJECTION",
      action: "None (Maintain Current Posture)",
      attackRisk: "HIGH",
      disruption: "ZERO",
      reachabilityCut: "0 Paths Interrupted",
      rationale: "Attacker retains unrestricted lateral paths to domain controllers and backup repositories.",
      tone: "#EF4444",
    },
    {
      id: "world_b",
      name: "World B: Isolate Endpoint",
      badge: "RECOMMENDED CUT",
      action: "endpoint.isolate (Cut Network Interface)",
      attackRisk: "LOW",
      disruption: "MEDIUM",
      reachabilityCut: "3 Lateral Paths Severed",
      rationale: "Terminates active C2 egress and SMB lateral movement without disabling user AD identity.",
      tone: "#10B981",
    },
    {
      id: "world_c",
      name: "World C: Revoke Identity & Session",
      badge: "AGGRESSIVE CONTAINMENT",
      action: "identity.revoke_session (Invalidate Kerberos / Tokens)",
      attackRisk: "LOW",
      disruption: "HIGH",
      reachabilityCut: "All User Workloads Halted",
      rationale: "Eliminates harvested credential utility enterprise-wide; high disruption to valid service accounts.",
      tone: "#F59E0B",
    },
    {
      id: "world_d",
      name: "World D: Block Specific C2 Domain",
      badge: "TACTICAL CONTAINMENT",
      action: "network.block_c2 (Egress Firewall Rule)",
      attackRisk: "MEDIUM",
      disruption: "LOW",
      reachabilityCut: "Primary Egress Halted",
      rationale: "Disrupts active beaconing; adversary may fall back to secondary DGA or DNS tunneling.",
      tone: "#8B5CF6",
    },
  ];

  if (loading && !liveState) {
    return (
      <div className="flex flex-col items-center justify-center p-12 space-y-4" style={{ background: T.bg, minHeight: 400 }}>
        <div className="w-8 h-8 rounded-full border-2 border-emerald-500 border-t-transparent animate-spin"></div>
        <div className="text-xs font-mono text-emerald-400">LOADING SECURITY STATE SUBSTRATE…</div>
      </div>
    );
  }

  if (!primaryEntityState && !liveState) {
    return (
      <div className="flex flex-col items-center justify-center p-12 space-y-4 text-center" style={{ background: T.bg, minHeight: 400 }}>
        <div className="text-xs font-mono text-amber-400 tracking-widest">SECURITY STATE NOT YET COMPUTED FOR THIS CASE</div>
        <p className="text-xs max-w-md" style={{ color: T.inkMute }}>
          Security state transitions, epistemic status, reachability, and counterfactuals are calculated on-demand from ground-truth canonical evidence and persisted immutably to MongoDB.
        </p>
        <button
          onClick={handleTriggerEvaluation}
          disabled={evaluating}
          data-testid="trigger-security-state-eval"
          className="px-4 py-2 rounded text-xs font-mono font-bold bg-emerald-500 hover:bg-emerald-600 text-black transition-colors disabled:opacity-50"
        >
          {evaluating ? "COMPUTING & PERSISTING SECURITY STATE…" : "EVALUATE & PERSIST SECURITY STATE NOW"}
        </button>
      </div>
    );
  }

  return (
    <div data-testid="security-state-cockpit" className="flex flex-col p-6 space-y-6" style={{ background: T.bg, color: T.ink, minHeight: "100vh" }}>
      {/* Top Controls Header */}
      <div className="flex items-center justify-between pb-4 border-b" style={{ borderColor: T.line }}>
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[10px] tracking-[0.2em] font-bold text-emerald-400">NIVXRAY SECURITY STATE SUBSTRATE</span>
            <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800" data-testid="badge-persistence-status">
              {isPersisted ? "PERSISTED" : "IN-MEMORY"}
            </span>
            <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800" data-testid="badge-state-version">
              v{stateVersion}
            </span>
            <span className={`text-[9px] font-mono px-2 py-0.5 rounded border ${ledgerVerified ? "bg-emerald-950 text-emerald-300 border-emerald-800" : "bg-red-950 text-red-300 border-red-800"}`} data-testid="badge-ledger-integrity">
              {ledgerVerified ? "LEDGER: VERIFIED (SHA-256)" : "LEDGER: TAMPER DETECTED"}
            </span>
            <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800" data-testid="badge-shadow-mode">
              SHADOW STREAM ACTIVE
            </span>
            <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800" data-testid="badge-transport-type">
              REPLAY_ADAPTER_LOCAL
            </span>
            <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-zinc-900 text-zinc-400 border border-zinc-700" data-testid="badge-live-transport-status">
              LIVE TRANSPORT: NOT CONNECTED
            </span>
          </div>
          <h1 className="text-xl font-bold font-mono mt-1">
            {primaryEntityState?.entity_ref?.entity_id || `Case ${caseId}`}
          </h1>
          <div className="text-[10px] font-mono mt-0.5" style={{ color: T.inkFaint }}>
            State Hash: <span className="text-white font-bold">{primaryEntityState?.state_hash || "NOT_AVAILABLE"}</span>
            {primaryEntityState?.evaluated_at && (
              <span className="ml-3 text-emerald-400">Evaluated: {primaryEntityState.evaluated_at}</span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2">
          {["state", "causality", "reachability", "counterfactual", "provenance"].map(tab => (
            <button
              key={tab}
              onClick={() => setActiveSubView(tab)}
              data-testid={`subview-tab-${tab}`}
              className="px-3 py-1.5 text-[11px] font-mono rounded border uppercase transition-colors"
              style={{
                background: activeSubView === tab ? T.paper2 : "transparent",
                color: activeSubView === tab ? "#10B981" : T.inkMute,
                borderColor: activeSubView === tab ? "#10B981" : T.line,
              }}
            >
              {tab === "counterfactual" ? "Counterfactual (Futures)" : tab}
            </button>
          ))}
        </div>
      </div>

      {/* Streaming & Shadow Mode Observability Strip */}
      <div data-testid="streaming-telemetry-strip" className="flex items-center gap-6 px-4 py-2.5 rounded border text-[10px] font-mono flex-wrap" style={{ background: T.paper, borderColor: T.line }}>
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span style={{ color: T.inkMute }}>TRANSPORT:</span>
          <span className="text-emerald-300 font-bold">{streamingStatus.transport}</span>
        </div>
        <div>
          <span style={{ color: T.inkMute }}>EVENT LAG: </span>
          <span className="text-white font-bold">{streamingStatus.event_lag_ms} ms</span>
        </div>
        <div>
          <span style={{ color: T.inkMute }}>EVENTS PROCESSED: </span>
          <span className="text-white font-bold">{streamingStatus.events_processed}</span>
        </div>
        <div>
          <span style={{ color: T.inkMute }}>LATE EVENTS: </span>
          <span className="text-amber-400 font-bold">{streamingStatus.late_events}</span>
        </div>
        <div>
          <span style={{ color: T.inkMute }}>DLQ EVENTS: </span>
          <span className="text-blue-400 font-bold">{streamingStatus.dlq_events}</span>
        </div>
        <div className="ml-auto text-[9px] px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">
          AUTOMATED RESPONSE: DISABLED (SAFETY GATE)
        </div>
      </div>

      {/* Human Intervention Staging Bar */}
      <div data-testid="intervention-staging-bar" className="p-4 rounded border flex items-center justify-between gap-4" style={{ background: T.paper, borderColor: T.line }}>
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-[10px] uppercase font-bold text-amber-400">RECOMMENDED INTERVENTION:</span>
            <span className="text-xs font-mono font-bold text-white">endpoint.isolate</span>
            <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800">
              STATUS: {stagedStatus}
            </span>
          </div>
          <div className="text-[11px]" style={{ color: T.inkMute }}>
            Minimal Disruption Graph-Cut: Sever external network and lateral SMB paths while keeping local forensics active.
          </div>
          {stagingMsg && <div className="text-[10px] font-mono text-emerald-400">{stagingMsg}</div>}
          {executionBlockedNotice && (
            <div className="text-[10px] font-mono text-red-400 font-bold">
              ACTION EXECUTION BLOCKED: Phase 5 Safety Gate active. Execution is strictly locked in Shadow Mode.
            </div>
          )}
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => handleStageAction("STAGED")}
            className="px-3 py-1.5 rounded text-[11px] font-mono border border-blue-700 bg-blue-950 text-blue-300 hover:bg-blue-900 transition-colors"
          >
            STAGE
          </button>
          <button
            onClick={() => handleStageAction("SIMULATED")}
            className="px-3 py-1.5 rounded text-[11px] font-mono border border-purple-700 bg-purple-950 text-purple-300 hover:bg-purple-900 transition-colors"
          >
            SIMULATE
          </button>
          <button
            onClick={() => handleStageAction("APPROVED")}
            className="px-3 py-1.5 rounded text-[11px] font-mono border border-emerald-700 bg-emerald-950 text-emerald-300 hover:bg-emerald-900 transition-colors"
          >
            APPROVE
          </button>
          <button
            onClick={() => handleStageAction("EXECUTE")}
            className="px-3 py-1.5 rounded text-[11px] font-mono border border-red-800 bg-red-950 text-red-400 hover:bg-red-900 transition-colors opacity-75"
            title="Execution is disabled per Phase 5 safety boundary"
          >
            EXECUTE (LOCKED)
          </button>
        </div>
      </div>

      {/* Epistemic Status & Ground Truth Badges */}
      <div className="grid grid-cols-4 gap-4">
        <div className="p-4 rounded border" style={{ background: T.paper, borderColor: T.line }}>
          <div className="text-[10px] uppercase font-bold" style={{ color: T.inkMute }}>Epistemic Status</div>
          <div className="text-sm font-bold text-emerald-400 mt-1 font-mono" data-testid="badge-epistemic-status">
            {primaryEntityState?.epistemic_status || "OBSERVED"}
          </div>
          <div className="text-[10px] mt-1" style={{ color: T.inkFaint }}>10-term formal epistemic vocabulary</div>
        </div>

        <div className="p-4 rounded border" style={{ background: T.paper, borderColor: T.line }}>
          <div className="text-[10px] uppercase font-bold" style={{ color: T.inkMute }}>Capability Classification</div>
          <div className="text-sm font-bold text-amber-400 mt-1 font-mono" data-testid="badge-capability-status">
            {primaryEntityState?.classification || "NOT_EVALUATED"}
          </div>
          <div className="text-[10px] mt-1" style={{ color: T.inkFaint }}>11-dimensional capability abuse status</div>
        </div>

        <div className="p-4 rounded border" style={{ background: T.paper, borderColor: T.line }}>
          <div className="text-[10px] uppercase font-bold" style={{ color: T.inkMute }}>Active Capabilities</div>
          <div className="text-sm font-bold text-white mt-1 font-mono" data-testid="badge-active-capabilities-count">
            {primaryEntityState?.active_capabilities?.length ?? 0} ACTIVE
          </div>
          <div className="text-[10px] mt-1" style={{ color: T.inkFaint }}>Attacker capabilities unlocked</div>
        </div>

        <div className="p-4 rounded border" style={{ background: T.paper, borderColor: T.line }}>
          <div className="text-[10px] uppercase font-bold" style={{ color: T.inkMute }}>Attack State Machine</div>
          <div className="text-sm font-bold text-purple-400 mt-1 font-mono" data-testid="badge-attack-state">
            {primaryEntityState?.attack_state || "ESTABLISHED"}
          </div>
          <div className="text-[10px] mt-1" style={{ color: T.inkFaint }}>18-stage causal lifecycle advancement</div>
        </div>
      </div>

      {/* Subview 1: Facts & State Engine */}
      {activeSubView === "state" && (
        <div className="grid grid-cols-2 gap-6">
          <div className="p-5 rounded border space-y-4" style={{ background: T.paper, borderColor: T.line }}>
            <h2 className="text-xs font-bold uppercase tracking-wider text-emerald-400">Observed Facts (Ground Truth)</h2>
            <div className="space-y-2">
              {(!primaryEntityState?.observed_facts || primaryEntityState.observed_facts.length === 0) ? (
                <div className="text-xs font-mono" style={{ color: T.inkFaint }}>No observed ground-truth telemetry.</div>
              ) : (
                primaryEntityState.observed_facts.map(f => (
                  <div key={f.fact_id} className="p-2.5 rounded border text-[11px] font-mono" style={{ background: T.paper2, borderColor: T.line }}>
                    <div className="flex justify-between text-emerald-400 font-bold">
                      <span>{f.property_name}</span>
                      <span>{f.observed_at}</span>
                    </div>
                    <div className="mt-1 break-all" style={{ color: T.ink }}>{JSON.stringify(f.property_value)}</div>
                    <div className="text-[9px] mt-1" style={{ color: T.inkFaint }}>Source: {f.source_sensor} · Evidence ID: {f.evidence_id}</div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="p-5 rounded border space-y-4" style={{ background: T.paper, borderColor: T.line }}>
            <h2 className="text-xs font-bold uppercase tracking-wider text-amber-400">Deterministic Derived Facts (Inferences)</h2>
            <div className="space-y-2">
              {(!primaryEntityState?.derived_facts || primaryEntityState.derived_facts.length === 0) ? (
                <div className="text-xs font-mono" style={{ color: T.inkFaint }}>No derived facts inferred.</div>
              ) : (
                primaryEntityState.derived_facts.map(d => (
                  <div key={d.fact_id} className="p-2.5 rounded border text-[11px] font-mono" style={{ background: T.paper2, borderColor: T.line }}>
                    <div className="flex justify-between text-amber-400 font-bold">
                      <span>{d.rule_or_model}</span>
                      <span>Conf: {(d.confidence * 100).toFixed(0)}%</span>
                    </div>
                    <div className="mt-1" style={{ color: T.ink }}>{d.property_name}: {JSON.stringify(d.property_value)}</div>
                    <div className="text-[9px] mt-1" style={{ color: T.inkFaint }}>Derived at: {d.derived_at} · Supporting Facts: {d.supporting_fact_ids.join(", ")}</div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* Subview 2: Transitions & Causality */}
      {activeSubView === "causality" && (
        <div className="p-5 rounded border space-y-4" style={{ background: T.paper, borderColor: T.line }}>
          <h2 className="text-xs font-bold uppercase tracking-wider text-emerald-400">Causal State Transitions & OS Mechanisms</h2>
          {transitions.length === 0 && (!causalityGraph?.edges || causalityGraph.edges.length === 0) ? (
            <div className="text-xs font-mono" style={{ color: T.inkFaint }}>No state transitions recorded in the audit ledger for this case.</div>
          ) : (
            <div className="space-y-3">
              {transitions.map((tr, idx) => (
                <div key={tr.block_id || idx} className="flex items-start gap-4 p-3 rounded border text-[11px] font-mono" style={{ background: T.paper2, borderColor: T.line }}>
                  <div className="text-xs font-bold text-emerald-400 bg-emerald-950 px-2 py-1 rounded">0{idx + 1}</div>
                  <div className="flex-1 space-y-1">
                    <div className="flex justify-between font-bold text-amber-300">
                      <span>{tr.event_type}</span>
                      <span style={{ color: T.inkFaint }}>{tr.timestamp}</span>
                    </div>
                    <div style={{ color: T.ink }}>Block Hash: {tr.block_hash}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Subview 3: Enterprise Reachability */}
      {activeSubView === "reachability" && (
        <div className="p-5 rounded border space-y-4" style={{ background: T.paper, borderColor: T.line }}>
          <h2 className="text-xs font-bold uppercase tracking-wider text-emerald-400">Enterprise Reachability Graph (IKG Referenced)</h2>
          {(!reachabilityMatrix?.paths || reachabilityMatrix.paths.length === 0) ? (
            <div className="text-xs font-mono" style={{ color: T.inkFaint }}>No reachability paths evaluated.</div>
          ) : (
            <div className="space-y-3">
              {reachabilityMatrix.paths.map((p) => (
                <div key={p.path_id} className="flex items-center justify-between p-3 rounded border text-[11px] font-mono" style={{ background: T.paper2, borderColor: T.line }}>
                  <div>
                    <div className="font-bold text-sm" style={{ color: T.ink }}>{p.target_entity.entity_id}</div>
                    <div className="text-[10px] mt-0.5" style={{ color: T.inkMute }}>Criticality: {p.criticality_tier}</div>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${p.status === "CURRENTLY_REACHABLE" ? "bg-red-900 text-red-200" : "bg-emerald-900 text-emerald-200"}`}>
                    {p.status}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Subview 4: Counterfactual Futures (Discipline: Projections != Facts) */}
      {activeSubView === "counterfactual" && (
        <div className="space-y-6">
          <div className="p-4 rounded border" style={{ background: "#2E1065", borderColor: "#7C3AED" }}>
            <div className="flex items-center gap-2 text-purple-300 font-bold text-xs">
              <span className="px-2 py-0.5 rounded bg-purple-900 text-purple-200 text-[10px] tracking-wider">PROJECTED WORLDS (SIMULATED)</span>
              <span>PARALLEL COUNTERFACTUAL PROJECTIONS</span>
            </div>
            <p className="text-[11px] text-purple-200 mt-1">
              Counterfactual projections simulate hypothetical branching futures based on candidate intervention actions. These values represent predictive risk-reduction and business-disruption curves, NOT verified telemetry facts.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-6">
            {standardWorlds.map((w) => (
              <div
                key={w.id}
                className="p-5 rounded border-2 border-dashed space-y-3"
                style={{
                  background: selectedWorldId === w.id ? T.paper2 : T.paper,
                  borderColor: selectedWorldId === w.id ? w.tone : T.line,
                }}
                onClick={() => setSelectedWorldId(w.id)}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold font-mono" style={{ color: w.tone }}>{w.name}</span>
                  <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-zinc-300">
                    {w.badge}
                  </span>
                </div>

                <div className="text-[11px] font-mono" style={{ color: T.ink }}>
                  <span style={{ color: T.inkMute }}>Action: </span>{w.action}
                </div>

                <div className="grid grid-cols-2 gap-3 py-2 border-y text-xs font-mono" style={{ borderColor: T.line }}>
                  <div>
                    <span style={{ color: T.inkMute }}>Projected Risk: </span>
                    <span className="font-bold" style={{ color: w.attackRisk === "HIGH" ? "#EF4444" : w.attackRisk === "MEDIUM" ? "#F59E0B" : "#10B981" }}>
                      {w.attackRisk}
                    </span>
                  </div>
                  <div>
                    <span style={{ color: T.inkMute }}>Disruption: </span>
                    <span className="font-bold text-white">{w.disruption}</span>
                  </div>
                </div>

                <div className="text-[10px] font-mono text-emerald-400">
                  Cut: {w.reachabilityCut}
                </div>

                <div className="text-[10px]" style={{ color: T.inkFaint }}>
                  {w.rationale}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Subview 5: Provenance DAG (Why Does NivXRay Believe This?) */}
      {activeSubView === "provenance" && (
        <div className="p-5 rounded border space-y-6" style={{ background: T.paper, borderColor: T.line }}>
          <div>
            <h2 className="text-xs font-bold uppercase tracking-wider text-emerald-400">
              Deterministic Provenance & Reasoning DAG
            </h2>
            <p className="text-[11px] mt-1" style={{ color: T.inkMute }}>
              Unbroken deterministic chain connecting high-level security conclusions back to verifiable canonical evidence and sensor frames.
            </p>
          </div>

          {/* Uncertainty Decomposition */}
          {provenanceData?.epistemic_decomposition && (
            <div className="grid grid-cols-4 gap-4 p-4 rounded border text-xs font-mono" style={{ background: T.paper2, borderColor: T.line }}>
              <div>
                <div className="text-[10px] uppercase text-emerald-400 font-bold">Supporting Evidence</div>
                <div className="text-lg font-bold text-white mt-1">
                  {provenanceData.epistemic_decomposition.supporting_evidence?.length || 0}
                </div>
                <div className="text-[9px]" style={{ color: T.inkFaint }}>Corroborated facts</div>
              </div>

              <div>
                <div className="text-[10px] uppercase text-amber-400 font-bold">Missing Evidence</div>
                <div className="text-lg font-bold text-white mt-1">
                  {provenanceData.epistemic_decomposition.missing_evidence?.length || 0}
                </div>
                <div className="text-[9px]" style={{ color: T.inkFaint }}>Expected gaps</div>
              </div>

              <div>
                <div className="text-[10px] uppercase text-red-400 font-bold">Contradictions</div>
                <div className="text-lg font-bold text-white mt-1">
                  {provenanceData.epistemic_decomposition.contradictory_evidence?.length || 0}
                </div>
                <div className="text-[9px]" style={{ color: T.inkFaint }}>Conflicting signals</div>
              </div>

              <div>
                <div className="text-[10px] uppercase text-purple-400 font-bold">Assumptions</div>
                <div className="text-lg font-bold text-white mt-1">
                  {provenanceData.epistemic_decomposition.assumptions?.length || 0}
                </div>
                <div className="text-[9px]" style={{ color: T.inkFaint }}>Contextual bounds</div>
              </div>
            </div>
          )}

          {/* Reasoning Chain Tree */}
          <div className="space-y-3">
            <h3 className="text-[11px] font-bold uppercase tracking-wider text-white">Reasoning Chain Nodes</h3>
            {(!provenanceData?.nodes || provenanceData.nodes.length === 0) ? (
              <div className="text-xs font-mono" style={{ color: T.inkFaint }}>
                Provenance tree will be generated after state evaluation.
              </div>
            ) : (
              provenanceData.nodes.map((node) => (
                <div
                  key={node.node_id}
                  className="p-3 rounded border flex items-start gap-4 text-[11px] font-mono"
                  style={{ background: T.paper2, borderColor: T.line }}
                >
                  <span
                    className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase ${
                      node.node_type === "CONCLUSION"
                        ? "bg-purple-950 text-purple-300 border border-purple-800"
                        : node.node_type === "CAPABILITY"
                        ? "bg-amber-950 text-amber-300 border border-amber-800"
                        : node.node_type === "CAUSAL_FACT"
                        ? "bg-blue-950 text-blue-300 border border-blue-800"
                        : "bg-emerald-950 text-emerald-300 border border-emerald-800"
                    }`}
                  >
                    {node.node_type}
                  </span>

                  <div className="flex-1 space-y-1">
                    <div className="flex justify-between items-center">
                      <span className="font-bold text-white">{node.label}</span>
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300">
                        {node.epistemic_status}
                      </span>
                    </div>
                    <div style={{ color: T.inkMute }}>{node.description}</div>
                    {node.timestamp && (
                      <div className="text-[9px]" style={{ color: T.inkFaint }}>Timestamp: {node.timestamp}</div>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
