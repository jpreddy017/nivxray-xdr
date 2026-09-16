/**
 * NivXRay XDR Intelligence Controls — reusable governance panel.
 *
 * Renders the hierarchical intelligence policy at a scope:
 *   scope="global"    → MSS/tenant-wide policy (ceiling)
 *   scope="incident"  → per-incident override (narrows only)
 *
 * Contract (FINAL Intelligence Controls spec):
 *   · Online AI is master permission for Online LLM.
 *   · Offline AI, Offline LLM and NivXRay XDR Narration Engine
 *     are ALWAYS_ON — no OFF switch exists.  We render them as
 *     health indicators.
 *   · Incident may only NARROW global.  UI reflects "Inherited
 *     from MSS Policy" when the value comes from the ceiling.
 *   · RBAC is enforced SERVER-SIDE.  We optimistically render
 *     controls but any unauthorised mutation is rejected 403
 *     and surfaced as an in-panel error.
 */
import React, { useEffect, useState, useMemo } from "react";
import {
  Cpu, ShieldCheck, Radio, WifiOff, Wifi, History as HistoryIcon,
  AlertTriangle, RefreshCcw, Lock,
} from "lucide-react";
import api from "@/lib/api";

// ---- Presets (Quick Actions) --------------------------------------
const PRESETS = [
  {
    id: "standard",
    label: "Standard",
    describe: "Online AI + Online LLM permitted",
    values: { online_ai: "on",  online_llm: "on"  },
  },
  {
    id: "online_ai_only",
    label: "Online AI Only",
    describe: "Online AI permitted · Online LLM disabled",
    values: { online_ai: "on",  online_llm: "off" },
  },
  {
    id: "offline_only",
    label: "Offline Only",
    describe: "No cloud data leaves this scope",
    values: { online_ai: "off", online_llm: "off" },
  },
];

function presetOf(values) {
  return PRESETS.find(p =>
    p.values.online_ai === values.online_ai &&
    p.values.online_llm === values.online_llm)?.id || null;
}

// ---- Component ----------------------------------------------------
export default function IntelligenceControlPanel({
  scope,               // "global" | "incident"
  incidentId,          // required when scope === "incident"
  compact = false,     // condensed rendering for the incident header
}) {
  const [policy, setPolicy]           = useState(null);
  const [effective, setEffective]     = useState(null);
  const [health, setHealth]           = useState(null);
  const [globalPol, setGlobalPol]     = useState(null);   // for hierarchy display
  const [loading, setLoading]         = useState(false);
  const [savingKey, setSavingKey]     = useState(null);
  const [error, setError]             = useState(null);
  const [reason, setReason]           = useState("");
  const [showHistory, setShowHistory] = useState(false);
  const [history, setHistory]         = useState([]);

  const scopeKind = scope === "incident" ? "incident" : "global";
  const scopeId   = scope === "incident" ? incidentId : "global";

  // ---- fetch --------------------------------------------------------
  const load = async () => {
    setLoading(true); setError(null);
    try {
      const h = await api.get("/intelligence/health");
      setHealth(h.data);
      if (scope === "global") {
        const p = await api.get("/intelligence/policy/global");
        setPolicy(p.data);
        setEffective(null);
        setGlobalPol(p.data);
      } else {
        const [ov, ef] = await Promise.all([
          api.get(`/intelligence/policy/incident/${incidentId}`),
          api.get(`/intelligence/policy/incident/${incidentId}/effective`),
        ]);
        setPolicy(ov.data);
        setEffective(ef.data.effective);
        setGlobalPol(ef.data.global);
      }
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || String(e));
    } finally { setLoading(false); }
  };

  useEffect(() => { load(); /* eslint-disable-next-line */ },
    [scope, incidentId]);

  // ---- write --------------------------------------------------------
  const persist = async (patch, opts = {}) => {
    setSavingKey(opts.savingKey || "any"); setError(null);
    try {
      const body = { ...patch, reason: reason || undefined };
      const url = scope === "global"
        ? "/intelligence/policy/global"
        : `/intelligence/policy/incident/${incidentId}`;
      const { data } = await api.put(url, body);
      setPolicy(data);
      if (scope === "incident") {
        const ef = await api.get(
          `/intelligence/policy/incident/${incidentId}/effective`);
        setEffective(ef.data.effective);
        setGlobalPol(ef.data.global);
      } else {
        setGlobalPol(data);
      }
    } catch (e) {
      const d = e?.response?.data;
      const detail = d?.detail || d?.message || e?.message;
      // RBAC denial arrives as { code:"ACCESS_DENIED", ... }
      if (d?.detail?.code === "ACCESS_DENIED") {
        setError("You do not have permission to change this policy. " +
                         "Ask a tenant_admin or soc_manager.");
      } else {
        setError(typeof detail === "string" ? detail :
                         JSON.stringify(detail || e));
      }
    } finally { setSavingKey(null); }
  };

  const clearOverride = async () => {
    if (scope !== "incident") return;
    setSavingKey("clear"); setError(null);
    try {
      await api.delete(
        `/intelligence/policy/incident/${incidentId}` +
        `?reason=${encodeURIComponent(reason || "cleared")}`);
      await load();
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message);
    } finally { setSavingKey(null); }
  };

  const loadHistory = async () => {
    setShowHistory(v => !v);
    if (!showHistory) {
      try {
        const { data } = await api.get(
          `/intelligence/policy/${scopeKind}/${scopeId}/history`);
        setHistory(data.history || []);
      } catch (e) {
        setError(e?.response?.data?.detail || e?.message);
      }
    }
  };

  // ---- computed -----------------------------------------------------
  const values = useMemo(() => {
    if (scope === "global") {
      return {
        online_ai:  policy?.online_ai  || "on",
        online_llm: policy?.online_llm || "on",
      };
    }
    return {
      online_ai:  effective?.online_ai  || "on",
      online_llm: effective?.online_llm || "on",
    };
  }, [policy, effective, scope]);

  const overrideIsActive = scope === "incident" &&
    (policy?.online_ai !== null || policy?.online_llm !== null);

  const activePreset = presetOf(values);

  // Whether a control can be toggled at THIS scope.  Global can
  // always toggle both.  Incident can only toggle to a value ≤
  // (i.e. no-wider-than) the global ceiling.
  const canRaiseOnlineAi  = scope === "global"
    ? true : (globalPol?.online_ai  ?? "on") === "on";
  const canRaiseOnlineLlm = scope === "global"
    ? true : (globalPol?.online_llm ?? "on") === "on";

  const modeBadge = () => {
    if (values.online_ai === "off")
      return { label: "OFFLINE ONLY", tone: "offline" };
    if (values.online_llm === "off")
      return { label: "LOCAL + ONLINE AI", tone: "restricted",
                     detail: "Cloud LLM disabled" };
    return { label: "LOCAL + ONLINE AI + LLM", tone: "standard" };
  };
  const badge = modeBadge();

  // ---- render helpers -----------------------------------------------
  const Toggle = ({ testid, on, disabled, onChange, dim }) => (
    <button
      data-testid={testid}
      data-on={on ? "true" : "false"}
      onClick={() => !disabled && onChange(!on)}
      disabled={disabled}
      title={disabled ? "Restricted by MSS Global policy" : (on ? "Turn OFF" : "Turn ON")}
      style={{
        display: "inline-flex", alignItems: "center", gap: 6,
        padding: "2px 10px", fontSize: 10,
        borderRadius: 999,
        border: "1px solid " + (on ? "#7c3aed" : "#334155"),
        background: on ? "#4c1d95" : "#0f172a",
        color: on ? "#f5f3ff" : "#94a3b8",
        cursor: disabled ? "not-allowed" : "pointer",
        letterSpacing: 0.5, textTransform: "uppercase",
        fontWeight: 700,
        opacity: dim ? 0.55 : 1,
      }}>
      {disabled ? <Lock size={9} /> : (on
        ? <span style={{ width: 6, height: 6, borderRadius: 999,
                                    background: "#c4b5fd", boxShadow: "0 0 6px #a78bfa" }} />
        : <span style={{ width: 6, height: 6, borderRadius: 999,
                                    background: "#475569" }} />)}
      {on ? "ON" : "OFF"}
    </button>
  );

  const AlwaysOn = ({ label, hp }) => (
    <span style={{ display: "inline-flex", alignItems: "center",
                             gap: 6, fontSize: 10, color: hp === "ready" ? "#5eead4" : "#94a3b8",
                             letterSpacing: 0.4, textTransform: "uppercase", fontWeight: 700 }}
              title={hp === "ready" ? "Runtime provisioned" : "Runtime not provisioned"}>
      <span style={{ width: 6, height: 6, borderRadius: 999,
                            background: hp === "ready" ? "#22d3ee" : "#64748b" }} />
      {label}
    </span>
  );

  return (
    <section
      data-testid={`xdr-intelligence-panel-${scope}`}
      data-mode={badge.tone}
      style={{
        background: "linear-gradient(180deg, #0b1220 0%, #0a0e1a 100%)",
        border: "1px solid #1e293b", borderRadius: 6,
        padding: compact ? 10 : 14, color: "#e2e8f0",
        fontFamily: "ui-sans-serif, system-ui",
      }}>
      {/* Header row */}
      <div style={{ display: "flex", alignItems: "center", gap: 10,
                          marginBottom: 10 }}>
        <Cpu size={14} style={{ color: "#a78bfa" }} />
        <span data-testid={`${scope}-intel-title`}
                  style={{ fontWeight: 700, fontSize: 12, letterSpacing: 0.4,
                              textTransform: "uppercase", color: "#c4b5fd" }}>
          NivXRay XDR Intelligence · {scope === "global"
            ? "Global Policy" : "Incident Policy"}
        </span>
        <span data-testid={`${scope}-intel-mode-badge`}
                  style={{ marginLeft: "auto",
                              padding: "2px 8px", borderRadius: 3,
                              fontSize: 10, letterSpacing: 0.4,
                              textTransform: "uppercase", fontWeight: 700,
                              background: badge.tone === "offline"
                                ? "#0f172a" : badge.tone === "restricted"
                                ? "#292412" : "#0f2724",
                              color: badge.tone === "offline"
                                ? "#94a3b8" : badge.tone === "restricted"
                                ? "#fbbf24" : "#5eead4",
                              border: "1px solid " + (badge.tone === "offline"
                                ? "#334155" : badge.tone === "restricted"
                                ? "#78350f" : "#134e4a") }}
                  title={badge.detail || badge.label}>
          ● {badge.label}
        </span>
        <button
          onClick={load}
          disabled={loading}
          data-testid={`${scope}-intel-refresh`}
          title="Refresh policy"
          style={{ background: "transparent", border: "1px solid #334155",
                          borderRadius: 3, cursor: "pointer",
                          color: "#94a3b8", padding: "3px 6px" }}>
          <RefreshCcw size={11}
            style={{ animation: loading ? "nx-spin .9s linear infinite" : "none" }} />
        </button>
      </div>

      {/* Error banner */}
      {error && (
        <div data-testid={`${scope}-intel-error`}
              style={{ color: "#fca5a5", fontSize: 11,
                          padding: "6px 10px", background: "#2b0f0f",
                          border: "1px solid #7f1d1d", borderRadius: 3,
                          marginBottom: 10, display: "flex",
                          alignItems: "center", gap: 6 }}>
          <AlertTriangle size={11} /> {error}
        </div>
      )}

      {/* ─── ONLINE INTELLIGENCE ─── */}
      <div style={{ marginBottom: 8 }}>
        <div style={{ fontSize: 10, letterSpacing: 0.6,
                             textTransform: "uppercase", color: "#64748b",
                             marginBottom: 4 }}>
          Online Intelligence
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <Row
            testidBase={`${scope}-online-ai`}
            icon={<Wifi size={11} />}
            label="Online AI"
            sub={scope === "incident" && effective?.online_ai_source
              ? `${effective.online_ai_source.replace("_", " ")}` : "master permission"}
          >
            <Toggle
              testid={`${scope}-online-ai-toggle`}
              on={values.online_ai === "on"}
              disabled={!canRaiseOnlineAi || savingKey === "online_ai"}
              onChange={(next) => persist({
                online_ai:  next ? "on" : "off",
                online_llm: policy?.online_llm ?? (next ? "on" : "off"),
              }, { savingKey: "online_ai" })}
            />
          </Row>
          <Row
            testidBase={`${scope}-online-llm`}
            icon={<Radio size={11} />}
            label="  └─ Online LLM"
            sub={values.online_ai === "off"
              ? "unavailable · online AI is off"
              : (scope === "incident" && effective?.online_llm_source
                 ? effective.online_llm_source.replace("_", " ")
                 : "cloud LLM sub-permission")}
            dim={values.online_ai === "off"}
          >
            <Toggle
              testid={`${scope}-online-llm-toggle`}
              on={values.online_llm === "on"}
              disabled={values.online_ai === "off" || !canRaiseOnlineLlm ||
                                savingKey === "online_llm"}
              dim={values.online_ai === "off"}
              onChange={(next) => persist({
                online_ai:  policy?.online_ai  ?? values.online_ai,
                online_llm: next ? "on" : "off",
              }, { savingKey: "online_llm" })}
            />
          </Row>
        </div>
      </div>

      {/* ─── OFFLINE INTELLIGENCE ─── */}
      <div style={{ marginBottom: 8 }}>
        <div style={{ fontSize: 10, letterSpacing: 0.6,
                             textTransform: "uppercase", color: "#64748b",
                             marginBottom: 4 }}>
          Offline Intelligence
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <Row testidBase={`${scope}-offline-ai`}
                 icon={<WifiOff size={11} />}
                 label="Offline AI"
                 sub="always on">
            <AlwaysOn label={`ALWAYS ON · ${health?.offline_ai?.health || "…"}`}
                              hp={health?.offline_ai?.health} />
          </Row>
          <Row testidBase={`${scope}-offline-llm`}
                 icon={<WifiOff size={11} />}
                 label="  └─ Offline LLM"
                 sub="always on">
            <AlwaysOn label={`ALWAYS ON · ${health?.offline_llm?.health || "…"}`}
                              hp={health?.offline_llm?.health} />
          </Row>
          <Row testidBase={`${scope}-narration-engine`}
                 icon={<ShieldCheck size={11} />}
                 label="NivXRay XDR Narration Engine"
                 sub="guaranteed baseline">
            <AlwaysOn label="ALWAYS AVAILABLE" hp="ready" />
          </Row>
        </div>
      </div>

      {/* ─── PRESETS ─── */}
      <div style={{ marginBottom: 8 }}>
        <div style={{ fontSize: 10, letterSpacing: 0.6,
                            textTransform: "uppercase", color: "#64748b",
                            marginBottom: 4 }}>
          Intelligence Mode
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
          {PRESETS.map((p) => {
            // Ceiling gating for incident-scope presets — cannot widen
            // beyond MSS/Global.  A preset requiring online_ai=on when
            // global has online_ai=off must be disabled.
            const ceilingLocks =
              scope === "incident" &&
              ((p.values.online_ai  === "on" && !canRaiseOnlineAi) ||
               (p.values.online_llm === "on" && !canRaiseOnlineLlm));
            return (
              <button key={p.id}
                data-testid={`${scope}-preset-${p.id}`}
                data-active={activePreset === p.id ? "true" : "false"}
                data-locked={ceilingLocks ? "true" : "false"}
                onClick={() => !ceilingLocks && persist(p.values,
                  { savingKey: `preset-${p.id}` })}
                disabled={ceilingLocks || savingKey === `preset-${p.id}`}
                title={ceilingLocks
                  ? "Restricted by MSS Global policy — would widen beyond ceiling"
                  : p.describe}
                style={{
                  padding: "4px 10px", fontSize: 10,
                  border: "1px solid " +
                    (activePreset === p.id ? "#7c3aed" :
                     ceilingLocks ? "#334155" : "#334155"),
                  borderRadius: 3,
                  cursor: ceilingLocks ? "not-allowed" : "pointer",
                  background: activePreset === p.id ? "#4c1d95" : "transparent",
                  color: ceilingLocks ? "#475569"
                          : activePreset === p.id ? "#f5f3ff" : "#94a3b8",
                  letterSpacing: 0.4, textTransform: "uppercase",
                  fontWeight: 700,
                  opacity: ceilingLocks ? 0.55 : 1,
                }}>
                {ceilingLocks && <Lock size={9} style={{ marginRight: 4, verticalAlign: -1 }} />}
                {p.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* ─── REASON + OVERRIDE STATUS ─── */}
      <div style={{ display: "flex", gap: 8, alignItems: "center",
                          flexWrap: "wrap", marginTop: 8, marginBottom: 8 }}>
        <input
          data-testid={`${scope}-reason-input`}
          type="text"
          placeholder="Reason (recorded in audit)…"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          style={{
            flex: 1, minWidth: 180,
            background: "#0a0e1a", border: "1px solid #334155",
            borderRadius: 3, color: "#e2e8f0",
            padding: "4px 8px", fontSize: 11,
          }} />
        {scope === "incident" && overrideIsActive && (
          <button data-testid="incident-clear-override"
                        onClick={clearOverride}
                        disabled={savingKey === "clear"}
                        style={{ padding: "4px 10px", fontSize: 10,
                                     border: "1px solid #78350f", background: "#292412",
                                     color: "#fbbf24", borderRadius: 3, cursor: "pointer",
                                     letterSpacing: 0.4, textTransform: "uppercase",
                                     fontWeight: 700 }}>
            Clear Override
          </button>
        )}
      </div>

      {/* ─── HISTORY ─── */}
      <div>
        <button data-testid={`${scope}-history-toggle`}
                    onClick={loadHistory}
                    style={{ display: "inline-flex", alignItems: "center",
                                 gap: 6, fontSize: 10, color: "#94a3b8",
                                 background: "transparent", border: "1px solid #334155",
                                 borderRadius: 3, cursor: "pointer",
                                 padding: "3px 8px",
                                 letterSpacing: 0.4, textTransform: "uppercase",
                                 fontWeight: 700 }}>
          <HistoryIcon size={10} />
          {showHistory ? "Hide History" : "Show History"}
        </button>
        {showHistory && (
          <div data-testid={`${scope}-history-list`}
                style={{ marginTop: 6, fontSize: 11 }}>
            {history.length === 0 && (
              <div style={{ color: "#64748b" }}>No history entries yet.</div>
            )}
            {history.map((h, i) => (
              <div key={h.audit_id || i}
                       data-testid={`${scope}-history-entry-${i}`}
                       style={{ display: "grid",
                                    gridTemplateColumns: "auto 1fr",
                                    gap: "2px 10px",
                                    padding: "4px 6px",
                                    borderTop: "1px solid #1e293b",
                                    fontFamily: "ui-monospace, monospace" }}>
                <span style={{ color: "#a78bfa" }}>{h.recorded_at}</span>
                <span style={{ color: "#cbd5e1" }}>
                  {h.changed_by} · {h.changed_by_role}
                </span>
                <span></span>
                <span style={{ color: "#94a3b8" }}>
                  {JSON.stringify(h.previous)} → {JSON.stringify(h.new)}
                  {h.reason ? ` · ${h.reason}` : ""}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}


// ---- small row layout ---------------------------------------------
function Row({ icon, label, sub, testidBase, dim, children }) {
  return (
    <div
      data-testid={`${testidBase}-row`}
      style={{ display: "flex", alignItems: "center", gap: 10,
                    padding: "4px 6px",
                    background: "#0a0e1a", borderRadius: 3,
                    opacity: dim ? 0.65 : 1 }}>
      <span style={{ color: "#94a3b8" }}>{icon}</span>
      <span style={{ flex: 1, fontSize: 12, fontWeight: 500,
                             color: "#e2e8f0", whiteSpace: "pre" }}>
        {label}
        {sub && (
          <span style={{ marginLeft: 8, fontSize: 10, color: "#64748b",
                              fontFamily: "ui-monospace, monospace" }}>
            {sub}
          </span>
        )}
      </span>
      {children}
    </div>
  );
}
