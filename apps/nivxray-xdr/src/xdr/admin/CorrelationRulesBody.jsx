/**
 * Admin › Correlation Rules (P1).
 *
 * Real stateful event-stream correlation dashboard.  Never fabricates.
 * Every displayed number comes from /xdr/correlation/status.
 *
 * KEY UX INVARIANTS:
 *   * A correlation match is EVIDENCE, never a verdict.
 *   * Each row of the matches table shows the operator, level
 *     (OBSERVED / CANDIDATE / SUPPORTED), matched vs missing conditions,
 *     entity_key, evidence-chain length, and attack techniques.
 *   * Every rule row carries the operator and ATT&CK badges.
 */
import React, { useEffect, useMemo, useState } from "react";
import { RefreshCcw, Shuffle, ShieldCheck, AlertTriangle, Play,
                 CheckCircle2, XCircle, ChevronRight } from "lucide-react";
import api from "@/lib/api";


const LEVEL_COLOR = {
  CORRELATION_OBSERVED:  "var(--faint)",
  CORRELATION_CANDIDATE: "var(--amber)",
  CORRELATION_SUPPORTED: "var(--mint)",
};


export default function CorrelationRulesBody() {
  const [status,  setStatus]  = useState(null);
  const [rules,   setRules]   = useState([]);
  const [matches, setMatches] = useState([]);
  const [err,     setErr]     = useState(null);
  const [busy,    setBusy]    = useState(false);
  const [tab,     setTab]     = useState("rules");
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    (async () => {
      setBusy(true); setErr(null);
      try {
        const [s, r, m] = await Promise.all([
          api.get("/xdr/correlation/status"),
          api.get("/xdr/correlation/rules"),
          api.get("/xdr/correlation/matches", { params: { limit: 100 }}),
        ]);
        setStatus(s?.data?.data || null);
        setRules(r?.data?.data?.rules || []);
        setMatches(m?.data?.data?.matches || []);
      } catch (e) {
        setErr(e?.response?.data?.detail || e?.message || "load failed");
      } finally { setBusy(false); }
    })();
  }, [refresh]);

  const runDemoReplay = async () => {
    // A prepared "malicious chain" that exercises the Office → PowerShell
    // → external correlation.  dry_run=false → matches persist so operators
    // can review them under the Matches tab.
    const base = new Date();
    const iso = (offset) => new Date(base.getTime() + offset * 1000).toISOString();
    const signals = [
      { signal_kind: "detection", at: iso(0), host_id: "DEMO-HOST",
         detection_id: "proc_creation_win_office_spawns_shell" },
      { signal_kind: "detection", at: iso(15), host_id: "DEMO-HOST",
         detection_id: "proc_creation_win_susp_encoded_pshell" },
      { signal_kind: "event", at: iso(30), host_id: "DEMO-HOST",
         event_kind: "network.connection.external", dst_ip: "203.0.113.55" },
    ];
    try {
      await api.post("/xdr/correlation/replay",
        { scenario_name: "ui-demo", signals, dry_run: false });
      setRefresh((n) => n + 1);
    } catch (e) { alert(JSON.stringify(e?.response?.data?.detail || e?.message)); }
  };

  const s = status || {};

  return (
    <div data-testid="xdr-admin-correlation-body">
      <div style={{ display: "flex", gap: 10, marginBottom: 14,
                          alignItems: "center" }}>
        <Shuffle size={16} style={{ color: "var(--cyan)" }} />
        <b style={{ fontFamily: "var(--mono)", fontSize: 13 }}>
          Correlation Engine
        </b>
        <span data-testid="cor-status-badge"
                  style={{ padding: "1px 6px", border: "1px solid var(--mint)",
                                  color: "var(--mint)", borderRadius: 3, fontSize: 9.5,
                                  fontFamily: "var(--mono)", fontWeight: 700 }}>
          {(s.operators_implemented || []).length}/
          {(s.operators || []).length} OPERATORS IMPLEMENTED
        </span>
        <span style={{ flex: 1 }} />
        <button className="btn" onClick={runDemoReplay}
                     data-testid="cor-replay-demo"
                     style={{ padding: "3px 10px", fontSize: 11 }}>
          <Play size={11} /> Replay demo chain
        </button>
        <button className="btn ghost" onClick={() => setRefresh((n) => n + 1)}
                     data-testid="cor-refresh"
                     style={{ padding: "3px 10px", fontSize: 11 }}>
          <RefreshCcw size={11} /> Refresh
        </button>
      </div>

      {/* Stats */}
      <div style={statsGrid}>
        <Stat label="Rules total"       value={s.rules_total   ?? "—"}
                   testid="cor-stat-total" />
        <Stat label="Rules active"      value={s.rules_active  ?? "—"}
                   testid="cor-stat-active" color="var(--cyan)" />
        <Stat label="Matches total"     value={s.matches_total ?? "—"}
                   testid="cor-stat-matches" />
        <Stat label="Supported"         value={s.supported     ?? "—"}
                   testid="cor-stat-supported" color="var(--mint)" />
        <Stat label="Candidates"        value={s.candidates    ?? "—"}
                   testid="cor-stat-candidates" color="var(--amber)" />
        <Stat label="Operators"         value={(s.operators || []).length}
                   testid="cor-stat-operators" />
      </div>

      {err && <div style={{ color: "var(--amber)", fontSize: 11,
                                        marginBottom: 8 }}>{err}</div>}

      {/* Tabs */}
      <div style={{ display: "flex", gap: 4, marginBottom: 8 }}>
        <TabBtn active={tab === "rules"}   onClick={() => setTab("rules")}
                    testid="cor-tab-rules">Rules · {rules.length}</TabBtn>
        <TabBtn active={tab === "matches"} onClick={() => setTab("matches")}
                    testid="cor-tab-matches">Matches · {matches.length}</TabBtn>
      </div>

      {tab === "rules" ? (
        <RulesTable rules={rules} />
      ) : (
        <MatchesTable matches={matches} />
      )}
    </div>
  );
}


function RulesTable({ rules }) {
  return (
    <div style={{ border: "1px solid var(--border)", borderRadius: 3,
                          overflow: "hidden" }}>
      <div className="mono" style={rulesHead}>
        <div>Name</div><div>Operator</div><div>Window</div>
        <div>State</div><div>ATT&CK</div><div>Enabled</div>
      </div>
      {rules.map((r) => (
        <div key={r.id} className="mono" style={rulesBody}
                 data-testid={`cor-rule-${r.id}`}>
          <div>
            <div style={{ color: "var(--text)" }}>{r.name}</div>
            <div style={{ fontSize: 10, color: "var(--faint)" }}>
              {r.description}
            </div>
          </div>
          <div style={{ fontSize: 10.5, color: "var(--cyan)" }}>
            {r.operators?.type}
          </div>
          <div style={{ fontSize: 10.5, color: "var(--text-dim)" }}>
            {r.operators?.window_seconds}s
          </div>
          <div>
            <span style={{ fontSize: 9.5, color: "var(--mint)",
                                    fontWeight: 700 }}>{r.state}</span>
          </div>
          <div style={{ fontSize: 10, color: "var(--amber)" }}>
            {(r.attack_techniques || []).join(", ") || "—"}
          </div>
          <div>
            {r.enabled ? (
              <CheckCircle2 size={12} style={{ color: "var(--mint)" }} />
            ) : (
              <XCircle size={12} style={{ color: "#f87171" }} />
            )}
          </div>
        </div>
      ))}
      {rules.length === 0 && (
        <div style={emptyRow}>NO CORRELATION RULES</div>
      )}
    </div>
  );
}


function MatchesTable({ matches }) {
  return (
    <div style={{ border: "1px solid var(--border)", borderRadius: 3,
                          overflow: "hidden" }}>
      <div className="mono" style={matchesHead}>
        <div>Rule</div><div>Level</div><div>Entity</div>
        <div>Matched → Missing</div><div>Evidence</div><div>ATT&CK</div>
      </div>
      {matches.map((m) => (
        <div key={m.id} className="mono" style={matchesBody}
                 data-testid={`cor-match-${m.id}`}>
          <div style={{ color: "var(--text)" }}>{m.correlation_name}</div>
          <div>
            <span data-testid={`cor-level-${m.level}`}
                      style={{ padding: "1px 5px",
                                      border: `1px solid ${LEVEL_COLOR[m.level] || "var(--faint)"}`,
                                      color: LEVEL_COLOR[m.level] || "var(--faint)",
                                      borderRadius: 2, fontSize: 9.5,
                                      fontFamily: "var(--mono)", fontWeight: 700 }}>
              {m.level.replace("CORRELATION_", "")}
            </span>
          </div>
          <div style={{ fontSize: 10.5, color: "var(--text-dim)" }}>
            {m.entity_key}
          </div>
          <div style={{ fontSize: 10 }}>
            <span style={{ color: "var(--mint)" }}>
              ✓{(m.matched_conditions || []).join(", ")}
            </span>
            {(m.missing_conditions || []).length > 0 && (
              <span style={{ marginLeft: 6, color: "#f87171" }}>
                ✗{m.missing_conditions.join(", ")}
              </span>
            )}
          </div>
          <div style={{ fontSize: 10, color: "var(--faint)" }}>
            chain: {m.evidence_chain?.length || 0} · sigs:{" "}
            {m.signal_ids?.length || 0} · dets: {m.detection_ids?.length || 0}
          </div>
          <div style={{ fontSize: 10, color: "var(--amber)" }}>
            {(m.attack_techniques || []).join(", ") || "—"}
          </div>
        </div>
      ))}
      {matches.length === 0 && (
        <div style={emptyRow}>
          NO CORRELATION EVIDENCE YET · click "Replay demo chain" to exercise
          the engine against the built-in Office → PowerShell → external
          scenario.
        </div>
      )}
    </div>
  );
}


function TabBtn({ active, onClick, testid, children }) {
  return (
    <button data-testid={testid} onClick={onClick}
                 className={active ? "btn" : "btn ghost"}
                 style={{ padding: "3px 10px", fontSize: 11 }}>{children}</button>
  );
}


function Stat({ label, value, testid, color }) {
  return (
    <div data-testid={testid} style={statCard}>
      <div className="mono" style={statLabel}>{label}</div>
      <div className="mono" style={{ ...statValue,
                                                        color: color || "var(--text)" }}>
        {value}
      </div>
    </div>
  );
}


const statsGrid = {
  display: "grid", gridTemplateColumns: "repeat(6, 1fr)",
  gap: 8, marginBottom: 14,
};
const statCard = {
  padding: 10, border: "1px solid var(--border)", borderRadius: 3,
  background: "var(--panel2)",
};
const statLabel = {
  fontSize: 9.5, color: "var(--faint)", textTransform: "uppercase",
  marginBottom: 4, letterSpacing: ".3px",
};
const statValue = { fontSize: 20, fontWeight: 700 };

const rulesHead = {
  display: "grid",
  gridTemplateColumns: "2.2fr 0.9fr 0.7fr 0.7fr 1.4fr 0.5fr",
  gap: 6, padding: "4px 8px", background: "var(--panel2)",
  fontSize: 10, color: "var(--faint)", textTransform: "uppercase",
};
const rulesBody = {
  display: "grid",
  gridTemplateColumns: "2.2fr 0.9fr 0.7fr 0.7fr 1.4fr 0.5fr",
  gap: 6, padding: "6px 8px", fontSize: 11,
  color: "var(--text-dim)", borderTop: "1px solid var(--border)",
  alignItems: "center",
};
const matchesHead = {
  display: "grid",
  gridTemplateColumns: "1.8fr 0.7fr 0.9fr 1.4fr 1.2fr 0.9fr",
  gap: 6, padding: "4px 8px", background: "var(--panel2)",
  fontSize: 10, color: "var(--faint)", textTransform: "uppercase",
};
const matchesBody = {
  display: "grid",
  gridTemplateColumns: "1.8fr 0.7fr 0.9fr 1.4fr 1.2fr 0.9fr",
  gap: 6, padding: "6px 8px", fontSize: 11,
  color: "var(--text-dim)", borderTop: "1px solid var(--border)",
  alignItems: "center",
};
const emptyRow = { padding: 10, fontSize: 11, color: "var(--faint)",
                              fontFamily: "var(--mono)" };
