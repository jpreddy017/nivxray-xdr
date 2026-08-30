/**
 * Admin › Detection Content Registry (P1).
 *
 * Real, populated, executable detection-content registry.  Renders
 * honest counts from /xdr/detection/status — never fabricates.
 * ATT&CK coverage is the union of real rule tags, not a target.
 */
import React, { useEffect, useMemo, useState } from "react";
import { RefreshCcw, ShieldCheck, ShieldAlert, ShieldOff, BookOpen,
                 CheckCircle2, XCircle } from "lucide-react";
import api from "@/lib/api";


export default function DetectionRegistryBody() {
  const [status,  setStatus]  = useState(null);
  const [rules,   setRules]   = useState([]);
  const [err,     setErr]     = useState(null);
  const [busy,    setBusy]    = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [q,       setQ]       = useState("");
  const [filter,  setFilter]  = useState({ source: "", rule_type: "",
                                                                    state: "", attack: "" });
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    (async () => {
      setBusy(true); setErr(null);
      try {
        const [st, rl] = await Promise.all([
          api.get("/xdr/detection/status"),
          api.get("/xdr/detection/rules", { params: { limit: 1000,
              q: q || undefined, ...Object.fromEntries(Object.entries(filter)
                    .filter(([, v]) => v)) } }),
        ]);
        setStatus(st?.data?.data || null);
        setRules(rl?.data?.data?.rules || []);
      } catch (e) {
        setErr(e?.response?.data?.detail || e?.message || "load failed");
      } finally { setBusy(false); }
    })();
  }, [refresh, q, filter]);

  const doSync = async () => {
    setSyncing(true);
    try { await api.post("/xdr/detection/sync"); setRefresh((n) => n + 1); }
    catch (e) {
      alert(JSON.stringify(e?.response?.data?.detail || e?.message));
    } finally { setSyncing(false); }
  };

  const s = status || {};
  const attackTechniques = s.attack_techniques || [];

  return (
    <div data-testid="xdr-admin-detection-registry-body">
      <div style={{ display: "flex", gap: 10, marginBottom: 14,
                          alignItems: "center" }}>
        <ShieldCheck size={16} style={{ color: "var(--mint)" }} />
        <b style={{ fontFamily: "var(--mono)", fontSize: 13 }}>
          Detection Content Registry
        </b>
        <StateBadge state={s.sync_state || "NEVER_SYNCED"}
                          data-testid="det-status-badge" />
        {s.bundled_fallback_available && (
          <span data-testid="det-bundled-badge" style={{
              padding: "1px 6px", border: "1px solid var(--faint)",
              color: "var(--faint)", borderRadius: 3, fontSize: 9.5,
              fontFamily: "var(--mono)", letterSpacing: ".3px" }}
              title="Bundled DRL-1.1 snapshot ships with the backend">
            BUNDLED · OK
          </span>
        )}
        <span style={{ flex: 1 }} />
        <button className="btn" onClick={doSync} disabled={syncing}
                     data-testid="det-sync-btn"
                     style={{ padding: "3px 10px", fontSize: 11 }}>
          <RefreshCcw size={11} /> {syncing ? "Syncing…" : "Sync now"}
        </button>
      </div>

      {/* Stats grid */}
      <div style={statsGrid}>
        <Stat label="Total rules"       value={s.total_rules ?? "—"}
                   testid="det-stat-total" />
        <Stat label="Valid rules"       value={s.valid_rules ?? "—"}
                   testid="det-stat-valid" color="var(--mint)" />
        <Stat label="Active rules"      value={s.active_rules ?? "—"}
                   testid="det-stat-active" color="var(--cyan)" />
        <Stat label="ATT&CK techniques" value={s.attack_technique_count ?? "—"}
                   testid="det-stat-attack" color="var(--amber)" />
        <Stat label="Sources"           value={Object.keys(s.sources || {}).length}
                   testid="det-stat-sources" />
        <Stat label="Rule types"        value={Object.keys(s.rule_types || {}).length}
                   testid="det-stat-types" />
      </div>

      {/* ATT&CK coverage tag chips */}
      <div style={{ marginBottom: 12 }}>
        <div className="mono" style={sectionLabel}>ATT&CK Coverage</div>
        <div data-testid="det-attack-chips"
                  style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
          {attackTechniques.length === 0 ? (
            <div style={emptyText}>NO ATT&CK MAPPINGS</div>
          ) : attackTechniques.map((t) => (
            <span key={t} className="mono" style={chip}>
              {t}
            </span>
          ))}
        </div>
      </div>

      {/* Filter row */}
      <div style={{ display: "flex", gap: 6, marginBottom: 8, flexWrap: "wrap" }}>
        <input type="text" placeholder="Search title / description…"
                    value={q} onChange={(e) => setQ(e.target.value)}
                    data-testid="det-search" style={{ ...inputStyle, width: 260 }} />
        <select value={filter.source}
                    onChange={(e) => setFilter({ ...filter, source: e.target.value })}
                    data-testid="det-filter-source" style={inputStyle}>
          <option value="">All sources</option>
          {Object.entries(s.sources || {}).map(([k, n]) =>
            <option key={k} value={k}>{k} ({n})</option>)}
        </select>
        <select value={filter.rule_type}
                    onChange={(e) => setFilter({ ...filter, rule_type: e.target.value })}
                    data-testid="det-filter-type" style={inputStyle}>
          <option value="">All rule types</option>
          {Object.entries(s.rule_types || {}).map(([k, n]) =>
            <option key={k} value={k}>{k} ({n})</option>)}
        </select>
        <button className="btn ghost" onClick={() => setRefresh((n) => n + 1)}
                     data-testid="det-refresh"
                     style={{ padding: "4px 8px", fontSize: 11 }}>
          <RefreshCcw size={11} /> Refresh
        </button>
      </div>

      {err && <div data-testid="det-error" style={{ color: "var(--amber)",
                                          fontSize: 11, marginBottom: 8 }}>{err}</div>}

      {/* Rules table */}
      <div style={{ border: "1px solid var(--border)", borderRadius: 3,
                          overflow: "hidden" }}>
        <div className="mono" style={rowHead}>
          <div>Title</div><div>Source</div><div>Type</div>
          <div>ATT&CK</div><div>State</div><div>Level</div><div>Actions</div>
        </div>
        {rules.map((r) => (
          <div key={r.id} className="mono" style={rowBody}
                   data-testid={`det-row-${r.id}`}>
            <div>
              <div style={{ color: "var(--text)" }}>{r.title}
                {r.capability_not_verdict && (
                  <span title="Capability ≠ Verdict — evidence only" style={{
                      marginLeft: 4, padding: "0 4px",
                      background: "var(--panel2)", color: "var(--amber)",
                      fontSize: 9, border: "1px solid var(--border)",
                      borderRadius: 2 }}>CAPABILITY</span>)}
              </div>
              <div style={{ fontSize: 10, color: "var(--faint)" }}>
                {r.author} · {r.upstream_id}
              </div>
            </div>
            <div style={{ fontSize: 10.5, color: "var(--cyan)" }}>{r.source}</div>
            <div style={{ fontSize: 10.5, color: "var(--text-dim)" }}>
              {r.rule_type}
            </div>
            <div style={{ fontSize: 10, color: "var(--amber)",
                              maxWidth: 160, overflow: "hidden",
                              textOverflow: "ellipsis" }}>
              {(r.attack_techniques || []).join(", ") || "—"}
            </div>
            <RuleStateBadge state={r.state} />
            <div style={{ fontSize: 10, color: "var(--faint)" }}>{r.level || "—"}</div>
            <div style={{ display: "flex", gap: 4 }}>
              {r.enabled ? (
                <button className="btn ghost" style={iconBtn}
                             data-testid={`det-disable-${r.id}`}
                             title="Disable"
                             onClick={async () => {
                                try {
                                  await api.post(`/xdr/detection/rules/${r.id}/disable`);
                                  setRefresh((n) => n + 1);
                                } catch (e) {
                                  alert(JSON.stringify(e?.response?.data?.detail));
                                }
                             }}>
                  <ShieldOff size={11} />
                </button>
              ) : (
                <button className="btn ghost" style={iconBtn}
                             data-testid={`det-enable-${r.id}`}
                             title="Enable"
                             onClick={async () => {
                                try {
                                  await api.post(`/xdr/detection/rules/${r.id}/enable`);
                                  setRefresh((n) => n + 1);
                                } catch (e) {
                                  alert(JSON.stringify(e?.response?.data?.detail));
                                }
                             }}>
                  <ShieldCheck size={11} />
                </button>
              )}
            </div>
          </div>
        ))}
        {rules.length === 0 && !busy && (
          <div data-testid="det-empty" style={emptyRow}>
            NO RULES · run Sync now to populate from the bundled DRL-1.1 snapshot.
          </div>
        )}
      </div>
    </div>
  );
}


function StateBadge({ state, ...p }) {
  const color = state === "SYNCED" ? "var(--mint)"
                          : state === "PARTIAL" ? "var(--amber)"
                          : "var(--faint)";
  const Icon = state === "SYNCED" ? CheckCircle2 : ShieldAlert;
  return (
    <span {...p} style={{ display: "inline-flex", alignItems: "center",
                            gap: 3, padding: "1px 6px", border: `1px solid ${color}`,
                            color, borderRadius: 3, fontSize: 10,
                            fontFamily: "var(--mono)", fontWeight: 700 }}>
      <Icon size={10} /> {state}
    </span>
  );
}


function RuleStateBadge({ state }) {
  const good = state === "ACTIVE" || state === "VALIDATED"
                        || state === "COMPILED" || state === "TESTED"
                        || state === "ENABLED";
  const color = good ? "var(--mint)"
                          : state === "DISABLED" ? "var(--faint)"
                          : "#f87171";
  return (
    <span data-testid={`det-state-${state}`} className="mono" style={{
        padding: "1px 5px", border: `1px solid ${color}`, color,
        borderRadius: 2, fontSize: 9.5 }}>
      {state}
    </span>
  );
}


function Stat({ label, value, testid, color }) {
  return (
    <div data-testid={testid} style={statCard}>
      <div className="mono" style={statLabel}>{label}</div>
      <div className="mono" style={{ ...statValue, color: color || "var(--text)" }}>
        {value}
      </div>
    </div>
  );
}


const statsGrid = {
  display: "grid",
  gridTemplateColumns: "repeat(6, 1fr)",
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
const sectionLabel = {
  fontSize: 10, color: "var(--faint)", textTransform: "uppercase",
  marginBottom: 6, letterSpacing: ".3px",
};
const chip = {
  padding: "1px 5px", fontSize: 9.5,
  border: "1px solid var(--border)", color: "var(--amber)",
  borderRadius: 2, background: "var(--panel2)",
};
const inputStyle = {
  padding: "4px 8px", fontSize: 11, border: "1px solid var(--border)",
  borderRadius: 3, background: "var(--panel2)", color: "var(--text)",
  fontFamily: "var(--mono)",
};
const rowHead = {
  display: "grid",
  gridTemplateColumns: "2fr 0.8fr 0.8fr 1.4fr 0.7fr 0.5fr 0.6fr",
  gap: 6, padding: "4px 8px", background: "var(--panel2)",
  fontSize: 10, color: "var(--faint)", textTransform: "uppercase",
};
const rowBody = {
  display: "grid",
  gridTemplateColumns: "2fr 0.8fr 0.8fr 1.4fr 0.7fr 0.5fr 0.6fr",
  gap: 6, padding: "6px 8px", fontSize: 11,
  color: "var(--text-dim)", borderTop: "1px solid var(--border)",
  alignItems: "center",
};
const iconBtn = { padding: "2px 6px", fontSize: 10 };
const emptyRow = { padding: 10, fontSize: 11, color: "var(--faint)",
                              fontFamily: "var(--mono)" };
const emptyText = { fontSize: 10, color: "var(--faint)",
                                fontFamily: "var(--mono)" };
