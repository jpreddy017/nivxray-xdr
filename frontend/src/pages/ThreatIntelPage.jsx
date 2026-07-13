import { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import Header from "@/components/Header";
import api from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { RefreshCw, Cloud, CheckCircle2, AlertCircle, Circle, Search, Database } from "lucide-react";

const SEV_LABEL = { critical: "critical", high: "high", medium: "medium", low: "low" };

export default function ThreatIntelPage() {
  const { user } = useAuth();
  const [sources, setSources] = useState([]);
  const [stats, setStats] = useState(null);
  const [syncing, setSyncing] = useState({});
  const [syncAll, setSyncAll] = useState(false);

  // browser state
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [q, setQ] = useState("");
  const [kind, setKind] = useState("");
  const [source, setSource] = useState("");
  const [severity, setSeverity] = useState("");

  const load = async () => {
    const [s, st] = await Promise.all([
      api.get("/threat-intel/sources"),
      api.get("/threat-intel/stats"),
    ]);
    setSources(s.data);
    setStats(st.data);
  };

  const loadItems = async () => {
    const params = { q, kind, source, severity, limit: 100 };
    const r = await api.get("/threat-intel/iocs", { params });
    setItems(r.data.items);
    setTotal(r.data.total);
  };

  useEffect(() => { load(); }, []);
  useEffect(() => { loadItems(); }, [q, kind, source, severity]);

  if (!user) return <Navigate to="/login" replace />;

  const doSync = async (sid) => {
    setSyncing((s) => ({ ...s, [sid]: true }));
    try {
      await api.post(`/threat-intel/sync/${sid}`);
    } catch (_) {}
    await load();
    await loadItems();
    setSyncing((s) => ({ ...s, [sid]: false }));
  };

  const doSyncAll = async () => {
    setSyncAll(true);
    try { await api.post("/threat-intel/sync-all"); } catch (_) {}
    await load();
    await loadItems();
    setSyncAll(false);
  };

  const bulk = sources.filter((s) => s.bulk);
  const lookup = sources.filter((s) => !s.bulk);

  return (
    <div className="App">
      <Header />
      <div style={{ padding: 24, display: "grid", gap: 22, maxWidth: 1500, margin: "0 auto" }}>
        {/* Header */}
        <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
          <div>
            <div className="mono" style={{ fontSize: 11, color: "var(--warn)", letterSpacing: "0.2em", marginBottom: 6 }}>
              /// THREAT INTELLIGENCE
            </div>
            <h1 style={{ fontFamily: "Chivo", fontWeight: 900, fontSize: 34, margin: 0, letterSpacing: "-0.01em" }}>
              IOC<span style={{ color: "var(--accent)" }}> ·</span> Database
            </h1>
            <div className="mono" style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 6 }}>
              {stats && (
                <>
                  <span data-testid="ti-total">{stats.total.toLocaleString()} indicators</span>
                  <span style={{ margin: "0 10px", color: "var(--border-strong)" }}>│</span>
                  <span className="badge high" style={{ marginRight: 6 }}>{stats.critical.toLocaleString()} critical</span>
                  <span className="badge medium" style={{ marginRight: 6 }}>{stats.high.toLocaleString()} high</span>
                  <span className="badge low" style={{ marginRight: 6 }}>{stats.medium.toLocaleString()} medium</span>
                  <span className="badge neutral">{stats.low.toLocaleString()} low</span>
                </>
              )}
            </div>
          </div>
          {user?.role === "admin" && (
            <button className="nvx-btn primary" onClick={doSyncAll} disabled={syncAll} data-testid="btn-sync-all">
              <RefreshCw size={13} className={syncAll ? "spin" : ""} /> {syncAll ? "SYNCING…" : "SYNC ALL SOURCES"}
            </button>
          )}
        </div>

        {/* Sources — bulk feeds */}
        <section className="brut-border" style={{ background: "var(--surface)" }}>
          <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
            <div className="mono" style={{ fontSize: 11, letterSpacing: "0.24em", color: "var(--accent)", display: "flex", alignItems: "center", gap: 8 }}>
              <Cloud size={13} /> THREAT-INTEL SOURCE SYNC
              <span className="mono" style={{ color: "var(--text-mute)", letterSpacing: "0.06em", fontSize: 11, marginLeft: 8, fontWeight: 400 }}>
                One click · pulls curated indicators from every source that offers a bulk feed
              </span>
            </div>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 0 }}>
            {bulk.map((s, i) => (
              <SourceCard
                key={s.id}
                s={s}
                syncing={syncing[s.id]}
                canSync={user?.role === "admin"}
                onSync={() => doSync(s.id)}
                borderRight={i % 2 === 0}
                testId={`source-${s.id}`}
              />
            ))}
            {lookup.map((s, i) => (
              <SourceCard
                key={s.id}
                s={s}
                lookupOnly
                borderRight={(bulk.length + i) % 2 === 0}
                testId={`source-${s.id}`}
              />
            ))}
          </div>
        </section>

        {/* IOC browser */}
        <section className="brut-border" style={{ background: "var(--surface)" }}>
          <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)", display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <div className="mono" style={{ fontSize: 11, letterSpacing: "0.24em", color: "var(--accent)", display: "flex", alignItems: "center", gap: 8 }}>
              <Database size={13} /> INDICATORS
            </div>
            <span className="badge neutral" data-testid="ti-visible">{total.toLocaleString()} match</span>
            <div style={{ flex: 1 }} />
            <div style={{ position: "relative" }}>
              <Search size={13} color="var(--text-mute)" style={{ position: "absolute", left: 8, top: 10 }} />
              <input
                className="nvx-input"
                placeholder="Search value…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                data-testid="ti-search"
                style={{ paddingLeft: 26, width: 200 }}
              />
            </div>
            <select className="nvx-input" value={kind} onChange={(e) => setKind(e.target.value)} data-testid="ti-kind-filter" style={{ width: 110 }}>
              <option value="">all kinds</option>
              <option value="ip">ip</option>
              <option value="domain">domain</option>
              <option value="url">url</option>
              <option value="md5">md5</option>
              <option value="sha1">sha1</option>
              <option value="sha256">sha256</option>
            </select>
            <select className="nvx-input" value={source} onChange={(e) => setSource(e.target.value)} data-testid="ti-source-filter" style={{ width: 150 }}>
              <option value="">all sources</option>
              {sources.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
            </select>
            <select className="nvx-input" value={severity} onChange={(e) => setSeverity(e.target.value)} data-testid="ti-severity-filter" style={{ width: 120 }}>
              <option value="">all severities</option>
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
            </select>
          </div>

          <div style={{ maxHeight: "60vh", overflowY: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead style={{ position: "sticky", top: 0, background: "var(--inset)" }}>
                <tr style={{ borderBottom: "1px solid var(--border)" }}>
                  <Th w="70px">KIND</Th>
                  <Th>VALUE</Th>
                  <Th w="90px">SEVERITY</Th>
                  <Th w="180px">SOURCE</Th>
                  <Th w="180px">TAGS</Th>
                  <Th w="150px">LAST SEEN</Th>
                </tr>
              </thead>
              <tbody>
                {items.map((it, idx) => (
                  <tr key={idx} style={{ borderBottom: "1px solid var(--border)" }} data-testid={`ti-row-${idx}`}>
                    <Td><span className="badge neutral">{it.kind}</span></Td>
                    <Td style={{ wordBreak: "break-all", color: "var(--text)" }}>{it.value}</Td>
                    <Td><span className={`badge ${SEV_LABEL[it.severity] || "neutral"}`}>{it.severity}</span></Td>
                    <Td>{it.source}</Td>
                    <Td>
                      {(it.tags || []).slice(0, 3).map((t, i) => (
                        <span key={i} className="badge neutral" style={{ marginRight: 3 }}>{t}</span>
                      ))}
                    </Td>
                    <Td>{(it.last_seen || "").slice(0, 19).replace("T", " ")}</Td>
                  </tr>
                ))}
                {items.length === 0 && (
                  <tr>
                    <td colSpan={6} className="mono" style={{ padding: 30, textAlign: "center", color: "var(--text-mute)", fontSize: 12 }}>
                      No indicators — sync a source above to populate the database.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>

      <style>{`.spin { animation: spin 1s linear infinite; } @keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}

function SourceCard({ s, syncing, canSync, lookupOnly, onSync, borderRight, testId }) {
  const okIcon = () => {
    if (s.last_status === "error") return <AlertCircle size={14} color="var(--high)" />;
    if (s.last_status === "ok") return <CheckCircle2 size={14} color="var(--accent)" />;
    if (!s.configured) return <Circle size={14} color="var(--warn)" />;
    return <Circle size={14} color="var(--text-mute)" />;
  };
  return (
    <div
      className="fade-in"
      data-testid={testId}
      style={{
        padding: "14px 16px",
        borderBottom: "1px solid var(--border)",
        borderRight: borderRight ? "1px solid var(--border)" : "none",
        display: "flex",
        alignItems: "flex-start",
        gap: 12,
      }}
    >
      <div style={{ marginTop: 3 }}>{okIcon()}</div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <div className="mono" style={{ fontSize: 13, color: "var(--text)", fontWeight: 700 }}>{s.label}</div>
          {lookupOnly && <span className="badge warn">LOOKUP ONLY</span>}
          {!s.configured && !lookupOnly && s.needs_key && <span className="badge warn">KEY MISSING</span>}
        </div>
        <div className="mono" style={{ fontSize: 11, color: "var(--text-mute)", marginTop: 4 }}>
          {s.description}
        </div>
        {!lookupOnly && (
          <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 6, display: "flex", gap: 12, flexWrap: "wrap" }}>
            <span>
              {s.last_sync ? (
                <>Last sync {(s.last_sync || "").slice(0, 19).replace("T", " ")} · {s.last_new} new · {s.last_updated} updated</>
              ) : (
                <>Never synced</>
              )}
            </span>
            {s.total_indicators > 0 && <span style={{ color: "var(--accent)" }}>{s.total_indicators.toLocaleString()} stored</span>}
            {s.last_error && <span style={{ color: "var(--high)" }}>Error: {s.last_error}</span>}
          </div>
        )}
      </div>
      {!lookupOnly && (
        <button
          className="nvx-btn sm"
          disabled={syncing || !canSync || !s.configured}
          onClick={onSync}
          data-testid={`sync-${s.id}`}
          title={!canSync ? "Admin only" : !s.configured ? "Configure key first" : "Sync now"}
        >
          <RefreshCw size={12} className={syncing ? "spin" : ""} /> {syncing ? "…" : "SYNC"}
        </button>
      )}
    </div>
  );
}

function Th({ children, w }) {
  return (
    <th className="mono" style={{
      textAlign: "left", padding: "8px 12px", fontSize: 10, letterSpacing: "0.16em",
      color: "var(--text-mute)", fontWeight: 700, width: w,
    }}>{children}</th>
  );
}
function Td({ children, style }) {
  return <td className="mono" style={{ padding: "8px 12px", fontSize: 11, color: "var(--text-dim)", verticalAlign: "middle", ...style }}>{children}</td>;
}
