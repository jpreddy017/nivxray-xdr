import { useEffect, useState } from "react";
import api from "@/lib/api";
import Header from "@/components/Header";
import {
  BookOpen, RefreshCw, Search, X, ChevronRight, Trash2, Zap, Server,
  ShieldAlert, Info, Copy, Check,
} from "lucide-react";

const SEV_COLOURS = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#e6c34a",
  low:      "#5aa2ff",
  info:     "#8b949e",
  unknown:  "#4a4d51",
};

const VERDICT_COLOURS = {
  Malicious:  "#ef4444",
  Suspicious: "#f97316",
  Benign:     "#4aa890",
  unknown:    "#8b949e",
};

/**
 * KnowledgeBasePage — auto-generated archetypes from the analyst's history.
 * Reads /api/kb/* endpoints. Deterministic clustering + optional LLM synthesis.
 */
export default function KnowledgeBasePage() {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [stats, setStats] = useState(null);
  const [providers, setProviders] = useState([]);
  const [q, setQ] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [mitreFilter, setMitreFilter] = useState("");
  const [loading, setLoading] = useState(false);
  const [rebuilding, setRebuilding] = useState(false);
  const [rebuildInfo, setRebuildInfo] = useState(null);
  const [selected, setSelected] = useState(null);
  const [error, setError] = useState("");

  const load = async () => {
    setLoading(true); setError("");
    try {
      const params = new URLSearchParams();
      if (q) params.set("q", q);
      if (severityFilter) params.set("severity", severityFilter);
      if (mitreFilter) params.set("mitre", mitreFilter);
      params.set("limit", 40);
      const [entries, s, prov] = await Promise.all([
        api.get(`/kb/entries?${params}`),
        api.get(`/kb/stats`),
        api.get(`/system/llm-providers`),
      ]);
      setItems(entries.data.items || []);
      setTotal(entries.data.total || 0);
      setStats(s.data);
      setProviders(prov.data.chain || []);
    } catch (e) {
      setError(e?.response?.data?.detail || e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); /* eslint-disable-next-line */ }, []);

  const rebuild = async ({ synth = true } = {}) => {
    setRebuilding(true); setRebuildInfo(null); setError("");
    try {
      const r = await api.post(`/kb/rebuild`, { synth, limit: 500 });
      setRebuildInfo(r.data);
      await load();
    } catch (e) {
      setError(e?.response?.data?.detail || e.message);
    } finally {
      setRebuilding(false);
    }
  };

  const openEntry = async (slug) => {
    try {
      const r = await api.get(`/kb/entries/${slug}`);
      setSelected(r.data);
    } catch (e) {
      setError(e?.response?.data?.detail || e.message);
    }
  };

  const deleteEntry = async (slug) => {
    if (!window.confirm(`Delete KB entry '${slug}'?`)) return;
    try {
      await api.delete(`/kb/entries/${slug}`);
      setSelected(null);
      load();
    } catch (e) {
      setError(e?.response?.data?.detail || e.message);
    }
  };

  return (
    <>
      <Header />
      <div style={{ padding: 24, maxWidth: 1400, margin: "0 auto" }} data-testid="kb-page">
        {/* HEADER STRIP */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: 18 }}>
          <div>
            <div style={{ fontFamily: "Chivo", fontWeight: 900, fontSize: 26, letterSpacing: "0.05em", color: "var(--text)" }}>
              KNOWLEDGE BASE
            </div>
            <div className="mono" style={{ fontSize: 11, color: "var(--text-mute)", marginTop: 4, letterSpacing: "0.14em" }}>
              AUTO-GENERATED FROM YOUR INVESTIGATION HISTORY · DETERMINISTIC + LLM-SYNTHESISED
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <ProviderChainBadge chain={providers} />
            <button className="nvx-btn sm" onClick={() => rebuild({ synth: false })} disabled={rebuilding}
                    data-testid="btn-kb-rebuild-fast" title="Deterministic rebuild (no LLM — instant)">
              <Zap size={12} /> QUICK REBUILD
            </button>
            <button className="nvx-btn sm primary" onClick={() => rebuild({ synth: true })} disabled={rebuilding}
                    data-testid="btn-kb-rebuild-synth" title="Full rebuild with LLM-synthesised playbooks">
              <RefreshCw size={12} className={rebuilding ? "spin" : ""} />
              {rebuilding ? " REBUILDING…" : " FULL REBUILD"}
            </button>
          </div>
        </div>

        {rebuildInfo && (
          <div className="brut-border" style={{ padding: 10, marginBottom: 14, background: "var(--inset)",
                                                fontFamily: "JetBrains Mono", fontSize: 11,
                                                color: "var(--accent)" }}
               data-testid="kb-rebuild-info">
            ✓ Rebuild complete — {rebuildInfo.entries} entries from {rebuildInfo.buckets} bucket(s),
            {" "}{rebuildInfo.investigations_scanned} investigations scanned in {rebuildInfo.took_ms}ms
          </div>
        )}

        {/* STATS ROW */}
        {stats && stats.total > 0 && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                        gap: 10, marginBottom: 14 }} data-testid="kb-stats-row">
            <StatCard label="TOTAL ENTRIES" value={stats.total} />
            <StatCard label="CRITICAL" value={stats.by_severity?.critical || 0} colour={SEV_COLOURS.critical} />
            <StatCard label="HIGH" value={stats.by_severity?.high || 0} colour={SEV_COLOURS.high} />
            <StatCard label="MALICIOUS" value={stats.by_verdict?.Malicious || 0} colour={VERDICT_COLOURS.Malicious} />
            <StatCard label="TOP MITRE" value={stats.top_mitre?.[0]?.id || "—"} />
          </div>
        )}

        {/* SEARCH + FILTER STRIP */}
        <div style={{ display: "flex", gap: 8, marginBottom: 14, flexWrap: "wrap" }}>
          <div style={{ position: "relative", flex: 1, minWidth: 240 }}>
            <Search size={12} style={{ position: "absolute", left: 10, top: 10, color: "var(--text-mute)" }} />
            <input className="nvx-input" style={{ paddingLeft: 30, width: "100%" }} value={q}
                   onChange={(e) => setQ(e.target.value)}
                   onKeyDown={(e) => e.key === "Enter" && load()}
                   placeholder="search title / summary / MITRE…" data-testid="kb-search-input" />
          </div>
          <select className="nvx-input" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}
                  onBlur={load} data-testid="kb-severity-filter">
            <option value="">any severity</option>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
            <option value="info">info</option>
          </select>
          <input className="nvx-input" value={mitreFilter} onChange={(e) => setMitreFilter(e.target.value)}
                 onKeyDown={(e) => e.key === "Enter" && load()}
                 placeholder="MITRE ID (e.g. T1059.001)"
                 data-testid="kb-mitre-filter" style={{ width: 200 }} />
          <button className="nvx-btn sm ghost" onClick={load} data-testid="btn-kb-search">
            APPLY
          </button>
        </div>

        {error && (
          <div style={{ padding: 10, background: "rgba(239,68,68,0.1)", border: "1px solid var(--high)",
                        color: "var(--high)", fontFamily: "JetBrains Mono", fontSize: 11, marginBottom: 14 }}
               data-testid="kb-error">
            ERROR: {error}
          </div>
        )}

        {/* ENTRIES GRID */}
        {loading ? (
          <div style={{ padding: 40, textAlign: "center", color: "var(--text-mute)", fontFamily: "JetBrains Mono" }}>
            LOADING…
          </div>
        ) : items.length === 0 ? (
          <EmptyState onRebuild={() => rebuild({ synth: false })} />
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(340px, 1fr))",
                        gap: 12, marginBottom: 30 }} data-testid="kb-entries-grid">
            {items.map((e) => (
              <EntryCard key={e.id} entry={e} onOpen={() => openEntry(e.slug)} />
            ))}
          </div>
        )}
        <div className="mono" style={{ fontSize: 10, color: "var(--text-mute)", textAlign: "right" }}>
          {items.length} / {total} entries
        </div>

        {selected && (
          <EntryDrawer entry={selected} onClose={() => setSelected(null)} onDelete={() => deleteEntry(selected.slug)} />
        )}
      </div>
    </>
  );
}


function ProviderChainBadge({ chain }) {
  if (!chain?.length) return null;
  const online = chain.find((c) => c.kind === "online");
  const offline = chain.find((c) => c.kind === "offline");
  return (
    <div className="brut-border" style={{
      padding: "6px 10px", fontFamily: "JetBrains Mono", fontSize: 10,
      color: "var(--text-dim)", background: "var(--inset)",
      display: "flex", alignItems: "center", gap: 8,
    }} data-testid="kb-provider-chain">
      <Server size={11} color="var(--accent)" />
      <span style={{ color: "var(--accent)" }}>ONLINE:</span> {online?.name || "—"}
      <span style={{ color: "var(--border-strong)" }}>→</span>
      <span style={{ color: "var(--warn)" }}>OFFLINE:</span> {offline?.name || "—"}
    </div>
  );
}


function StatCard({ label, value, colour }) {
  return (
    <div className="brut-border" style={{
      padding: "10px 14px", background: "var(--surface)",
      fontFamily: "JetBrains Mono",
    }}>
      <div style={{ fontSize: 9, color: "var(--text-mute)", letterSpacing: "0.2em" }}>{label}</div>
      <div style={{ fontSize: 22, fontWeight: 700, color: colour || "var(--text)", marginTop: 4 }}>{value}</div>
    </div>
  );
}


function EntryCard({ entry, onOpen }) {
  const sev = SEV_COLOURS[entry.severity] || SEV_COLOURS.unknown;
  const verdictC = VERDICT_COLOURS[entry.verdict] || VERDICT_COLOURS.unknown;
  return (
    <div className="brut-border" style={{
      padding: 14, background: "var(--surface)", cursor: "pointer",
      transition: "border-color 0.15s",
    }}
      onClick={onOpen} data-testid={`kb-entry-${entry.slug}`}
      onMouseEnter={(e) => e.currentTarget.style.borderColor = "var(--accent)"}
      onMouseLeave={(e) => e.currentTarget.style.borderColor = ""}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
        <span style={{ padding: "2px 8px", fontSize: 10, fontFamily: "JetBrains Mono",
                       background: sev, color: "#000", fontWeight: 700, textTransform: "uppercase",
                       letterSpacing: "0.14em" }}>
          {entry.severity}
        </span>
        <span style={{ padding: "2px 8px", fontSize: 10, fontFamily: "JetBrains Mono",
                       border: `1px solid ${verdictC}`, color: verdictC, textTransform: "uppercase",
                       letterSpacing: "0.14em" }}>
          {entry.verdict || "unknown"}
        </span>
      </div>
      <div style={{ fontSize: 14, fontWeight: 700, color: "var(--text)", marginBottom: 6, minHeight: 40 }}>
        {entry.title || "(untitled)"}
      </div>
      <div style={{ fontSize: 12, color: "var(--text-dim)", lineHeight: 1.5, marginBottom: 10, minHeight: 54 }}>
        {(entry.summary || "").slice(0, 140)}
        {(entry.summary || "").length > 140 && "…"}
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginBottom: 8 }}>
        {(entry.mitre_ids || []).slice(0, 5).map((m) => (
          <span key={m} className="mono" style={{
            fontSize: 9, padding: "1px 6px", border: "1px solid var(--warn)",
            color: "var(--warn)", letterSpacing: "0.08em",
          }}>{m}</span>
        ))}
      </div>
      <div className="mono" style={{ fontSize: 10, color: "var(--text-mute)",
                                     display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span>{entry.investigation_count} investigation{entry.investigation_count !== 1 ? "s" : ""}</span>
        <ChevronRight size={12} />
      </div>
    </div>
  );
}


function EmptyState({ onRebuild }) {
  return (
    <div className="brut-border" style={{
      padding: 40, textAlign: "center", fontFamily: "JetBrains Mono", background: "var(--surface)",
    }} data-testid="kb-empty-state">
      <BookOpen size={36} style={{ color: "var(--text-mute)", marginBottom: 12 }} />
      <div style={{ fontSize: 14, color: "var(--text)", marginBottom: 6 }}>
        Your Knowledge Base is empty.
      </div>
      <div style={{ fontSize: 11, color: "var(--text-mute)", marginBottom: 16 }}>
        Click <b>QUICK REBUILD</b> to auto-generate archetypes from your investigation history.
      </div>
      <button className="nvx-btn sm primary" onClick={onRebuild}>
        <Zap size={11} /> QUICK REBUILD
      </button>
    </div>
  );
}


function EntryDrawer({ entry, onClose, onDelete }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(JSON.stringify(entry, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  const sev = SEV_COLOURS[entry.severity] || SEV_COLOURS.unknown;
  return (
    <div style={{
      position: "fixed", top: 0, right: 0, width: 520, height: "100vh",
      background: "var(--surface)", borderLeft: "1px solid var(--border)",
      zIndex: 100, overflowY: "auto", padding: 20,
    }} data-testid="kb-entry-drawer">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
        <span style={{ padding: "4px 12px", background: sev, color: "#000", fontWeight: 700,
                       fontFamily: "JetBrains Mono", fontSize: 11, letterSpacing: "0.14em" }}>
          {entry.severity?.toUpperCase()}
        </span>
        <div style={{ display: "flex", gap: 6 }}>
          <button className="nvx-btn sm ghost" onClick={copy} data-testid="btn-kb-copy">
            {copied ? <Check size={11} /> : <Copy size={11} />} JSON
          </button>
          <button className="nvx-btn sm ghost" onClick={onDelete} data-testid="btn-kb-delete">
            <Trash2 size={11} /> DELETE
          </button>
          <button className="nvx-btn sm ghost" onClick={onClose} data-testid="btn-kb-close">
            <X size={12} />
          </button>
        </div>
      </div>

      <h2 style={{ fontSize: 18, color: "var(--text)", margin: "0 0 8px 0" }} data-testid="kb-drawer-title">
        {entry.title || "(untitled)"}
      </h2>
      <div style={{ fontSize: 13, color: "var(--text-dim)", lineHeight: 1.6, marginBottom: 16 }}>
        {entry.summary}
      </div>

      <DField label="MITRE Techniques">
        <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
          {(entry.mitre_ids || []).map((m) => (
            <span key={m} className="mono" style={{
              fontSize: 10, padding: "2px 8px", border: "1px solid var(--warn)",
              color: "var(--warn)", letterSpacing: "0.08em",
            }}>{m}</span>
          )) || "—"}
        </div>
      </DField>

      {entry.tactics?.length > 0 && (
        <DField label="ATT&CK Tactics">{entry.tactics.join(" · ")}</DField>
      )}

      {entry.lolbins?.length > 0 && (
        <DField label="LOLBins observed">
          <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
            {entry.lolbins.map((l) => (
              <span key={l} className="mono" style={{
                fontSize: 10, padding: "2px 8px", background: "var(--inset)",
                color: "var(--warn)", border: "1px solid var(--warn)",
              }}>{l}</span>
            ))}
          </div>
        </DField>
      )}

      {entry.common_chains?.length > 0 && (
        <DField label="Common decode chains">
          {entry.common_chains.map((c, i) => (
            <div key={i} className="mono" style={{ fontSize: 11, color: "var(--text-dim)",
                                                   padding: "3px 0", borderBottom: i < entry.common_chains.length - 1 ? "1px dashed var(--border)" : "none" }}>
              {c}
            </div>
          ))}
        </DField>
      )}

      {entry.playbook_steps?.length > 0 && (
        <DField label="Triage playbook" icon={<ShieldAlert size={11} />}>
          <ol style={{ paddingLeft: 18, margin: 0, color: "var(--text)" }}>
            {entry.playbook_steps.map((step, i) => (
              <li key={i} style={{ fontSize: 12, marginBottom: 8, lineHeight: 1.5 }}>
                {step}
              </li>
            ))}
          </ol>
        </DField>
      )}

      {entry.hunt_queries?.length > 0 && (
        <DField label="Hunt opportunities">
          {entry.hunt_queries.map((h, i) => (
            <div key={i} style={{ fontSize: 11, color: "var(--text-dim)", padding: "3px 0",
                                   fontFamily: "JetBrains Mono" }}>· {h}</div>
          ))}
        </DField>
      )}

      <IocSection iocs={entry.iocs} />

      {entry.samples?.length > 0 && (
        <DField label="Sample investigations">
          {entry.samples.map((s, i) => (
            <div key={i} className="mono" style={{
              fontSize: 10, padding: 6, background: "var(--inset)", marginBottom: 4,
              border: "1px solid var(--border)", color: "var(--text-dim)",
            }}>
              <div style={{ color: "var(--accent)" }}>
                {s.engine || "unknown"} · {s.confidence}% · {s.verdict || "unknown"}
              </div>
              <div style={{ marginTop: 4, wordBreak: "break-all", whiteSpace: "pre-wrap" }}>
                {s.input_preview.slice(0, 140)}
              </div>
            </div>
          ))}
        </DField>
      )}

      {entry.warnings?.length > 0 && (
        <DField label="Synthesizer warnings" icon={<Info size={11} />}>
          {entry.warnings.map((w, i) => (
            <div key={i} className="mono" style={{ fontSize: 10, color: "var(--warn)",
                                                   padding: "2px 0" }}>· {w}</div>
          ))}
        </DField>
      )}

      <div className="mono" style={{ fontSize: 9, color: "var(--text-mute)", marginTop: 20 }}>
        slug: {entry.slug}<br />
        fingerprint: {entry.fingerprint}<br />
        first_seen: {entry.first_seen}<br />
        refreshed_at: {entry.refreshed_at}
      </div>
    </div>
  );
}


function IocSection({ iocs }) {
  if (!iocs) return null;
  const kinds = [
    ["urls", "URLs"],
    ["ips", "IPs"],
    ["domains", "Domains"],
    ["files", "Files"],
    ["hashes", "Hashes"],
  ];
  const has = kinds.some(([k]) => Object.keys(iocs[k] || {}).length);
  if (!has) return null;
  return (
    <DField label="Rollup IOCs">
      {kinds.map(([k, name]) => {
        const entries = Object.entries(iocs[k] || {});
        if (!entries.length) return null;
        return (
          <div key={k} style={{ marginBottom: 8 }}>
            <div className="mono" style={{ fontSize: 9, color: "var(--text-mute)", marginBottom: 3, letterSpacing: "0.14em" }}>{name}</div>
            {entries.slice(0, 6).map(([v, count]) => (
              <div key={v} className="mono" style={{ fontSize: 10, color: "var(--text-dim)",
                                                     display: "flex", justifyContent: "space-between",
                                                     padding: "2px 0" }}>
                <span style={{ wordBreak: "break-all" }}>{v}</span>
                <span style={{ color: "var(--warn)" }}>×{count}</span>
              </div>
            ))}
          </div>
        );
      })}
    </DField>
  );
}


function DField({ label, icon, children }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <div className="mono" style={{
        fontSize: 9, color: "var(--text-mute)", letterSpacing: "0.2em",
        marginBottom: 6, display: "flex", alignItems: "center", gap: 4,
      }}>
        {icon} {label.toUpperCase()}
      </div>
      <div>{children}</div>
    </div>
  );
}
