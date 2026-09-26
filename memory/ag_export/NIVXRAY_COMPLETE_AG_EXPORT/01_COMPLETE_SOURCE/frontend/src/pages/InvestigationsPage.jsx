/**
 * InvestigationsPage — Phase 4 · P1 · Cross-Artifact Correlation.
 *
 * Analyst-facing "Investigations" list. Each row is a first-class
 * Investigation entity (backend `correlations` collection) that groups
 * correlated cases into a single working object.
 *
 * Owner directive (2026-02-15):
 *   "An Investigation is a first-class entity, not a collection of
 *    linked cases."
 */
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import Header from "@/components/Header";
import api from "@/lib/api";
import { Radar, Network, Clock, ShieldAlert, Tag, ChevronRight, Search } from "lucide-react";

const VERDICT_COLOR = {
  Malicious:  "#f87171",
  Suspicious: "#fbbf24",
  Partial:    "#fbbf24",
  Benign:     "#86efac",
  Unknown:    "#94a3b8",
};

function verdictColor(v) {
  return VERDICT_COLOR[v] || VERDICT_COLOR.Unknown;
}

export default function InvestigationsPage() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");
  const [q, setQ] = useState("");

  const load = async () => {
    setLoading(true); setErr("");
    try {
      const r = await api.get("/correlations", { params: { limit: 200 } });
      setItems(r.data.correlations || []);
    } catch (e) { setErr(e?.response?.data?.detail || e.message || String(e)); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const filtered = useMemo(() => {
    if (!q.trim()) return items;
    const s = q.trim().toLowerCase();
    return items.filter(i =>
      (i.name || "").toLowerCase().includes(s)
      || (i.description || "").toLowerCase().includes(s)
      || (i.tags || []).some(t => t.toLowerCase().includes(s)));
  }, [items, q]);

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg,#0b1220)" }}>
      <Header />
      <div style={{ maxWidth: 1280, margin: "0 auto", padding: "28px 24px" }}>
        <PageTitle count={items.length} />
        <SearchBar q={q} setQ={setQ} onRefresh={load} />
        {err && <ErrorBanner err={err} />}
        {loading && !items.length ? (
          <LoadingSkeleton />
        ) : filtered.length === 0 ? (
          <EmptyState />
        ) : (
          <div style={{ display: "grid", gap: 14 }} data-testid="investigations-list">
            {filtered.map(inv => <InvestigationCard key={inv.id} inv={inv} />)}
          </div>
        )}
      </div>
    </div>
  );
}

function PageTitle({ count }) {
  return (
    <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginBottom: 8 }}>
      <Radar size={22} strokeWidth={1.6} style={{ color: "#67e8f9" }} />
      <h1 data-testid="investigations-title"
          style={{ margin: 0, fontFamily: "JetBrains Mono, ui-monospace, monospace",
                   fontSize: 22, fontWeight: 700, color: "#e2e8f0",
                   letterSpacing: "0.06em", textTransform: "uppercase" }}>
        Investigations
      </h1>
      <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 12,
                     color: "#64748b" }}>
        · {count} correlated
      </span>
      <span style={{ marginLeft: "auto", fontSize: 11, color: "#64748b",
                     fontFamily: "JetBrains Mono, monospace",
                     letterSpacing: "0.06em" }}>
        PHASE 4 · P1 · CROSS-ARTIFACT CORRELATION
      </span>
    </div>
  );
}

function SearchBar({ q, setQ, onRefresh }) {
  return (
    <div style={{ display: "flex", gap: 10, alignItems: "center",
                  marginBottom: 20, marginTop: 14 }}>
      <div style={{ flex: 1, position: "relative" }}>
        <Search size={14} style={{ position: "absolute", left: 10, top: "50%",
                                   transform: "translateY(-50%)",
                                   color: "#64748b" }} />
        <input
          data-testid="investigations-search"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search by name, description, or tag…"
          style={{
            width: "100%", padding: "9px 12px 9px 32px", fontSize: 13,
            background: "rgba(2,6,23,0.7)", color: "#e2e8f0",
            border: "1px solid rgba(148,163,184,0.18)", borderRadius: 8,
            fontFamily: "ui-sans-serif, system-ui",
            outline: "none",
          }}
        />
      </div>
      <button
        data-testid="investigations-refresh"
        onClick={onRefresh}
        style={{ padding: "9px 14px", fontSize: 12, fontFamily: "JetBrains Mono, monospace",
                 letterSpacing: "0.08em", textTransform: "uppercase",
                 background: "rgba(34,197,94,0.14)", color: "#86efac",
                 border: "1px solid rgba(34,197,94,0.35)", borderRadius: 7,
                 cursor: "pointer" }}>
        Refresh
      </button>
    </div>
  );
}

function ErrorBanner({ err }) {
  return (
    <div style={{ background: "rgba(248,113,113,0.12)",
                  border: "1px solid rgba(248,113,113,0.35)",
                  color: "#fca5a5", padding: 10, borderRadius: 8,
                  fontSize: 12, marginBottom: 14 }}>
      {err}
    </div>
  );
}

function LoadingSkeleton() {
  return (
    <div style={{ opacity: 0.5, fontSize: 13, color: "#64748b", fontFamily: "monospace" }}>
      Loading investigations…
    </div>
  );
}

function EmptyState() {
  return (
    <div data-testid="investigations-empty"
         style={{ textAlign: "center", padding: "60px 20px",
                  border: "1px dashed rgba(148,163,184,0.18)", borderRadius: 12,
                  background: "rgba(2,6,23,0.4)" }}>
      <Network size={36} strokeWidth={1.4} style={{ color: "#475569", marginBottom: 10 }} />
      <div style={{ fontSize: 15, fontWeight: 600, color: "#cbd5e1", marginBottom: 6,
                    fontFamily: "JetBrains Mono, monospace" }}>
        No investigations yet
      </div>
      <div style={{ fontSize: 12, color: "#64748b", maxWidth: 480, margin: "0 auto",
                    lineHeight: 1.6 }}>
        Investigations group related cases into a single attack story.
        Open a case in <Link to="/history" style={{ color: "#86efac" }}>History</Link>
        and use <b>“Find related cases”</b> to seed your first investigation.
      </div>
    </div>
  );
}

function InvestigationCard({ inv }) {
  const vcol = verdictColor(inv.summary_verdict || inv.verdict);
  return (
    <Link
      data-testid={`investigation-card-${inv.id}`}
      to={`/investigations/${inv.id}`}
      style={{
        display: "block",
        background: "linear-gradient(160deg, rgba(15,23,42,0.85), rgba(2,6,23,0.65))",
        border: "1px solid rgba(148,163,184,0.14)",
        borderRadius: 12, padding: 16, textDecoration: "none",
        color: "#e2e8f0",
        transition: "border-color 200ms ease, transform 200ms ease, box-shadow 200ms ease",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = "rgba(103,232,249,0.4)";
        e.currentTarget.style.transform = "translateY(-1px)";
        e.currentTarget.style.boxShadow = "0 8px 22px rgba(2,6,23,0.5)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = "rgba(148,163,184,0.14)";
        e.currentTarget.style.transform = "translateY(0)";
        e.currentTarget.style.boxShadow = "none";
      }}
    >
      <div style={{ display: "flex", alignItems: "start", gap: 12 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
            <span aria-hidden style={{ width: 8, height: 8, borderRadius: "50%",
                                       background: vcol, boxShadow: `0 0 8px ${vcol}` }} />
            <div style={{ fontSize: 15, fontWeight: 700, color: "#e2e8f0",
                          fontFamily: "JetBrains Mono, monospace",
                          overflow: "hidden", textOverflow: "ellipsis",
                          whiteSpace: "nowrap" }}>
              {inv.name || `Investigation ${inv.id.slice(0, 8)}`}
            </div>
          </div>
          {inv.description && (
            <div style={{ fontSize: 12, color: "#94a3b8", marginBottom: 8, lineHeight: 1.5 }}>
              {inv.description}
            </div>
          )}
          <div style={{ display: "flex", gap: 14, alignItems: "center", flexWrap: "wrap",
                        fontFamily: "JetBrains Mono, monospace", fontSize: 11 }}>
            <Chip icon={<Network size={11} />} label={`${inv.case_count || 0} cases`} tone="cyan" />
            <Chip icon={<ShieldAlert size={11} />}
                  label={`${inv.node_count || 0} nodes · ${inv.edge_count || 0} edges`}
                  tone="amber" />
            {inv.tags && inv.tags.length > 0 && (
              <div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>
                {inv.tags.slice(0, 4).map(t => (
                  <span key={t} style={{ background: "rgba(139,92,246,0.14)",
                                         color: "#c4b5fd", padding: "1px 6px",
                                         borderRadius: 3, fontSize: 10 }}>
                    <Tag size={9} style={{ display: "inline", marginRight: 3, verticalAlign: -1 }} />{t}
                  </span>
                ))}
              </div>
            )}
            <span style={{ marginLeft: "auto", color: "#64748b" }}>
              <Clock size={10} style={{ display: "inline", marginRight: 4, verticalAlign: -1 }} />
              {inv.updated_at ? new Date(inv.updated_at).toLocaleString() : "—"}
            </span>
          </div>
        </div>
        <ChevronRight size={16} style={{ color: "#64748b", flexShrink: 0, marginTop: 2 }} />
      </div>
    </Link>
  );
}

function Chip({ icon, label, tone }) {
  const map = {
    cyan:   { fg: "#67e8f9", bg: "rgba(6,182,212,0.14)", bd: "rgba(6,182,212,0.35)" },
    amber:  { fg: "#fcd34d", bg: "rgba(245,158,11,0.14)", bd: "rgba(245,158,11,0.35)" },
    accent: { fg: "#86efac", bg: "rgba(34,197,94,0.14)", bd: "rgba(34,197,94,0.35)" },
  };
  const c = map[tone] || map.accent;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 5,
                   padding: "2px 8px", borderRadius: 4, fontSize: 10,
                   background: c.bg, color: c.fg,
                   border: `1px solid ${c.bd}`, letterSpacing: "0.04em" }}>
      {icon}{label}
    </span>
  );
}
