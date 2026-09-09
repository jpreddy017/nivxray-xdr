/**
 * XdrKbPage — Native NivXRay XDR Knowledge Base surface.
 *
 * Consumes the authoritative NivXRay backend `/api/kb/*` (routers/kb.py)
 * — never re-implements the KB engine.  Provides:
 *   • KB stats  (`/api/kb/stats`)
 *   • Entry list & search  (`/api/kb/entries`, `/api/kb/search`)
 *   • Entry viewer  (`/api/kb/entries/{slug}`)
 *
 * On backend error the panel shows the honest state — never fabricates.
 */
import React, { useEffect, useMemo, useState } from "react";
import { BookOpen, Search, RefreshCcw, FileText } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import api from "@/lib/api";


export default function XdrKbPage() {
  const [stats,   setStats]   = useState(null);
  const [entries, setEntries] = useState([]);
  const [err,     setErr]     = useState(null);
  const [busy,    setBusy]    = useState(false);
  const [q,       setQ]       = useState("");
  const [refresh, setRefresh] = useState(0);
  const [openEntry, setOpenEntry] = useState(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setBusy(true); setErr(null);
      try {
        const [s, e] = await Promise.all([
          api.get("/kb/stats"),
          api.get("/kb/entries", { params: { limit: 500 }}),
        ]);
        if (cancelled) return;
        setStats(s?.data || null);
        const rows = e?.data?.entries || e?.data || [];
        setEntries(Array.isArray(rows) ? rows : []);
      } catch (x) {
        setErr(x?.response?.data?.detail || x?.message || "load failed");
      } finally {
        if (!cancelled) setBusy(false);
      }
    })();
    return () => { cancelled = true; };
  }, [refresh]);

  const filtered = useMemo(() => {
    if (!q) return entries;
    const qs = q.toLowerCase();
    return entries.filter((e) =>
      `${e.title || ""} ${e.slug || ""} ${(e.tags || []).join(" ")}`
        .toLowerCase().includes(qs));
  }, [entries, q]);

  const viewEntry = async (slug) => {
    setErr(null);
    try {
      const r = await api.get(`/kb/entries/${encodeURIComponent(slug)}`);
      setOpenEntry(r?.data || null);
    } catch (x) {
      setErr(x?.response?.data?.detail || x?.message);
    }
  };

  return (
    <XdrShell>
      <div data-testid="xdr-kb-page">
        <div style={{ display: "flex", alignItems: "center", gap: 10,
                                marginBottom: 6 }}>
          <BookOpen size={16} style={{ color: "var(--nx-purple)" }} />
          <h1 className="page-h1" style={{ margin: 0 }}>Knowledge Base</h1>
          <span style={{ flex: 1 }} />
          <button className="btn ghost" disabled={busy}
                        onClick={() => setRefresh((n) => n + 1)}
                        data-testid="xdr-kb-refresh"
                        style={{ padding: "6px 12px", fontSize: 12,
                                        opacity: busy ? 0.5 : 1 }}>
            <RefreshCcw size={12} /> {busy ? "Loading…" : "Refresh"}
          </button>
        </div>
        <div className="page-sub" style={{ marginBottom: 20 }}>
          Operational knowledge base — playbooks, runbooks and standard
          operating procedures for the SOC.
        </div>

        {/* Stats */}
        <div style={statsGrid}>
          <Stat label="Total entries" value={stats?.total_entries ?? entries.length}
                    testid="xdr-kb-stat-total" />
          <Stat label="Distinct tags" value={stats?.distinct_tags ?? "—"}
                    testid="xdr-kb-stat-tags" color="var(--cyan)" />
          <Stat label="Last update" value={stats?.last_update?.slice(0,10) ?? "—"}
                    testid="xdr-kb-stat-updated" />
        </div>

        {err && <div style={errBox} data-testid="xdr-kb-error">{err}</div>}

        {/* Search */}
        <div style={{ display: "flex", gap: 6, marginBottom: 8,
                                alignItems: "center" }}>
          <Search size={12} style={{ color: "var(--faint)" }} />
          <input value={q} onChange={(e) => setQ(e.target.value)}
                       placeholder="Search KB entries…"
                       data-testid="xdr-kb-search"
                       style={inputStyle} />
        </div>

        <div style={{ color: "var(--faint)", fontSize: 10.5,
                                fontFamily: "var(--mono)", marginBottom: 6 }}>
          {busy ? "Loading…" : `${filtered.length} of ${entries.length} entries`}
        </div>

        {/* Entries table */}
        <div style={{ border: "1px solid var(--border)", borderRadius: 3,
                                overflow: "hidden" }}>
          <div style={rowHead}>
            <div>Slug</div><div>Title</div><div>Tags</div><div>Updated</div>
          </div>
          {filtered.map((e) => (
            <div key={e.slug || e.id} style={rowBody}
                       data-testid={`xdr-kb-entry-${e.slug || e.id}`}
                       onClick={() => viewEntry(e.slug || e.id)}>
              <div style={{ color: "var(--cyan)" }}>{e.slug || e.id}</div>
              <div>{e.title || "—"}</div>
              <div style={{ color: "var(--amber)", fontSize: 10 }}>
                {(e.tags || []).slice(0, 4).join(", ") || "—"}
              </div>
              <div style={{ color: "var(--faint)", fontSize: 10 }}>
                {(e.updated_at || e.created_at || "").slice(0, 10) || "—"}
              </div>
            </div>
          ))}
          {!busy && filtered.length === 0 && (
            <div style={emptyRow}>NO ENTRIES — the KB is empty or unreachable</div>
          )}
        </div>

        {/* Entry drawer */}
        {openEntry && (
          <div style={drawerBackdrop} onClick={() => setOpenEntry(null)}>
            <div style={drawerPanel} onClick={(e) => e.stopPropagation()}
                       data-testid="xdr-kb-entry-drawer">
              <div style={{ display: "flex", alignItems: "center",
                                      gap: 8, marginBottom: 8 }}>
                <FileText size={12} style={{ color: "var(--cyan)" }} />
                <b>{openEntry.title || openEntry.slug}</b>
                <span style={{ flex: 1 }} />
                <button className="btn ghost" onClick={() => setOpenEntry(null)}
                              style={{ padding: "3px 8px", fontSize: 11 }}>Close</button>
              </div>
              <div style={{ color: "var(--faint)", fontSize: 10.5,
                                      fontFamily: "var(--mono)", marginBottom: 8 }}>
                {openEntry.slug}
              </div>
              <pre style={{ background: "var(--panel2)", padding: 10,
                                        borderRadius: 3, overflow: "auto",
                                        fontSize: 11, color: "var(--text-dim)",
                                        whiteSpace: "pre-wrap", maxHeight: "60vh" }}>
                {openEntry.content || openEntry.body ||
                    JSON.stringify(openEntry, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>
    </XdrShell>
  );
}

function Stat({ label, value, testid, color }) {
  return (
    <div data-testid={testid} style={statCard}>
      <div style={statLabel}>{label}</div>
      <div style={{ ...statValue, color: color || "var(--text)" }}>{value}</div>
    </div>
  );
}

const statsGrid = { display: "grid", gridTemplateColumns: "repeat(3, 1fr)",
                                    gap: 8, marginBottom: 14 };
const statCard = { padding: 10, border: "1px solid var(--border)",
                                   borderRadius: 3, background: "var(--panel2)" };
const statLabel = { fontSize: 9.5, fontFamily: "var(--mono)",
                                     color: "var(--faint)", textTransform: "uppercase",
                                     marginBottom: 4, letterSpacing: ".3px", fontWeight: 700 };
const statValue = { fontSize: 20, fontWeight: 700, fontFamily: "var(--mono)" };
const inputStyle = { flex: 1, padding: "4px 8px",
                                     background: "var(--panel2)",
                                     border: "1px solid var(--border)",
                                     color: "var(--text)", fontSize: 11,
                                     borderRadius: 3, fontFamily: "var(--mono)" };
const rowHead = { display: "grid",
                                gridTemplateColumns: "1.5fr 2.5fr 1.5fr 0.8fr",
                                gap: 6, padding: "5px 10px",
                                background: "var(--panel2)", fontSize: 10,
                                color: "var(--faint)", textTransform: "uppercase",
                                fontFamily: "var(--mono)", fontWeight: 700 };
const rowBody = { display: "grid",
                                gridTemplateColumns: "1.5fr 2.5fr 1.5fr 0.8fr",
                                gap: 6, padding: "6px 10px", fontSize: 11,
                                color: "var(--text-dim)",
                                borderTop: "1px solid var(--border)",
                                fontFamily: "var(--mono)", cursor: "pointer" };
const emptyRow = { padding: 12, fontSize: 11, color: "var(--faint)",
                                  fontFamily: "var(--mono)" };
const errBox = { padding: "6px 10px", border: "1px solid var(--amber)",
                             color: "var(--amber)", fontSize: 11,
                             fontFamily: "var(--mono)", borderRadius: 3,
                             marginBottom: 8 };
const drawerBackdrop = {
  position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
  background: "rgba(0,0,0,.6)", display: "flex", alignItems: "center",
  justifyContent: "center", zIndex: 1000,
};
const drawerPanel = {
  width: "min(760px, 90vw)", padding: 16, borderRadius: 3,
  background: "var(--panel)", border: "1px solid var(--border)",
  fontFamily: "var(--mono)",
};
