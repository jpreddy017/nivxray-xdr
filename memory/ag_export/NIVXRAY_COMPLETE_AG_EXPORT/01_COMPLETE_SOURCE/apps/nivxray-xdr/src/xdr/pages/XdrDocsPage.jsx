/**
 * XdrDocsPage — Native NivXRay XDR Documentation surface.
 *
 * Consumes the authoritative NivXRay backend `/api/docs/*`
 * (routers/docs.py) — never re-implements the docs engine.  Provides:
 *   • Docs stats     (`/api/docs/stats`, `/api/docs/rag/stats`)
 *   • Feature list   (`/api/docs/features`)
 *   • Feature viewer (`/api/docs/features/{id}`)
 *   • Workflow list  (`/api/docs/workflows`)
 *
 * On backend error the panel shows the honest state — never fabricates.
 */
import React, { useEffect, useMemo, useState } from "react";
import { BookOpen, Search, RefreshCcw, FileText, Zap } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import api from "@/lib/api";


export default function XdrDocsPage() {
  const [docsStats, setDocsStats] = useState(null);
  const [ragStats,  setRagStats]  = useState(null);
  const [features,  setFeatures]  = useState([]);
  const [workflows, setWorkflows] = useState([]);
  const [err,       setErr]       = useState(null);
  const [busy,      setBusy]      = useState(false);
  const [tab,       setTab]       = useState("features");
  const [q,         setQ]         = useState("");
  const [refresh,   setRefresh]   = useState(0);
  const [openFeat,  setOpenFeat]  = useState(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setBusy(true); setErr(null);
      try {
        const [s, r, f, w] = await Promise.all([
          api.get("/docs/stats").catch(() => null),
          api.get("/docs/rag/stats").catch(() => null),
          api.get("/docs/features").catch(() => null),
          api.get("/docs/workflows").catch(() => null),
        ]);
        if (cancelled) return;
        setDocsStats(s?.data || null);
        setRagStats(r?.data || null);
        setFeatures(f?.data?.features || f?.data || []);
        setWorkflows(w?.data?.workflows || w?.data || []);
      } catch (x) {
        setErr(x?.response?.data?.detail || x?.message || "load failed");
      } finally { if (!cancelled) setBusy(false); }
    })();
    return () => { cancelled = true; };
  }, [refresh]);

  const filteredFeat = useMemo(() => {
    if (!q) return features;
    const qs = q.toLowerCase();
    return features.filter((e) =>
      `${e.title || e.name || ""} ${e.id || ""} ${e.description || ""}`
        .toLowerCase().includes(qs));
  }, [features, q]);

  const filteredWf = useMemo(() => {
    if (!q) return workflows;
    const qs = q.toLowerCase();
    return workflows.filter((e) =>
      `${e.title || e.name || ""} ${e.id || ""}`.toLowerCase().includes(qs));
  }, [workflows, q]);

  const viewFeature = async (id) => {
    setErr(null);
    try {
      const r = await api.get(`/docs/features/${encodeURIComponent(id)}`);
      setOpenFeat(r?.data || null);
    } catch (x) { setErr(x?.response?.data?.detail || x?.message); }
  };

  return (
    <XdrShell>
      <div data-testid="xdr-docs-page">
        <div style={{ display: "flex", alignItems: "center", gap: 10,
                                marginBottom: 6 }}>
          <FileText size={16} style={{ color: "var(--nx-purple)" }} />
          <h1 className="page-h1" style={{ margin: 0 }}>Documentation</h1>
          <span style={{ flex: 1 }} />
          <a href={`${(import.meta.env.VITE_XDR_API || "")}/docs`}
                target="_blank" rel="noreferrer"
                className="btn ghost" style={{ padding: "6px 12px", fontSize: 12,
                                                              textDecoration: "none" }}
                data-testid="xdr-docs-openapi-link">
            <BookOpen size={12} /> OpenAPI Explorer
          </a>
          <button className="btn ghost" disabled={busy}
                        onClick={() => setRefresh((n) => n + 1)}
                        data-testid="xdr-docs-refresh"
                        style={{ padding: "6px 12px", fontSize: 12,
                                        opacity: busy ? 0.5 : 1 }}>
            <RefreshCcw size={12} /> {busy ? "Loading…" : "Refresh"}
          </button>
        </div>
        <div className="page-sub" style={{ marginBottom: 20 }}>
          Product documentation — features, workflows and searchable
          knowledge articles for the platform.
        </div>

        <div style={statsGrid}>
          <Stat label="Docs total"  value={docsStats?.total ?? "—"}
                    testid="xdr-docs-stat-total" />
          <Stat label="Features"    value={features.length}
                    testid="xdr-docs-stat-features" color="var(--cyan)" />
          <Stat label="Workflows"   value={workflows.length}
                    testid="xdr-docs-stat-workflows" color="var(--amber)" />
          <Stat label="RAG indexed" value={ragStats?.indexed ?? ragStats?.total ?? "—"}
                    testid="xdr-docs-stat-rag" color="var(--mint)" />
        </div>

        {err && <div style={errBox} data-testid="xdr-docs-error">{err}</div>}

        {/* Tabs */}
        <div style={{ display: "flex", gap: 4, marginBottom: 8 }}>
          <TabBtn active={tab === "features"} onClick={() => setTab("features")}
                        testid="xdr-docs-tab-features">
            Features · {features.length}
          </TabBtn>
          <TabBtn active={tab === "workflows"} onClick={() => setTab("workflows")}
                        testid="xdr-docs-tab-workflows">
            Workflows · {workflows.length}
          </TabBtn>
        </div>

        <div style={{ display: "flex", gap: 6, marginBottom: 8,
                                alignItems: "center" }}>
          <Search size={12} style={{ color: "var(--faint)" }} />
          <input value={q} onChange={(e) => setQ(e.target.value)}
                       placeholder={`Search ${tab}…`}
                       data-testid="xdr-docs-search"
                       style={inputStyle} />
        </div>

        {tab === "features" ? (
          <List rows={filteredFeat} kind="feature"
                    onClick={(r) => viewFeature(r.id)} />
        ) : (
          <List rows={filteredWf} kind="workflow" />
        )}

        {openFeat && (
          <div style={drawerBackdrop} onClick={() => setOpenFeat(null)}>
            <div style={drawerPanel} onClick={(e) => e.stopPropagation()}
                       data-testid="xdr-docs-feature-drawer">
              <div style={{ display: "flex", alignItems: "center", gap: 8,
                                      marginBottom: 8 }}>
                <Zap size={12} style={{ color: "var(--cyan)" }} />
                <b>{openFeat.title || openFeat.name || openFeat.id}</b>
                <span style={{ flex: 1 }} />
                <button className="btn ghost" onClick={() => setOpenFeat(null)}
                              style={{ padding: "3px 8px", fontSize: 11 }}>Close</button>
              </div>
              <pre style={{ background: "var(--panel2)", padding: 10,
                                        borderRadius: 3, overflow: "auto",
                                        fontSize: 11, color: "var(--text-dim)",
                                        whiteSpace: "pre-wrap", maxHeight: "60vh" }}>
                {openFeat.description || openFeat.body ||
                    JSON.stringify(openFeat, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>
    </XdrShell>
  );
}


function List({ rows, kind, onClick }) {
  return (
    <div style={{ border: "1px solid var(--border)", borderRadius: 3,
                            overflow: "hidden" }}>
      <div style={rowHead}>
        <div>ID</div><div>Title</div><div>Description</div>
      </div>
      {rows.map((r) => (
        <div key={r.id || r.slug || r.name} style={rowBody}
                   data-testid={`xdr-docs-${kind}-${r.id || r.slug || r.name}`}
                   onClick={onClick ? () => onClick(r) : undefined}>
          <div style={{ color: "var(--cyan)" }}>{r.id || r.slug || "—"}</div>
          <div>{r.title || r.name || "—"}</div>
          <div style={{ color: "var(--faint)", fontSize: 10 }}>
            {(r.description || r.summary || "").slice(0, 120) || "—"}
          </div>
        </div>
      ))}
      {rows.length === 0 && (
        <div style={emptyRow}>NO {kind.toUpperCase()}S — the docs service is empty or unreachable</div>
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
      <div style={statLabel}>{label}</div>
      <div style={{ ...statValue, color: color || "var(--text)" }}>{value}</div>
    </div>
  );
}


const statsGrid = { display: "grid", gridTemplateColumns: "repeat(4, 1fr)",
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
                                gridTemplateColumns: "1.2fr 2fr 3fr",
                                gap: 6, padding: "5px 10px",
                                background: "var(--panel2)", fontSize: 10,
                                color: "var(--faint)", textTransform: "uppercase",
                                fontFamily: "var(--mono)", fontWeight: 700 };
const rowBody = { display: "grid",
                                gridTemplateColumns: "1.2fr 2fr 3fr",
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
