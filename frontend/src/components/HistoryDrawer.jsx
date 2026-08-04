import React, { useEffect, useMemo, useState, useCallback } from "react";
import api from "@/lib/api";
import { X, Star, Tag as TagIcon, StickyNote, Download, Upload, Trash2, Search } from "lucide-react";

/**
 * HistoryDrawer — investigation history panel.
 *
 * Ships in two layouts (2026-02 · owner nav-consolidation directive):
 *   • layout="drawer" (default) — right-side slide-out with dimmed backdrop.
 *   • layout="page"             — in-flow full-page shell (used by
 *                                  /pages/HistoryPage.jsx). No backdrop,
 *                                  no fixed positioning, no CLOSE control
 *                                  in the header (parent page owns nav).
 *
 * Features (unchanged from Feb-2026 approved spec):
 *   • Auto-populated from every /decode/smart + /ai/auto-investigate run
 *   • Dedup by input SHA-256 hash (re-runs bump run_count instead of duplicating)
 *   • Star/Pin (survives 30-day TTL cleanup)
 *   • Tags + notes editable per-row
 *   • Advanced search: text, IOC value, MITRE technique id, verdict, engine
 *   • Filters: STARRED, SHELLCODE, TODAY / WEEK / MONTH
 *   • Row actions: ▸ RESTORE (rehydrate), ⇩ EXPORT, 🗑 DELETE
 *   • Bulk actions: EXPORT ALL (JSON), IMPORT (from previous export)
 *
 * Props:
 *   open            bool                — ignored when layout="page"
 *   onClose         () => void          — omitted when layout="page"
 *   onRehydrate     (record) => void    — pushes input+recipe+trace back into workspace
 *   layout          "drawer" | "page"   — default "drawer"
 */
export default function HistoryDrawer({ open, onClose, onRehydrate, layout = "drawer" }) {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [q, setQ] = useState("");
  const [ioc, setIoc] = useState("");
  const [mitre, setMitre] = useState("");
  const [engine, setEngine] = useState("");
  const [verdict, setVerdict] = useState("");
  // ▲ 2026-02 · Owner-approved enhancements (Rec 1 · Rich filters)
  const [interpreter, setInterpreter] = useState("");
  const [terminalState, setTerminalState] = useState("");
  const [starredOnly, setStarredOnly] = useState(false);
  const [shellcodeOnly, setShellcodeOnly] = useState(false);
  const [chainsOnly, setChainsOnly] = useState(false);
  const [sinceDays, setSinceDays] = useState(0);
  const [editing, setEditing] = useState(null); // {id, tags:'', notes:''}

  const isPage = layout === "page";

  // The list must always fetch when this component mounts as a page —
  // there is no `open` toggle in that mode.
  const _openFlag = isPage ? true : open;
  const fetchItems = useCallback(async () => {
    if (!_openFlag) return;
    setLoading(true);
    try {
      const params = { limit: 100 };
      if (q) params.q = q;
      if (ioc) params.ioc = ioc;
      if (mitre) params.mitre = mitre;
      if (engine) params.engine = engine;
      if (verdict) params.verdict = verdict;
      if (starredOnly) params.starred = true;
      if (shellcodeOnly) params.shellcode = true;
      if (chainsOnly) params.kind = "chain";
      if (interpreter) params.interpreter = interpreter;
      if (terminalState) params.terminal_state = terminalState;
      if (sinceDays > 0) params.since_days = sinceDays;
      const r = await api.get("/history", { params });
      setItems(r.data.items || []);
      setTotal(r.data.total || 0);
    } catch (e) {
      console.warn("history load failed:", e);
    }
    setLoading(false);
  }, [_openFlag, q, ioc, mitre, engine, verdict, starredOnly, shellcodeOnly, chainsOnly, interpreter, terminalState, sinceDays]);

  useEffect(() => { fetchItems(); }, [fetchItems]);

  const toggleStar = async (item) => {
    try {
      await api.patch(`/history/${item.id}`, { starred: !item.starred });
      fetchItems();
    } catch { /* noop */ }
  };
  const removeItem = async (item) => {
    if (!window.confirm("Delete this investigation from your history?")) return;
    await api.delete(`/history/${item.id}`);
    fetchItems();
  };
  const saveEdit = async () => {
    if (!editing) return;
    const tags = editing.tags.split(",").map((s) => s.trim()).filter(Boolean);
    await api.patch(`/history/${editing.id}`, { tags, notes: editing.notes });
    setEditing(null); fetchItems();
  };
  const exportAll = async () => {
    const r = await api.get("/history/export/bundle", { responseType: "blob" });
    const blob = new Blob([r.data], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `nivxray_history_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };
  const importBundle = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const items = Array.isArray(parsed) ? parsed : parsed.items || [];
      const r = await api.post("/history/import", { items });
      alert(`Imported ${r.data.imported}, skipped ${r.data.skipped} (of ${r.data.total_submitted})`);
      fetchItems();
    } catch (err) {
      alert("Import failed: " + (err?.message || "bad file"));
    }
  };

  const relTime = (iso) => {
    if (!iso) return "";
    // Feb 2026 fix — backend serialises `datetime` without a tz suffix, so
    // JS's Date() parses the string as *local* time (a 5.5-hour skew for IST
    // users → "5h ago" instead of "just now"). Force UTC parse by appending
    // 'Z' when no offset / no 'Z' is present.
    let s = String(iso);
    if (!/[Zz]|[+-]\d{2}:?\d{2}$/.test(s)) s = s + "Z";
    const t = new Date(s).getTime();
    if (!isFinite(t)) return "";
    const dt = Math.floor((Date.now() - t) / 1000);
    if (dt < 60) return `${dt}s ago`;
    if (dt < 3600) return `${Math.floor(dt / 60)}m ago`;
    if (dt < 86400) return `${Math.floor(dt / 3600)}h ago`;
    return `${Math.floor(dt / 86400)}d ago`;
  };

  if (!isPage && !open) return null;

  // Outer wrapper: dimmed overlay for drawer, in-flow full-page container
  // for the /history route. Both variants render the same shell inside.
  const outerStyle = isPage
    ? {
        position: "relative",
        width: "100%",
        minHeight: "100%",
        background: "var(--bg, transparent)",
      }
    : {
        position: "fixed", inset: 0, zIndex: 60,
        background: "rgba(0,0,0,0.55)",
        display: "flex", justifyContent: "flex-end",
      };

  const shellStyle = isPage
    ? {
        width: "100%",
        minHeight: "calc(100vh - 60px)",
        background: "var(--surface)",
        display: "flex", flexDirection: "column",
      }
    : {
        width: "min(720px, 100vw)", height: "100vh",
        background: "var(--surface)", display: "flex", flexDirection: "column",
      };

  return (
    <div
      data-testid={isPage ? "history-page" : "history-drawer"}
      style={outerStyle}
      onClick={
        isPage
          ? undefined
          : (e) => { if (e.target === e.currentTarget) onClose?.(); }
      }
    >
      <div className={isPage ? "" : "brut-border"} style={shellStyle}>
        {/* HEADER */}
        <div style={{
          padding: "14px 18px", borderBottom: "1px solid var(--border)",
          display: "flex", alignItems: "center", gap: 12,
        }}>
          <span className="mono" style={{ color: "var(--accent)", fontWeight: 700, letterSpacing: "0.22em", fontSize: 12 }}>
            📜 INVESTIGATION HISTORY
          </span>
          <span className="mono" style={{ color: "var(--text-dim)", fontSize: 10 }} data-testid="history-total">
            {total} total{starredOnly ? " (favorites)" : ""}
          </span>
          <div style={{ flex: 1 }} />
          <button className="nvx-btn sm ghost" onClick={exportAll} data-testid="btn-history-export-all" title="Export all">
            <Download size={11} /> EXPORT
          </button>
          <label className="nvx-btn sm ghost" title="Import bundle" style={{ cursor: "pointer" }}>
            <Upload size={11} /> IMPORT
            <input type="file" accept="application/json" onChange={importBundle} style={{ display: "none" }}
                   data-testid="input-history-import" />
          </label>
          <button className="nvx-btn sm ghost" onClick={onClose} data-testid="btn-history-close"
                  style={{ display: isPage ? "none" : undefined }}>
            <X size={11} /> CLOSE
          </button>
        </div>

        {/* ▲ 2026-02 · Case Manager Views — segmented control */}
        <div
          data-testid="history-view-tabs"
          style={{
            padding: "10px 14px",
            borderBottom: "1px solid var(--border)",
            display: "flex", gap: 6, alignItems: "center",
          }}
        >
          {[
            { key: "all",       label: "ALL",         onSelect: () => { setStarredOnly(false); setSinceDays(0); } },
            { key: "favorites", label: "⭐ FAVORITES", onSelect: () => { setStarredOnly(true); setSinceDays(0); } },
            { key: "recent",    label: "RECENT · 7d",  onSelect: () => { setStarredOnly(false); setSinceDays(7); } },
          ].map((v) => {
            const active =
              (v.key === "favorites" && starredOnly) ||
              (v.key === "recent"    && sinceDays === 7 && !starredOnly) ||
              (v.key === "all"       && !starredOnly && sinceDays === 0);
            return (
              <button
                key={v.key}
                type="button"
                onClick={v.onSelect}
                data-testid={`view-tab-${v.key}`}
                className="mono"
                style={{
                  padding: "4px 10px",
                  fontSize: 10.5,
                  letterSpacing: "0.14em",
                  fontWeight: 700,
                  color: active ? "#0d1a13" : "var(--text)",
                  background: active ? "var(--accent)" : "transparent",
                  border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`,
                  borderRadius: 4,
                  cursor: "pointer",
                  transition: "background 120ms ease",
                }}
              >
                {v.label}
              </button>
            );
          })}
          <span style={{ flex: 1 }} />
          <span className="mono" style={{ fontSize: 10, color: "var(--text-dim)" }}>
            {total} case{total === 1 ? "" : "s"}
          </span>
        </div>

        {/* FILTERS */}
        <div style={{
          padding: "10px 14px", borderBottom: "1px solid var(--border)",
          display: "grid", gap: 8, gridTemplateColumns: "1fr 1fr",
        }}>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <Search size={12} style={{ color: "var(--text-dim)" }} />
            <input type="text" className="nvx-input sm" placeholder="Search case name / input / notes"
                   value={q} onChange={(e) => setQ(e.target.value)}
                   data-testid="input-history-search"
                   style={{ flex: 1, fontSize: 11 }} />
          </div>
          <input type="text" className="nvx-input sm" placeholder="IOC (URL / IP / domain / hash)"
                 value={ioc} onChange={(e) => setIoc(e.target.value)}
                 data-testid="input-history-ioc" style={{ fontSize: 11 }} />
          <input type="text" className="nvx-input sm" placeholder="MITRE ID (e.g. T1059.001)"
                 value={mitre} onChange={(e) => setMitre(e.target.value)}
                 data-testid="input-history-mitre" style={{ fontSize: 11 }} />
          <select className="nvx-input sm" value={verdict} onChange={(e) => setVerdict(e.target.value)}
                  data-testid="select-history-verdict" style={{ fontSize: 11 }}>
            <option value="">Any verdict</option>
            <option value="Malicious">Malicious</option>
            <option value="Suspicious">Suspicious</option>
            <option value="Benign">Benign</option>
          </select>
          <select className="nvx-input sm" value={engine} onChange={(e) => setEngine(e.target.value)}
                  data-testid="select-history-engine" style={{ fontSize: 11 }}>
            <option value="">Any engine</option>
            <option value="magic">magic</option>
            <option value="smart">smart</option>
            <option value="ai">ai</option>
            <option value="custom_recipe">custom_recipe</option>
          </select>
          <select className="nvx-input sm" value={sinceDays} onChange={(e) => setSinceDays(Number(e.target.value))}
                  data-testid="select-history-since" style={{ fontSize: 11 }}>
            <option value={0}>All time</option>
            <option value={1}>Today</option>
            <option value={7}>Last 7d</option>
            <option value={30}>Last 30d</option>
          </select>
          {/* ▲ IEDDE-aware filters (2026-02) */}
          <select className="nvx-input sm" value={interpreter} onChange={(e) => setInterpreter(e.target.value)}
                  data-testid="select-history-interpreter" style={{ fontSize: 11 }}>
            <option value="">Any interpreter</option>
            <option value="powershell">PowerShell</option>
            <option value="cmd">CMD</option>
            <option value="bash">Bash</option>
            <option value="python">Python</option>
            <option value="perl">Perl</option>
            <option value="php">PHP</option>
            <option value="ruby">Ruby</option>
          </select>
          <select className="nvx-input sm" value={terminalState} onChange={(e) => setTerminalState(e.target.value)}
                  data-testid="select-history-terminal-state" style={{ fontSize: 11 }}>
            <option value="">Any terminal state</option>
            <option value="canonical">Canonical</option>
            <option value="binary_artifact_recovered">Binary Artifact Recovered</option>
            <option value="stability_gate">Stability Gate</option>
            <option value="partial_recovery">Partial Recovery</option>
          </select>
        </div>
        <div style={{ padding: "6px 14px", borderBottom: "1px solid var(--border)", display: "flex", gap: 10, alignItems: "center" }}>
          <label className="mono" style={{ fontSize: 10, color: "var(--text-dim)", cursor: "pointer" }} data-testid="chk-history-favorites-label">
            <input type="checkbox" checked={starredOnly} onChange={(e) => setStarredOnly(e.target.checked)}
                   data-testid="chk-history-favorites" style={{ marginRight: 5 }} />
            ⭐ FAVORITES
          </label>
          <label className="mono" style={{ fontSize: 10, color: "var(--text-dim)", cursor: "pointer" }}>
            <input type="checkbox" checked={shellcodeOnly} onChange={(e) => setShellcodeOnly(e.target.checked)}
                   data-testid="chk-history-shellcode" style={{ marginRight: 5 }} />
            ▲ SHELLCODE ONLY
          </label>
          <label className="mono" style={{ fontSize: 10, color: "var(--text-dim)", cursor: "pointer" }}>
            <input type="checkbox" checked={chainsOnly} onChange={(e) => setChainsOnly(e.target.checked)}
                   data-testid="chk-history-chains" style={{ marginRight: 5 }} />
            ▪ CHAINS ONLY
          </label>
        </div>

        {/* LIST */}
        <div style={{ flex: 1, overflowY: "auto", padding: "8px 14px" }}>
          {loading && <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)" }}>loading…</div>}
          {!loading && items.length === 0 && (
            <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", padding: 20, textAlign: "center" }}>
              No investigations match these filters.
            </div>
          )}
          {items.map((it) => (
            <HistoryRow
              key={it.id} item={it}
              onOpen={() => onRehydrate?.(it)}
              onStar={() => toggleStar(it)}
              onDelete={() => removeItem(it)}
              onEdit={() => setEditing({ id: it.id, tags: (it.tags || []).join(", "), notes: it.notes || "" })}
              onExport={async () => {
                try {
                  const r = await api.get(`/history/${it.id}`);
                  const blob = new Blob([JSON.stringify(r.data, null, 2)], { type: "application/json" });
                  const a = document.createElement("a");
                  a.href = URL.createObjectURL(blob);
                  a.download = `nivxray_case_${it.id}.json`;
                  a.click();
                  URL.revokeObjectURL(a.href);
                } catch (e) { console.warn("export failed", e); }
              }}
              onDuplicate={() => {
                try {
                  window.sessionStorage.setItem("nvx_restore_history_id", String(it.id));
                  // Marker so Workspace can (optionally) treat it as a fresh
                  // duplicate — for now we simply rehydrate; downstream code
                  // can key off this flag to skip case-name association.
                  window.sessionStorage.setItem("nvx_history_duplicate", "1");
                } catch { /* noop */ }
                window.location.assign("/");
              }}
              onOpenNewTab={() => {
                try { window.sessionStorage.setItem("nvx_restore_history_id", String(it.id)); } catch { /* noop */ }
                window.open("/", "_blank", "noopener");
              }}
              relTime={relTime}
            />
          ))}
        </div>

        {/* EDIT MODAL */}
        {editing && (
          <div style={{
            position: "absolute", inset: 0, background: "rgba(0,0,0,0.6)",
            display: "flex", alignItems: "center", justifyContent: "center", zIndex: 5,
          }} onClick={(e) => { if (e.target === e.currentTarget) setEditing(null); }}>
            <div className="brut-border" style={{ background: "var(--surface)", padding: 18, width: 480 }}>
              <div className="mono" style={{ color: "var(--accent)", letterSpacing: "0.22em", fontSize: 11, marginBottom: 12 }}>
                EDIT TAGS + NOTES
              </div>
              <input type="text" className="nvx-input" placeholder="tags (comma-separated)"
                     value={editing.tags} onChange={(e) => setEditing({ ...editing, tags: e.target.value })}
                     data-testid="input-edit-tags" style={{ marginBottom: 10 }} />
              <textarea className="nvx-textarea" placeholder="notes"
                        value={editing.notes} onChange={(e) => setEditing({ ...editing, notes: e.target.value })}
                        data-testid="input-edit-notes" rows={6} style={{ height: 140 }} />
              <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 12 }}>
                <button className="nvx-btn sm ghost" onClick={() => setEditing(null)}>CANCEL</button>
                <button className="nvx-btn sm primary" onClick={saveEdit} data-testid="btn-edit-save">SAVE</button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}


// ─── Rich Case Card (2026-02 · owner Rec 3 · one-glance analyst summary) ─
//
// Displays:  ▸ Verdict severity pill (Critical / Malicious / Suspicious / Benign)
//            ▸ Interpreter chip     (PowerShell / CMD / Bash / Python / …)
//            ▸ Terminal state pill  (Canonical / Binary / Stability Gate / …)
//            ▸ Canonical confidence % (from IEDDE)
//            ▸ Top-1 MITRE technique   (T-id + name)
//            ▸ Input preview          (mono, 2-line clamp)
//            ▸ Evidence + MITRE counts + engine + run-count + shellcode flag
//            ▸ Relative timestamp (right-aligned)
//            ▸ Action row: ▸ RESTORE | ⋯ menu (Open in New Tab · Duplicate ·
//                                                 Export · Delete)
//
// The card falls back gracefully when the IEDDE fields are absent (legacy
// records saved before Feb-2026) — verdict pill + input preview always render.
function HistoryRow({
  item, onOpen, onStar, onDelete, onEdit, onExport, onDuplicate, onOpenNewTab, relTime,
}) {
  const [menuOpen, setMenuOpen] = React.useState(false);
  const menuRef = React.useRef(null);
  React.useEffect(() => {
    if (!menuOpen) return;
    const onDoc = (e) => { if (!menuRef.current?.contains(e.target)) setMenuOpen(false); };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [menuOpen]);

  const isChain = item.kind === "chain";
  const chainOps = (item.chain || []).slice(0, 5).join(" → ");
  const iocCount =
    ((item.iocs?.urls || []).length) +
    ((item.iocs?.ips || []).length) +
    ((item.iocs?.domains || []).length) +
    ((item.iocs?.md5 || []).length) +
    ((item.iocs?.sha1 || []).length) +
    ((item.iocs?.sha256 || []).length);
  const mitreList = item.mitre || [];
  const topMitre = mitreList[0];
  const topMitreId = typeof topMitre === "string" ? topMitre : topMitre?.id;
  const topMitreName = typeof topMitre === "object" ? (topMitre?.name || topMitre?.technique) : "";

  // ── IEDDE-derived summary chips ────────────────────────────────────
  const iedde = item.iedde || {};
  const interpreter =
    (iedde.stages && iedde.stages[0]?.interpreter && iedde.stages[0].interpreter !== "unknown")
      ? iedde.stages[0].interpreter
      : (iedde.final_interpreter && iedde.final_interpreter !== "unknown"
          ? iedde.final_interpreter
          : null);
  const terminal = item.iedde_terminal_state || null;
  const canonicalConfidence =
    typeof item.canonical_confidence === "number" ? item.canonical_confidence : null;

  const verdictName = item.verdict?.verdict || null;
  const verdictColor =
    verdictName === "Malicious" ? "#f87171"
    : verdictName === "Suspicious" ? "#fbbf24"
    : verdictName === "Benign" ? "#86efac"
    : "#94a3b8";
  const verdictBg =
    verdictName === "Malicious" ? "rgba(248,113,113,0.10)"
    : verdictName === "Suspicious" ? "rgba(251,191,36,0.10)"
    : verdictName === "Benign" ? "rgba(134,239,172,0.08)"
    : "rgba(148,163,184,0.06)";

  const _termColor = (t) => {
    if (t === "canonical") return { fg: "#86efac", bg: "rgba(34,197,94,0.10)", br: "rgba(34,197,94,0.35)" };
    if (t === "binary_artifact_recovered") return { fg: "#67e8f9", bg: "rgba(6,182,212,0.10)", br: "rgba(6,182,212,0.35)" };
    if (t === "stability_gate") return { fg: "#fcd34d", bg: "rgba(245,158,11,0.10)", br: "rgba(245,158,11,0.35)" };
    return { fg: "#94a3b8", bg: "rgba(148,163,184,0.08)", br: "rgba(148,163,184,0.25)" };
  };
  const _termLabel = (t) => (
    t === "canonical" ? "Canonical"
    : t === "binary_artifact_recovered" ? "Binary Recovered"
    : t === "stability_gate" ? "Stability Gate"
    : t === "partial_recovery" ? "Partial"
    : t
  );

  const chipStyle = {
    fontFamily: "JetBrains Mono, ui-monospace, monospace",
    fontSize: 9.5, letterSpacing: "0.10em", padding: "2px 7px",
    borderRadius: 4, textTransform: "uppercase", fontWeight: 700,
    display: "inline-flex", alignItems: "center", gap: 4, whiteSpace: "nowrap",
  };

  return (
    <div
      data-testid={`history-row-${item.id}`}
      style={{
        border: "1px solid var(--border)", borderRadius: 8,
        padding: "12px 14px", marginBottom: 10,
        background: item.starred ? "rgba(226,204,80,0.05)" : "var(--inset)",
        transition: "border-color 160ms ease, transform 160ms ease",
      }}
      onMouseEnter={(e) => { e.currentTarget.style.borderColor = "rgba(148,163,184,0.35)"; }}
      onMouseLeave={(e) => { e.currentTarget.style.borderColor = "var(--border)"; }}
    >
      {/* ─── Header row: severity + chips + timestamp ─────────────── */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 6 }}>
        <button
          onClick={onStar} data-testid={`btn-star-${item.id}`}
          title={item.starred ? "Remove from favorites" : "Mark as favorite"}
          style={{ background: "transparent", border: "none", cursor: "pointer",
                   color: item.starred ? "#e2cc50" : "var(--text-dim)", padding: 0, marginRight: 2 }}
        >
          <Star size={14} fill={item.starred ? "#e2cc50" : "none"} />
        </button>

        {/* Verdict severity pill */}
        {verdictName && (
          <span
            data-testid={`chip-verdict-${item.id}`}
            style={{ ...chipStyle, color: verdictColor, background: verdictBg, border: `1px solid ${verdictColor}55` }}
          >
            ● {verdictName}
          </span>
        )}

        {/* Interpreter chip */}
        {interpreter && (
          <span
            data-testid={`chip-interpreter-${item.id}`}
            style={{ ...chipStyle, color: "#7dd3fc", background: "rgba(56,189,248,0.10)",
                     border: "1px solid rgba(56,189,248,0.35)" }}
          >
            {interpreter}
          </span>
        )}

        {/* Terminal state pill */}
        {terminal && (() => {
          const c = _termColor(terminal);
          return (
            <span
              data-testid={`chip-terminal-${item.id}`}
              style={{ ...chipStyle, color: c.fg, background: c.bg, border: `1px solid ${c.br}` }}
            >
              {_termLabel(terminal)}
            </span>
          );
        })()}

        {/* Canonical Confidence badge */}
        {canonicalConfidence != null && (
          <span
            data-testid={`chip-canonical-${item.id}`}
            title="Canonical confidence — completeness of the deterministic recovery."
            style={{ ...chipStyle, color: "#e2e8f0", background: "rgba(2,6,23,0.55)",
                     border: "1px solid rgba(148,163,184,0.30)" }}
          >
            CANON {canonicalConfidence}%
          </span>
        )}

        {/* Top-1 MITRE technique */}
        {topMitreId && (
          <span
            data-testid={`chip-mitre-${item.id}`}
            title={topMitreName || topMitreId}
            style={{ ...chipStyle, color: "#c4b5fd", background: "rgba(139,92,246,0.10)",
                     border: "1px solid rgba(139,92,246,0.35)" }}
          >
            {topMitreId}
            {topMitreName ? ` · ${String(topMitreName).slice(0, 22)}` : ""}
          </span>
        )}

        {item.case_name && (
          <span
            data-testid={`history-case-name-${item.id}`}
            title={`Saved case · ${item.case_name}`}
            style={{
              ...chipStyle,
              color: "#7ee3c9", border: "1px solid #7ee3c9",
              background: "rgba(126,227,201,0.08)",
              maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "inline-block",
            }}
          >
            💾 {item.case_name}
          </span>
        )}

        {isChain && (
          <span
            data-testid={`chain-badge-${item.id}`}
            style={{ ...chipStyle, color: "var(--accent)", border: "1px solid var(--accent)" }}
            title="Multi-stage chain investigation"
          >
            ▪ CHAIN · {item.stage_count || (item.stages || []).length || 0}
          </span>
        )}

        {item.reached_shellcode && (
          <span
            style={{ ...chipStyle, color: "#f87171", border: "1px solid #f87171" }}
            title="Deterministic decoder reached shellcode"
          >
            ▲ SHELLCODE
          </span>
        )}

        {item.run_count > 1 && (
          <span style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "JetBrains Mono, ui-monospace, monospace" }}>
            ×{item.run_count}
          </span>
        )}

        <span style={{ flex: 1 }} />
        <span style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "JetBrains Mono, ui-monospace, monospace" }}>
          {relTime(item.ts)}
        </span>
      </div>

      {/* ─── Input preview ────────────────────────────────────────── */}
      <div style={{
        fontSize: 11.5, color: "var(--text)", marginBottom: 4, wordBreak: "break-all",
        fontFamily: "JetBrains Mono, ui-monospace, monospace",
        overflow: "hidden", display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical",
      }}>
        {item.input_preview?.slice(0, 200)}{(item.input_preview?.length || 0) > 200 ? "…" : ""}
      </div>

      {/* Chain ops trace (multi-stage only) */}
      {chainOps && (
        <div style={{
          fontSize: 10, color: "var(--accent)", marginBottom: 4,
          fontFamily: "JetBrains Mono, ui-monospace, monospace",
        }}>
          {chainOps}
        </div>
      )}

      {/* ─── Footer: counts + tags + action row ───────────────────── */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 8, flexWrap: "wrap" }}>
        {iocCount > 0 && (
          <span style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "JetBrains Mono, ui-monospace, monospace" }}>
            {iocCount} IOC{iocCount > 1 ? "s" : ""}
          </span>
        )}
        {mitreList.length > 0 && (
          <span style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "JetBrains Mono, ui-monospace, monospace" }}>
            {mitreList.length} MITRE
          </span>
        )}
        {item.engine && (
          <span style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "JetBrains Mono, ui-monospace, monospace" }}>
            {item.engine} · {item.confidence || 0}%
          </span>
        )}
        {(item.tags || []).map((t) => (
          <span key={t} style={{ ...chipStyle, color: "var(--warn)", border: "1px solid var(--warn)", background: "transparent" }}>
            {t}
          </span>
        ))}

        <span style={{ flex: 1 }} />

        <button className="nvx-btn sm ghost" onClick={onEdit}
                data-testid={`btn-edit-${item.id}`} title="edit tags/notes">
          <TagIcon size={10} /> EDIT
        </button>

        <button className="nvx-btn sm primary" onClick={onOpen}
                data-testid={`btn-restore-${item.id}`}>
          ▸ RESTORE
        </button>

        {/* Action menu (Rec 2 · Open New Tab / Duplicate / Export / Delete) */}
        <div style={{ position: "relative" }} ref={menuRef}>
          <button className="nvx-btn sm ghost" onClick={() => setMenuOpen((v) => !v)}
                  data-testid={`btn-actions-${item.id}`} title="More actions">
            ⋯
          </button>
          {menuOpen && (
            <div
              data-testid={`actions-menu-${item.id}`}
              className="brut-border"
              style={{
                position: "absolute", right: 0, top: "calc(100% + 6px)",
                background: "var(--surface)", zIndex: 40, minWidth: 190,
                boxShadow: "0 10px 30px rgba(0,0,0,0.55)",
              }}
            >
              <MenuItem testId={`btn-open-new-tab-${item.id}`}
                        onClick={() => { setMenuOpen(false); onOpenNewTab?.(); }}>
                🗔  Open in New Tab
              </MenuItem>
              <MenuItem testId={`btn-duplicate-${item.id}`}
                        onClick={() => { setMenuOpen(false); onDuplicate?.(); }}>
                ⧉  Duplicate Case
              </MenuItem>
              <MenuItem testId={`btn-export-${item.id}`}
                        onClick={() => { setMenuOpen(false); onExport?.(); }}>
                <Download size={11} style={{ verticalAlign: "middle", marginRight: 6 }} />
                Export JSON
              </MenuItem>
              <MenuItem testId={`btn-delete-menu-${item.id}`}
                        danger onClick={() => { setMenuOpen(false); onDelete?.(); }}>
                <Trash2 size={11} style={{ verticalAlign: "middle", marginRight: 6 }} />
                Delete
              </MenuItem>
            </div>
          )}
        </div>
      </div>

      {item.notes && (
        <div style={{ fontSize: 10.5, color: "var(--text-dim)", marginTop: 8, fontStyle: "italic" }}>
          <StickyNote size={10} style={{ display: "inline", verticalAlign: "middle", marginRight: 4 }} />
          {item.notes.slice(0, 240)}
        </div>
      )}
    </div>
  );
}

function MenuItem({ children, onClick, testId, danger }) {
  return (
    <button
      type="button"
      onClick={onClick}
      data-testid={testId}
      style={{
        display: "block", width: "100%", textAlign: "left",
        padding: "9px 14px", background: "transparent", border: "none",
        color: danger ? "#f87171" : "var(--text)",
        fontFamily: "JetBrains Mono, ui-monospace, monospace",
        fontSize: 11, letterSpacing: "0.06em", cursor: "pointer",
      }}
      onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(148,163,184,0.10)"; }}
      onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
    >
      {children}
    </button>
  );
}
