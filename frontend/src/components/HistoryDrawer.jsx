import React, { useEffect, useMemo, useState, useCallback } from "react";
import api from "@/lib/api";
import { X, Star, Tag as TagIcon, StickyNote, Download, Upload, Trash2, Search } from "lucide-react";

/**
 * HistoryDrawer — slide-out panel showing the analyst's investigation history.
 *
 * Features (matches Feb-2026 approved spec):
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
 *   open            bool
 *   onClose         () => void
 *   onRehydrate     (record) => void        — pushes input+recipe+trace back into workspace
 */
export default function HistoryDrawer({ open, onClose, onRehydrate }) {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [q, setQ] = useState("");
  const [ioc, setIoc] = useState("");
  const [mitre, setMitre] = useState("");
  const [engine, setEngine] = useState("");
  const [verdict, setVerdict] = useState("");
  const [starredOnly, setStarredOnly] = useState(false);
  const [shellcodeOnly, setShellcodeOnly] = useState(false);
  const [chainsOnly, setChainsOnly] = useState(false);
  const [sinceDays, setSinceDays] = useState(0);
  const [editing, setEditing] = useState(null); // {id, tags:'', notes:''}

  const fetchItems = useCallback(async () => {
    if (!open) return;
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
      if (sinceDays > 0) params.since_days = sinceDays;
      const r = await api.get("/history", { params });
      setItems(r.data.items || []);
      setTotal(r.data.total || 0);
    } catch (e) {
      console.warn("history load failed:", e);
    }
    setLoading(false);
  }, [open, q, ioc, mitre, engine, verdict, starredOnly, shellcodeOnly, chainsOnly, sinceDays]);

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

  if (!open) return null;

  return (
    <div
      data-testid="history-drawer"
      style={{
        position: "fixed", inset: 0, zIndex: 60,
        background: "rgba(0,0,0,0.55)",
        display: "flex", justifyContent: "flex-end",
      }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose?.(); }}
    >
      <div
        className="brut-border"
        style={{
          width: "min(720px, 100vw)", height: "100vh",
          background: "var(--surface)", display: "flex", flexDirection: "column",
        }}
      >
        {/* HEADER */}
        <div style={{
          padding: "14px 18px", borderBottom: "1px solid var(--border)",
          display: "flex", alignItems: "center", gap: 12,
        }}>
          <span className="mono" style={{ color: "var(--accent)", fontWeight: 700, letterSpacing: "0.22em", fontSize: 12 }}>
            📜 INVESTIGATION HISTORY
          </span>
          <span className="mono" style={{ color: "var(--text-dim)", fontSize: 10 }} data-testid="history-total">
            {total} total{starredOnly ? " (starred)" : ""}
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
          <button className="nvx-btn sm ghost" onClick={onClose} data-testid="btn-history-close">
            <X size={11} /> CLOSE
          </button>
        </div>

        {/* FILTERS */}
        <div style={{
          padding: "10px 14px", borderBottom: "1px solid var(--border)",
          display: "grid", gap: 8, gridTemplateColumns: "1fr 1fr",
        }}>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <Search size={12} style={{ color: "var(--text-dim)" }} />
            <input type="text" className="nvx-input sm" placeholder="Search input / notes / tags"
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
        </div>
        <div style={{ padding: "6px 14px", borderBottom: "1px solid var(--border)", display: "flex", gap: 10, alignItems: "center" }}>
          <label className="mono" style={{ fontSize: 10, color: "var(--text-dim)", cursor: "pointer" }} data-testid="chk-history-starred-label">
            <input type="checkbox" checked={starredOnly} onChange={(e) => setStarredOnly(e.target.checked)}
                   data-testid="chk-history-starred" style={{ marginRight: 5 }} />
            ⭐ STARRED
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


function HistoryRow({ item, onOpen, onStar, onDelete, onEdit, relTime }) {
  const isChain = item.kind === "chain";
  const chainOps = (item.chain || []).slice(0, 5).join(" → ");
  const iocCount =
    ((item.iocs?.urls || []).length) +
    ((item.iocs?.ips || []).length) +
    ((item.iocs?.domains || []).length) +
    ((item.iocs?.md5 || []).length) +
    ((item.iocs?.sha1 || []).length) +
    ((item.iocs?.sha256 || []).length);
  const verdictColor = {
    Malicious: "var(--danger)", Suspicious: "var(--warn)", Benign: "var(--accent)",
  }[item.verdict?.verdict] || "var(--text-dim)";
  return (
    <div
      data-testid={`history-row-${item.id}`}
      className="mono"
      style={{
        border: "1px solid var(--border)", padding: "10px 12px", marginBottom: 8,
        background: item.starred ? "rgba(226,204,80,0.05)" : "var(--inset)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
        <button
          onClick={onStar} data-testid={`btn-star-${item.id}`}
          title={item.starred ? "unstar" : "star"}
          style={{ background: "transparent", border: "none", cursor: "pointer",
                   color: item.starred ? "#e2cc50" : "var(--text-dim)" }}
        >
          <Star size={14} fill={item.starred ? "#e2cc50" : "none"} />
        </button>
        <span style={{ display: "inline-block", width: 6, height: 6, borderRadius: 999,
                       background: verdictColor }} />
        {isChain && (
          <span
            data-testid={`chain-badge-${item.id}`}
            style={{ fontSize: 9, color: "var(--accent)", border: "1px solid var(--accent)",
                     padding: "1px 5px", letterSpacing: "0.14em", fontWeight: 700 }}
            title="Multi-stage chain investigation"
          >
            ▪ CHAIN · {item.stage_count || (item.stages || []).length || 0} STAGES
          </span>
        )}
        <span style={{ fontSize: 10, color: "var(--text-dim)" }}>
          {item.engine || "?"} · {item.confidence || 0}%
        </span>
        {item.reached_shellcode && (
          <span style={{ fontSize: 9, color: "var(--danger)", border: "1px solid var(--danger)",
                         padding: "1px 5px" }}>▲ SC</span>
        )}
        {item.run_count > 1 && (
          <span style={{ fontSize: 9, color: "var(--text-dim)" }}>×{item.run_count}</span>
        )}
        <span style={{ flex: 1 }} />
        <span style={{ fontSize: 10, color: "var(--text-dim)" }}>{relTime(item.ts)}</span>
      </div>
      <div style={{ fontSize: 10.5, color: "var(--text)", marginBottom: 4, wordBreak: "break-all" }}>
        {item.input_preview?.slice(0, 130)}{item.input_preview?.length > 130 ? "…" : ""}
      </div>
      {chainOps && (
        <div style={{ fontSize: 10, color: "var(--accent)", marginBottom: 4 }}>
          {chainOps}
        </div>
      )}
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 6, flexWrap: "wrap" }}>
        {iocCount > 0 && <span style={{ fontSize: 10, color: "var(--text-dim)" }}>{iocCount} IOC{iocCount > 1 ? "s" : ""}</span>}
        {(item.mitre || []).length > 0 && <span style={{ fontSize: 10, color: "var(--text-dim)" }}>{item.mitre.length} MITRE</span>}
        {(item.tags || []).map((t) => (
          <span key={t} style={{ fontSize: 9, color: "var(--warn)", border: "1px solid var(--warn)",
                                  padding: "1px 5px" }}>{t}</span>
        ))}
        <span style={{ flex: 1 }} />
        <button className="nvx-btn sm ghost" onClick={onEdit} data-testid={`btn-edit-${item.id}`} title="edit tags/notes">
          <TagIcon size={10} /> EDIT
        </button>
        <button className="nvx-btn sm ghost" onClick={onOpen} data-testid={`btn-restore-${item.id}`}>
          ▸ RESTORE
        </button>
        <button className="nvx-btn sm ghost" onClick={onDelete} data-testid={`btn-delete-${item.id}`}>
          <Trash2 size={10} />
        </button>
      </div>
      {item.notes && (
        <div style={{ fontSize: 10, color: "var(--text-dim)", marginTop: 6, fontStyle: "italic" }}>
          <StickyNote size={9} style={{ display: "inline", verticalAlign: "middle" }} /> {item.notes.slice(0, 200)}
        </div>
      )}
    </div>
  );
}
