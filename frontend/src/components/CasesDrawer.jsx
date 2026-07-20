import { useEffect, useState, useCallback } from "react";
import api from "@/lib/api";
import { X, Trash2, Search, RefreshCw, FolderOpen, Shield } from "lucide-react";

/**
 * CasesDrawer — slide-out panel showing SAVED cases (workspace_cases).
 * Mirrors HistoryDrawer UX with case-specific actions:
 *   ▸ OPEN         → rehydrate case into workspace
 *   🔄 RE-DECODE   → POST /cases/{id}/reinvestigate → refresh row
 *   🗑 DELETE      → DELETE /cases/{id}
 *
 * Props:
 *   open            bool
 *   onClose         () => void
 *   onRestore       (case) => void   — main workspace rehydrate handler
 */
export default function CasesDrawer({ open, onClose, onRestore }) {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(null);

  const load = useCallback(async () => {
    if (!open) return;
    setLoading(true);
    try {
      const r = await api.get("/cases", { params: { limit: 100 } });
      setItems(r.data.cases || []);
    } catch (e) {
      console.warn("cases load failed:", e);
    }
    setLoading(false);
  }, [open]);

  useEffect(() => { load(); }, [load]);

  const reinvestigate = async (item) => {
    setBusy(item.id);
    try {
      const r = await api.post(`/cases/${item.id}/reinvestigate`);
      const updated = r.data?.case;
      if (updated) {
        setItems((prev) => prev.map((c) => (c.id === item.id ? { ...c, ...updated } : c)));
      }
    } catch (e) {
      alert("Re-investigate failed: " + (e?.response?.data?.detail || e.message));
    } finally {
      setBusy(null);
    }
  };

  const remove = async (item) => {
    if (!window.confirm(`Delete case "${item.name}"?`)) return;
    try {
      await api.delete(`/cases/${item.id}`);
      setItems((prev) => prev.filter((c) => c.id !== item.id));
    } catch (e) {
      alert("Delete failed: " + (e?.response?.data?.detail || e.message));
    }
  };

  const openCase = async (item) => {
    // Fetch the full case doc (input+output) then hand off to workspace
    try {
      const r = await api.get(`/cases/${item.id}`);
      onRestore?.(r.data);
      onClose?.();
    } catch (e) {
      alert("Open failed: " + (e?.response?.data?.detail || e.message));
    }
  };

  const exportSigma = async (item) => {
    try {
      // fetch with axios so auth header is included, get YAML text back
      const r = await api.get(`/cases/${item.id}/sigma`, { responseType: "text" });
      const yamlText = typeof r.data === "string" ? r.data : String(r.data);
      const blob = new Blob([yamlText], { type: "application/x-yaml" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `nivxray-${(item.name || "case").toLowerCase().replace(/[^a-z0-9]+/g, "-")}.yml`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      alert("Sigma export failed: " + (e?.response?.data?.detail || e.message));
    }
  };

  const filtered = q
    ? items.filter((c) => (c.name || "").toLowerCase().includes(q.toLowerCase()))
    : items;

  if (!open) return null;

  return (
    <div
      data-testid="cases-drawer"
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
        <div style={{
          padding: "14px 18px", borderBottom: "1px solid var(--border)",
          display: "flex", alignItems: "center", gap: 12,
        }}>
          <span className="mono" style={{ color: "#7ee3c9", fontWeight: 700, letterSpacing: "0.22em", fontSize: 12 }}>
            💾 CASE LIBRARY
          </span>
          <span className="mono" style={{ color: "var(--text-dim)", fontSize: 10 }} data-testid="cases-total">
            {filtered.length} of {items.length}
          </span>
          <div style={{ flex: 1 }} />
          <button className="nvx-btn sm ghost" onClick={load} data-testid="btn-cases-refresh" title="Refresh">
            <RefreshCw size={11} /> REFRESH
          </button>
          <button className="nvx-btn sm ghost" onClick={onClose} data-testid="btn-cases-close">
            <X size={11} /> CLOSE
          </button>
        </div>

        <div style={{ padding: "10px 14px", borderBottom: "1px solid var(--border)", display: "flex", gap: 6, alignItems: "center" }}>
          <Search size={12} style={{ color: "var(--text-dim)" }} />
          <input type="text" className="nvx-input sm" placeholder="Search by case name"
                 value={q} onChange={(e) => setQ(e.target.value)}
                 data-testid="input-cases-search"
                 style={{ flex: 1, fontSize: 11 }} />
        </div>

        <div style={{ flex: 1, overflowY: "auto", padding: "8px 14px" }}>
          {loading && <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)" }}>loading…</div>}
          {!loading && filtered.length === 0 && (
            <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", padding: 20, textAlign: "center" }}>
              No saved cases. Save one from the workspace via 💾 SAVE CASE.
            </div>
          )}
          {filtered.map((c) => {
            const v = c.verdict?.verdict || c.verdict || "";
            const color = v === "Malicious" ? "var(--danger)"
                        : v === "Suspicious" ? "var(--warn)"
                        : v === "Benign" ? "var(--accent)"
                        : v === "Undecoded" ? "var(--text-dim)"
                        : "var(--text-dim)";
            return (
              <div
                key={c.id}
                data-testid={`case-row-${c.id}`}
                className="mono"
                style={{
                  border: "1px solid var(--border)", padding: "10px 12px", marginBottom: 8,
                  background: "var(--inset)",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
                  <span style={{ display: "inline-block", width: 6, height: 6, borderRadius: 999, background: color }} />
                  <span
                    data-testid={`case-name-${c.id}`}
                    style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.12em",
                             color: "#7ee3c9", maxWidth: 340, overflow: "hidden",
                             textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                    title={c.name}
                  >
                    💾 {c.name}
                  </span>
                  {v && (
                    <span style={{ fontSize: 9, color: color, border: `1px solid ${color}`, padding: "1px 5px" }}>
                      {v.toUpperCase()}
                    </span>
                  )}
                  <span style={{ fontSize: 10, color: "var(--text-dim)" }}>
                    {c.engine || "?"} · in {c.input_len || 0}c · out {c.output_len || 0}c
                  </span>
                </div>
                <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
                  <button className="nvx-btn sm ghost" onClick={() => reinvestigate(c)}
                          disabled={busy === c.id} data-testid={`btn-case-reinvestigate-${c.id}`}>
                    <RefreshCw size={10} /> {busy === c.id ? "RUNNING…" : "RE-DECODE"}
                  </button>
                  <button className="nvx-btn sm ghost" onClick={() => exportSigma(c)}
                          data-testid={`btn-case-sigma-${c.id}`}
                          title="Export as Sigma detection rule (SIEM-ready YAML)"
                          style={{ borderColor: "#f59e0b", color: "#f59e0b" }}>
                    <Shield size={10} /> SIGMA
                  </button>
                  <button className="nvx-btn sm ghost" onClick={() => openCase(c)}
                          data-testid={`btn-case-open-${c.id}`}>
                    <FolderOpen size={10} /> OPEN
                  </button>
                  <button className="nvx-btn sm ghost" onClick={() => remove(c)}
                          data-testid={`btn-case-delete-${c.id}`}>
                    <Trash2 size={10} />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
