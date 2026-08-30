/**
 * Admin › Data Sources (P0-8).
 *
 * Native, RBAC-gated, audit-tracked data-source control plane.
 * Consumes:
 *   GET/POST/PUT/DELETE /xdr/data-sources
 *   POST /xdr/data-sources/{id}/(enable|disable|test)
 *   GET  /xdr/data-sources/kinds/catalog
 *
 * Contract:
 *  - Never fabricates state; empty renders honestly.
 *  - Kind dropdown is populated from the backend catalog, not hard-coded.
 *  - No client-only authz; the backend rejects unauthorized users with
 *    HTTP 403 · ACCESS_DENIED and the UI surfaces the exact reason.
 */
import React, { useEffect, useMemo, useState } from "react";
import { Plus, RefreshCcw, Power, PowerOff, PlayCircle, Trash2,
                 CheckCircle2, AlertTriangle, HardDrive } from "lucide-react";
import api from "@/lib/api";


export default function DataSourcesBody() {
  const [rows,    setRows]    = useState([]);
  const [kinds,   setKinds]   = useState({});
  const [busy,    setBusy]    = useState(false);
  const [err,     setErr]     = useState(null);
  const [showAdd, setShowAdd] = useState(false);
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    (async () => {
      setBusy(true); setErr(null);
      try {
        const [ds, cat] = await Promise.all([
          api.get("/xdr/data-sources"),
          api.get("/xdr/data-sources/kinds/catalog"),
        ]);
        setRows(ds?.data?.data?.data_sources || []);
        setKinds(cat?.data?.data?.kinds || {});
      } catch (e) {
        setErr(e?.response?.data?.detail || e?.message || "load failed");
      } finally { setBusy(false); }
    })();
  }, [refresh]);

  const kindKeys = useMemo(() => Object.keys(kinds).sort(), [kinds]);

  const act = async (fn) => {
    try { await fn(); setRefresh((n) => n + 1); }
    catch (e) {
      const d = e?.response?.data?.detail;
      alert(typeof d === "string" ? d : JSON.stringify(d || e.message));
    }
  };

  return (
    <div data-testid="xdr-admin-data-sources-body">
      <div style={rowBar}>
        <button className="btn" data-testid="ds-add-btn"
                     onClick={() => setShowAdd(true)}>
          <Plus size={11} /> Add data source
        </button>
        <button className="btn ghost" data-testid="ds-refresh"
                     onClick={() => setRefresh((n) => n + 1)}>
          <RefreshCcw size={11} /> Refresh
        </button>
        <span style={{ flex: 1 }} />
        <span className="mono" style={{ fontSize: 10.5, color: "var(--faint)" }}>
          {rows.length} data source{rows.length === 1 ? "" : "s"}
        </span>
      </div>

      {err && <div data-testid="ds-error"
                             style={{ color: "var(--amber)", fontSize: 11,
                                             marginBottom: 8 }}>{err}</div>}

      <div style={{ border: "1px solid var(--border)", borderRadius: 3,
                          overflow: "hidden" }}>
        <div className="mono" style={rowHead}>
          <div>Name</div><div>Kind</div><div>Protocol</div>
          <div>State</div><div>Enabled</div><div>Events</div><div>Actions</div>
        </div>
        {rows.map((r) => (
          <div key={r.id} className="mono" style={rowBody}
                   data-testid={`ds-row-${r.id}`}>
            <div style={{ color: "var(--text)" }}>{r.name}
              {r.description && <div style={{ fontSize: 10,
                                                                  color: "var(--faint)" }}>
                {r.description}
              </div>}
            </div>
            <div style={{ fontSize: 10.5, color: "var(--cyan)" }}>{r.kind}</div>
            <div style={{ fontSize: 10.5, color: "var(--text-dim)" }}>
              {r.protocol}
            </div>
            <StateBadge state={r.state} />
            <div>{r.enabled
              ? <span style={{ color: "var(--mint)" }}>ENABLED</span>
              : <span style={{ color: "#f87171" }}>DISABLED</span>}</div>
            <div style={{ fontSize: 10, color: "var(--faint)" }}>
              {r.events_received || 0} rx
              {" · "}{r.events_normalized || 0} norm
              {r.events_error > 0 && <span style={{ color: "var(--amber)" }}>
                {" · "}{r.events_error} err
              </span>}
            </div>
            <div style={{ display: "flex", gap: 4 }}>
              <button className="btn ghost" style={iconBtn}
                           data-testid={`ds-toggle-${r.id}`}
                           title={r.enabled ? "Disable" : "Enable"}
                           onClick={() => act(() => api.post(
                              `/xdr/data-sources/${r.id}/${r.enabled ? "disable" : "enable"}`))}>
                {r.enabled ? <PowerOff size={11} /> : <Power size={11} />}
              </button>
              <button className="btn ghost" style={iconBtn}
                           data-testid={`ds-test-${r.id}`}
                           title="Test connection"
                           onClick={() => act(() => api.post(
                              `/xdr/data-sources/${r.id}/test`))}>
                <PlayCircle size={11} />
              </button>
              <button className="btn ghost" style={iconBtn}
                           data-testid={`ds-delete-${r.id}`}
                           title="Delete"
                           onClick={() => {
                              if (!window.confirm(`Delete '${r.name}'?`)) return;
                              act(() => api.delete(`/xdr/data-sources/${r.id}`));
                           }}>
                <Trash2 size={11} />
              </button>
            </div>
          </div>
        ))}
        {rows.length === 0 && !busy && (
          <div data-testid="ds-empty" style={emptyRow}>
            NO DATA SOURCES · click Add data source to create one.
          </div>
        )}
      </div>

      {showAdd && <AddDataSourceModal
        kindKeys={kindKeys} kinds={kinds}
        onClose={() => setShowAdd(false)}
        onCreated={() => { setShowAdd(false); setRefresh((n) => n + 1); }}
      />}
    </div>
  );
}


function StateBadge({ state }) {
  const color = state === "CONNECTED" ? "var(--mint)"
                          : state === "DEGRADED"  ? "var(--amber)"
                          : state === "DISABLED"  ? "var(--faint)"
                          : state === "PARSE_ERROR" ? "#f87171"
                          : state === "AUTH_FAILED" ? "#f87171"
                          : state === "CONNECTION_FAILED" ? "#f87171"
                          : "var(--faint)";
  const Icon = state === "CONNECTED" ? CheckCircle2 : AlertTriangle;
  return (
    <span data-testid={`state-${state}`}
              style={{ display: "inline-flex", alignItems: "center", gap: 3,
                              padding: "1px 6px", border: `1px solid ${color}`,
                              color, borderRadius: 3, fontSize: 9.5,
                              fontFamily: "var(--mono)", fontWeight: 700 }}>
      <Icon size={10} /> {state || "—"}
    </span>
  );
}


function AddDataSourceModal({ kindKeys, kinds, onClose, onCreated }) {
  const [name, setName]         = useState("");
  const [kind, setKind]         = useState(kindKeys[0] || "");
  const [desc, setDesc]         = useState("");
  const [busy, setBusy]         = useState(false);
  const [err,  setErr]          = useState(null);
  const submit = async () => {
    setBusy(true); setErr(null);
    try {
      await api.post("/xdr/data-sources",
        { name, kind, description: desc });
      onCreated();
    } catch (e) {
      const d = e?.response?.data?.detail;
      setErr(typeof d === "string" ? d : JSON.stringify(d || e.message));
    } finally { setBusy(false); }
  };
  return (
    <div data-testid="ds-add-modal"
             style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.5)",
                             display: "flex", alignItems: "center",
                             justifyContent: "center", zIndex: 60 }}>
      <div className="panel" style={{ padding: 18, width: 480 }}>
        <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
          <HardDrive size={14} style={{ color: "var(--cyan)" }} />
          <b style={{ fontFamily: "var(--mono)", fontSize: 13 }}>
            New Data Source
          </b>
        </div>
        <Field label="Name">
          <input value={name} onChange={(e) => setName(e.target.value)}
                     data-testid="ds-add-name" style={inputStyle} />
        </Field>
        <Field label="Kind">
          <select value={kind} onChange={(e) => setKind(e.target.value)}
                      data-testid="ds-add-kind" style={inputStyle}>
            {kindKeys.map((k) =>
              <option key={k} value={k}>
                {k} · {kinds[k]?.protocol}
              </option>)}
          </select>
        </Field>
        <Field label="Description">
          <input value={desc} onChange={(e) => setDesc(e.target.value)}
                     data-testid="ds-add-desc" style={inputStyle} />
        </Field>
        {err && <div style={{ color: "var(--amber)", fontSize: 11,
                                          marginBottom: 8 }}>{err}</div>}
        <div style={{ display: "flex", gap: 6 }}>
          <button className="btn" onClick={submit} disabled={busy}
                       data-testid="ds-add-submit">
            {busy ? "Creating…" : "Create"}
          </button>
          <button className="btn ghost" onClick={onClose}
                       data-testid="ds-add-cancel">Cancel</button>
        </div>
      </div>
    </div>
  );
}


function Field({ label, children }) {
  return (
    <div style={{ marginBottom: 10 }}>
      <div className="mono" style={{ fontSize: 9.5, color: "var(--faint)",
                                                    textTransform: "uppercase",
                                                    marginBottom: 3 }}>{label}</div>
      {children}
    </div>
  );
}


const inputStyle = {
  padding: "4px 8px", fontSize: 11, border: "1px solid var(--border)",
  borderRadius: 3, background: "var(--panel2)", color: "var(--text)",
  fontFamily: "var(--mono)", width: "100%",
};
const rowBar = {
  display: "flex", gap: 6, marginBottom: 10, alignItems: "center",
};
const rowHead = {
  display: "grid",
  gridTemplateColumns: "1.5fr 1fr 0.8fr 0.9fr 0.7fr 1.2fr 0.9fr",
  gap: 6, padding: "4px 8px", background: "var(--panel2)",
  fontSize: 10, color: "var(--faint)", textTransform: "uppercase",
};
const rowBody = {
  display: "grid",
  gridTemplateColumns: "1.5fr 1fr 0.8fr 0.9fr 0.7fr 1.2fr 0.9fr",
  gap: 6, padding: "6px 8px", fontSize: 11,
  color: "var(--text-dim)", borderTop: "1px solid var(--border)",
  alignItems: "center",
};
const iconBtn = { padding: "2px 6px", fontSize: 10 };
const emptyRow = { padding: 10, fontSize: 11, color: "var(--faint)",
                              fontFamily: "var(--mono)" };
