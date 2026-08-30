/**
 * Admin › Collectors (P0-8).
 *
 * Native, RBAC-gated, audit-tracked collector control plane with an
 * evidence-backed state machine and honest protocol registry.
 *
 * Consumes:
 *   GET/POST/PUT/DELETE /xdr/collectors
 *   POST /xdr/collectors/{id}/(start|stop|enable|disable|test)
 *   GET  /xdr/collectors/protocols/catalog
 *
 * CRITICAL invariant surfaced in the UI:
 *   CONNECTED may only appear after real telemetry has been received,
 *   parsed and normalized.  The State Evidence panel shows exactly why
 *   the collector currently holds its state.  No fake CONNECTED.
 */
import React, { useEffect, useMemo, useState } from "react";
import { Plus, RefreshCcw, Play, Square, Power, PowerOff, PlayCircle,
                 Trash2, CheckCircle2, AlertTriangle, XCircle, Cpu,
                 ChevronRight } from "lucide-react";
import api from "@/lib/api";


const STATE_COLOR = {
  ADOPTED:           "var(--faint)",
  CONFIGURED:        "var(--faint)",
  STARTING:          "var(--amber)",
  AUTH_FAILED:       "#f87171",
  CONNECTION_FAILED: "#f87171",
  NO_TELEMETRY:      "var(--amber)",
  PARSE_ERROR:       "#f87171",
  CONNECTED:         "var(--mint)",
  DEGRADED:          "var(--amber)",
  DISABLED:          "var(--faint)",
};


export default function CollectorsBody() {
  const [rows,      setRows]      = useState([]);
  const [protocols, setProtocols] = useState({});
  const [counts,    setCounts]    = useState({});
  const [busy,      setBusy]      = useState(false);
  const [err,       setErr]       = useState(null);
  const [showAdd,   setShowAdd]   = useState(false);
  const [openId,    setOpenId]    = useState(null);
  const [refresh,   setRefresh]   = useState(0);

  useEffect(() => {
    (async () => {
      setBusy(true); setErr(null);
      try {
        const [list, cat] = await Promise.all([
          api.get("/xdr/collectors"),
          api.get("/xdr/collectors/protocols/catalog"),
        ]);
        setRows(list?.data?.data?.collectors || []);
        setProtocols(cat?.data?.data?.protocols || {});
        setCounts(cat?.data?.data?.counts || {});
      } catch (e) {
        setErr(e?.response?.data?.detail || e?.message || "load failed");
      } finally { setBusy(false); }
    })();
  }, [refresh]);

  const act = async (fn) => {
    try { await fn(); setRefresh((n) => n + 1); }
    catch (e) {
      const d = e?.response?.data?.detail;
      alert(typeof d === "string" ? d : JSON.stringify(d || e.message));
    }
  };

  const openRow = useMemo(() =>
    rows.find((r) => r.id === openId), [rows, openId]);

  return (
    <div data-testid="xdr-admin-collectors-body">
      <div style={rowBar}>
        <button className="btn" data-testid="col-add-btn"
                     onClick={() => setShowAdd(true)}>
          <Plus size={11} /> Add collector
        </button>
        <button className="btn ghost" data-testid="col-refresh"
                     onClick={() => setRefresh((n) => n + 1)}>
          <RefreshCcw size={11} /> Refresh
        </button>
        <span style={{ flex: 1 }} />
        <ProtoBadge counts={counts} />
      </div>

      {err && <div data-testid="col-error"
                             style={{ color: "var(--amber)", fontSize: 11,
                                             marginBottom: 8 }}>{err}</div>}

      <div style={{ border: "1px solid var(--border)", borderRadius: 3,
                          overflow: "hidden" }}>
        <div className="mono" style={rowHead}>
          <div>Name</div><div>Protocol</div><div>Impl.</div><div>State</div>
          <div>Enabled</div><div>Events (rx / parsed / norm / err)</div>
          <div>Actions</div>
        </div>
        {rows.map((r) => (
          <div key={r.id} className="mono" style={rowBody}
                   data-testid={`col-row-${r.id}`}
                   onClick={() => setOpenId(r.id)}>
            <div style={{ color: "var(--text)", cursor: "pointer" }}>
              <ChevronRight size={9} style={{ marginRight: 3 }} />
              {r.name}
              {r.description && <div style={{ fontSize: 10,
                                                                  color: "var(--faint)" }}>
                {r.description}
              </div>}
            </div>
            <div style={{ fontSize: 10.5, color: "var(--cyan)" }}>{r.protocol}</div>
            <ImplBadge value={r.implementation} />
            <StateBadge state={r.state} />
            <div>{r.enabled
              ? <span style={{ color: "var(--mint)" }}>ENABLED</span>
              : <span style={{ color: "#f87171" }}>DISABLED</span>}</div>
            <div style={{ fontSize: 10, color: "var(--faint)" }}>
              {r.events_received || 0} / {r.events_parsed || 0} /{" "}
              {r.events_normalized || 0}
              {r.events_error > 0 && <span style={{ color: "var(--amber)" }}>
                {" / "}{r.events_error} err
              </span>}
            </div>
            <div style={{ display: "flex", gap: 4 }}
                     onClick={(e) => e.stopPropagation()}>
              <button className="btn ghost" style={iconBtn}
                           title="Start"
                           data-testid={`col-start-${r.id}`}
                           onClick={() => act(() => api.post(
                              `/xdr/collectors/${r.id}/start`))}>
                <Play size={11} />
              </button>
              <button className="btn ghost" style={iconBtn}
                           title="Stop"
                           data-testid={`col-stop-${r.id}`}
                           onClick={() => act(() => api.post(
                              `/xdr/collectors/${r.id}/stop`))}>
                <Square size={11} />
              </button>
              <button className="btn ghost" style={iconBtn}
                           title={r.enabled ? "Disable" : "Enable"}
                           data-testid={`col-toggle-${r.id}`}
                           onClick={() => act(() => api.post(
                              `/xdr/collectors/${r.id}/${r.enabled ? "disable" : "enable"}`))}>
                {r.enabled ? <PowerOff size={11} /> : <Power size={11} />}
              </button>
              <button className="btn ghost" style={iconBtn}
                           title="Test"
                           data-testid={`col-test-${r.id}`}
                           onClick={() => act(() => api.post(
                              `/xdr/collectors/${r.id}/test`))}>
                <PlayCircle size={11} />
              </button>
              <button className="btn ghost" style={iconBtn}
                           title="Delete"
                           data-testid={`col-delete-${r.id}`}
                           onClick={() => {
                              if (!window.confirm(`Delete '${r.name}'?`)) return;
                              act(() => api.delete(`/xdr/collectors/${r.id}`));
                           }}>
                <Trash2 size={11} />
              </button>
            </div>
          </div>
        ))}
        {rows.length === 0 && !busy && (
          <div data-testid="col-empty" style={emptyRow}>
            NO COLLECTORS · click Add collector to create one.
          </div>
        )}
      </div>

      {showAdd && <AddCollectorModal
        protocols={protocols}
        onClose={() => setShowAdd(false)}
        onCreated={() => { setShowAdd(false); setRefresh((n) => n + 1); }}
      />}

      {openRow && <StateEvidencePanel row={openRow}
                                                    onClose={() => setOpenId(null)} />}
    </div>
  );
}


function StateBadge({ state }) {
  const color = STATE_COLOR[state] || "var(--faint)";
  const Icon  = state === "CONNECTED" ? CheckCircle2
                            : (state === "AUTH_FAILED"
                                  || state === "CONNECTION_FAILED"
                                  || state === "PARSE_ERROR") ? XCircle
                            : AlertTriangle;
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


function ImplBadge({ value }) {
  const color = value === "IMPLEMENTED" ? "var(--mint)"
                          : value === "SCAFFOLD"    ? "var(--amber)"
                          :                                           "#f87171";
  return (
    <span data-testid={`impl-${value}`}
              style={{ fontFamily: "var(--mono)", fontSize: 9.5,
                              color, letterSpacing: ".3px" }}>
      {value || "—"}
    </span>
  );
}


function ProtoBadge({ counts }) {
  return (
    <span className="mono" style={{ fontSize: 10.5, color: "var(--faint)" }}>
      protocols: <span style={{ color: "var(--mint)" }}>
        {counts.implemented || 0} implemented
      </span>{" · "}<span style={{ color: "var(--amber)" }}>
        {counts.scaffold || 0} scaffold
      </span>{" · "}{counts.blocked || 0} blocked
    </span>
  );
}


function AddCollectorModal({ protocols, onClose, onCreated }) {
  const keys = Object.keys(protocols).sort();
  const [name,     setName]     = useState("");
  const [protocol, setProtocol] = useState(keys[0] || "syslog");
  const [tls,      setTls]      = useState(false);
  const [auth,     setAuth]     = useState("none");
  const [busy,     setBusy]     = useState(false);
  const [err,      setErr]      = useState(null);
  const proto = protocols[protocol] || {};
  const submit = async () => {
    setBusy(true); setErr(null);
    try {
      await api.post("/xdr/collectors",
        { name, protocol, tls, auth_kind: auth });
      onCreated();
    } catch (e) {
      const d = e?.response?.data?.detail;
      setErr(typeof d === "string" ? d : JSON.stringify(d || e.message));
    } finally { setBusy(false); }
  };
  return (
    <div data-testid="col-add-modal"
             style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.5)",
                             display: "flex", alignItems: "center",
                             justifyContent: "center", zIndex: 60 }}>
      <div className="panel" style={{ padding: 18, width: 520 }}>
        <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
          <Cpu size={14} style={{ color: "var(--cyan)" }} />
          <b style={{ fontFamily: "var(--mono)", fontSize: 13 }}>
            New Collector
          </b>
        </div>
        <Field label="Name">
          <input value={name} onChange={(e) => setName(e.target.value)}
                     data-testid="col-add-name" style={inputStyle} />
        </Field>
        <Field label="Protocol">
          <select value={protocol} onChange={(e) => setProtocol(e.target.value)}
                      data-testid="col-add-protocol" style={inputStyle}>
            {keys.map((k) =>
              <option key={k} value={k}>
                {k} · {protocols[k]?.implementation}
              </option>)}
          </select>
        </Field>
        <div style={{ fontSize: 10, color: "var(--faint)",
                          marginBottom: 8, fontFamily: "var(--mono)" }}>
          {proto.notes}
        </div>
        <Field label="Auth kind">
          <select value={auth} onChange={(e) => setAuth(e.target.value)}
                      data-testid="col-add-auth" style={inputStyle}>
            <option value="none">none</option>
            <option value="basic">basic</option>
            <option value="bearer">bearer</option>
            <option value="hmac">hmac</option>
            <option value="mtls">mtls</option>
          </select>
        </Field>
        <label style={{ display: "flex", gap: 6, alignItems: "center",
                              fontSize: 11, color: "var(--text-dim)",
                              marginBottom: 10 }}>
          <input type="checkbox" checked={tls}
                     data-testid="col-add-tls"
                     onChange={(e) => setTls(e.target.checked)} /> TLS
        </label>
        {err && <div style={{ color: "var(--amber)", fontSize: 11,
                                          marginBottom: 8 }}>{err}</div>}
        <div style={{ display: "flex", gap: 6 }}>
          <button className="btn" onClick={submit} disabled={busy}
                       data-testid="col-add-submit">
            {busy ? "Creating…" : "Create"}
          </button>
          <button className="btn ghost" onClick={onClose}
                       data-testid="col-add-cancel">Cancel</button>
        </div>
      </div>
    </div>
  );
}


function StateEvidencePanel({ row, onClose }) {
  const ev = row.state_evidence || {};
  return (
    <div data-testid="col-state-evidence"
             style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.55)",
                             display: "flex", alignItems: "center",
                             justifyContent: "center", zIndex: 60 }}>
      <div className="panel" style={{ padding: 18, width: 620 }}>
        <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
          <Cpu size={14} style={{ color: "var(--cyan)" }} />
          <b style={{ fontFamily: "var(--mono)", fontSize: 13 }}>
            {row.name}
          </b>
          <StateBadge state={row.state} />
          <span style={{ flex: 1 }} />
          <button className="btn ghost"
                       data-testid="col-state-evidence-close"
                       onClick={onClose}
                       style={{ padding: "2px 8px", fontSize: 11 }}>Close</button>
        </div>
        <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                      textTransform: "uppercase",
                                                      marginBottom: 4 }}>
          State evidence
        </div>
        <div style={{ padding: 10, borderRadius: 3,
                          background: "var(--panel2)",
                          border: "1px solid var(--border)",
                          fontFamily: "var(--mono)", fontSize: 11,
                          color: "var(--text-dim)" }}>
          <div><b>Reason:</b> {row.state_reason || "—"}</div>
          <div>events received:   {row.events_received   || 0}</div>
          <div>events parsed:     {row.events_parsed     || 0}</div>
          <div>events normalized: {row.events_normalized || 0}</div>
          <div>events error:      {row.events_error      || 0}</div>
          <div>last event:        {row.last_event_at || "—"}</div>
          {ev.at && <div>recorded at:        {ev.at}</div>}
          {ev.by && <div>recorded by:        {ev.by}</div>}
        </div>
        <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                      marginTop: 8, lineHeight: 1.5 }}>
          CONNECTED requires evidence: received &gt; 0 AND parsed &gt; 0 AND
          normalized &gt; 0.  Admin actions cannot promote to CONNECTED —
          only the ingest telemetry path can.
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
  gridTemplateColumns: "1.4fr 0.7fr 0.7fr 1fr 0.7fr 1.6fr 1.2fr",
  gap: 6, padding: "4px 8px", background: "var(--panel2)",
  fontSize: 10, color: "var(--faint)", textTransform: "uppercase",
};
const rowBody = {
  display: "grid",
  gridTemplateColumns: "1.4fr 0.7fr 0.7fr 1fr 0.7fr 1.6fr 1.2fr",
  gap: 6, padding: "6px 8px", fontSize: 11,
  color: "var(--text-dim)", borderTop: "1px solid var(--border)",
  alignItems: "center", cursor: "pointer",
};
const iconBtn = { padding: "2px 6px", fontSize: 10 };
const emptyRow = { padding: 10, fontSize: 11, color: "var(--faint)",
                              fontFamily: "var(--mono)" };
