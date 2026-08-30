/**
 * Admin › API / Webhooks — P0-5 live surface.
 *
 * Consumes:
 *   GET  /api/xdr/webhooks
 *   POST /api/xdr/webhooks                        (returns secret ONCE)
 *   POST /api/xdr/webhooks/{id}/rotate-secret     (returns new secret)
 *   POST /api/xdr/webhooks/{id}/test              (delivery states)
 *   POST /api/xdr/webhooks/{id}/replay/{delivery} (replay from history)
 *   GET  /api/xdr/webhooks/{id}/deliveries
 *   DELETE /api/xdr/webhooks/{id}
 */
import React, { useEffect, useState } from "react";
import {
  Webhook, Plus, RefreshCcw, RotateCw, PlayCircle, Trash2, Copy, X,
  History,
} from "lucide-react";
import api from "@/lib/api";


function Badge({ label, color = "var(--faint)" }) {
  return <span style={{
    display: "inline-block", padding: "1px 6px", borderRadius: 3,
    border: `1px solid ${color}`, color, fontSize: 9.5,
    letterSpacing: ".3px", fontWeight: 700, textTransform: "uppercase",
    fontFamily: "var(--mono)",
  }}>{label}</span>;
}
const stateColor = (s) => (
  s === "DELIVERED" ? "var(--mint)"
    : s === "DLQ" || s === "FAILED" ? "#f87171"
    : s === "RETRYING" ? "var(--amber)"
    : "var(--faint)"
);


function RevealModal({ secret, onClose }) {
  return (
    <div style={overlay}>
      <div className="panel" style={{ padding: 18, width: 540 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
          <Webhook size={14} style={{ color: "var(--amber)" }} />
          <b style={{ fontFamily: "var(--mono)", fontSize: 12 }}>WEBHOOK SECRET · ONE-TIME</b>
          <span style={{ flex: 1 }} />
          <button className="btn ghost" onClick={onClose} style={{ padding: "2px 8px", fontSize: 11 }}><X size={11} /></button>
        </div>
        <div className="mono" data-testid="xdr-webhook-secret"
                 style={{ padding: 10, background: "var(--panel2)",
                                 border: "1px solid var(--border)", borderRadius: 3,
                                 color: "var(--amber)", wordBreak: "break-all",
                                 fontSize: 12 }}>
          {secret}
        </div>
        <div style={{ display: "flex", gap: 6, marginTop: 10 }}>
          <button className="btn ghost" onClick={() => navigator.clipboard?.writeText(secret)}
                       style={{ padding: "3px 10px", fontSize: 11 }}>
            <Copy size={11} /> Copy
          </button>
          <span style={{ flex: 1 }} />
          <button className="btn" onClick={onClose} style={{ padding: "3px 10px", fontSize: 11 }}>
            I've stored the secret
          </button>
        </div>
      </div>
    </div>
  );
}


function AddModal({ onClose, onCreated }) {
  const [f, setF] = useState({ name: "", url: "", events: "ALERT_*,INCIDENT_*",
                                                      max_retries: 3, timeout_seconds: 10 });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const submit = async () => {
    setBusy(true); setErr(null);
    try {
      const body = { ...f,
                              events: f.events.split(/[\s,]+/).filter(Boolean) };
      const r = await api.post("/api/xdr/webhooks", body);
      onCreated?.(r?.data); onClose();
    } catch (e) {
      setErr(e?.response?.data?.detail?.reason
                 || e?.response?.data?.detail || e?.message);
    } finally { setBusy(false); }
  };
  return (
    <div style={overlay} data-testid="xdr-webhook-add-modal">
      <div className="panel" style={{ padding: 18, width: 500 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
          <Webhook size={14} style={{ color: "var(--mint)" }} />
          <b style={{ fontFamily: "var(--mono)", fontSize: 12 }}>NEW WEBHOOK</b>
          <span style={{ flex: 1 }} />
          <button className="btn ghost" onClick={onClose} style={{ padding: "2px 8px", fontSize: 11 }}><X size={11} /></button>
        </div>
        <label style={lbl}>Name<input value={f.name}
          data-testid="xdr-webhook-add-name"
          onChange={(e) => setF({ ...f, name: e.target.value })} style={inp} /></label>
        <label style={lbl}>URL<input value={f.url}
          data-testid="xdr-webhook-add-url"
          onChange={(e) => setF({ ...f, url: e.target.value })} style={inp}
          placeholder="https://example.com/hook" /></label>
        <label style={lbl}>Events (comma-separated · supports `*` prefix)
          <input value={f.events}
            data-testid="xdr-webhook-add-events"
            onChange={(e) => setF({ ...f, events: e.target.value })} style={inp} /></label>
        <div style={{ display: "flex", gap: 8 }}>
          <label style={{ ...lbl, flex: 1 }}>Max retries<input type="number"
            value={f.max_retries} onChange={(e) => setF({ ...f, max_retries: +e.target.value })} style={inp} /></label>
          <label style={{ ...lbl, flex: 1 }}>Timeout (s)<input type="number"
            value={f.timeout_seconds} onChange={(e) => setF({ ...f, timeout_seconds: +e.target.value })} style={inp} /></label>
        </div>
        {err && <div style={{ color: "#f87171", fontSize: 11 }}
                                data-testid="xdr-webhook-add-error">{err}</div>}
        <div style={{ display: "flex", gap: 6, marginTop: 12 }}>
          <span style={{ flex: 1 }} />
          <button className="btn ghost" onClick={onClose} style={{ padding: "3px 10px", fontSize: 11 }}>Cancel</button>
          <button className="btn" disabled={busy || !f.name || !f.url}
                       data-testid="xdr-webhook-add-submit"
                       onClick={submit} style={{ padding: "3px 10px", fontSize: 11 }}>
            <Plus size={11} /> {busy ? "Creating…" : "Create"}
          </button>
        </div>
      </div>
    </div>
  );
}


function DeliveriesPanel({ hook, onClose }) {
  const [rows, setRows] = useState([]);
  useEffect(() => {
    (async () => {
      try {
        const r = await api.get(`/api/xdr/webhooks/${hook.id}/deliveries`);
        setRows(r?.data?.data?.deliveries || []);
      } catch { setRows([]); }
    })();
  }, [hook]);
  const replay = async (d) => {
    try {
      await api.post(`/api/xdr/webhooks/${hook.id}/replay/${d.id}`);
      const r = await api.get(`/api/xdr/webhooks/${hook.id}/deliveries`);
      setRows(r?.data?.data?.deliveries || []);
    } catch { /* honest */ }
  };
  return (
    <div style={overlay}>
      <div className="panel" style={{ padding: 18, width: 720, maxHeight: "82vh", overflow: "auto" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
          <History size={14} />
          <b style={{ fontFamily: "var(--mono)", fontSize: 12 }}>
            DELIVERIES · {hook.name}
          </b>
          <span style={{ flex: 1 }} />
          <button className="btn ghost" onClick={onClose} style={{ padding: "2px 8px", fontSize: 11 }}>Close</button>
        </div>
        {rows.length === 0 && <div style={{ padding: 10, fontSize: 11, color: "var(--faint)" }}>NO DELIVERIES YET</div>}
        {rows.map((d) => (
          <div key={d.id} className="mono" style={{ padding: 6, borderBottom: "1px solid var(--border)",
                                                                                fontSize: 10.5, color: "var(--text-dim)" }}
                   data-testid={`xdr-webhook-delivery-${d.id}`}>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <Badge label={d.final_state} color={stateColor(d.final_state)} />
              <span style={{ color: "var(--cyan)" }}>{d.event}</span>
              <span>attempt {d.attempt_count}</span>
              <span style={{ color: "var(--faint)" }}>{(d.created_at || "").slice(0, 19)}</span>
              {d.last_status && <span>http={d.last_status}</span>}
              <span style={{ flex: 1 }} />
              {(d.final_state === "DLQ" || d.final_state === "FAILED") && (
                <button className="btn ghost" onClick={() => replay(d)}
                             data-testid={`xdr-webhook-replay-${d.id}`}
                             style={{ padding: "2px 6px", fontSize: 10 }}>
                  <PlayCircle size={10} /> Replay
                </button>
              )}
            </div>
            {d.last_error && <div style={{ color: "#f87171" }}>{d.last_error}</div>}
          </div>
        ))}
      </div>
    </div>
  );
}


export default function WebhooksBody() {
  const [rows, setRows] = useState([]);
  const [err, setErr] = useState(null);
  const [addOpen, setAddOpen] = useState(false);
  const [revealSecret, setRevealSecret] = useState(null);
  const [historyFor, setHistoryFor] = useState(null);
  const [tick, setTick] = useState(0);
  const [lastAudit, setLastAudit] = useState(null);
  useEffect(() => {
    (async () => {
      try {
        const r = await api.get("/api/xdr/webhooks");
        const j = r?.data;
        if (j?.ok === false) { setErr(j?.error?.detail || "unavailable"); setRows([]); return; }
        setRows(j?.data?.webhooks || []); setErr(null);
      } catch (e) {
        setErr(e?.response?.data?.detail?.reason || e?.message);
        setRows([]);
      }
    })();
  }, [tick]);

  const test = async (h) => {
    try {
      const r = await api.post(`/api/xdr/webhooks/${h.id}/test`, {
        event: "webhook.test", payload: { hello: "nivxray" },
      });
      setLastAudit(r?.data?.audit_ref);
      alert(`Test delivery · state=${r?.data?.data?.final_state} · ${r?.data?.data?.last_status ?? "no-http-status"}`);
    } catch (e) { alert(e?.response?.data?.detail || e?.message); }
  };
  const rotate = async (h) => {
    try {
      const r = await api.post(`/api/xdr/webhooks/${h.id}/rotate-secret`);
      setRevealSecret(r?.data?.data?.secret);
      setLastAudit(r?.data?.audit_ref);
    } catch (e) { alert(e?.response?.data?.detail || e?.message); }
  };
  const remove = async (h) => {
    if (!window.confirm(`Delete webhook '${h.name}'?`)) return;
    try {
      const r = await api.delete(`/api/xdr/webhooks/${h.id}`);
      setLastAudit(r?.data?.audit_ref); setTick((n) => n + 1);
    } catch (e) { alert(e?.response?.data?.detail || e?.message); }
  };
  const toggle = async (h) => {
    try {
      const r = await api.put(`/api/xdr/webhooks/${h.id}`, { enabled: !h.enabled });
      setLastAudit(r?.data?.audit_ref); setTick((n) => n + 1);
    } catch (e) { alert(e?.response?.data?.detail || e?.message); }
  };

  return (
    <div data-testid="xdr-webhooks-body">
      <div style={{ display: "flex", gap: 8, marginBottom: 8, alignItems: "center" }}>
        <button className="btn" onClick={() => setAddOpen(true)}
                     data-testid="xdr-webhook-add-btn"
                     style={{ padding: "3px 10px", fontSize: 11 }}>
          <Plus size={11} /> Add webhook
        </button>
        <button className="btn ghost" onClick={() => setTick((n) => n + 1)}
                     style={{ padding: "3px 10px", fontSize: 11 }}>
          <RefreshCcw size={11} /> Refresh
        </button>
        <span style={{ flex: 1 }} />
        {lastAudit && <span style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--faint)" }}>
          last audit: {lastAudit}
        </span>}
      </div>
      {err && <div data-testid="xdr-webhook-error"
                              style={{ padding: 8, border: "1px dashed var(--amber)", borderRadius: 3,
                                              color: "var(--amber)", fontSize: 11, fontFamily: "var(--mono)" }}>
        WEBHOOKS UNAVAILABLE · {err}
      </div>}
      <div data-testid="xdr-webhook-rows" style={{ border: "1px solid var(--border)", borderRadius: 3, overflow: "hidden" }}>
        <div className="mono" style={rowHead}>
          <div>Name</div><div>URL</div><div>Events</div><div>Status</div>
          <div>Secret</div><div>Actions</div>
        </div>
        {rows.length === 0 && (
          <div data-testid="xdr-webhook-empty" style={{ padding: 10, fontSize: 11, color: "var(--faint)",
                                                                                        fontFamily: "var(--mono)" }}>
            NO WEBHOOKS CONFIGURED FOR THIS TENANT YET
          </div>
        )}
        {rows.map((h) => (
          <div key={h.id} className="mono" style={rowBody}
                   data-testid={`xdr-webhook-row-${h.id}`}>
            <div>{h.name}
              {h.description && <div style={{ fontSize: 10, color: "var(--faint)" }}>{h.description}</div>}
            </div>
            <div style={{ color: "var(--cyan)", wordBreak: "break-all", fontSize: 10 }}>{h.url}</div>
            <div style={{ fontSize: 10, color: "var(--text-dim)" }}>{(h.events || []).join(", ")}</div>
            <div>{h.enabled
              ? <Badge label="ENABLED" color="var(--mint)" />
              : <Badge label="DISABLED" color="#f87171" />}</div>
            <div style={{ color: "var(--amber)" }}>{h.secret_preview}</div>
            <div style={{ display: "flex", gap: 4 }}>
              <button className="btn ghost" title="Test delivery"
                           data-testid={`xdr-webhook-test-${h.id}`}
                           onClick={() => test(h)} disabled={!h.enabled}
                           style={iconBtn}><PlayCircle size={11} /></button>
              <button className="btn ghost" title="Deliveries"
                           data-testid={`xdr-webhook-history-${h.id}`}
                           onClick={() => setHistoryFor(h)}
                           style={iconBtn}><History size={11} /></button>
              <button className="btn ghost" title="Rotate secret"
                           data-testid={`xdr-webhook-rotate-${h.id}`}
                           onClick={() => rotate(h)}
                           style={iconBtn}><RotateCw size={11} /></button>
              <button className="btn ghost" title={h.enabled ? "Disable" : "Enable"}
                           data-testid={`xdr-webhook-toggle-${h.id}`}
                           onClick={() => toggle(h)}
                           style={iconBtn}>{h.enabled ? "OFF" : "ON"}</button>
              <button className="btn ghost" title="Delete"
                           data-testid={`xdr-webhook-delete-${h.id}`}
                           onClick={() => remove(h)}
                           style={{ ...iconBtn, color: "#f87171" }}><Trash2 size={11} /></button>
            </div>
          </div>
        ))}
      </div>
      <div style={{ marginTop: 10, fontSize: 10.5, color: "var(--faint)", fontFamily: "var(--mono)" }}>
        source: <span style={{ color: "var(--cyan)" }}>/api/xdr/webhooks</span> ·
        HMAC-SHA256 signed · secret persisted via P0-2 Secrets Store ·
        `DELIVERED` recorded only after real 2xx HTTP response.
      </div>

      {addOpen && (
        <AddModal onClose={() => setAddOpen(false)}
                          onCreated={(res) => {
                            setRevealSecret(res?.data?.secret);
                            setLastAudit(res?.audit_ref);
                            setTick((n) => n + 1);
                          }} />
      )}
      {revealSecret && <RevealModal secret={revealSecret} onClose={() => setRevealSecret(null)} />}
      {historyFor && <DeliveriesPanel hook={historyFor} onClose={() => setHistoryFor(null)} />}
    </div>
  );
}

const inp = { display: "block", width: "100%", marginTop: 3, padding: "4px 8px", fontSize: 11,
                    border: "1px solid var(--border)", borderRadius: 3,
                    background: "var(--panel2)", color: "var(--text)",
                    fontFamily: "var(--mono)" };
const lbl = { color: "var(--faint)", fontSize: 11, marginBottom: 6, display: "block" };
const overlay = { position: "fixed", inset: 0, background: "rgba(0,0,0,.55)",
                              display: "flex", alignItems: "center", justifyContent: "center", zIndex: 60 };
const rowHead = { display: "grid",
                            gridTemplateColumns: "1fr 1.4fr 1fr 0.6fr 0.6fr 1.1fr",
                            gap: 6, padding: "4px 8px", background: "var(--panel2)",
                            fontSize: 10, color: "var(--faint)", textTransform: "uppercase" };
const rowBody = { display: "grid",
                            gridTemplateColumns: "1fr 1.4fr 1fr 0.6fr 0.6fr 1.1fr",
                            gap: 6, padding: "6px 8px", fontSize: 11,
                            color: "var(--text-dim)", borderTop: "1px solid var(--border)",
                            alignItems: "center" };
const iconBtn = { padding: "2px 6px", fontSize: 10 };
