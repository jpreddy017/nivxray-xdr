/**
 * Admin › Secrets Store — P0-2 write surface.
 *
 * Reads GET /api/xdr/secrets  (masked)
 * Writes POST/PUT/POST rotate/DELETE  and POST reveal (audit-logged).
 *
 * Contract:
 *  • Plaintext values NEVER hit the list view.  Only `preview` (last-4).
 *  • Reveal is explicit — requires `X-Secret-Reveal: yes` and shows a
 *    modal with the plaintext + a "the audit chain has recorded this"
 *    banner.  Copy-to-clipboard is provided; the value is redacted the
 *    moment the modal closes.
 *  • Every mutation displays the returned audit_ref so operators can
 *    trace it back to Audit Log.
 *  • Empty state renders honestly (no fabricated rows).
 */
import React, { useEffect, useState } from "react";
import {
  KeyRound, Plus, RefreshCcw, Eye, Trash2, RotateCw, PowerOff,
  Power, X, Copy, ShieldCheck,
} from "lucide-react";

import api from "@/lib/api";


const KINDS = ["api_key", "bearer_token", "oauth_client_secret",
                       "hmac_secret", "password", "generic"];


function Badge({ label, color = "var(--faint)", testid }) {
  return (
    <span data-testid={testid} style={{
      display: "inline-block", padding: "1px 6px", borderRadius: 3,
      border: `1px solid ${color}`, color, fontSize: 9.5,
      letterSpacing: ".3px", fontWeight: 700, textTransform: "uppercase",
      fontFamily: "var(--mono)",
    }}>{label}</span>
  );
}


function AddSecretModal({ onClose, onCreated }) {
  const [form, setForm] = useState({
    name: "", kind: "api_key", value: "", description: "",
  });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  const submit = async () => {
    setBusy(true); setErr(null);
    try {
      const r = await api.post("/api/xdr/secrets", form);
      onCreated?.(r?.data);
      onClose();
    } catch (e) {
      setErr(e?.response?.data?.detail || e?.message || "create failed");
    } finally { setBusy(false); }
  };

  return (
    <div data-testid="xdr-secret-add-modal"
             style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.55)",
                             display: "flex", alignItems: "center",
                             justifyContent: "center", zIndex: 60 }}>
      <div className="panel" style={{ padding: 18, width: 460 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8,
                          marginBottom: 10 }}>
          <KeyRound size={14} style={{ color: "var(--mint)" }} />
          <b style={{ fontFamily: "var(--mono)", fontSize: 12 }}>ADD SECRET</b>
          <span style={{ flex: 1 }} />
          <button onClick={onClose} className="btn ghost"
                       data-testid="xdr-secret-add-cancel"
                       style={{ padding: "2px 6px", fontSize: 11 }}>
            <X size={11} />
          </button>
        </div>
        <div style={{ display: "grid", gap: 8, fontSize: 11 }}>
          <label style={{ color: "var(--faint)" }}>Name (unique per tenant)
            <input value={form.name} data-testid="xdr-secret-add-name"
                       onChange={(e) => setForm({ ...form, name: e.target.value })}
                       style={inputStyle} placeholder="vt-api-key" />
          </label>
          <label style={{ color: "var(--faint)" }}>Kind
            <select value={form.kind} data-testid="xdr-secret-add-kind"
                        onChange={(e) => setForm({ ...form, kind: e.target.value })}
                        style={inputStyle}>
              {KINDS.map((k) => <option key={k}>{k}</option>)}
            </select>
          </label>
          <label style={{ color: "var(--faint)" }}>Value (never displayed after save)
            <input type="password" value={form.value}
                       data-testid="xdr-secret-add-value"
                       onChange={(e) => setForm({ ...form, value: e.target.value })}
                       style={inputStyle} placeholder="secret plaintext" />
          </label>
          <label style={{ color: "var(--faint)" }}>Description
            <input value={form.description}
                       data-testid="xdr-secret-add-desc"
                       onChange={(e) => setForm({ ...form, description: e.target.value })}
                       style={inputStyle} placeholder="What this is used for" />
          </label>
        </div>
        {err && <div style={{ marginTop: 8, color: "#f87171", fontSize: 11 }}
                              data-testid="xdr-secret-add-error">{err}</div>}
        <div style={{ display: "flex", gap: 6, marginTop: 12 }}>
          <span style={{ flex: 1 }} />
          <button className="btn ghost" onClick={onClose}
                       style={{ padding: "3px 10px", fontSize: 11 }}>Cancel</button>
          <button className="btn" disabled={busy || !form.name || !form.value}
                       data-testid="xdr-secret-add-submit"
                       onClick={submit}
                       style={{ padding: "3px 10px", fontSize: 11 }}>
            <Plus size={11} /> {busy ? "Saving…" : "Save secret"}
          </button>
        </div>
      </div>
    </div>
  );
}


function RevealModal({ secret, onClose, onRevealed }) {
  const [reason, setReason] = useState("");
  const [plain, setPlain]   = useState(null);
  const [auditRef, setAR]   = useState(null);
  const [err, setErr]       = useState(null);
  const [busy, setBusy]     = useState(false);

  const doReveal = async () => {
    setBusy(true); setErr(null);
    try {
      const r = await api.post(
        `/api/xdr/secrets/${secret.id}/reveal`, null,
        { headers: { "X-Secret-Reveal": "yes",
                             "X-Secret-Reveal-Reason": reason || "unspecified" }},
      );
      setPlain(r?.data?.data?.value ?? null);
      setAR(r?.data?.audit_ref);
      onRevealed?.(r?.data);
    } catch (e) {
      setErr(e?.response?.data?.detail || e?.message || "reveal failed");
    } finally { setBusy(false); }
  };

  return (
    <div data-testid="xdr-secret-reveal-modal"
             style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.55)",
                             display: "flex", alignItems: "center",
                             justifyContent: "center", zIndex: 60 }}>
      <div className="panel" style={{ padding: 18, width: 520 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8,
                          marginBottom: 8 }}>
          <Eye size={14} style={{ color: "var(--amber)" }} />
          <b style={{ fontFamily: "var(--mono)", fontSize: 12 }}>
            REVEAL SECRET · {secret.name}
          </b>
          <span style={{ flex: 1 }} />
          <button onClick={onClose} className="btn ghost"
                       data-testid="xdr-secret-reveal-close"
                       style={{ padding: "2px 6px", fontSize: 11 }}>
            <X size={11} />
          </button>
        </div>
        <div style={{ marginBottom: 8, fontSize: 11,
                          color: "var(--text-dim)", lineHeight: 1.5 }}>
          <ShieldCheck size={11} style={{ verticalAlign: "middle",
                                                                 color: "var(--mint)" }} />
          {" "}Every reveal writes an append-only
          <b> SECRET_REVEALED </b> event to the tamper-evident Audit Log.
        </div>

        {!plain && (
          <>
            <label style={{ color: "var(--faint)", fontSize: 11 }}>
              Reason for reveal (required for compliance)
              <input value={reason}
                         data-testid="xdr-secret-reveal-reason"
                         onChange={(e) => setReason(e.target.value)}
                         style={inputStyle}
                         placeholder="e.g. debugging VT sync failure" />
            </label>
            {err && <div style={{ marginTop: 8, color: "#f87171",
                                                fontSize: 11 }}
                                   data-testid="xdr-secret-reveal-error">{err}</div>}
            <div style={{ display: "flex", gap: 6, marginTop: 12 }}>
              <span style={{ flex: 1 }} />
              <button className="btn ghost" onClick={onClose}
                           style={{ padding: "3px 10px", fontSize: 11 }}>Cancel</button>
              <button className="btn" onClick={doReveal} disabled={busy || !reason}
                           data-testid="xdr-secret-reveal-submit"
                           style={{ padding: "3px 10px", fontSize: 11 }}>
                <Eye size={11} /> {busy ? "Revealing…" : "Reveal plaintext"}
              </button>
            </div>
          </>
        )}

        {plain && (
          <div>
            <div style={{ padding: 10, marginTop: 6,
                              background: "var(--panel2)",
                              border: "1px solid var(--border)", borderRadius: 3,
                              fontFamily: "var(--mono)", fontSize: 12,
                              color: "var(--amber)", wordBreak: "break-all" }}
                    data-testid="xdr-secret-reveal-value">
              {plain}
            </div>
            <div style={{ display: "flex", gap: 6, marginTop: 8 }}>
              <button className="btn ghost"
                           data-testid="xdr-secret-reveal-copy"
                           onClick={() => navigator.clipboard?.writeText(plain)}
                           style={{ padding: "3px 10px", fontSize: 11 }}>
                <Copy size={11} /> Copy
              </button>
              <span style={{ flex: 1 }} />
              {auditRef && (
                <span style={{ fontFamily: "var(--mono)", fontSize: 10,
                                     color: "var(--faint)" }}>
                  audit: {auditRef}
                </span>
              )}
              <button className="btn" onClick={onClose}
                           style={{ padding: "3px 10px", fontSize: 11 }}>Close</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}


function RotateModal({ secret, onClose, onRotated }) {
  const [val, setVal] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr]   = useState(null);
  const submit = async () => {
    setBusy(true); setErr(null);
    try {
      const r = await api.post(`/api/xdr/secrets/${secret.id}/rotate`,
                                            { value: val });
      onRotated?.(r?.data);
      onClose();
    } catch (e) {
      setErr(e?.response?.data?.detail || e?.message || "rotate failed");
    } finally { setBusy(false); }
  };
  return (
    <div data-testid="xdr-secret-rotate-modal"
             style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.55)",
                             display: "flex", alignItems: "center",
                             justifyContent: "center", zIndex: 60 }}>
      <div className="panel" style={{ padding: 18, width: 440 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8,
                          marginBottom: 10 }}>
          <RotateCw size={14} style={{ color: "var(--cyan)" }} />
          <b style={{ fontFamily: "var(--mono)", fontSize: 12 }}>
            ROTATE · {secret.name}
          </b>
          <span style={{ flex: 1 }} />
          <button onClick={onClose} className="btn ghost"
                       style={{ padding: "2px 6px", fontSize: 11 }}>
            <X size={11} />
          </button>
        </div>
        <label style={{ color: "var(--faint)", fontSize: 11 }}>New value
          <input type="password" value={val}
                     data-testid="xdr-secret-rotate-value"
                     onChange={(e) => setVal(e.target.value)}
                     style={inputStyle} placeholder="new secret plaintext" />
        </label>
        <div style={{ marginTop: 6, fontSize: 10.5, color: "var(--faint)" }}>
          Version <b>{secret.version}</b> → <b>{secret.version + 1}</b> ·
          previous ciphertext preserved (last 3).
        </div>
        {err && <div style={{ marginTop: 6, color: "#f87171", fontSize: 11 }}
                              data-testid="xdr-secret-rotate-error">{err}</div>}
        <div style={{ display: "flex", gap: 6, marginTop: 12 }}>
          <span style={{ flex: 1 }} />
          <button className="btn ghost" onClick={onClose}
                       style={{ padding: "3px 10px", fontSize: 11 }}>Cancel</button>
          <button className="btn" disabled={busy || !val}
                       data-testid="xdr-secret-rotate-submit"
                       onClick={submit}
                       style={{ padding: "3px 10px", fontSize: 11 }}>
            <RotateCw size={11} /> {busy ? "Rotating…" : "Rotate"}
          </button>
        </div>
      </div>
    </div>
  );
}


export default function SecretsBody() {
  const [rows, setRows] = useState([]);
  const [state, setState] = useState({ loading: true, err: null });
  const [addOpen, setAddOpen] = useState(false);
  const [revealFor, setRevealFor] = useState(null);
  const [rotateFor, setRotateFor] = useState(null);
  const [tick, setTick] = useState(0);
  const [lastAudit, setLastAudit] = useState(null);

  const load = async () => {
    setState({ loading: true, err: null });
    try {
      const r = await api.get("/api/xdr/secrets");
      const j = r?.data;
      if (j && j.ok === false) {
        setRows([]);
        setState({ loading: false,
                        err: j?.error?.detail || "storage unavailable" });
        return;
      }
      setRows(j?.data?.secrets || []);
      setState({ loading: false, err: null });
    } catch (e) {
      setRows([]);
      setState({ loading: false,
                      err: e?.response?.data?.detail || e?.message
                              || "secrets fetch failed" });
    }
  };

  useEffect(() => { load(); /* eslint-disable-next-line */ }, [tick]);

  const toggleEnabled = async (s) => {
    try {
      const r = await api.put(`/api/xdr/secrets/${s.id}`,
                                          { enabled: !s.enabled });
      setLastAudit(r?.data?.audit_ref);
      setTick((n) => n + 1);
    } catch {/* keep UI honest — no fake mutation */}
  };

  const removeSecret = async (s) => {
    if (!window.confirm(`Delete secret '${s.name}'?`)) return;
    try {
      const r = await api.delete(`/api/xdr/secrets/${s.id}`);
      setLastAudit(r?.data?.audit_ref);
      setTick((n) => n + 1);
    } catch {/* no-op */}
  };

  return (
    <div data-testid="xdr-secrets-body">
      <div style={{ display: "flex", alignItems: "center", gap: 8,
                       marginBottom: 8 }}>
        <button className="btn" onClick={() => setAddOpen(true)}
                     data-testid="xdr-secret-add-btn"
                     style={{ padding: "3px 10px", fontSize: 11 }}>
          <Plus size={11} /> Add secret
        </button>
        <button className="btn ghost" onClick={() => setTick((n) => n + 1)}
                     data-testid="xdr-secret-refresh"
                     style={{ padding: "3px 10px", fontSize: 11 }}>
          <RefreshCcw size={11} /> Refresh
        </button>
        <span style={{ flex: 1 }} />
        {lastAudit && (
          <span data-testid="xdr-secret-last-audit"
                    style={{ fontFamily: "var(--mono)", fontSize: 10,
                                color: "var(--faint)" }}>
            last audit: {lastAudit}
          </span>
        )}
      </div>

      {state.loading && (
        <div style={{ fontSize: 11, color: "var(--faint)" }}>
          Loading secrets…
        </div>
      )}
      {state.err && (
        <div data-testid="xdr-secret-error"
                 style={{ padding: 8, borderRadius: 3, marginBottom: 8,
                                 border: "1px dashed var(--amber)",
                                 color: "var(--amber)", fontSize: 11,
                                 fontFamily: "var(--mono)" }}>
          SECRETS STORE UNAVAILABLE · {state.err}
        </div>
      )}
      {!state.loading && !state.err && rows.length === 0 && (
        <div data-testid="xdr-secret-empty"
                 style={{ padding: 10, fontSize: 11, color: "var(--faint)",
                                 fontFamily: "var(--mono)" }}>
          NO SECRETS STORED FOR THIS TENANT YET
        </div>
      )}
      {rows.length > 0 && (
        <div data-testid="xdr-secret-rows"
                 style={{ border: "1px solid var(--border)",
                                 borderRadius: 3, overflow: "hidden" }}>
          <div className="mono" style={header}>
            <div>Name</div><div>Kind</div><div>Preview</div>
            <div>Ver</div><div>Enabled</div><div>Created</div><div>Actions</div>
          </div>
          {rows.map((r) => (
            <div key={r.id} className="mono"
                     data-testid={`xdr-secret-row-${r.id}`}
                     style={rowStyle}>
              <div>{r.name}
                {r.description && <div style={{ color: "var(--faint)",
                                                                    fontSize: 10 }}>
                  {r.description}
                </div>}
              </div>
              <div><Badge label={r.kind} color="var(--cyan)"
                                    testid={`xdr-secret-kind-${r.id}`} /></div>
              <div style={{ color: "var(--amber)" }}>••••…{r.preview}</div>
              <div>{r.version}</div>
              <div>{r.enabled
                ? <Badge label="ENABLED" color="var(--mint)"
                                 testid={`xdr-secret-enabled-${r.id}`} />
                : <Badge label="DISABLED" color="#f87171"
                                 testid={`xdr-secret-disabled-${r.id}`} />}</div>
              <div style={{ color: "var(--faint)" }}>
                {(r.created_at || "").slice(0, 10)}
              </div>
              <div style={{ display: "flex", gap: 4 }}>
                <button className="btn ghost"
                             title="Reveal plaintext (audited)"
                             data-testid={`xdr-secret-reveal-${r.id}`}
                             onClick={() => setRevealFor(r)}
                             style={iconBtn}><Eye size={11} /></button>
                <button className="btn ghost" title="Rotate"
                             data-testid={`xdr-secret-rotate-${r.id}`}
                             onClick={() => setRotateFor(r)}
                             style={iconBtn}><RotateCw size={11} /></button>
                <button className="btn ghost"
                             title={r.enabled ? "Disable" : "Enable"}
                             data-testid={`xdr-secret-toggle-${r.id}`}
                             onClick={() => toggleEnabled(r)}
                             style={iconBtn}>
                  {r.enabled ? <PowerOff size={11} /> : <Power size={11} />}
                </button>
                <button className="btn ghost" title="Delete"
                             data-testid={`xdr-secret-delete-${r.id}`}
                             onClick={() => removeSecret(r)}
                             style={{ ...iconBtn, color: "#f87171" }}>
                  <Trash2 size={11} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      <div style={{ marginTop: 10, fontSize: 10.5, color: "var(--faint)",
                       fontFamily: "var(--mono)" }}>
        source: <span style={{ color: "var(--cyan)" }}>
          /api/xdr/secrets
        </span>{" "}· envelope-encrypted · tenant-isolated ·
        every mutation audited.
      </div>

      {addOpen && (
        <AddSecretModal onClose={() => setAddOpen(false)}
                                  onCreated={(res) => {
                                    setLastAudit(res?.audit_ref);
                                    setTick((n) => n + 1);
                                  }} />
      )}
      {revealFor && (
        <RevealModal secret={revealFor}
                             onClose={() => setRevealFor(null)}
                             onRevealed={(res) => setLastAudit(res?.audit_ref)} />
      )}
      {rotateFor && (
        <RotateModal secret={rotateFor}
                             onClose={() => setRotateFor(null)}
                             onRotated={(res) => {
                               setLastAudit(res?.audit_ref);
                               setTick((n) => n + 1);
                             }} />
      )}
    </div>
  );
}


// ── Styles ────────────────────────────────────────────────────────
const inputStyle = {
  display: "block", width: "100%", marginTop: 3, padding: "4px 8px",
  fontSize: 11, border: "1px solid var(--border)", borderRadius: 3,
  background: "var(--panel2)", color: "var(--text)",
  fontFamily: "var(--mono)",
};
const header = {
  display: "grid",
  gridTemplateColumns: "1.4fr 0.9fr 0.7fr 0.4fr 0.7fr 0.9fr 1fr",
  gap: 6, padding: "4px 8px", background: "var(--panel2)",
  fontSize: 10, color: "var(--faint)", textTransform: "uppercase",
};
const rowStyle = {
  display: "grid",
  gridTemplateColumns: "1.4fr 0.9fr 0.7fr 0.4fr 0.7fr 0.9fr 1fr",
  gap: 6, padding: "4px 8px", fontSize: 11,
  color: "var(--text-dim)", borderTop: "1px solid var(--border)",
  alignItems: "center",
};
const iconBtn = { padding: "2px 6px", fontSize: 10 };
