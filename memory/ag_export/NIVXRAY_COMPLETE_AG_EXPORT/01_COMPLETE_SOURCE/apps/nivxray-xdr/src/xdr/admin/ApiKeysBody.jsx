/**
 * Admin › Identity & Access › API Keys — P0-4 live surface.
 *
 * Consumes:
 *   GET  /api/xdr/api-keys                       (masked list)
 *   POST /api/xdr/api-keys                       (returns plaintext ONCE)
 *   POST /api/xdr/api-keys/{id}/rotate           (returns new plaintext)
 *   POST /api/xdr/api-keys/{id}/revoke
 *   DELETE /api/xdr/api-keys/{id}
 *
 * Contract:
 *   • Plaintext is displayed ONCE (create / rotate) in a modal with a
 *     Copy button.  Never re-shown.  Never sent by any list/get call.
 *   • `prefix` (`nvx_XXXXXXXX`) is the persistent identifier the SOC
 *     sees in logs and audit events.
 *   • All mutations return `audit_ref`; surfaced to the operator.
 *   • Backend enforces RBAC — the UI reflects 403s honestly.
 */
import React, { useEffect, useState } from "react";
import {
  KeyRound, Plus, RefreshCcw, Copy, RotateCw, Ban, Trash2, X, Eye,
  CheckCircle2,
} from "lucide-react";

import api from "@/lib/api";
import AdminHero from "@/xdr/admin/AdminHero";


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


function RevealModal({ plaintext, prefix, onClose, notice }) {
  return (
    <div style={overlay} data-testid="xdr-api-key-reveal">
      <div className="panel" style={{ padding: 18, width: 540 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8,
                          marginBottom: 8 }}>
          <Eye size={14} style={{ color: "var(--amber)" }} />
          <b style={{ fontFamily: "var(--mono)", fontSize: 12 }}>
            NEW API KEY · {prefix}
          </b>
          <span style={{ flex: 1 }} />
          <button className="btn ghost" onClick={onClose}
                       data-testid="xdr-api-key-reveal-close"
                       style={{ padding: "2px 8px", fontSize: 11 }}>
            <X size={11} />
          </button>
        </div>
        <div style={{ padding: 10, marginTop: 6,
                          background: "var(--panel2)",
                          border: "1px solid var(--border)", borderRadius: 3,
                          fontFamily: "var(--mono)", fontSize: 12,
                          color: "var(--amber)", wordBreak: "break-all" }}
                 data-testid="xdr-api-key-plaintext">
          {plaintext}
        </div>
        <div style={{ marginTop: 8, fontSize: 11, color: "var(--faint)",
                          fontFamily: "var(--mono)" }}>
          {notice}
        </div>
        <div style={{ display: "flex", gap: 6, marginTop: 12 }}>
          <button className="btn ghost"
                       data-testid="xdr-api-key-copy"
                       onClick={() => navigator.clipboard?.writeText(plaintext)}
                       style={{ padding: "3px 10px", fontSize: 11 }}>
            <Copy size={11} /> Copy
          </button>
          <span style={{ flex: 1 }} />
          <button className="btn" onClick={onClose}
                       style={{ padding: "3px 10px", fontSize: 11 }}>
            <CheckCircle2 size={11} /> I've stored the key
          </button>
        </div>
      </div>
    </div>
  );
}


function AddKeyModal({ onClose, onCreated }) {
  const [f, setF] = useState({ name: "", description: "", scopes: "",
                                                      expires_at: "" });
  const [busy, setBusy] = useState(false);
  const [err, setErr]   = useState(null);
  const submit = async () => {
    setBusy(true); setErr(null);
    try {
      const scopes = f.scopes.split(/[\s,]+/).map((s) => s.trim())
                                        .filter(Boolean);
      const body = { name: f.name, description: f.description || null,
                              scopes };
      if (f.expires_at) body.expires_at = f.expires_at;
      const r = await api.post("/xdr/api-keys", body);
      onCreated?.(r?.data);
      onClose();
    } catch (e) {
      setErr(e?.response?.data?.detail?.reason
                 || e?.response?.data?.detail || e?.message || "create failed");
    } finally { setBusy(false); }
  };
  return (
    <div style={overlay} data-testid="xdr-api-key-add-modal">
      <div className="panel" style={{ padding: 18, width: 480 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8,
                          marginBottom: 10 }}>
          <KeyRound size={14} style={{ color: "var(--mint)" }} />
          <b style={{ fontFamily: "var(--mono)", fontSize: 12 }}>
            NEW API KEY
          </b>
          <span style={{ flex: 1 }} />
          <button className="btn ghost" onClick={onClose}
                       data-testid="xdr-api-key-add-cancel"
                       style={{ padding: "2px 6px", fontSize: 11 }}>
            <X size={11} />
          </button>
        </div>
        <label style={lbl}>Name (unique per tenant)
          <input value={f.name} data-testid="xdr-api-key-add-name"
                     onChange={(e) => setF({ ...f, name: e.target.value })}
                     style={inp} placeholder="ci-runner" />
        </label>
        <label style={lbl}>Description
          <input value={f.description}
                     data-testid="xdr-api-key-add-desc"
                     onChange={(e) => setF({ ...f, description: e.target.value })}
                     style={inp} placeholder="What this key is used for" />
        </label>
        <label style={lbl}>Scopes (space/comma-separated permissions)
          <input value={f.scopes}
                     data-testid="xdr-api-key-add-scopes"
                     onChange={(e) => setF({ ...f, scopes: e.target.value })}
                     style={inp}
                     placeholder="lolbas.sync audit.read" />
        </label>
        <label style={lbl}>Expires at (ISO-8601 UTC · empty = never)
          <input value={f.expires_at}
                     data-testid="xdr-api-key-add-expires"
                     onChange={(e) => setF({ ...f, expires_at: e.target.value })}
                     style={inp} placeholder="2026-12-31T23:59:59Z" />
        </label>
        {err && <div style={{ color: "#f87171", fontSize: 11 }}
                                data-testid="xdr-api-key-add-error">{err}</div>}
        <div style={{ display: "flex", gap: 6, marginTop: 12 }}>
          <span style={{ flex: 1 }} />
          <button className="btn ghost" onClick={onClose}
                       style={{ padding: "3px 10px", fontSize: 11 }}>Cancel</button>
          <button className="btn" disabled={busy || !f.name}
                       data-testid="xdr-api-key-add-submit"
                       onClick={submit}
                       style={{ padding: "3px 10px", fontSize: 11 }}>
            <Plus size={11} /> {busy ? "Creating…" : "Create key"}
          </button>
        </div>
      </div>
    </div>
  );
}


export default function ApiKeysBody() {
  const [rows, setRows] = useState([]);
  const [state, setState] = useState({ loading: true, err: null });
  const [addOpen, setAddOpen] = useState(false);
  const [reveal, setReveal] = useState(null);   // {plaintext, prefix, notice}
  const [tick, setTick] = useState(0);
  const [lastAudit, setLastAudit] = useState(null);

  const load = async () => {
    setState({ loading: true, err: null });
    try {
      const r = await api.get("/xdr/api-keys");
      const j = r?.data;
      if (j && j.ok === false) {
        setRows([]);
        setState({ loading: false,
                        err: j?.error?.detail || "storage unavailable" });
        return;
      }
      setRows(j?.data?.api_keys || []);
      setState({ loading: false, err: null });
    } catch (e) {
      setRows([]);
      setState({ loading: false,
                      err: e?.response?.data?.detail?.reason
                              || e?.response?.data?.detail
                              || e?.message || "fetch failed" });
    }
  };

  useEffect(() => { load(); /* eslint-disable-next-line */ }, [tick]);

  const rotate = async (k) => {
    try {
      const r = await api.post(`/xdr/api-keys/${k.id}/rotate`);
      setReveal({ plaintext: r?.data?.data?.plaintext,
                          prefix:    r?.data?.data?.prefix,
                          notice:    r?.data?.data?.reveal_notice
                                      || "The rotated key is displayed only once." });
      setLastAudit(r?.data?.audit_ref);
      setTick((n) => n + 1);
    } catch (e) {
      alert(e?.response?.data?.detail?.reason || e?.message || "rotate failed");
    }
  };
  const revoke = async (k) => {
    if (!window.confirm(`Revoke API key '${k.name}'?  This cannot be undone.`)) return;
    try {
      const r = await api.post(`/xdr/api-keys/${k.id}/revoke`);
      setLastAudit(r?.data?.audit_ref);
      setTick((n) => n + 1);
    } catch (e) {
      alert(e?.response?.data?.detail?.reason || e?.message || "revoke failed");
    }
  };
  const remove = async (k) => {
    if (!window.confirm(`Delete API key '${k.name}'?`)) return;
    try {
      const r = await api.delete(`/xdr/api-keys/${k.id}`);
      setLastAudit(r?.data?.audit_ref);
      setTick((n) => n + 1);
    } catch (e) {
      alert(e?.response?.data?.detail?.reason || e?.message || "delete failed");
    }
  };

  const active  = rows.filter((r) => r.enabled).length;
  const revoked = rows.filter((r) => !r.enabled).length;
  const totalUses = rows.reduce((s, r) => s + (r.use_count || 0), 0);
  const heroStats = [
    { label: "Provisioned", value: rows.length,     testid: "ak-hero-stat-total" },
    { label: "Active",      value: active,          color: "var(--mint)",
      testid: "ak-hero-stat-active" },
    { label: "Revoked",     value: revoked,
      color: revoked ? "var(--faint)" : undefined,
      testid: "ak-hero-stat-revoked" },
    { label: "Total uses",  value: totalUses,       testid: "ak-hero-stat-uses" },
  ];

  return (
    <div data-testid="xdr-api-keys-body">
      <AdminHero
        icon={KeyRound}
        eyebrow="Admin › Identity & Access › API Keys"
        title="Programmatic Access Tokens"
        subtitle="Long-lived credentials for CI runners, automation and integrations. Plaintext is revealed exactly once at create/rotate; only the SHA-256 hash is persisted. Every mutation is RBAC-gated and appended to the tamper-evident audit log."
        source="/api/xdr/api-keys"
        stats={heroStats}
        testid="ak-hero"
        actions={<>
          <button className="btn" onClick={() => setAddOpen(true)}
                       data-testid="xdr-api-key-add-btn"
                       style={{ padding: "3px 10px", fontSize: 11 }}>
            <Plus size={11} /> Add API key
          </button>
          <button className="btn ghost" onClick={() => setTick((n) => n + 1)}
                       data-testid="xdr-api-key-refresh"
                       style={{ padding: "3px 10px", fontSize: 11 }}>
            <RefreshCcw size={11} /> Refresh
          </button>
        </>}
      />

      <div style={{ display: "flex", alignItems: "center", gap: 8,
                       marginBottom: 8 }}>
        <span style={{ flex: 1 }} />
        {lastAudit && (
          <span data-testid="xdr-api-key-last-audit"
                    style={{ fontFamily: "var(--mono)", fontSize: 10,
                                    color: "var(--faint)" }}>
            last audit: {lastAudit}
          </span>
        )}
      </div>

      {state.loading && (
        <div style={{ fontSize: 11, color: "var(--faint)" }}>
          Loading API keys…
        </div>
      )}
      {state.err && (
        <div data-testid="xdr-api-key-error"
                 style={{ padding: 8, borderRadius: 3, marginBottom: 8,
                                 border: "1px dashed var(--amber)",
                                 color: "var(--amber)", fontSize: 11,
                                 fontFamily: "var(--mono)" }}>
          API KEYS UNAVAILABLE · {state.err}
        </div>
      )}
      {!state.loading && !state.err && rows.length === 0 && (
        <div data-testid="xdr-api-key-empty"
                 style={{ padding: 10, fontSize: 11, color: "var(--faint)",
                                 fontFamily: "var(--mono)" }}>
          NO API KEYS PROVISIONED FOR THIS TENANT YET
        </div>
      )}
      {rows.length > 0 && (
        <div data-testid="xdr-api-key-rows"
                 style={{ border: "1px solid var(--border)", borderRadius: 3,
                                 overflow: "hidden" }}>
          <div className="mono" style={rowHead}>
            <div>Name</div><div>Prefix</div><div>Scopes</div>
            <div>Status</div><div>Last Used</div>
            <div>Expires</div><div>Uses</div><div>Actions</div>
          </div>
          {rows.map((r) => (
            <div key={r.id} className="mono" style={rowBody}
                     data-testid={`xdr-api-key-row-${r.id}`}>
              <div>{r.name}
                {r.description && <div style={{ fontSize: 10,
                                                                    color: "var(--faint)" }}>
                  {r.description}
                </div>}
              </div>
              <div style={{ color: "var(--amber)" }}>{r.prefix}…</div>
              <div style={{ fontSize: 10, color: "var(--text-dim)",
                                wordBreak: "break-word" }}>
                {(r.scopes || []).join(", ") || "—"}
              </div>
              <div>{r.enabled
                ? <Badge label="ACTIVE" color="var(--mint)"
                                 testid={`xdr-api-key-active-${r.id}`} />
                : <Badge label="REVOKED" color="#f87171"
                                 testid={`xdr-api-key-revoked-${r.id}`} />}</div>
              <div style={{ color: "var(--faint)", fontSize: 10 }}>
                {(r.last_used_at || "").slice(0, 19) || "never"}
              </div>
              <div style={{ color: "var(--faint)", fontSize: 10 }}>
                {(r.expires_at || "").slice(0, 10) || "never"}
              </div>
              <div>{r.use_count ?? 0}</div>
              <div style={{ display: "flex", gap: 4 }}>
                <button className="btn ghost" title="Rotate"
                             data-testid={`xdr-api-key-rotate-${r.id}`}
                             disabled={!r.enabled}
                             onClick={() => rotate(r)}
                             style={iconBtn}><RotateCw size={11} /></button>
                <button className="btn ghost" title="Revoke"
                             data-testid={`xdr-api-key-revoke-${r.id}`}
                             disabled={!r.enabled}
                             onClick={() => revoke(r)}
                             style={{ ...iconBtn, color: "var(--amber)" }}>
                  <Ban size={11} />
                </button>
                <button className="btn ghost" title="Delete"
                             data-testid={`xdr-api-key-delete-${r.id}`}
                             onClick={() => remove(r)}
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
        source: <span style={{ color: "var(--cyan)" }}>/api/xdr/api-keys</span>
        {" "}· only SHA-256 hashes stored server-side · plaintext revealed
        once at create/rotate · every mutation audited & RBAC-gated.
      </div>

      {addOpen && (
        <AddKeyModal onClose={() => setAddOpen(false)}
                              onCreated={(res) => {
                                setReveal({
                                  plaintext: res?.data?.plaintext,
                                  prefix:    res?.data?.prefix,
                                  notice:    res?.data?.reveal_notice
                                              || "This key will be shown only once.",
                                });
                                setLastAudit(res?.audit_ref);
                                setTick((n) => n + 1);
                              }} />
      )}
      {reveal && (
        <RevealModal plaintext={reveal.plaintext}
                                 prefix={reveal.prefix}
                                 notice={reveal.notice}
                                 onClose={() => setReveal(null)} />
      )}
    </div>
  );
}

// ── Styles ────────────────────────────────────────────────────────
const inp = {
  display: "block", width: "100%", marginTop: 3, padding: "4px 8px",
  fontSize: 11, border: "1px solid var(--border)", borderRadius: 3,
  background: "var(--panel2)", color: "var(--text)",
  fontFamily: "var(--mono)",
};
const lbl = { color: "var(--faint)", fontSize: 11, marginBottom: 6,
                     display: "block" };
const overlay = {
  position: "fixed", inset: 0, background: "rgba(0,0,0,.55)",
  display: "flex", alignItems: "center", justifyContent: "center",
  zIndex: 60,
};
const rowHead = {
  display: "grid",
  gridTemplateColumns: "1.2fr 0.8fr 1.4fr 0.6fr 0.8fr 0.6fr 0.35fr 0.9fr",
  gap: 6, padding: "4px 8px", background: "var(--panel2)",
  fontSize: 10, color: "var(--faint)", textTransform: "uppercase",
};
const rowBody = {
  display: "grid",
  gridTemplateColumns: "1.2fr 0.8fr 1.4fr 0.6fr 0.8fr 0.6fr 0.35fr 0.9fr",
  gap: 6, padding: "6px 8px", fontSize: 11,
  color: "var(--text-dim)", borderTop: "1px solid var(--border)",
  alignItems: "center",
};
const iconBtn = { padding: "2px 6px", fontSize: 10 };
