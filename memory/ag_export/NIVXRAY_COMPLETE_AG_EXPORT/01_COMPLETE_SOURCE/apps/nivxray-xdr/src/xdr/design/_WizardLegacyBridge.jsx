/**
 * _WizardLegacyBridge · Round 24.9.
 *
 * The connector-configuration wizard is being redesigned as a
 * 5-stage flow in Round 25 (Credential Vault + Integration
 * Lifecycle).  Until then, the Round 24.9 Integration Control
 * Center reuses the SAME markup as the legacy wizard so behaviour
 * is identical and no form regressions ship with the design-system
 * cutover.
 *
 * This file is scoped to Round 24.9 and will be replaced wholesale
 * by the Round 25 wizard.  DO NOT extend it.
 *
 * Kept 1:1 with `IntegrationsBody.jsx`'s `ConnectorWizard` so both
 * surfaces render an identical experience.  When Round 25 lands,
 * this file and the wizard-related tail of `IntegrationsBody.jsx`
 * are deleted together.
 */
import React, { useState } from "react";
import { Plug, X } from "lucide-react";
import * as C from "@/xdr/admin/collectorApi";

export function ConnectorWizard({ category, editing, onClose, onCreated }) {
  const isEdit    = !!editing;
  const transport = editing?.source_type || category?.transport;
  const [label,   setLabel]   = useState(editing?.label || category?.label || "");
  const [cfg,     setCfg]     = useState(() => (editing?.config || {}));
  const [saving,  setSaving]  = useState(false);
  const [err,     setErr]     = useState(null);
  const [tenant,  setTenant]  = useState("default");

  const patch = (k, v) => setCfg((c) => ({ ...c, [k]: v }));
  const patchCred = (k, v) =>
    setCfg((c) => ({ ...c, credentials: { ...(c.credentials || {}), [k]: v } }));

  const save = async () => {
    setSaving(true); setErr(null);
    try {
      if (isEdit) {
        await C.updateConnector(editing.id, { label, config: cfg });
      } else {
        await C.createConnector({ source_type: transport, label, config: cfg }, tenant);
      }
      onCreated();
    } catch (e) {
      setErr(e?.response?.data?.detail || e?.message || "Save failed.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div role="dialog" data-testid="xdr-int-wizard"
            style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.5)",
                        display: "flex", alignItems: "center", justifyContent: "center",
                        zIndex: 65, padding: 20 }}
            onClick={onClose}>
      <div className="panel" onClick={(e) => e.stopPropagation()}
              style={{ maxWidth: 620, width: "100%", padding: 20, maxHeight: "90vh",
                          overflow: "auto", background: "var(--nx-surf-primary)",
                          border: "1px solid var(--nx-bd-strong)", borderRadius: 8 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
          <Plug size={16} style={{ color: "var(--nx-purple)" }} />
          <h2 style={{ margin: 0, color: "var(--nx-text)", fontSize: 15,
                          fontWeight: 700 }}>
            {isEdit ? `Edit ${editing.label}` : `Add ${category.label} — ${transport?.toUpperCase()} connector`}
          </h2>
          <span style={{ flex: 1 }} />
          <button className="btn ghost" onClick={onClose} style={{ padding: 4 }}
                    data-testid="xdr-int-wizard-close"><X size={13} /></button>
        </div>

        <Field label="Label" testid="xdr-int-wizard-label">
          <input value={label} onChange={(e) => setLabel(e.target.value)}
                    data-testid="xdr-int-wizard-label-input"
                    className="x-input" placeholder="e.g. Corporate SIEM" />
        </Field>

        {!isEdit && (
          <Field label="Tenant" testid="xdr-int-wizard-tenant">
            <input value={tenant} onChange={(e) => setTenant(e.target.value)}
                      data-testid="xdr-int-wizard-tenant-input"
                      className="x-input" placeholder="default" />
          </Field>
        )}

        {transport === "rest"    && <RestFields cfg={cfg} patch={patch} patchCred={patchCred} isEdit={isEdit} />}
        {transport === "webhook" && <WebhookFields cfg={cfg} patch={patch} patchCred={patchCred} isEdit={isEdit} />}
        {transport === "syslog"  && <SyslogFields cfg={cfg} patch={patch} />}

        {err && (
          <div style={{ marginTop: 10, padding: 8, borderRadius: 4,
                          background: "rgba(153,27,27,.06)",
                          border: "1px solid var(--evops-ev-unavail-fg, #991B1B)",
                          color: "var(--evops-ev-unavail-fg, #991B1B)",
                          fontSize: 11.5 }}
                 data-testid="xdr-int-wizard-error">
            {String(err)}
          </div>
        )}

        <div style={{ marginTop: 14, textAlign: "right", display: "flex", gap: 8,
                         justifyContent: "flex-end" }}>
          <button className="btn ghost" onClick={onClose}
                    style={{ padding: "5px 12px" }}>Cancel</button>
          <button className="btn primary" onClick={save} disabled={saving || !label}
                    style={{ padding: "5px 12px" }}
                    data-testid="xdr-int-wizard-save">
            {saving ? "Saving…" : (isEdit ? "Save changes" : "Create connector")}
          </button>
        </div>
        <div style={{ marginTop: 10, color: "var(--nx-faint)", fontSize: 10.5,
                         fontFamily: "var(--mono)", lineHeight: 1.5 }}>
          Secrets are stored on the collector and redacted (<span style={{ color: "var(--evops-cap-degraded-fg)" }}>***</span>)
          in every subsequent API response. To rotate, enter the new value; leave blank to keep the existing one.
        </div>
      </div>
    </div>
  );
}

function Field({ label, hint, testid, children }) {
  return (
    <div style={{ marginBottom: 10 }} data-testid={testid}>
      <div style={{ fontFamily: "var(--mono)", fontSize: 9.5,
                       letterSpacing: ".3px", fontWeight: 800,
                       color: "var(--nx-faint)", textTransform: "uppercase",
                       marginBottom: 4 }}>{label}</div>
      {children}
      {hint && (
        <div style={{ color: "var(--nx-faint)", fontSize: 10.5, marginTop: 3,
                        fontFamily: "var(--mono)" }}>{hint}</div>
      )}
    </div>
  );
}
function RestFields({ cfg, patch, patchCred, isEdit }) {
  const auth = cfg.auth?.type || "none";
  return (
    <>
      <Field label="URL"><input className="x-input" placeholder="https://vendor.example.com/api/events"
              value={cfg.url || ""} onChange={(e) => patch("url", e.target.value)} /></Field>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
        <Field label="Method">
          <select className="x-input" value={cfg.method || "GET"}
                     onChange={(e) => patch("method", e.target.value)}>
            <option>GET</option><option>POST</option>
          </select>
        </Field>
        <Field label="Interval (seconds)">
          <input className="x-input" type="number" min={5}
                    value={cfg.interval_seconds || 60}
                    onChange={(e) => patch("interval_seconds", parseInt(e.target.value || 60, 10))} />
        </Field>
      </div>
      <Field label="Auth type">
        <select className="x-input" value={auth}
                   onChange={(e) => patch("auth", { ...(cfg.auth || {}), type: e.target.value })}>
          <option value="none">none</option><option value="bearer">bearer</option>
          <option value="basic">basic</option><option value="api_key">api_key</option>
        </select>
      </Field>
      {auth === "bearer" && (
        <Field label={`Bearer token${isEdit ? " (leave blank to keep existing)" : ""}`}>
          <input className="x-input" type="password" placeholder="xoxb-…"
                    onChange={(e) => patchCred("token", e.target.value)} />
        </Field>
      )}
      {auth === "basic" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
          <Field label="Username"><input className="x-input"
              onChange={(e) => patchCred("username", e.target.value)} /></Field>
          <Field label="Password"><input className="x-input" type="password"
              onChange={(e) => patchCred("password", e.target.value)} /></Field>
        </div>
      )}
      {auth === "api_key" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
          <Field label="Header name"><input className="x-input" placeholder="X-API-Key"
              value={cfg.auth?.header || ""}
              onChange={(e) => patch("auth", { ...(cfg.auth || {}), header: e.target.value })} /></Field>
          <Field label="Prefix"><input className="x-input"
              value={cfg.auth?.prefix || ""}
              onChange={(e) => patch("auth", { ...(cfg.auth || {}), prefix: e.target.value })} /></Field>
          <Field label="API key"><input className="x-input" type="password"
              onChange={(e) => patchCred("api_key", e.target.value)} /></Field>
        </div>
      )}
      <Field label="Records path" hint="Dotted JSON path to the events array (blank = whole body).">
        <input className="x-input" placeholder="results" value={cfg.records_path || ""}
                  onChange={(e) => patch("records_path", e.target.value)} />
      </Field>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
        <Field label="Event ID path" hint="Dedup key"><input className="x-input" placeholder="id"
            value={cfg.event_id_path || ""}
            onChange={(e) => patch("event_id_path", e.target.value)} /></Field>
        <Field label="Timestamp path"><input className="x-input" placeholder="ts"
            value={cfg.timestamp_path || ""}
            onChange={(e) => patch("timestamp_path", e.target.value)} /></Field>
        <Field label="Cursor param" hint="Query param for pagination">
          <input className="x-input" placeholder="after" value={cfg.cursor_param || ""}
              onChange={(e) => patch("cursor_param", e.target.value)} />
        </Field>
      </div>
      <Field label="Cursor path" hint="Dotted JSON path in the response that carries the next cursor.">
        <input className="x-input" placeholder="meta.next" value={cfg.cursor_path || ""}
              onChange={(e) => patch("cursor_path", e.target.value)} />
      </Field>
    </>
  );
}
function WebhookFields({ cfg, patch, patchCred, isEdit }) {
  return (
    <>
      <Field label="Secret ID" hint="Path segment used in the public URL: /api/xdr/webhooks/{secret_id}">
        <input className="x-input" placeholder="wh-abc123" value={cfg.secret_id || ""}
                  onChange={(e) => patch("secret_id", e.target.value)} />
      </Field>
      <Field label={`HMAC secret${isEdit ? " (leave blank to keep existing)" : ""}`}
                hint="If unset, signatures are not enforced and every delivery is flagged unauthenticated.">
        <input className="x-input" type="password"
                  onChange={(e) => patchCred("hmac_secret", e.target.value)} />
      </Field>
      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr", gap: 10 }}>
        <Field label="Signature header"><input className="x-input"
            placeholder="X-Hub-Signature-256" value={cfg.signature?.header || ""}
            onChange={(e) => patch("signature", { ...(cfg.signature || {}), header: e.target.value })} /></Field>
        <Field label="Algo"><select className="x-input" value={cfg.signature?.algo || "sha256"}
            onChange={(e) => patch("signature", { ...(cfg.signature || {}), algo: e.target.value })}>
          <option>sha256</option><option>sha1</option>
        </select></Field>
        <Field label="Prefix"><input className="x-input" placeholder="sha256="
            value={cfg.signature?.prefix || ""}
            onChange={(e) => patch("signature", { ...(cfg.signature || {}), prefix: e.target.value })} /></Field>
      </div>
      <Field label="Records path" hint="Dotted path to the events array in the POST body (blank = whole body).">
        <input className="x-input" placeholder="events" value={cfg.records_path || ""}
                  onChange={(e) => patch("records_path", e.target.value)} />
      </Field>
      <Field label="Event ID path" hint="Dedup key per record."><input className="x-input" placeholder="id"
          value={cfg.event_id_path || ""}
          onChange={(e) => patch("event_id_path", e.target.value)} /></Field>
    </>
  );
}
function SyslogFields({ cfg, patch }) {
  return (
    <>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
        <Field label="Protocol"><select className="x-input" value={cfg.protocol || "udp"}
            onChange={(e) => patch("protocol", e.target.value)}>
          <option value="udp">UDP</option><option value="tcp">TCP</option>
        </select></Field>
        <Field label="Host"><input className="x-input" placeholder="0.0.0.0"
            value={cfg.host || ""} onChange={(e) => patch("host", e.target.value)} /></Field>
        <Field label="Port"><input className="x-input" type="number" min={1} max={65535}
            placeholder="5514" value={cfg.port || ""}
            onChange={(e) => patch("port", parseInt(e.target.value || 0, 10))} /></Field>
      </div>
      <Field label="Format"><select className="x-input" value={cfg.format || "auto"}
          onChange={(e) => patch("format", e.target.value)}>
        <option value="auto">auto-detect</option>
        <option value="rfc3164">RFC3164 (BSD syslog)</option>
        <option value="rfc5424">RFC5424 (IETF syslog)</option>
      </select></Field>
    </>
  );
}
