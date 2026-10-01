/**
 * IntegrationsBody · Phase B.5 — Live wizard.
 *
 * Talks to the NivXRay XDR Collector service via `collectorApi`.  The
 * catalog tiles now launch REAL connector-creation flows for the
 * three Phase-B transports (REST poller, Webhook receiver, Syslog
 * receiver).  Categories without a native connector (EDR, SIEM,
 * Firewall, etc.) map to the closest transport with a preset (e.g.
 * SIEM → Syslog, Cloud → REST, Webhook → Webhook) so operators aren't
 * blocked waiting on Phase-C vendor SDKs.
 *
 * Honest-state rules (owner-locked):
 *   • Collector URL not set  → COLLECTOR RUNTIME NOT DEPLOYED
 *   • Empty CRUD list        → NEVER CONNECTED
 *   • Ingest URL missing     → INGEST NOT CONFIGURED
 *   • Retryable ingest fail  → DEGRADED (with queue depth)
 *   • Fatal ingest fail      → ERROR
 *   • Delete/disabled state  → DISCONNECTED
 *   • Never a fake CONNECTED — comes straight from the connector API.
 *
 * Secrets: `credentials.*` fields are ONLY sent on create/update.  The
 * API returns them redacted to `***`, so this wizard shows `***` on
 * re-open and lets the operator rotate but never read the original.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  Monitor, Database, Flame, Globe, FileText, Mail,
  User as UserIcon, Cloud as CloudIcon, Puzzle, Command as CmdIcon,
  Link2, Wrench, X, Plug, CheckCircle2, AlertTriangle,
  Trash2, Play, Square, RotateCcw, ShieldAlert,
} from "lucide-react";

import * as C from "@/xdr/admin/collectorApi";
import AdminHero from "@/xdr/admin/AdminHero";
import PipelineStrip from "@/xdr/admin/PipelineStrip";

// ── 12-tile catalog mapped to Phase-B transports ────────────
const CATALOG = [
  { key: "edr",     label: "EDR / Endpoint",   icon: Monitor,   transport: "rest",
    note: "CrowdStrike / SentinelOne / Defender — REST/Graph poller until Phase C" },
  { key: "siem",    label: "SIEM",             icon: Database,  transport: "syslog",
    note: "Splunk / Sentinel / Chronicle / Elastic — syslog forwarder" },
  { key: "fw",      label: "Firewall",         icon: Flame,     transport: "syslog",
    note: "Palo Alto / Fortinet / Check Point — syslog (RFC5424)" },
  { key: "net",     label: "Network",          icon: Globe,     transport: "syslog",
    note: "Zeek / NDR sensors — syslog TCP/UDP" },
  { key: "dns",     label: "DNS",              icon: FileText,  transport: "syslog",
    note: "Umbrella / Infoblox — syslog or REST bulk export" },
  { key: "email",   label: "Email",            icon: Mail,      transport: "webhook",
    note: "M365 Defender / Proofpoint — webhook alerts" },
  { key: "id",      label: "Identity",         icon: UserIcon,  transport: "rest",
    note: "Entra ID / Okta — REST poller" },
  { key: "cloud",   label: "Cloud",            icon: CloudIcon, transport: "rest",
    note: "AWS CloudTrail / Azure activity — REST poller" },
  { key: "saas",    label: "SaaS",             icon: Puzzle,    transport: "webhook",
    note: "Salesforce / Slack / Box — webhook events" },
  { key: "app",     label: "Application",      icon: CmdIcon,   transport: "rest",
    note: "Custom app · REST or webhook" },
  { key: "webhook", label: "Generic Webhook",  icon: Link2,     transport: "webhook",
    note: "Any HMAC-signed push endpoint" },
  { key: "custom",  label: "Custom REST",      icon: Wrench,    transport: "rest",
    note: "Arbitrary REST API · cursor-paginated" },
];


function HonestBadge({ label, color = "var(--faint)", testid }) {
  return (
    <span data-testid={testid} style={{
      display: "inline-block", padding: "2px 7px", borderRadius: 3,
      border: `1px solid ${color}`, color,
      fontFamily: "var(--mono)", fontSize: 9.5, letterSpacing: ".4px",
      fontWeight: 800, textTransform: "uppercase",
    }}>{label}</span>
  );
}

const STATUS_MAP = {
  connected:            { label: "Connected",        color: "var(--mint)",   Icon: CheckCircle2 },
  disconnected:         { label: "Disconnected",     color: "var(--faint)",  Icon: X },
  never_connected:      { label: "Never Connected",  color: "var(--faint)",  Icon: AlertTriangle },
  degraded:             { label: "Degraded",         color: "var(--amber)",  Icon: AlertTriangle },
  authentication_failed:{ label: "Auth Failed",      color: "#ff5b5b",       Icon: ShieldAlert },
  rate_limited:         { label: "Rate Limited",     color: "var(--amber)",  Icon: AlertTriangle },
  error:                { label: "Error",            color: "#ff5b5b",       Icon: X },
  not_started:          { label: "Not Started",      color: "var(--faint)",  Icon: AlertTriangle },
};
function StatusPill({ status }) {
  const m = STATUS_MAP[status] || { label: status || "Unknown",
                                       color: "var(--faint)", Icon: AlertTriangle };
  const I = m.Icon;
  return (
    <span data-testid={`xdr-int-status-${status}`} style={{
      color: m.color, fontWeight: 700, fontSize: 11,
      display: "inline-flex", alignItems: "center", gap: 5,
    }}><I size={11} /> {m.label}</span>
  );
}


export default function IntegrationsBody() {
  const [state, setState]           = useState("loading");     // loading|deployed|not_deployed|error
  const [error, setError]           = useState(null);
  const [connectors, setConnectors] = useState([]);
  const [health, setHealth]         = useState(null);
  const [wizardCategory, setWiz]    = useState(null);          // catalog entry
  const [editConnector, setEdit]    = useState(null);          // existing connector row

  const load = useCallback(async () => {
    setState("loading"); setError(null);
    if (!C.COLLECTOR_CONFIGURED) { setState("not_deployed"); return; }
    try {
      const [conns, h] = await Promise.all([
        C.listCollectorConnectors(),
        C.getOutboxHealth(),
      ]);
      setConnectors(conns?.connectors || []);
      setHealth(h);
      setState("deployed");
    } catch (e) {
      if (e?.code === "COLLECTOR_RUNTIME_NOT_DEPLOYED") {
        setState("not_deployed");
      } else {
        setError(e?.response?.data?.detail || e?.message || "Load failed.");
        setState("error");
      }
    }
  }, []);
  useEffect(() => { load(); }, [load]);
  // Poll health every 15s so the ingest state stays fresh.
  useEffect(() => {
    if (state !== "deployed") return;
    const t = setInterval(() => C.getOutboxHealth().then(setHealth).catch(() => {}),
                              15000);
    return () => clearInterval(t);
  }, [state]);

  const onCreated = async () => { setWiz(null); await load(); };
  const onEdited  = async () => { setEdit(null); await load(); };
  const onDelete  = async (row) => {
    if (!window.confirm(`Delete connector "${row.label}"? Queued events will still deliver.`)) return;
    await C.deleteConnector(row.id);
    await load();
  };
  const onToggle = async (row) => {
    if (row.runtime?.health === "connected") await C.stopConnector(row.id);
    else await C.startConnector(row.id);
    await load();
  };
  const onTest = async (row) => {
    try {
      const r = await C.testConnector(row.id);
      window.alert(`Test connection: ${r.ok ? "OK" : "FAILED"}\n\n${JSON.stringify(r, null, 2)}`);
    } catch (e) {
      window.alert(`Test failed: ${e?.message || e}`);
    }
  };

  return (
    <div data-testid="xdr-admin-integrations-body">
      {(() => {
        const connectedCount = connectors.filter((r) => r.runtime?.health === "connected").length;
        const heroStats = state === "not_deployed" ? [] : [
          { label: "Configured",   value: connectors.length,
            testid: "int-hero-stat-total" },
          { label: "Connected",    value: connectedCount, color: "var(--mint)",
            testid: "int-hero-stat-connected" },
          { label: "Queue depth",  value: health?.outbox?.queue_depth ?? 0,
            color: (health?.outbox?.queue_depth || 0) ? "var(--amber)" : undefined,
            testid: "int-hero-stat-queue" },
          { label: "Dead letter",  value: health?.outbox?.counts?.dead_letter ?? 0,
            color: (health?.outbox?.counts?.dead_letter || 0) ? "#f87171" : undefined,
            testid: "int-hero-stat-dlq" },
          { label: "Delivered",    value: health?.ingest?.delivered ?? 0, color: "var(--mint)",
            testid: "int-hero-stat-delivered" },
        ];
        return (
          <AdminHero
            icon={Plug}
            eyebrow="Admin › Integrations"
            title="Live Integration Fabric"
            subtitle="Configure real telemetry sources — every connector maps to a Phase-B transport (REST poller · Webhook receiver · Syslog receiver), flows into canonical evidence, and is only 'CONNECTED' after the runtime reports actual event delivery. Never fabricated."
            source="/api/xdr/collector/*  ·  /api/xdr/health/outbox"
            stats={heroStats}
            testid="int-hero"
            actions={
              <button className="btn ghost" data-testid="int-hero-refresh"
                          onClick={load}
                          style={{ padding: "3px 10px", fontSize: 11 }}>
                <RotateCcw size={11} /> Refresh
              </button>
            }
          />
        );
      })()}

      <PipelineStrip testid="int-pipeline" />

      {/* Ingest / outbox health strip */}
      <IngestHealthStrip state={state} health={health} onRefresh={load} />

      {/* Connected sources table */}
      <section className="panel" style={{ padding: 0, marginBottom: 14,
                                                overflow: "hidden" }}
                data-testid="xdr-integrations-connected">
        <div style={{
          padding: "10px 14px", borderBottom: "1px solid var(--border)",
          background: "var(--panel2)", display: "flex", alignItems: "center", gap: 10,
        }}>
          <div style={{
            fontFamily: "var(--mono)", fontSize: 10, letterSpacing: ".4px",
            fontWeight: 800, color: "var(--muted)", textTransform: "uppercase",
          }}>Connected Sources</div>
          <span style={{ flex: 1 }} />
          <span className="mono" style={{ color: "var(--mint)", fontSize: 10.5,
                                                fontWeight: 700 }}>
            {connectors.length} configured
          </span>
        </div>

        {state === "not_deployed" && (
          <div style={{ padding: 20 }}>
            <HonestBadge label="COLLECTOR RUNTIME NOT DEPLOYED" color="var(--amber)"
                            testid="xdr-int-collector-missing" />
            <div style={{ marginTop: 10, color: "var(--text-dim)", fontSize: 12,
                             lineHeight: 1.6 }}>
              The Live Integrations wizard consumes the NivXRay XDR Collector
              service — a separately deployable runtime. It is not wired to
              this XDR frontend yet.
            </div>
            <div style={{ marginTop: 6, color: "var(--faint)", fontSize: 11,
                             fontFamily: "var(--mono)" }}>
              To wire it: set <span style={{ color: "var(--cyan)" }}>
              VITE_XDR_COLLECTOR_URL</span> in Vercel to the deployed collector
              URL, then redeploy. Reference impl:{" "}
              <span style={{ color: "var(--cyan)" }}>/app/apps/nivxray-xdr-collector</span>.
            </div>
          </div>
        )}
        {state === "loading" && (
          <div className="x-empty" style={{ padding: 20 }}>Loading …</div>
        )}
        {state === "error" && (
          <div style={{ padding: 20 }}>
            <HonestBadge label="ERROR" color="#ff5b5b" />
            <div style={{ marginTop: 8, color: "#ff9494", fontSize: 12 }}>
              {String(error)}
            </div>
          </div>
        )}
        {state === "deployed" && connectors.length === 0 && (
          <div className="x-empty" style={{ padding: 20 }}
                 data-testid="xdr-int-never-connected">
            <b>NEVER CONNECTED</b> — no connectors configured for this tenant yet.
            Pick a category below to configure the first one.
          </div>
        )}
        {state === "deployed" && connectors.length > 0 && (
          <table className="x-table" style={{ width: "100%" }}
                    data-testid="xdr-int-table">
            <thead>
              <tr>
                <th>Source</th><th>Transport</th><th>Health</th>
                <th>Events</th><th>Last Success</th><th style={{ width: 200 }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {connectors.map((r) => (
                <ConnectorRow key={r.id} row={r}
                                 onEdit={setEdit} onDelete={onDelete}
                                 onToggle={onToggle} onTest={onTest} />
              ))}
            </tbody>
          </table>
        )}
      </section>

      {/* Add integration catalog */}
      <section className="panel" style={{ padding: 14 }}
                data-testid="xdr-integrations-catalog">
        <div style={{
          fontFamily: "var(--mono)", fontSize: 10, letterSpacing: ".4px",
          fontWeight: 800, color: "var(--muted)", textTransform: "uppercase",
          marginBottom: 12,
        }}>Add Integration — what do you want to connect?</div>
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
          gap: 10,
        }}>
          {CATALOG.map((c) => (
            <button
              key={c.key} type="button" className="btn"
              onClick={() => C.COLLECTOR_CONFIGURED && setWiz(c)}
              disabled={!C.COLLECTOR_CONFIGURED}
              data-testid={`xdr-int-tile-${c.key}`}
              style={{
                display: "flex", flexDirection: "column",
                alignItems: "center", justifyContent: "center",
                padding: "18px 12px", gap: 6, minHeight: 108,
                border: "1px solid var(--border)", borderRadius: 6,
                background: "var(--panel2)",
                opacity: C.COLLECTOR_CONFIGURED ? 1 : 0.5,
              }}
              title={c.note}
            >
              <c.icon size={22} style={{ color: "var(--purple)" }} />
              <span style={{ fontSize: 12, color: "var(--text-dim)",
                                fontWeight: 700 }}>{c.label}</span>
              <span className="mono" style={{ fontSize: 9.5,
                                                     color: "var(--faint)" }}>
                via {c.transport.toUpperCase()}
              </span>
            </button>
          ))}
        </div>
      </section>

      {wizardCategory && (
        <ConnectorWizard category={wizardCategory}
                            onClose={() => setWiz(null)}
                            onCreated={onCreated} />
      )}
      {editConnector && (
        <ConnectorWizard editing={editConnector}
                            onClose={() => setEdit(null)}
                            onCreated={onEdited} />
      )}
    </div>
  );
}


function IngestHealthStrip({ state, health, onRefresh }) {
  if (state !== "deployed" || !health) return null;
  const st = health.state;
  const map = {
    healthy:        { label: "HEALTHY",         color: "var(--mint)" },
    degraded:       { label: "DEGRADED",        color: "var(--amber)" },
    idle:           { label: "IDLE",            color: "var(--faint)" },
    not_configured: { label: "INGEST NOT CONFIGURED", color: "#ff5b5b" },
  };
  const m = map[st] || { label: String(st).toUpperCase(), color: "var(--faint)" };
  return (
    <div className="panel" data-testid="xdr-int-health-strip"
            style={{ display: "flex", flexWrap: "wrap", gap: 14, alignItems: "center",
                        padding: "10px 14px", marginBottom: 14 }}>
      <HonestBadge label={m.label} color={m.color} testid={`xdr-int-health-${st}`} />
      <span className="mono" style={{ fontSize: 11, color: "var(--text-dim)" }}>
        <b style={{ color: "var(--faint)" }}>DELIVERED</b>{" "}
        <b style={{ color: "var(--text)" }}>{health.ingest?.delivered ?? 0}</b>
      </span>
      <span className="mono" style={{ fontSize: 11, color: "var(--text-dim)" }}>
        <b style={{ color: "var(--faint)" }}>QUEUE DEPTH</b>{" "}
        <b style={{ color: health.outbox?.queue_depth ? "var(--amber)" : "var(--text)" }}>
          {health.outbox?.queue_depth ?? 0}
        </b>
      </span>
      <span className="mono" style={{ fontSize: 11, color: "var(--text-dim)" }}>
        <b style={{ color: "var(--faint)" }}>DEAD LETTER</b>{" "}
        <b style={{ color: (health.outbox?.counts?.dead_letter || 0) > 0 ? "#ff5b5b" : "var(--text)" }}>
          {health.outbox?.counts?.dead_letter ?? 0}
        </b>
      </span>
      {health.ingest?.last_error && (
        <span className="mono" style={{ fontSize: 11, color: "#ff9494" }}>
          <b style={{ color: "var(--faint)" }}>LAST ERROR</b>{" "}
          {String(health.ingest.last_error).slice(0, 80)}
        </span>
      )}
      <span style={{ flex: 1 }} />
      <button className="btn" style={{ padding: "3px 10px" }}
                onClick={async () => {
                  try {
                    const r = await C.ingestPreflight();
                    const status = r.status_code ? ` (HTTP ${r.status_code})` : "";
                    window.alert(
                      `Ingest preflight: ${r.state?.toUpperCase()}${status}\n\n` +
                      (r.reason ? `Reason: ${r.reason}\n\n` : "") +
                      `Outcome: ${r.outcome || "n/a"}\n` +
                      `Ok: ${r.ok}\n` +
                      `See INGEST_CONTRACT.md §3 for the wire contract.`
                    );
                    onRefresh();
                  } catch (e) {
                    window.alert("Preflight request failed: " + (e?.message || e));
                  }
                }}
                data-testid="xdr-int-preflight">
        Preflight
      </button>
      <button className="btn" style={{ padding: "3px 10px" }} onClick={onRefresh}
                data-testid="xdr-int-health-refresh">
        <RotateCcw size={11} /> Refresh
      </button>
    </div>
  );
}


function ConnectorRow({ row, onEdit, onDelete, onToggle, onTest }) {
  const rt      = row.runtime || {};
  const metrics = rt.metrics  || {};
  const health  = rt.health   || "not_started";
  return (
    <tr data-testid={`xdr-int-row-${row.id}`}>
      <td style={{ color: "var(--text)", fontWeight: 700 }}>
        {row.label}
        <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                              fontWeight: 500, marginTop: 2 }}>
          {row.id}
        </div>
      </td>
      <td className="mono" style={{ color: "var(--text-dim)" }}>
        {row.source_type.toUpperCase()}
      </td>
      <td><StatusPill status={health} /></td>
      <td className="mono" style={{ color: "var(--text-dim)" }}>
        <div><span style={{ color: "var(--faint)" }}>C</span>{" "}{metrics.events_collected || 0}</div>
        <div><span style={{ color: "var(--faint)" }}>A</span>{" "}{metrics.events_accepted  || 0}</div>
        {(metrics.events_duplicated || 0) > 0 && (
          <div style={{ color: "var(--amber)" }}>
            <span style={{ color: "var(--faint)" }}>D</span>{" "}{metrics.events_duplicated}
          </div>
        )}
      </td>
      <td className="mono" style={{ color: "var(--muted)" }}>
        {metrics.last_success
          ? String(metrics.last_success).slice(0, 19).replace("T", " ")
          : <span style={{ color: "var(--faint)" }}>never</span>}
      </td>
      <td>
        <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
          {row.source_type === "rest" && (
            <button className="btn ghost" style={{ padding: "3px 8px" }}
                        onClick={() => onTest(row)}
                        data-testid={`xdr-int-test-${row.id}`}
                        title="Test connection">
              <ShieldAlert size={11} /> Test
            </button>
          )}
          <button className="btn ghost" style={{ padding: "3px 8px" }}
                    onClick={() => onToggle(row)}
                    data-testid={`xdr-int-toggle-${row.id}`}>
            {health === "connected"
              ? <><Square size={11} /> Stop</>
              : <><Play size={11} /> Start</>}
          </button>
          <button className="btn ghost" style={{ padding: "3px 8px" }}
                    onClick={() => onEdit(row)}
                    data-testid={`xdr-int-edit-${row.id}`}>
            Edit
          </button>
          <button className="btn ghost" style={{ padding: "3px 8px", color: "#ff9494" }}
                    onClick={() => onDelete(row)}
                    data-testid={`xdr-int-delete-${row.id}`}>
            <Trash2 size={11} /> Delete
          </button>
        </div>
      </td>
    </tr>
  );
}


// ── Wizard ─────────────────────────────────────────────────
function ConnectorWizard({ category, editing, onClose, onCreated }) {
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
        await C.createConnector({ source_type: transport, label, config: cfg },
                                     tenant);
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
            style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.7)",
                        display: "flex", alignItems: "center", justifyContent: "center",
                        zIndex: 60, padding: 20 }}
            onClick={onClose}>
      <div className="panel" onClick={(e) => e.stopPropagation()}
              style={{ maxWidth: 620, width: "100%", padding: 20, maxHeight: "90vh",
                          overflow: "auto" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10,
                         marginBottom: 12 }}>
          <Plug size={18} style={{ color: "var(--purple)" }} />
          <h2 style={{ margin: 0, color: "var(--text)", fontSize: 15 }}>
            {isEdit ? `Edit ${editing.label}` : `Add ${category.label} — ${transport.toUpperCase()} connector`}
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
                          background: "rgba(255,91,91,.1)",
                          border: "1px solid #ff5b5b", color: "#ff9494",
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
        <div style={{ marginTop: 10, color: "var(--faint)", fontSize: 10.5,
                         fontFamily: "var(--mono)", lineHeight: 1.5 }}>
          Secrets are stored on the collector and redacted (<span style={{ color: "var(--amber)" }}>***</span>)
          in every subsequent API response. To rotate, enter the new value; leave blank to keep the existing one.
        </div>
      </div>
    </div>
  );
}


// ── Wizard field building blocks ─────────────────────────────
function Field({ label, hint, testid, children }) {
  return (
    <div style={{ marginBottom: 10 }} data-testid={testid}>
      <div style={{ fontFamily: "var(--mono)", fontSize: 9.5,
                       letterSpacing: ".3px", fontWeight: 800,
                       color: "var(--faint)", textTransform: "uppercase",
                       marginBottom: 4 }}>{label}</div>
      {children}
      {hint && (
        <div style={{ color: "var(--faint)", fontSize: 10.5, marginTop: 3,
                        fontFamily: "var(--mono)" }}>{hint}</div>
      )}
    </div>
  );
}
function RestFields({ cfg, patch, patchCred, isEdit }) {
  const auth = cfg.auth?.type || "none";
  return (
    <>
      <Field label="URL" testid="xdr-int-wiz-url">
        <input className="x-input" placeholder="https://vendor.example.com/api/events"
                  value={cfg.url || ""} onChange={(e) => patch("url", e.target.value)} />
      </Field>
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
          <option value="none">none</option>
          <option value="bearer">bearer</option>
          <option value="basic">basic</option>
          <option value="api_key">api_key</option>
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
          <Field label="Username">
            <input className="x-input"
                      onChange={(e) => patchCred("username", e.target.value)} />
          </Field>
          <Field label="Password">
            <input className="x-input" type="password"
                      onChange={(e) => patchCred("password", e.target.value)} />
          </Field>
        </div>
      )}
      {auth === "api_key" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
          <Field label="Header name">
            <input className="x-input" placeholder="X-API-Key"
                      value={cfg.auth?.header || ""}
                      onChange={(e) => patch("auth", { ...(cfg.auth || {}), header: e.target.value })} />
          </Field>
          <Field label="Prefix">
            <input className="x-input" placeholder=""
                      value={cfg.auth?.prefix || ""}
                      onChange={(e) => patch("auth", { ...(cfg.auth || {}), prefix: e.target.value })} />
          </Field>
          <Field label="API key">
            <input className="x-input" type="password"
                      onChange={(e) => patchCred("api_key", e.target.value)} />
          </Field>
        </div>
      )}
      <Field label="Records path" hint="Dotted JSON path to the events array (blank = whole body).">
        <input className="x-input" placeholder="results"
                  value={cfg.records_path || ""}
                  onChange={(e) => patch("records_path", e.target.value)} />
      </Field>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
        <Field label="Event ID path" hint="Dedup key">
          <input className="x-input" placeholder="id"
                    value={cfg.event_id_path || ""}
                    onChange={(e) => patch("event_id_path", e.target.value)} />
        </Field>
        <Field label="Timestamp path">
          <input className="x-input" placeholder="ts"
                    value={cfg.timestamp_path || ""}
                    onChange={(e) => patch("timestamp_path", e.target.value)} />
        </Field>
        <Field label="Cursor param" hint="Query param for pagination">
          <input className="x-input" placeholder="after"
                    value={cfg.cursor_param || ""}
                    onChange={(e) => patch("cursor_param", e.target.value)} />
        </Field>
      </div>
      <Field label="Cursor path" hint="Dotted JSON path in the response that carries the next cursor.">
        <input className="x-input" placeholder="meta.next"
                  value={cfg.cursor_path || ""}
                  onChange={(e) => patch("cursor_path", e.target.value)} />
      </Field>
    </>
  );
}
function WebhookFields({ cfg, patch, patchCred, isEdit }) {
  return (
    <>
      <Field label="Secret ID" hint="Path segment used in the public URL: /api/xdr/webhooks/{secret_id}">
        <input className="x-input" placeholder="wh-abc123"
                  value={cfg.secret_id || ""}
                  onChange={(e) => patch("secret_id", e.target.value)} />
      </Field>
      <Field label={`HMAC secret${isEdit ? " (leave blank to keep existing)" : ""}`}
                hint="If unset, signatures are not enforced and every delivery is flagged unauthenticated.">
        <input className="x-input" type="password"
                  onChange={(e) => patchCred("hmac_secret", e.target.value)} />
      </Field>
      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr", gap: 10 }}>
        <Field label="Signature header">
          <input className="x-input" placeholder="X-Hub-Signature-256"
                    value={cfg.signature?.header || ""}
                    onChange={(e) => patch("signature", { ...(cfg.signature || {}), header: e.target.value })} />
        </Field>
        <Field label="Algo">
          <select className="x-input" value={cfg.signature?.algo || "sha256"}
                     onChange={(e) => patch("signature", { ...(cfg.signature || {}), algo: e.target.value })}>
            <option>sha256</option><option>sha1</option>
          </select>
        </Field>
        <Field label="Prefix">
          <input className="x-input" placeholder="sha256="
                    value={cfg.signature?.prefix || ""}
                    onChange={(e) => patch("signature", { ...(cfg.signature || {}), prefix: e.target.value })} />
        </Field>
      </div>
      <Field label="Records path" hint="Dotted path to the events array in the POST body (blank = whole body).">
        <input className="x-input" placeholder="events"
                  value={cfg.records_path || ""}
                  onChange={(e) => patch("records_path", e.target.value)} />
      </Field>
      <Field label="Event ID path" hint="Dedup key per record.">
        <input className="x-input" placeholder="id"
                  value={cfg.event_id_path || ""}
                  onChange={(e) => patch("event_id_path", e.target.value)} />
      </Field>
    </>
  );
}
function SyslogFields({ cfg, patch }) {
  return (
    <>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
        <Field label="Protocol">
          <select className="x-input" value={cfg.protocol || "udp"}
                     onChange={(e) => patch("protocol", e.target.value)}>
            <option value="udp">UDP</option>
            <option value="tcp">TCP</option>
          </select>
        </Field>
        <Field label="Host">
          <input className="x-input" placeholder="0.0.0.0"
                    value={cfg.host || ""}
                    onChange={(e) => patch("host", e.target.value)} />
        </Field>
        <Field label="Port">
          <input className="x-input" type="number" min={1} max={65535}
                    placeholder="5514"
                    value={cfg.port || ""}
                    onChange={(e) => patch("port", parseInt(e.target.value || 0, 10))} />
        </Field>
      </div>
      <Field label="Format">
        <select className="x-input" value={cfg.format || "auto"}
                   onChange={(e) => patch("format", e.target.value)}>
          <option value="auto">auto-detect</option>
          <option value="rfc3164">RFC3164 (BSD syslog)</option>
          <option value="rfc5424">RFC5424 (IETF syslog)</option>
        </select>
      </Field>
    </>
  );
}
