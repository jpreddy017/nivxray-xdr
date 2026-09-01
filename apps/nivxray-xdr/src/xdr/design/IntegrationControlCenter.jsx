/**
 * IntegrationControlCenter · Round 24.9 reference surface.
 *
 * The first surface expressed entirely in the NivXRay Evidence
 * Operations grammar.  Replaces the legacy `IntegrationsBody` when
 * the design-v2 feature flag is active.
 *
 * Information architecture (owner-locked):
 *
 *   1. CAPABILITY ROSTER (primary)
 *      A list — not a grid — of connected sources.  Each row is
 *      an <Entity> plus a capability <EvidenceState> plus honest
 *      <Action>s.  This is the answer to:
 *        "Can NivXRay actually perform useful operations through
 *         this integration right now?"
 *
 *   2. EVIDENCE HEALTH (subordinate strip)
 *      Real ingest/outbox key-values.  NOT stat cards.
 *      This is the answer to:
 *        "Is the evidence stream healthy?"
 *
 *   3. ADD SOURCE (compact catalogue drawer, opened on demand)
 *      A single-column list of transport-mapped sources —
 *      replaces the 12-tile icon grid.
 *
 * Real data.  Never fabricated.  When the collector runtime is
 * not deployed the entire surface renders one honest empty state
 * with a machine-readable remediation hint.
 */
import React, { useCallback, useEffect, useState } from "react";
import {
  Plug, RotateCcw, Play, Square, Trash2, ShieldAlert, X,
  Server, Cloud, Wifi, Webhook, FileText, Terminal, Database,
  Layers,
} from "lucide-react";

import * as C from "@/xdr/admin/collectorApi";
import Entity from "./Entity";
import EvidenceState from "./EvidenceState";
import Action, { ActionGroup } from "./Action";
import "./tokens.css";
import { ConnectorWizard } from "./_WizardLegacyBridge";

// ── Legacy runtime → capability-tier mapping ──────────────────
// Deterministic.  Consumes the collector's real fields; NEVER
// invents a tier from credential presence alone.
export function deriveCapability(row) {
  const rt      = row?.runtime  || {};
  const metrics = rt.metrics    || {};
  const health  = rt.health     || "not_started";

  if (health === "authentication_failed") {
    return { state: "cap-unavailable", reason: "AUTH_FAILED" };
  }
  if (health === "error") {
    return { state: "cap-unavailable", reason: "COLLECTOR_ERROR" };
  }
  if (health === "disconnected" || health === "not_started") {
    return { state: "cap-standby", reason: "NOT_STARTED" };
  }
  if (health === "never_connected") {
    return { state: "cap-standby", reason: "NEVER_CONNECTED" };
  }
  if (health === "rate_limited") {
    return { state: "cap-degraded", reason: "RATE_LIMITED" };
  }
  if (health === "degraded") {
    return { state: "cap-degraded", reason: "COLLECTOR_DEGRADED" };
  }
  // health === "connected"
  const collected = metrics.events_collected || 0;
  const accepted  = metrics.events_accepted  || 0;
  const duped     = metrics.events_duplicated || 0;
  if (accepted > 0 && duped === 0) {
    return { state: "cap-full", reason: null };
  }
  if (accepted > 0 && duped > 0) {
    return { state: "cap-degraded", reason: `DUPED ${duped}` };
  }
  if (collected > 0 && accepted === 0) {
    return { state: "cap-ingest", reason: "PARSE_UNVERIFIED" };
  }
  return { state: "cap-ingest", reason: "NO_EVENTS_YET" };
}

// ── Catalog · human-first ───────────────────────────────────
const CATALOG = [
  { key: "edr",     label: "EDR / Endpoint", transport: "rest",
    icon: Server,   note: "REST poller — Cortex XDR, CrowdStrike, SentinelOne, Defender" },
  { key: "siem",    label: "SIEM",           transport: "syslog",
    icon: Database, note: "Syslog forwarder — Splunk, Sentinel, Chronicle, Elastic" },
  { key: "fw",      label: "Firewall",       transport: "syslog",
    icon: Wifi,     note: "Syslog (RFC5424) — Palo Alto, Fortinet, Check Point" },
  { key: "network", label: "Network / NDR",  transport: "syslog",
    icon: Wifi,     note: "Zeek, NDR sensors — syslog TCP/UDP" },
  { key: "dns",     label: "DNS",            transport: "syslog",
    icon: FileText, note: "Umbrella, Infoblox — syslog or REST bulk export" },
  { key: "identity",label: "Identity",       transport: "rest",
    icon: Server,   note: "REST poller — Entra ID, Okta" },
  { key: "cloud",   label: "Cloud audit",    transport: "rest",
    icon: Cloud,    note: "REST poller — AWS CloudTrail, Azure activity" },
  { key: "saas",    label: "SaaS webhook",   transport: "webhook",
    icon: Webhook,  note: "Webhook events — Salesforce, Slack, Box, M365" },
  { key: "app",     label: "Custom REST",    transport: "rest",
    icon: Terminal, note: "Any cursor-paginated REST API" },
];

// ── Component ────────────────────────────────────────────────
export default function IntegrationControlCenter() {
  const [state, setState] = useState("loading");
  const [error, setError] = useState(null);
  const [rows,  setRows]  = useState([]);
  const [health, setHealth] = useState(null);
  const [catalogOpen, setCatalogOpen] = useState(false);
  const [wizardCategory, setWizardCategory] = useState(null);
  const [editing, setEditing] = useState(null);

  const load = useCallback(async () => {
    setError(null);
    if (!C.COLLECTOR_CONFIGURED) { setState("not_deployed"); return; }
    setState("loading");
    try {
      const [conns, h] = await Promise.all([
        C.listCollectorConnectors(), C.getOutboxHealth(),
      ]);
      setRows(conns?.connectors || []);
      setHealth(h);
      setState("ready");
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
  useEffect(() => {
    if (state !== "ready") return;
    const t = setInterval(() => {
      C.getOutboxHealth().then(setHealth).catch(() => {});
    }, 15000);
    return () => clearInterval(t);
  }, [state]);

  const onDelete = async (row) => {
    if (!window.confirm(`Delete "${row.label}"? Queued events will still deliver.`)) return;
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
    } catch (e) { window.alert(`Test failed: ${e?.message || e}`); }
  };

  return (
    <div className="evops evops-canvas" data-testid="evops-integrations">
      <Band
        source={state === "not_deployed" ? null : "collector/*  ·  health/outbox"}
        onRefresh={state === "ready" ? load : null}
      />

      {state === "not_deployed" && <CollectorNotDeployed />}
      {state === "loading"      && <LoadingSection />}
      {state === "error"        && <ErrorSection message={error} onRetry={load} />}
      {state === "ready" && (
        <>
          <CapabilityRoster
            rows={rows}
            onEdit={setEditing}
            onDelete={onDelete}
            onToggle={onToggle}
            onTest={onTest}
            onAdd={() => setCatalogOpen(true)}
          />
          <EvidenceHealth health={health} onRefresh={load} />
        </>
      )}

      {catalogOpen && (
        <CatalogDrawer
          onClose={() => setCatalogOpen(false)}
          onPick={(cat) => { setCatalogOpen(false); setWizardCategory(cat); }}
        />
      )}
      {(wizardCategory || editing) && (
        <ConnectorWizard
          category={wizardCategory}
          editing={editing}
          onClose={() => { setWizardCategory(null); setEditing(null); }}
          onCreated={async () => {
            setWizardCategory(null); setEditing(null); await load();
          }}
        />
      )}
    </div>
  );
}

// ── Band ─────────────────────────────────────────────────────
function Band({ source, onRefresh }) {
  return (
    <div className="evops-band" data-testid="evops-band">
      <div>
        <div className="evops-band__eyebrow">Admin › Integrations</div>
        <div className="evops-band__title">Integration Control Center</div>
      </div>
      <div className="evops-band__spacer" />
      {source && <div className="evops-band__source">source · {source}</div>}
      {onRefresh && (
        <Action
          label="Refresh"
          icon={RotateCcw}
          onRun={onRefresh}
          testid="evops-band-refresh"
        />
      )}
    </div>
  );
}

// ── Capability roster ────────────────────────────────────────
function CapabilityRoster({ rows, onEdit, onDelete, onToggle, onTest, onAdd }) {
  if (!rows.length) {
    return (
      <div className="evops-section" data-testid="evops-roster-empty">
        <div className="evops-section__head">
          <div className="evops-section__eyebrow">Capability roster</div>
          <div className="evops-section__spacer" />
          <Action label="Add source" tone="primary" onRun={onAdd}
                     testid="evops-add-source" />
        </div>
        <div className="evops-empty">
          <div className="evops-empty__title">No integrations configured</div>
          <div className="evops-empty__reason">
            NivXRay has not been wired to any telemetry source yet.  Until an
            adapter reports evidence delivery this tenant has zero operational
            capability — no fabricated readiness is shown.
          </div>
          <div className="evops-empty__hint">
            Add the first source to bring evidence online.
          </div>
        </div>
      </div>
    );
  }
  return (
    <div className="evops-section" data-testid="evops-roster">
      <div className="evops-section__head">
        <div className="evops-section__eyebrow">Capability roster</div>
        <div className="evops-section__count">
          {rows.length} adapter{rows.length === 1 ? "" : "s"} configured
        </div>
        <div className="evops-section__spacer" />
        <Action label="Add source" tone="primary" onRun={onAdd}
                   testid="evops-add-source" />
      </div>
      <div className="evops-roster">
        {rows.map((row) => (
          <RosterRow
            key={row.id}
            row={row}
            onEdit={onEdit}
            onDelete={onDelete}
            onToggle={onToggle}
            onTest={onTest}
          />
        ))}
      </div>
    </div>
  );
}

function RosterRow({ row, onEdit, onDelete, onToggle, onTest }) {
  const cap = deriveCapability(row);
  const metrics = row.runtime?.metrics || {};
  const running = row.runtime?.health === "connected";
  const lastSuccess = metrics.last_success
    ? String(metrics.last_success).slice(0, 19).replace("T", " ")
    : null;
  const events = metrics.events_accepted ?? 0;
  return (
    <div
      className="evops-roster__row"
      data-testid={`evops-row-${row.id}`}
    >
      <Entity
        kind="adapter"
        name={row.label}
        id={row.id}
        icon={iconForTransport(row.source_type)}
        testid={`evops-entity-${row.id}`}
      />

      <div>
        <EvidenceState
          state={cap.state}
          reason={cap.reason}
          testid={`evops-cap-${row.id}`}
        />
      </div>

      <div className="evops-mono" data-testid={`evops-meta-${row.id}`}>
        <div>
          <span style={{ color: "var(--nx-muted)", marginRight: 6 }}>events</span>
          {events}
          {metrics.events_duplicated
            ? <span style={{ color: "var(--evops-cap-degraded-fg)", marginLeft: 6 }}>
                · duped {metrics.events_duplicated}
              </span>
            : null}
        </div>
        <div style={{ marginTop: 2 }}>
          <span style={{ color: "var(--nx-muted)", marginRight: 6 }}>last</span>
          {lastSuccess || (
            <span style={{ color: "var(--nx-faint)", fontStyle: "italic" }}>
              no successful poll
            </span>
          )}
        </div>
        <div style={{ marginTop: 2, color: "var(--nx-muted)" }}>
          transport · {row.source_type?.toUpperCase()}
        </div>
      </div>

      <ActionGroup testid={`evops-actions-${row.id}`}>
        {row.source_type === "rest" && (
          <Action
            label="Test"
            icon={ShieldAlert}
            onRun={() => onTest(row)}
            capability={cap.state === "cap-unavailable" ? "cap-unavailable" : "cap-full"}
            reason={cap.state === "cap-unavailable" ? cap.reason : null}
            testid={`evops-test-${row.id}`}
          />
        )}
        <Action
          label={running ? "Stop" : "Start"}
          icon={running ? Square : Play}
          onRun={() => onToggle(row)}
          testid={`evops-toggle-${row.id}`}
        />
        <Action
          label="Edit"
          onRun={() => onEdit(row)}
          testid={`evops-edit-${row.id}`}
        />
        <Action
          label="Delete"
          icon={Trash2}
          tone="destructive"
          onRun={() => onDelete(row)}
          testid={`evops-delete-${row.id}`}
        />
      </ActionGroup>
    </div>
  );
}

function iconForTransport(transport) {
  if (transport === "rest") return Server;
  if (transport === "webhook") return Webhook;
  if (transport === "syslog") return Layers;
  return Plug;
}

// ── Evidence health strip ───────────────────────────────────
function EvidenceHealth({ health, onRefresh }) {
  if (!health) return null;
  const cells = [
    { label: "Ingest state",     value: (health.state || "").toUpperCase(),
      absent: !health.state },
    { label: "Delivered",        value: health.ingest?.delivered,
      machine: true, absent: health.ingest?.delivered == null },
    { label: "Queue depth",      value: health.outbox?.queue_depth,
      machine: true, absent: health.outbox?.queue_depth == null },
    { label: "Dead-letter",      value: health.outbox?.counts?.dead_letter,
      machine: true, absent: health.outbox?.counts?.dead_letter == null },
    { label: "Last ingest error",
      value: health.ingest?.last_error
              ? String(health.ingest.last_error).slice(0, 90)
              : null,
      machine: true,
      absent: !health.ingest?.last_error,
      absentLabel: "no error observed" },
  ];
  return (
    <div className="evops-section evops-section--sub" data-testid="evops-health">
      <div className="evops-section__head">
        <div className="evops-section__eyebrow">Evidence health</div>
        <div className="evops-section__spacer" />
        <Action
          label="Preflight ingest"
          onRun={async () => {
            try {
              const r = await C.ingestPreflight();
              window.alert(
                `Ingest preflight: ${String(r.state || "").toUpperCase()}` +
                (r.status_code ? ` (HTTP ${r.status_code})` : "") +
                (r.reason ? `\n\nReason: ${r.reason}` : "") +
                `\n\nOutcome: ${r.outcome || "n/a"}\nOk: ${r.ok}`
              );
              onRefresh && onRefresh();
            } catch (e) {
              window.alert("Preflight request failed: " + (e?.message || e));
            }
          }}
          testid="evops-preflight"
        />
      </div>
      <div className="evops-health">
        {cells.map((c) => (
          <div className="evops-health__cell" key={c.label}>
            <div className="evops-health__label">{c.label}</div>
            <div
              className={`evops-health__value ${c.machine ? "evops-health__value--machine" : ""}`}
              data-absent={c.absent ? "true" : "false"}
            >
              {c.absent
                ? (c.absentLabel || "not reported")
                : String(c.value)}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Catalogue drawer ────────────────────────────────────────
function CatalogDrawer({ onClose, onPick }) {
  return (
    <div
      role="dialog"
      aria-label="Add integration source"
      data-testid="evops-catalog-drawer"
      style={{
        position: "fixed", inset: 0, background: "rgba(17, 24, 39, 0.35)",
        display: "flex", justifyContent: "flex-end", zIndex: 60,
      }}
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 440, maxWidth: "100%", height: "100%",
          background: "var(--nx-surf-primary)",
          borderLeft: "1px solid var(--nx-bd-strong)",
          padding: "22px 22px 32px",
          overflow: "auto",
          fontFamily: "var(--sans)",
        }}
      >
        <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 20 }}>
          <div className="evops-band__eyebrow">Add source</div>
          <div className="evops-band__title" style={{ fontSize: 15 }}>
            Choose telemetry origin
          </div>
          <div style={{ flex: 1 }} />
          <button
            type="button"
            className="evops-action"
            onClick={onClose}
            data-testid="evops-catalog-close"
          >
            <X size={12} /> Close
          </button>
        </div>

        <div className="evops-catalog">
          {CATALOG.map((c) => {
            const Icon = c.icon;
            return (
              <button
                key={c.key}
                type="button"
                className="evops-catalog__row"
                onClick={() => onPick(c)}
                data-testid={`evops-catalog-${c.key}`}
              >
                <span className="evops-catalog__icon"><Icon size={16} /></span>
                <span>
                  <span className="evops-catalog__label">{c.label}</span>
                  <span className="evops-catalog__note">{c.note}</span>
                </span>
                <span className="evops-catalog__transport">
                  via {c.transport}
                </span>
                <span className="evops-catalog__go">Configure →</span>
              </button>
            );
          })}
        </div>

        <p
          className="evops-hint"
          style={{ marginTop: 20, maxWidth: "100%" }}
        >
          Every source maps to a Phase-B transport (REST poller · Webhook receiver
          · Syslog receiver).  A source becomes <strong>CONNECTED</strong> only after
          the collector runtime reports actual event delivery — capability is never
          inferred from credentials alone.
        </p>
      </div>
    </div>
  );
}

// ── State surfaces ──────────────────────────────────────────
function CollectorNotDeployed() {
  return (
    <div className="evops-section" data-testid="evops-not-deployed">
      <div className="evops-section__head">
        <div className="evops-section__eyebrow">Runtime</div>
        <div className="evops-section__spacer" />
        <EvidenceState state="unavailable" label="Collector not deployed" />
      </div>
      <div className="evops-empty">
        <div className="evops-empty__title">Collector runtime not wired</div>
        <div className="evops-empty__reason">
          The Integration Control Center consumes the NivXRay XDR Collector — a
          separately deployable runtime.  This XDR frontend has not been pointed at
          any collector yet, so no capability state can be honestly reported.
        </div>
        <div className="evops-empty__hint">
          Set <span style={{ color: "var(--evops-prov-canonical)" }}>VITE_XDR_COLLECTOR_URL</span>{" "}
          in the deployment env to the collector URL, then redeploy.  Reference
          implementation: <span>/app/apps/nivxray-xdr-collector</span>.
        </div>
      </div>
    </div>
  );
}
function LoadingSection() {
  return (
    <div className="evops-section" data-testid="evops-loading">
      <div className="evops-section__head">
        <div className="evops-section__eyebrow">Capability roster</div>
      </div>
      <div className="evops-empty">
        <div className="evops-empty__title">Loading …</div>
        <div className="evops-empty__reason">Fetching real capability state from the collector.</div>
      </div>
    </div>
  );
}
function ErrorSection({ message, onRetry }) {
  return (
    <div className="evops-section" data-testid="evops-error">
      <div className="evops-section__head">
        <div className="evops-section__eyebrow">Capability roster</div>
        <div className="evops-section__spacer" />
        <EvidenceState state="unavailable" label="Collector call failed" />
        <Action label="Retry" icon={RotateCcw} onRun={onRetry}
                   testid="evops-retry" />
      </div>
      <div className="evops-empty">
        <div className="evops-empty__title">Unable to load capability state</div>
        <div className="evops-empty__reason">
          {String(message || "The collector API did not return a payload.")}
        </div>
      </div>
    </div>
  );
}
