/**
 * Data Sources · Integrations catalog · Add Data Source wizard · Verify.
 *
 * Catalog cards for discovery, tables once connected, and a guided
 * Choose → Recommended setup → Configure/Deploy → Verify → Ready flow.
 * A step that the platform cannot honestly perform yet says so.
 */
import React, { useEffect, useState } from "react";
import { NxChip, NxDataTable, NxFlyout, NxStatus, NxSurface } from "@/xdr/nx";
import { BUILD_CONTRACTS, probeAcceptedDelivery } from "./dsApi";

const CATEGORY = {
  windows: "Windows", endpoint: "Endpoint", network: "Network",
  identity: "Identity", cloud: "Cloud", email: "Email", saas: "SaaS",
  api: "Custom", intel: "Threat Intelligence", custom: "Custom",
};

function categorise(entry) {
  const id = (entry.declared_source || entry.source_type || "").toLowerCase();
  if (id.includes("sysmon") || id.includes("windows")) return "Windows";
  if (id.includes("auditd") || id.includes("sensor") || id.includes("edr")) return "Endpoint";
  if (id.includes("zeek") || id.includes("snort") || id.includes("cef")) return "Network";
  if (id.includes("m365") || id.includes("office")) return "SaaS";
  if (id.includes("aws") || id.includes("azure") || id.includes("gcp")) return "Cloud";
  return CATEGORY[entry.category] || "Custom";
}

export function IntegrationsTab({ state, loading, onAdd }) {
  const [scope, setScope] = useState("all");
  const [cat, setCat] = useState("All");

  const items = [
    ...(state.catalog || []).map((s) => ({
      key: s.declared_source, title: s.declared_source,
      sub: `Interpreted by ${s.dsm_id}`,
      connected: (s.accepted ?? 0) > 0, category: categorise(s), kind: "source",
    })),
    ...(state.sourceTypes || []).map((t) => ({
      key: t.source_type, title: t.label || t.source_type,
      sub: `${t.transport || "—"} · ${(t.capabilities || []).join(", ") || "no declared capability"}`,
      connected: (state.connectors || []).some((c) => c.source_type === t.source_type),
      category: categorise(t), kind: "transport",
    })),
  ];
  const cats = ["All", ...Array.from(new Set(items.map((i) => i.category)))];
  const shown = items.filter((i) =>
    (cat === "All" || i.category === cat)
    && (scope === "all" || (scope === "connected" ? i.connected : !i.connected)));

  return (
    <NxSurface title="Integration catalog"
      subtitle="Everything NivXRay XDR can interpret today. Connected sources move to Sources."
      action={<button className="nx-dt-btn" onClick={onAdd}
                      data-testid="ds-add-from-catalog">+ Add data source</button>}
      testid="ds-integrations">
      <div className="nx-dt-toolbar" style={{ marginBottom: 12 }}>
        {["all", "connected", "available"].map((s) => (
          <button key={s} className={`nx-tab${scope === s ? " is-active" : ""}`}
                  data-testid={`ds-scope-${s}`} onClick={() => setScope(s)}>
            {s === "all" ? "All" : s === "connected" ? "Connected" : "Available"}
          </button>
        ))}
        <span className="nx-dt-spacer" />
        {cats.map((c) => (
          <button key={c} className="nx-dt-btn" data-testid={`ds-cat-${c}`}
                  style={c === cat ? { borderColor: "var(--nx-purple)" } : null}
                  onClick={() => setCat(c)}>{c}</button>
        ))}
      </div>
      {loading ? <NxStatus state="not_measured" label="Loading catalog…" /> : (
        <div className="nx-cards" data-testid="ds-catalog-cards">
          {shown.map((i) => (
            <button key={`${i.kind}-${i.key}`} className="nx-card"
                    data-testid={`ds-card-${i.key}`} onClick={onAdd}>
              <div className="nx-card-title">{i.title}</div>
              <div className="nx-card-sub">{i.sub}</div>
              <div style={{ display: "flex", gap: 6, marginTop: "auto" }}>
                <NxChip tone="purple" variant="dashed">{i.category}</NxChip>
                <NxStatus state={i.connected ? "connected" : "available"} />
              </div>
            </button>
          ))}
          {shown.length === 0 && <NxStatus state="unavailable"
            label="Nothing in this filter" />}
        </div>
      )}
    </NxSurface>
  );
}

const STEPS = ["Choose", "Recommended setup", "Configure / deploy",
               "Verify", "Ready"];

export function AddSourceWizard({ open, onClose, state }) {
  const [step, setStep] = useState(0);
  const [pick, setPick] = useState(null);
  useEffect(() => { if (open) { setStep(0); setPick(null); } }, [open]);

  const windowsPick = pick && /sysmon|windows/i.test(pick.declared_source || "");
  return (
    <NxFlyout open={open} onClose={onClose} width={640} testid="ds-wizard"
              eyebrow="Data Sources" title="Add data source"
              footer={
                <>
                  <button className="nx-dt-btn" disabled={step === 0}
                          data-testid="ds-wizard-back"
                          onClick={() => setStep((s) => s - 1)}>Back</button>
                  <button className="nx-dt-btn" data-testid="ds-wizard-next"
                          disabled={!pick || step >= STEPS.length - 1}
                          onClick={() => setStep((s) => s + 1)}>Continue</button>
                </>
              }>
      <div className="nx-steps" data-testid="ds-wizard-steps">
        {STEPS.map((s, i) => (
          <span key={s} className={`nx-step${i === step ? " is-active"
            : i < step ? " is-done" : ""}`}>{i + 1}. {s}</span>
        ))}
      </div>

      {step === 0 && (
        <div className="nx-cards">
          {(state.catalog || []).map((s) => (
            <button key={s.declared_source} className="nx-card"
                    data-testid={`ds-wizard-pick-${s.declared_source}`}
                    style={pick?.declared_source === s.declared_source
                      ? { borderColor: "var(--nx-purple)" } : null}
                    onClick={() => setPick(s)}>
              <div className="nx-card-title">{s.declared_source}</div>
              <div className="nx-card-sub">Interpreted by {s.dsm_id}</div>
            </button>
          ))}
        </div>
      )}

      {step === 1 && pick && (
        <dl className="nx-kv" data-testid="ds-wizard-recommended">
          <dt>Source</dt><dd>{pick.declared_source}</dd>
          <dt>Interpreted by</dt><dd>{pick.dsm_id}</dd>
          <dt>Accepted aliases</dt><dd>{(pick.aliases || []).join(", ") || "—"}</dd>
          <dt>Tenant</dt><dd>{state.tenant || "no active tenant"}</dd>
          <dt>Declaration</dt>
          <dd>Every delivery must declare <code>{pick.declared_source}</code> and
              the collector must be authorised for it. Undeclared or
              unauthorised telemetry is refused, not guessed.</dd>
        </dl>
      )}

      {step === 2 && pick && (
        <div style={{ display: "grid", gap: 12 }} data-testid="ds-wizard-deploy">
          {windowsPick ? (
            <>
              <NxStatus state="unavailable"
                reason="The native Windows multi-channel collector is in engineering (W2). Only the proven Sysmon path exists today." />
              <p className="nx-t-body">
                Sysmon telemetry is already proven into production. Additional
                Windows channels — Security, PowerShell, Defender, AppLocker,
                WMI, Task Scheduler — are not claimed here until the W2
                acquisition engine proves them.
              </p>
            </>
          ) : (
            <>
              <NxStatus state={state.collectorPlaneConfigured
                ? "available" : "not_configured"}
                reason={state.collectorPlaneConfigured ? null
                  : "No collector runtime is configured for this deployment"} />
              <p className="nx-t-body">
                Enrol a collector, authorise <code>{pick.declared_source}</code>
                {" "}on it, and mint an ingest key scoped to this tenant.
                Collector enrolment and key minting live in Administration and
                are unchanged by this slice.
              </p>
            </>
          )}
        </div>
      )}

      {step >= 3 && pick && <VerifyPanel state={state} source={pick} />}
    </NxFlyout>
  );
}

/** The screen the benchmarks do not have: prove the path, or say you cannot. */
export function VerifyPanel({ state, source = null }) {
  const [delivery, setDelivery] = useState(undefined);
  useEffect(() => {
    let live = true;
    probeAcceptedDelivery()
      .then((d) => live && setDelivery(d))
      .catch(() => live && setDelivery(null));
    return () => { live = false; };
  }, []);

  const th = state.telemetryHealth || {};
  const ingest = th.ingest || {};
  const accepted = state.accepted?.total ?? null;
  const src = source?.declared_source;
  const srcAccepted = src
    ? (state.accepted?.by_declared_source?.[src] ?? 0) : accepted;

  const rows = [
    { label: "Collector plane reachable",
      src: "collector plane · GET /telemetry-health",
      state: state.telemetryHealth ? "healthy" : "unavailable",
      reason: state.telemetryHealth ? null : "No response from the collector plane" },
    { label: "Authenticated and tenant-scoped",
      src: "session bearer + X-Tenant-Id",
      state: state.tenant ? "connected" : "not_configured",
      reason: state.tenant ? null : "No active tenant selected" },
    { label: "Ingest configured",
      src: "telemetry-health · ingest.state",
      state: ingest.configured ? "connected" : "not_configured",
      reason: ingest.configured ? null
        : `ingest.state = ${ingest.state || "unknown"}` },
    { label: "Telemetry accepted",
      src: "GET /api/xdr/ingest/routing/summary · accepted",
      state: srcAccepted > 0 ? "receiving" : "not_receiving",
      reason: srcAccepted > 0 ? null
        : "No accepted delivery recorded in this scope" },
    { label: "Durable delivery",
      src: "collector plane · GET /outbox/health",
      state: state.outbox
        ? (state.outbox.outbox?.counts?.dead_letter > 0 ? "degraded" : "healthy")
        : "unavailable",
      reason: state.outbox ? null : "Outbox health unavailable" },
    { label: "Parsed and normalised",
      src: "raw row parser_ok / normalized_ok",
      state: "not_measured", reason: BUILD_CONTRACTS.parse_measured },
    { label: "Canonical evidence created",
      src: "GET /api/xdr/ingest/routing/deliveries · evidence_ref",
      state: delivery === undefined ? "not_measured"
        : delivery?.evidence_ref ? "healthy" : "not_receiving",
      reason: delivery === undefined ? "checking…"
        : delivery?.evidence_ref ? delivery.evidence_ref
        : "No accepted delivery carried an evidence reference" },
    { label: "Evidence completeness",
      src: "COLLECTION_GAP integrity records",
      state: "unavailable", reason: BUILD_CONTRACTS.completeness },
    { label: "Detection readiness",
      src: "rule-to-source binding",
      state: "unavailable", reason: BUILD_CONTRACTS.rules },
  ];

  const blocking = rows.filter((r) =>
    ["not_configured", "not_receiving", "offline", "degraded"].includes(r.state));

  return (
    <NxSurface title={src ? `Verify ${src}` : "Verify ingestion"}
      subtitle="Acquisition → durability → transport → processing → evidence → detection. A tick appears only when a backend field proves it."
      testid="ds-verify">
      <div>
        {rows.map((r) => (
          <div className="nx-verify-row" key={r.label}
               data-testid={`ds-verify-${r.label.toLowerCase().replace(/[^a-z]+/g, "-")}`}>
            <NxStatus state={r.state} reason={r.reason} />
            <div className="nx-vr-body">
              <div className="nx-vr-label">{r.label}</div>
              <div className="nx-vr-src">{r.src}{r.reason ? ` · ${r.reason}` : ""}</div>
            </div>
          </div>
        ))}
      </div>
      <div style={{ marginTop: 14 }} data-testid="ds-verify-verdict">
        {blocking.length === 0
          ? <NxStatus state="healthy" label={src ? `${src} is ready` : "Path verified"} />
          : <NxStatus state="unavailable"
              label={`${blocking.length} step${blocking.length > 1 ? "s" : ""} not proven`}
              reason={blocking.map((b) => b.label).join(" · ")} />}
      </div>
    </NxSurface>
  );
}

export function HealthTab({ state, loading, error, reload }) {
  const th = state.telemetryHealth || {};
  const ob = state.outbox?.outbox || th.outbox || {};
  const worker = state.outbox?.worker || th.worker || {};
  const columns = [
    { key: "source_type", header: "Transport", width: 180 },
    { key: "health", header: "Health", width: 170,
      render: (r) => <NxStatus
        state={r.health === "healthy" ? "healthy"
          : r.health === "never_connected" ? "never_connected" : "degraded"}
        reason={r.note} /> },
    { key: "instances", header: "Instances", align: "right", width: 120 },
    { key: "note", header: "Note", sortable: false },
  ];
  return (
    <div style={{ display: "grid", gap: 16 }}>
      <NxSurface title="Transports" testid="ds-health-transports">
        <NxDataTable testid="ds-health-table" columns={columns}
          rows={th.transports || []} rowKey={(r) => r.source_type}
          loading={loading} error={error} onRefresh={reload} searchable={false}
          emptyTitle="No transports reported" />
      </NxSurface>
      <NxSurface title="Durability" subtitle="Queue truth from the collector outbox."
                 testid="ds-health-durability">
        <dl className="nx-kv">
          <dt>Queue depth</dt><dd>{ob.queue_depth ?? "—"}</dd>
          <dt>Oldest queued</dt><dd>{ob.oldest_queued_at || "—"}</dd>
          <dt>Dead letter</dt><dd>{ob.counts?.dead_letter ?? "—"}</dd>
          <dt>Delivered</dt><dd>{ob.counts?.delivered ?? "—"}</dd>
          <dt>Retrying</dt><dd>{ob.counts?.retrying ?? "—"}</dd>
          <dt>Last success</dt><dd>{ob.last_successful_at || "—"}</dd>
          <dt>Worker running</dt><dd>{String(worker.running ?? "—")}</dd>
          <dt>Dropped events</dt>
          <dd><NxStatus state="unavailable" reason={BUILD_CONTRACTS.drops} /></dd>
          <dt>Collection latency</dt>
          <dd><NxStatus state="unavailable" reason={BUILD_CONTRACTS.latency} /></dd>
        </dl>
      </NxSurface>
    </div>
  );
}
