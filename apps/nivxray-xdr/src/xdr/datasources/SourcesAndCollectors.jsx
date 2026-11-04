/**
 * Data Sources · Sources · Collectors · Coverage.
 *
 * One NxDataTable, one flyout, one status grammar — no page-local table.
 */
import React, { useState } from "react";
import { NxDataTable, NxFlyout, NxStatus, NxSurface } from "@/xdr/nx";
import { BUILD_CONTRACTS } from "./dsApi";

const num = (n) => (n == null ? "—" : Number(n).toLocaleString());

export function SourcesTab({ state, loading, error, reload }) {
  const [open, setOpen] = useState(null);
  const columns = [
    { key: "declared_source", header: "Source", width: 230,
      render: (r) => <strong>{r.declared_source}</strong> },
    { key: "dsm_id", header: "Interpreted by (DSM)", width: 210 },
    { key: "state", header: "Telemetry", width: 150,
      render: (r) => <NxStatus state={r.state}
        reason={r.state === "not_receiving"
          ? "No accepted delivery recorded for this source in scope" : null} /> },
    { key: "accepted", header: "Accepted events", align: "right", width: 140,
      render: (r) => num(r.accepted) },
    { key: "aliases", header: "Also accepts", sortable: false,
      value: (r) => (r.aliases || []).join(", "),
      render: (r) => (r.aliases || []).join(", ") || "—" },
  ];
  return (
    <>
      <NxDataTable testid="ds-sources" columns={columns} rows={state.catalog}
        rowKey={(r) => r.declared_source} loading={loading} error={error}
        onRefresh={reload} onRowClick={setOpen}
        searchPlaceholder="Search sources"
        emptyTitle="No declared sources"
        emptyHint="The source catalog is served by /api/xdr/collectors/sources/catalog." />
      <NxFlyout open={!!open} onClose={() => setOpen(null)} testid="ds-source-fly"
                eyebrow="Data source" title={open?.declared_source || ""}>
        {open && (
          <>
            <dl className="nx-kv">
              <dt>Declared source</dt><dd>{open.declared_source}</dd>
              <dt>Interpreted by</dt><dd>{open.dsm_id}</dd>
              <dt>Accepted events</dt><dd>{num(open.accepted)}</dd>
              <dt>Accepted aliases</dt><dd>{(open.aliases || []).join(", ") || "—"}</dd>
            </dl>
            <div style={{ marginTop: 16, display: "grid", gap: 8 }}>
              <NxStatus state="unavailable" reason={BUILD_CONTRACTS.rules} />
              <div className="nx-t-meta">Rules consuming this source</div>
              <NxStatus state="unavailable" reason={BUILD_CONTRACTS.completeness} />
              <div className="nx-t-meta">Evidence completeness</div>
            </div>
          </>
        )}
      </NxFlyout>
    </>
  );
}

export function CollectorsTab({ state, loading, error, reload }) {
  const [open, setOpen] = useState(null);
  const columns = [
    { key: "id", header: "Collector", width: 260,
      value: (r) => r.id || r.collector_id,
      render: (r) => <strong>{r.id || r.collector_id}</strong> },
    { key: "state", header: "State", width: 150,
      render: (r) => {
        const s = String(r.state || r.status || "").toUpperCase();
        const map = { CONNECTED: "connected", HEALTHY: "healthy",
                      STARTING: "degraded", CONFIGURED: "not_configured",
                      ADOPTED: "not_configured" };
        return <NxStatus state={map[s] || "unavailable"} label={s || "UNKNOWN"}
                         reason={r.state_reason} />;
      } },
    { key: "authorized_sources", header: "Authorised sources", sortable: false,
      value: (r) => (r.authorized_sources || []).join(", "),
      render: (r) => (r.authorized_sources || []).join(", ") || "—" },
    { key: "events_received", header: "Events received", align: "right",
      width: 140, render: (r) => num(r.events_received ?? r.events_processed) },
    { key: "last_event_at", header: "Last event", width: 190,
      render: (r) => r.last_event_at || r.last_heartbeat || "—" },
  ];
  const rows = [...(state.collectors || []), ...(state.runtime || [])];
  return (
    <>
      <NxDataTable testid="ds-collectors" columns={columns} rows={rows}
        rowKey={(r, i) => r.id || r.collector_id || i} loading={loading}
        error={error} onRefresh={reload} onRowClick={setOpen}
        searchPlaceholder="Search collectors"
        emptyTitle="No collectors in this tenant"
        emptyHint="Enrol a collector to begin receiving telemetry." />
      <NxFlyout open={!!open} onClose={() => setOpen(null)} testid="ds-col-fly"
                eyebrow="Collector" title={open?.id || open?.collector_id || ""}>
        {open && (
          <>
            <dl className="nx-kv">
              {Object.entries(open)
                .filter(([, v]) => typeof v !== "object" || Array.isArray(v))
                .map(([k, v]) => (
                  <React.Fragment key={k}>
                    <dt>{k.replace(/_/g, " ")}</dt>
                    <dd>{Array.isArray(v) ? (v.join(", ") || "—")
                                          : String(v ?? "—")}</dd>
                  </React.Fragment>
                ))}
            </dl>
            <div style={{ marginTop: 16, display: "grid", gap: 8 }}>
              <NxStatus state="unavailable" reason={BUILD_CONTRACTS.eps} />
              <div className="nx-t-meta">Per-stream event rate</div>
              <NxStatus state="unavailable" reason={BUILD_CONTRACTS.drops} />
              <div className="nx-t-meta">Dropped events</div>
            </div>
          </>
        )}
      </NxFlyout>
    </>
  );
}

export function CoverageTab({ state, loading, error, reload }) {
  const byDsm = state.accepted?.by_selected_dsm || {};
  const rows = (state.catalog || []).map((s) => ({
    ...s, interpreted: byDsm[s.dsm_id] ?? 0,
  }));
  const columns = [
    { key: "declared_source", header: "Source", width: 230 },
    { key: "dsm_id", header: "DSM", width: 210 },
    { key: "accepted", header: "Declared as", align: "right", width: 130,
      render: (r) => num(r.accepted) },
    { key: "interpreted", header: "Interpreted by DSM", align: "right",
      width: 170, render: (r) => num(r.interpreted) },
    { key: "rules", header: "Rules consuming", sortable: false, width: 190,
      render: () => <NxStatus state="unavailable" reason={BUILD_CONTRACTS.rules} /> },
  ];
  return (
    <NxSurface title="Interpretation coverage"
      subtitle="What arrives, what understands it, and what still needs a contract."
      testid="ds-coverage">
      <NxDataTable testid="ds-coverage-table" columns={columns} rows={rows}
        rowKey={(r) => r.declared_source} loading={loading} error={error}
        onRefresh={reload} searchable={false}
        emptyTitle="No coverage data" />
    </NxSurface>
  );
}
