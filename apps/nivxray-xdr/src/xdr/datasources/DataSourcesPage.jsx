/**
 * Data Sources · first-class XDR destination (Slice 1).
 *
 * Replaces the fragmented telemetry surfaces with one experience answering
 * the operator's questions in order: what can I connect · what is connected ·
 * is telemetry arriving · is it healthy · did NivXRay understand it · is the
 * evidence complete · what needs attention.
 *
 * Engineering internals (routing, parsers, normalisation, DSM detail) stay
 * reachable in Administration — they are not the default experience.
 */
import React, { useCallback, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Database } from "lucide-react";
import XdrShell from "@/xdr/XdrShell";
import {
  NxKpi, NxMetric, NxPageShell, NxStatus, NxSurface, NxTabs,
} from "@/xdr/nx";
import { BUILD_CONTRACTS, loadDataSources } from "./dsApi";
import {
  CollectorsTab, CoverageTab, SourcesTab,
} from "./SourcesAndCollectors";
import {
  AddSourceWizard, HealthTab, IntegrationsTab, VerifyPanel,
} from "./IntegrationsAndAdd";

const TABS = [
  { key: "overview", label: "Overview" },
  { key: "sources", label: "Sources" },
  { key: "collectors", label: "Collectors" },
  { key: "integrations", label: "Integrations" },
  { key: "coverage", label: "Coverage" },
  { key: "health", label: "Health" },
  { key: "verify", label: "Verify" },
];

export default function DataSourcesPage() {
  const { tab } = useParams();
  const navigate = useNavigate();
  const active = TABS.some((t) => t.key === tab) ? tab : "overview";

  const [state, setState] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [wizard, setWizard] = useState(false);

  const reload = useCallback(() => {
    setLoading(true);
    loadDataSources()
      .then((s) => { setState(s); setError(null); })
      .catch((e) => setError(e?.message || String(e)))
      .finally(() => setLoading(false));
  }, []);
  useEffect(reload, [reload]);

  const s = state || {
    catalog: [], sourceTypes: [], connectors: [], collectors: [],
    runtime: [], loaders: [],
  };
  const receiving = (s.catalog || []).filter((c) => c.accepted > 0).length;
  const failedLoaders = (s.loaders || []).filter((l) => !l.ok);

  return (
    <XdrShell>
      <NxPageShell
        eyebrow="NivXRay XDR"
        title="Data Sources"
        description="Everything that feeds evidence into NivXRay XDR — what is connected, whether telemetry is arriving, and whether the evidence is complete."
        action={
          <button className="nx-dt-btn" data-testid="ds-add-source"
                  onClick={() => setWizard(true)}>+ Add data source</button>
        }
        testid="data-sources-page">
        <NxTabs tabs={TABS} active={active} testid="ds-tabs"
                onChange={(k) => navigate(`/xdr/data-sources/${k}`)} />

        {failedLoaders.length > 0 && (
          <div className="nx-dt-error" style={{ marginBottom: 16 }}
               data-testid="ds-loader-errors">
            <strong>Some sources of truth did not answer.</strong>
            {failedLoaders.map((l) => (
              <span key={l.label}>{l.label}: {l.error}</span>
            ))}
          </div>
        )}

        {active === "overview" && (
          <div style={{ display: "grid", gap: 16 }}>
            <div className="nx-ds-kpis" data-testid="ds-overview-kpis">
              <NxKpi icon={Database} label="Sources NivXRay can interpret"
                     value={loading ? null : s.catalog.length}
                     sub="/api/xdr/collectors/sources/catalog"
                     testid="ds-kpi-catalog" />
              <NxKpi label="Sources receiving telemetry"
                     value={loading ? null : receiving}
                     sub="routing summary · accepted by declared source"
                     testid="ds-kpi-receiving" />
              <NxKpi label="Accepted events in scope"
                     value={loading ? null : (s.accepted?.total ?? null)}
                     sub="/api/xdr/ingest/routing/summary"
                     testid="ds-kpi-accepted" />
              <NxKpi label="Collectors enrolled"
                     value={loading ? null : s.collectors.length}
                     sub="/api/xdr/collectors" testid="ds-kpi-collectors" />
              <NxMetric label="Events per second" value={null}
                        reason={BUILD_CONTRACTS.eps} testid="ds-kpi-eps" />
              <NxMetric label="Evidence completeness" value={null}
                        state="unavailable" reason={BUILD_CONTRACTS.completeness}
                        testid="ds-kpi-completeness" />
            </div>

            <NxSurface title="What needs attention"
              subtitle="Only conditions an authoritative field can prove."
              testid="ds-attention">
              <div style={{ display: "grid", gap: 10 }}>
                <AttentionRow
                  label="Ingest pipeline"
                  ok={!!s.telemetryHealth?.ingest?.configured}
                  okLabel="Configured"
                  badState="not_configured"
                  reason={`ingest.state = ${s.telemetryHealth?.ingest?.state || "unknown"}`} />
                <AttentionRow
                  label="Telemetry arriving"
                  ok={(s.accepted?.total ?? 0) > 0}
                  okLabel="Receiving" badState="not_receiving"
                  reason="No accepted delivery recorded in this scope" />
                <AttentionRow
                  label="Collector runtime"
                  ok={!!s.collectorPlaneConfigured}
                  okLabel="Configured" badState="not_configured"
                  reason="No collector runtime configured for this deployment" />
                <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                  <NxStatus state="unavailable" reason={BUILD_CONTRACTS.completeness} />
                  <span className="nx-t-body">Collection gaps — a collector can be
                    online while its evidence history is incomplete, so this stays
                    unproven until integrity records exist.</span>
                </div>
              </div>
            </NxSurface>
          </div>
        )}

        {active === "sources" && (
          <SourcesTab state={s} loading={loading} error={error} reload={reload} />
        )}
        {active === "collectors" && (
          <CollectorsTab state={s} loading={loading} error={error} reload={reload} />
        )}
        {active === "integrations" && (
          <IntegrationsTab state={s} loading={loading}
                           onAdd={() => setWizard(true)} />
        )}
        {active === "coverage" && (
          <CoverageTab state={s} loading={loading} error={error} reload={reload} />
        )}
        {active === "health" && (
          <HealthTab state={s} loading={loading} error={error} reload={reload} />
        )}
        {active === "verify" && <VerifyPanel state={s} />}

        <AddSourceWizard open={wizard} state={s}
                         onClose={() => setWizard(false)} />
      </NxPageShell>
    </XdrShell>
  );
}

function AttentionRow({ label, ok, okLabel, badState, reason }) {
  return (
    <div style={{ display: "flex", gap: 10, alignItems: "center" }}
         data-testid={`ds-attention-${label.toLowerCase().replace(/\s+/g, "-")}`}>
      <NxStatus state={ok ? "healthy" : badState}
                label={ok ? okLabel : undefined}
                reason={ok ? null : reason} />
      <span className="nx-t-body">{label}</span>
    </div>
  );
}
