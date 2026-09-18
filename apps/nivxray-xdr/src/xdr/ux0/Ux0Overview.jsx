/**
 * E2E-UX0 · Overview tab (blueprint §3.2).
 *
 * Asymmetric 8/4 on a 12-column grid. Band A answer first (assessment prose,
 * not fields), then band B impact as metric cards that behave as drawers.
 * Zero raw JSON on this tab, at any depth.
 */
import React from "react";
import { NxProvenanceChip, NxPriority, NxLifecycle, NxEmpty, NxDataTable } from "@/xdr/nx";
import { Panel, MetricDrawerCard, StageRail } from "./Ux0Parts";

const DETECTIONS = [
  { id: "d1", sev: "critical", rule: "Obfuscated PowerShell — runtime string assembly",
    asset: "FIN-WS-014", seen: "09:22:14Z" },
  { id: "d2", sev: "high", rule: "AMSI in-process tamper", asset: "FIN-WS-014", seen: "09:22:16Z" },
  { id: "d3", sev: "medium", rule: "Browser credential store read", asset: "FIN-WS-014", seen: "09:23:02Z" },
  { id: "d4", sev: "low", rule: "Beacon-like DNS periodicity", asset: "FIN-WS-014", seen: "09:23:05Z" },
];

export default function Ux0Overview({ incident, metrics, stages, onDrawer }) {
  const c = incident.correlation;
  return (
    <div className="ux0-grid">
      <div className="ux0-col8">
        <Panel title="Assessment" testid="ux0-assessment"
               right={<NxProvenanceChip provenance="correlated"
                                        basis={`${c.detections} detections`} />}>
          <p className="ux0-prose">{incident.assessment}</p>
          <div className="ux0-chiprow" style={{ marginTop: 12 }}>
            <NxProvenanceChip provenance="observed" />
            <NxProvenanceChip provenance="reconstructed" />
            <NxProvenanceChip provenance="decoded" />
          </div>
        </Panel>

        <Panel title="Attack chain" testid="ux0-overview-chain">
          <StageRail stages={stages} active="execution" onSelect={() => {}} />
        </Panel>

        <div className="ux0-metrics">
          {metrics.map((m) => (
            <MetricDrawerCard key={m.key} label={m.label} value={m.value}
                              sub={m.sub} testid={`ux0-metric-${m.key}`}
                              onViewAll={() => onDrawer(m.kind)} />
          ))}
        </div>

        <Panel title={`Detections (${DETECTIONS.length})`} flush
               testid="ux0-overview-detections">
          <NxDataTable
            testid="ux0-detections-table"
            searchable={false} pageSize={10}
            onRowClick={() => onDrawer("detection")}
            columns={[
              { key: "sev", header: "Severity", width: 110,
                render: (r) => (
                  <span className="ux0-chiprow">
                    <span className="ux0-sevdot" data-sev={r.sev} />
                    <span style={{ fontSize: 12 }}>{r.sev}</span>
                  </span>
                ) },
              { key: "rule", header: "Rule" },
              { key: "asset", header: "Asset", width: 140 },
              { key: "seen", header: "First seen", width: 110 },
            ]}
            rows={DETECTIONS}
          />
        </Panel>
      </div>

      <div className="ux0-col4">
        <Panel title="Priority & SLA" testid="ux0-sla">
          <div className="ux0-chiprow">
            <NxPriority priority={incident.priority} />
            <NxLifecycle value={incident.lifecycle} />
          </div>
          <div className="ux0-fact__v is-warn" style={{ marginTop: 10 }}>
            Breach in 02:14
          </div>
          <div style={{ marginTop: 8, height: 6, borderRadius: 3,
                        background: "var(--nx-inset)", overflow: "hidden" }}>
            <div style={{ width: "68%", height: "100%", background: "var(--nx-high)" }} />
          </div>
        </Panel>

        <Panel title="Assignment" testid="ux0-assignment">
          <div className="ux0-kv">
            <span className="ux0-kv__k">Owner</span>
            <span className="ux0-kv__v">a.rahman</span>
            <span className="ux0-kv__k">Queue</span>
            <span className="ux0-kv__v">FIN-EMEA</span>
          </div>
        </Panel>

        <Panel title="Correlation basis" testid="ux0-correlation">
          <div className="ux0-kv">
            <span className="ux0-kv__k">Inputs</span>
            <span className="ux0-kv__v">{c.detections} detections · {c.rules} rules</span>
            <span className="ux0-kv__k">Pivot</span>
            <span className="ux0-kv__v">{c.pivot}</span>
          </div>
        </Panel>

        <Panel title="Contributing sources" testid="ux0-sources">
          <div className="ux0-chiprow">
            {c.sources.map((s) => (
              <span key={s} className="ux0-proof" style={{ cursor: "default" }}>{s}</span>
            ))}
          </div>
          <NxEmpty compact
                   title={`${c.sourcesConnected} of ${c.sourcesTotal} sources contributing`}
                   hint="Identity and Email telemetry are not connected, so identity-side blast radius cannot be computed for this incident."
                   cta={<button type="button" className="ux0-btn"
                                data-testid="ux0-connect-source">Connect source</button>}
                   data-testid="ux0-empty-unavailable" />
        </Panel>
      </div>
    </div>
  );
}
