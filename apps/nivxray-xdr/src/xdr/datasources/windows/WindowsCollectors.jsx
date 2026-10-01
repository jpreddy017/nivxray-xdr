/**
 * Windows · Collectors inventory.
 *
 * INSTALLED ≠ CONFIGURED ≠ CONNECTED ≠ RECEIVING ≠ HEALTHY. Installation
 * state is never used to manufacture connectivity here: a collector that
 * exists but has delivered nothing reads exactly that.
 */
import React, { useState } from "react";
import { NxDataTable, NxFlyout, NxKeyFact, NxFacts, NxSection, NxState,
         NxTechnical, NxRaw, NxTokenList, NxVendorIcon } from "@/xdr/nx";

function CollectorPane({ row, onClose }) {
  if (!row) return null;
  return (
    <NxFlyout open title={row.name || row.collector_id}
              eyebrow="Windows collector" onClose={onClose} width={640}
              testid="wx-collector-pane">
      <NxSection title="Authorization" testid="wx-collector-auth"
                 note={row.authorization_note}>
        <NxFacts>
          <NxKeyFact label="Collector id" value={row.collector_id} mono />
          <NxKeyFact label="State"
                     value={<NxState value={row.state} reason={row.reason} />} />
          <NxKeyFact label="Windows source authorized"
                     value={row.is_windows_collector
                       ? <NxTokenList values={row.windows_authorized_sources} />
                       : null}
                     reason={row.is_windows_collector ? null
                       : "no Windows source is on this collector's allowlist, so a Windows delivery from it is refused"} />
          <NxKeyFact label="Host" value={row.host} />
          <NxKeyFact label="Version" value={row.version} mono />
          <NxKeyFact label="Last seen" value={row.last_seen} mono />
        </NxFacts>
      </NxSection>
      <NxTechnical>
        <NxRaw>{JSON.stringify(row, null, 2)}</NxRaw>
      </NxTechnical>
    </NxFlyout>
  );
}

export default function WindowsCollectors({ collectors = [], note, loading,
                                            error, onRefresh }) {
  const [row, setRow] = useState(null);
  return (
    <div className="wx-stack" data-testid="wx-collectors">
      <NxSection variant="card" title="Collector inventory" note={note}
                 aside={`${collectors.length} enrolled`}>
        <NxDataTable rows={collectors} loading={loading} error={error}
                     onRefresh={onRefresh}
                     rowKey={(r) => r.collector_id || r.name}
                     onRowClick={setRow}
                     searchPlaceholder="Search collector, host, source"
                     emptyTitle="No collector is enrolled in this customer"
                     emptyHint="A collector appears here only after an
                                administrative enrolment; nothing is implied
                                by telemetry arriving"
                     testid="wx-collectors-table"
                     columns={[
        { key: "name", header: "Collector", width: "230px",
          value: (r) => r.name || r.collector_id,
          render: (r) => (
            <NxVendorIcon id="nivxray/collector"
                          name={r.name || r.collector_id} withLabel />) },
        { key: "host", header: "Host", width: "180px",
          value: (r) => r.host || "",
          render: (r) => (r.host
            ? <span className="nx-mono">{r.host}</span>
            : <span className="nx-absent">—</span>) },
        { key: "version", header: "Version", width: "110px",
          value: (r) => r.version || "",
          render: (r) => (r.version
            ? <span className="nx-mono">{r.version}</span>
            : <span className="nx-absent">—</span>) },
        { key: "sources", header: "Authorized Windows sources",
          value: (r) => (r.windows_authorized_sources || []).join(","),
          render: (r) => (r.is_windows_collector
            ? <NxTokenList values={r.windows_authorized_sources} limit={4} />
            : <span className="nx-absent">no Windows source authorized</span>) },
        { key: "last_seen", header: "Last seen", width: "180px",
          value: (r) => r.last_seen || "",
          render: (r) => (r.last_seen
            ? <span className="nx-mono">{r.last_seen}</span>
            : <span className="nx-absent">—</span>) },
        { key: "state", header: "State", width: "160px",
          value: (r) => r.state || "",
          render: (r) => <NxState value={r.state || "NOT_AVAILABLE"}
                                  reason={r.reason} /> },
      ]} />
      </NxSection>
      <CollectorPane row={row} onClose={() => setRow(null)} />
    </div>
  );
}
