/**
 * E2E-UX0 · Evidence + Entities tabs (blueprint §3.4).
 *
 * One table grammar (`NxDataTable`), one verdict grammar (`NxVerdict`), row
 * click opens a flyout — never a page hop.
 */
import React from "react";
import { NxVerdict, NxProvenanceChip, NxDataTable, NxRisk } from "@/xdr/nx";
import { Panel } from "./Ux0Parts";

export function Ux0Evidence({ rows, onRow }) {
  return (
    <div style={{ marginTop: 18 }}>
      <Panel title={`Evidence & response (${rows.length})`} flush
             testid="ux0-evidence-panel">
        <NxDataTable
          testid="ux0-evidence-table"
          rows={rows} selectable pageSize={25}
          searchPlaceholder="Search entity, type or source"
          onRowClick={onRow}
          bulkActions={(keys) => (
            <button type="button" className="ux0-btn"
                    data-testid="ux0-evidence-bulk-block">
              Block {keys.length} observable(s)
            </button>
          )}
          columns={[
            { key: "verdict", header: "Verdict", width: 118,
              render: (r) => <NxVerdict value={r.verdict} /> },
            { key: "entity", header: "Entity",
              render: (r) => <span className="ux0-mono">{r.entity}</span> },
            { key: "type", header: "Type", width: 96 },
            { key: "provenance", header: "Provenance", width: 130,
              render: (r) => <NxProvenanceChip provenance={r.provenance} /> },
            { key: "seen", header: "First seen", width: 104 },
            { key: "source", header: "Source", width: 110 },
            { key: "remediation", header: "Remediation", width: 130 },
          ]}
        />
      </Panel>
    </div>
  );
}

export function Ux0Entities({ rows, onRow }) {
  return (
    <div style={{ marginTop: 18 }}>
      <Panel title={`Assets, identities & observables (${rows.length})`} flush
             testid="ux0-entities-panel">
        <NxDataTable
          testid="ux0-entities-table"
          rows={rows} pageSize={25} onRowClick={onRow}
          searchPlaceholder="Search entity"
          columns={[
            { key: "verdict", header: "Verdict", width: 118,
              render: (r) => <NxVerdict value={r.verdict} /> },
            { key: "name", header: "Entity",
              render: (r) => <span className="ux0-mono">{r.name}</span> },
            { key: "type", header: "Type", width: 100 },
            { key: "role", header: "Role in incident", width: 150 },
            { key: "risk", header: "Risk", width: 92,
              render: (r) => <NxRisk score={r.risk} /> },
            { key: "os", header: "Platform", width: 180 },
            { key: "owner", header: "Owner", width: 110 },
          ]}
        />
      </Panel>
    </div>
  );
}

export function Ux0Activity({ rows }) {
  return (
    <div style={{ marginTop: 18 }}>
      <Panel title={`Activity worklog (${rows.length})`} flush
             testid="ux0-activity-panel">
        <div className="ux0-log">
          {rows.map((r, i) => (
            <div key={i} className="ux0-log__row" data-testid={`ux0-activity-${i}`}>
              <div className="ux0-log__t">{r.t}</div>
              <div className="ux0-log__who">{r.who}<small>{r.role}</small></div>
              <div className="ux0-log__what">{r.what}</div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}
