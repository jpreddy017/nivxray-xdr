/**
 * EndpointLanes · P1 · Endpoint investigation lanes
 *
 * File / Network / Registry / Service observation grids for one
 * endpoint entity.
 *
 * Zero-fabrication contract: this component adds NO data source.  It
 * projects the same `/api/edr/device-trajectory` payload the canvas
 * already consumes, so every row is a persisted
 * `v2_shadow_observations` document reachable through its
 * `evidence_ref`.  A column with no observed value renders `◇` — never
 * a plausible-looking placeholder.
 */
import React, { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { FileText, Network, Database, Cog } from "lucide-react";

const LANES = [
  { key: "file",     label: "Files",    icon: FileText,
    kinds: ["file_create", "file_write", "file_delete"] },
  { key: "network",  label: "Network",  icon: Network,
    kinds: ["network_connect", "network_listen"] },
  { key: "registry", label: "Registry", icon: Database,
    kinds: ["registry_value_set"] },
  { key: "service",  label: "Services", icon: Cog,
    kinds: ["service_install"] },
];

const COLUMNS = {
  file: [
    ["timestamp",       "Timestamp (UTC)"],
    ["observation_kind","Operation"],
    ["file",            "Target"],
    ["sha256",          "SHA-256"],
    ["process",         "Process"],
    ["user",            "User"],
    ["process_iid",     "Process IID"],
  ],
  network: [
    ["timestamp",       "Timestamp (UTC)"],
    ["observation_kind","Operation"],
    ["file",            "Remote / Endpoint"],
    ["process",         "Process"],
    ["user",            "User"],
    ["process_iid",     "Process IID"],
  ],
  registry: [
    ["timestamp",       "Timestamp (UTC)"],
    ["observation_kind","Operation"],
    ["file",            "Registry Path"],
    ["process",         "Process"],
    ["user",            "User"],
    ["process_iid",     "Process IID"],
  ],
  service: [
    ["timestamp",       "Timestamp (UTC)"],
    ["observation_kind","Operation"],
    ["file",            "Service / Image"],
    ["process",         "Process"],
    ["user",            "User"],
    ["process_iid",     "Process IID"],
  ],
};

function cell(v) {
  if (v === null || v === undefined || v === "") {
    return <span className="nx-ep" data-ep="no_evidence" data-known="true">◇</span>;
  }
  return <span className="mono">{String(v)}</span>;
}

export default function EndpointLanes({ events, onSelect }) {
  const [lane, setLane] = useState("file");

  const buckets = useMemo(() => {
    const out = {};
    for (const l of LANES) {
      out[l.key] = (events || []).filter((e) =>
        l.kinds.includes(e.observation_kind));
    }
    return out;
  }, [events]);

  const rows = buckets[lane] || [];
  const cols = COLUMNS[lane];

  return (
    <section className="panel" style={{ padding: 0 }}
              data-testid="edr-endpoint-lanes">
      <div style={{ display: "flex", gap: 4, padding: "8px 10px",
                      borderBottom: "1px solid var(--border)" }}>
        {LANES.map((l) => {
          const Icon = l.icon;
          const n = (buckets[l.key] || []).length;
          const active = lane === l.key;
          return (
            <button
              key={l.key}
              className={`btn ${active ? "primary" : ""}`}
              style={{ padding: "4px 9px", fontSize: 11 }}
              onClick={() => setLane(l.key)}
              data-testid={`edr-lane-tab-${l.key}`}
            >
              <Icon size={11} /> {l.label}
              <span className="mono" style={{ marginLeft: 5,
                                                  color: active ? "inherit"
                                                                : "var(--faint)" }}>
                {n}
              </span>
            </button>
          );
        })}
      </div>

      {rows.length === 0 ? (
        <div className="x-empty" data-testid={`edr-lane-empty-${lane}`}>
          <b>◇ NO EVIDENCE</b>
          <div style={{ marginTop: 4 }}>
            No {LANES.find((l) => l.key === lane)?.label.toLowerCase()}{" "}
            observations are persisted for this endpoint in the selected
            window.
          </div>
        </div>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table className="x-table" data-testid={`edr-lane-table-${lane}`}>
            <thead>
              <tr>
                {cols.map(([k, label]) => <th key={k}>{label}</th>)}
                <th>Source Case</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.id}
                     className="rowlink"
                     onClick={() => onSelect && onSelect(e)}
                     data-testid={`edr-lane-row-${e.id}`}>
                  {cols.map(([k]) => <td key={k}>{cell(e[k])}</td>)}
                  <td>
                    {e.incident_id ? (
                      <Link to={`/xdr/incidents/${e.incident_id}`}
                              onClick={(ev) => ev.stopPropagation()}
                              style={{ color: "var(--cyan)", fontSize: 10.5 }}
                              className="mono"
                              title={`${e.evidence_ref?.type || "observation"} · ${e.incident_id}`}
                              data-testid={`edr-lane-evidence-${e.id}`}>
                        {String(e.incident_id).length > 28
                          ? String(e.incident_id).slice(0, 28) + "…"
                          : e.incident_id}
                      </Link>
                    ) : cell(null)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
