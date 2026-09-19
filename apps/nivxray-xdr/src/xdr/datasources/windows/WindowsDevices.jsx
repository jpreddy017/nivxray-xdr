/**
 * Windows console · Devices tab + the device pane.
 *
 * `evidence_origin` is the machine identity the delivered record asserted.
 * It is NOT the permanent asset identity, and this surface says so: the
 * canonical NivX device id is shown as NOT ESTABLISHED with the alias
 * block that will carry the stronger identifiers when they exist.
 */
import React, { useEffect, useState } from "react";
import { NxDataTable, NxFlyout } from "@/xdr/nx";
import { Fact, Section, StateChip } from "./WindowsPrimitives";
import { getWindowsDevice, measured } from "./windowsApi";

const Tags = ({ values = [] }) => (
  values.length
    ? <span className="wx-tags">
        {values.map((v) => <span className="wx-tag" key={String(v)}>{String(v)}</span>)}
      </span>
    : <span className="wx-dim">—</span>
);

function DevicePane({ origin, onClose, onPivotEvents }) {
  const [state, setState] = useState({ loading: true, data: null, error: null });
  useEffect(() => {
    if (!origin) return;
    setState({ loading: true, data: null, error: null });
    getWindowsDevice(origin)
      .then((d) => setState({ loading: false, data: d, error: null }))
      .catch((e) => setState({ loading: false, data: null, error: e.message }));
  }, [origin]);

  if (!origin) return null;
  const d = state.data?.device;
  const matrix = state.data?.channel_matrix || [];

  return (
    <NxFlyout open title={origin} eyebrow="Windows event origin"
              onClose={onClose} width={720} testid="wx-device-pane">
      <div className="wx-pane">
        {state.loading && <p className="wx-dim">loading…</p>}
        {state.error && <p className="wx-attn">{state.error}</p>}
        {d && (
          <>
            <Section title="Identity" note={d.identity_note}
                     testid="wx-device-identity">
              <div className="wx-facts">
                <Fact label="Evidence origin" value={d.evidence_origin} />
                <Fact label="Identity state" value={<StateChip value={d.identity_state} />} />
                <Fact label="Canonical NivX device id" value={d.canonical_device_id}
                      reason={d.canonical_device_id_reason} />
                <Fact label="EDR association"
                      value={<StateChip value={d.edr_association} />}
                      reason={d.edr_association_reason} />
                <Fact label="Collector host(s)" value={<Tags values={d.collector_hosts} />}
                      reason={d.collector_host_note} />
                <Fact label="OS" value={d.os} reason={d.os_reason} />
              </div>
            </Section>

            <Section title="Aliases · the seam for stronger identifiers"
                     note={d.aliases?.note} testid="wx-device-aliases">
              <table className="wx-kv">
                <tbody>
                  {Object.entries(d.aliases || {})
                    .filter(([k]) => k !== "note")
                    .map(([k, v]) => (
                      <tr key={k}>
                        <td>{k}</td>
                        <td>{Array.isArray(v)
                          ? (v.length ? v.join(", ") : <span className="wx-dim">—</span>)
                          : (v || <span className="wx-dim">NOT AVAILABLE</span>)}</td>
                      </tr>))}
                </tbody>
              </table>
            </Section>

            <Section title="Collection" testid="wx-device-collection">
              <div className="wx-facts">
                <Fact label="Collection state" value={<StateChip value={d.collection_state} />} />
                <Fact label="Last telemetry" value={d.last_telemetry_at} />
                <Fact label="Events delivered" value={measured(d.events_delivered)} />
                <Fact label="Evidence coverage" value={d.evidence_coverage} />
                <Fact label="Profile" value={<Tags values={d.profiles} />} />
                <Fact label="Profile version" value={<Tags values={d.profile_versions} />} />
                <Fact label="Parser version" value={<Tags values={d.parser_versions} />} />
                <Fact label="Collectors" value={<Tags values={d.collectors} />} />
              </div>
            </Section>

            <Section title="Channel matrix" testid="wx-device-matrix">
              <table className="wx-kv">
                <tbody>
                  {matrix.map((c) => (
                    <tr key={c.channel}>
                      <td>{c.channel}</td>
                      <td>
                        <StateChip value={c.collection.state} />{" "}
                        <StateChip value={c.normalization.state} />{" "}
                        <StateChip value={c.detection_capability.state} />
                      </td>
                    </tr>))}
                </tbody>
              </table>
            </Section>

            <button type="button" className="wx-btn"
                    data-testid="wx-device-pivot-events"
                    onClick={() => onPivotEvents && onPivotEvents(d.evidence_origin)}>
              Open host in Event Explorer
            </button>
          </>
        )}
      </div>
    </NxFlyout>
  );
}

export default function WindowsDevices({ devices, loading, error, onRefresh,
                                         onPivotEvents }) {
  const [origin, setOrigin] = useState(null);
  const columns = [
    { key: "origin", label: "Device (event origin)",
      value: (r) => r.evidence_origin,
      render: (r) => (
        <span>
          <strong>{r.evidence_origin}</strong>
          <div className="wx-dim">identity: {r.identity_state}</div>
        </span>) },
    { key: "os", label: "OS", value: (r) => r.os || "",
      render: (r) => (r.os || <span className="wx-dim">—</span>) },
    { key: "collector", label: "Collector",
      value: (r) => (r.collectors || []).join(","),
      render: (r) => <Tags values={r.collectors} /> },
    { key: "profile", label: "Profile",
      value: (r) => (r.profiles || []).join(","),
      render: (r) => <Tags values={r.profiles} /> },
    { key: "collection", label: "Collection",
      value: (r) => r.collection_state,
      render: (r) => <StateChip value={r.collection_state} /> },
    { key: "last", label: "Last telemetry", value: (r) => r.last_telemetry_at,
      render: (r) => <span className="wx-mono">{r.last_telemetry_at || "—"}</span> },
    { key: "channels", label: "Channels receiving",
      value: (r) => (r.channels_observed || []).length,
      render: (r) => `${(r.channels_observed || []).length}` },
    { key: "coverage", label: "Evidence coverage",
      value: (r) => r.evidence_coverage || "",
      render: (r) => (r.evidence_coverage || <span className="wx-dim">—</span>) },
    { key: "gaps", label: "Gaps", value: (r) => (r.gaps || []).length,
      render: (r) => ((r.gaps || []).length
        ? <StateChip value="GAP DETECTED" /> : <span className="wx-dim">—</span>) },
    { key: "edr", label: "EDR", value: (r) => r.edr_association,
      render: (r) => <StateChip value={r.edr_association} title={r.edr_association_reason} /> },
    { key: "attention", label: "Attention",
      value: (r) => (r.attention || []).length,
      render: (r) => ((r.attention || []).length
        ? <span className="wx-attn">{r.attention.join(" · ")}</span>
        : <span className="wx-dim">—</span>) },
  ];

  return (
    <>
      <NxDataTable columns={columns} rows={devices || []} loading={loading}
                   error={error} onRefresh={onRefresh}
                   rowKey={(r) => r.evidence_origin}
                   searchPlaceholder="Search device, collector, profile"
                   onRowClick={(r) => setOrigin(r.evidence_origin)}
                   emptyTitle="No Windows event origin has delivered telemetry"
                   emptyHint="A device appears here only when an authenticated delivery asserted it as the origin — nothing is pre-populated"
                   testid="wx-devices-table" />
      <DevicePane origin={origin} onClose={() => setOrigin(null)}
                  onPivotEvents={onPivotEvents} />
    </>
  );
}
