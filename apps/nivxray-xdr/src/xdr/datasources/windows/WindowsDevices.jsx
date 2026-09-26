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
    ? <span className="nx-tokens">
        {values.map((v) => <span className="nx-token" key={String(v)}>{String(v)}</span>)}
      </span>
    : <span className="nx-absent">—</span>
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
      <div className="wx-stack">
        {state.loading && <p className="nx-absent">loading…</p>}
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
              <NxDataTable searchable={false} pageSize={50}
                           testid="wx-device-aliases-table"
                           rowKey={(r) => r.alias}
                           emptyTitle="No stronger identifier has been asserted"
                           rows={Object.entries(d.aliases || {})
                             .filter(([k]) => k !== "note")
                             .map(([k, v]) => ({ alias: k, value: v }))}
                           columns={[
                { key: "alias", header: "Identifier", width: "200px",
                  render: (r) => <span className="nx-mono">{r.alias}</span> },
                { key: "value", header: "Value",
                  render: (r) => (Array.isArray(r.value)
                    ? (r.value.length
                      ? <Tags values={r.value} />
                      : <span className="nx-absent">—</span>)
                    : (r.value
                      || <span className="nx-absent">Not available</span>)) },
              ]} />
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
              <NxDataTable rows={matrix} rowKey={(c) => c.channel}
                           searchable={false} pageSize={30}
                           testid="wx-device-matrix-table"
                           emptyTitle="No channel has been observed on this device"
                           columns={[
                { key: "channel", header: "Channel", width: "230px",
                  render: (c) => <span className="nx-mono">{c.channel}</span> },
                { key: "collection", header: "Collection", width: "140px",
                  render: (c) => <StateChip value={c.collection.state} /> },
                { key: "normalization", header: "Evidence", width: "140px",
                  render: (c) => <StateChip value={c.normalization.state} /> },
                { key: "capability", header: "Detection capability",
                  render: (c) => (
                    <StateChip value={c.detection_capability.state} />) },
              ]} />
            </Section>

            <button type="button" className="nx-btn nx-btn--primary"
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
                                         initialOrigin = null,
                                         onPivotEvents }) {
  const [origin, setOrigin] = useState(initialOrigin);
  useEffect(() => { if (initialOrigin) setOrigin(initialOrigin); },
            [initialOrigin]);
  const columns = [
    { key: "origin", header: "Device (event origin)",
      value: (r) => r.evidence_origin,
      render: (r) => (
        <span>
          <strong>{r.evidence_origin}</strong>
          <div className="nx-absent">identity: {r.identity_state}</div>
        </span>) },
    { key: "os", header: "OS", value: (r) => r.os || "",
      render: (r) => (r.os || <span className="nx-absent">—</span>) },
    { key: "collector", header: "Collector",
      value: (r) => (r.collectors || []).join(","),
      render: (r) => <Tags values={r.collectors} /> },
    { key: "profile", header: "Profile",
      value: (r) => (r.profiles || []).join(","),
      render: (r) => <Tags values={r.profiles} /> },
    { key: "collection", header: "Collection",
      value: (r) => r.collection_state,
      render: (r) => <StateChip value={r.collection_state} /> },
    { key: "last", header: "Last telemetry", value: (r) => r.last_telemetry_at,
      render: (r) => <span className="nx-mono">{r.last_telemetry_at || "—"}</span> },
    { key: "channels", header: "Channels receiving",
      value: (r) => (r.channels_observed || []).length,
      render: (r) => `${(r.channels_observed || []).length}` },
    { key: "coverage", header: "Evidence coverage",
      value: (r) => r.evidence_coverage || "",
      render: (r) => (r.evidence_coverage || <span className="nx-absent">—</span>) },
    { key: "gaps", header: "Gaps", value: (r) => (r.gaps || []).length,
      render: (r) => ((r.gaps || []).length
        ? <StateChip value="GAP DETECTED" /> : <span className="nx-absent">—</span>) },
    { key: "edr", header: "EDR", value: (r) => r.edr_association,
      render: (r) => <StateChip value={r.edr_association} title={r.edr_association_reason} /> },
    { key: "attention", header: "Attention",
      value: (r) => (r.attention || []).length,
      render: (r) => ((r.attention || []).length
        ? <span className="wx-attn">{r.attention.join(" · ")}</span>
        : <span className="nx-absent">—</span>) },
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
