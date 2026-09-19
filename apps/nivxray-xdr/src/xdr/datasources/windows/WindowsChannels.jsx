/**
 * Windows console · Channels tab + the contextual channel pane.
 *
 * The table shows the five dimensions side by side, and the pane exposes
 * every fact each one stands on. Nothing here merges two dimensions, and
 * a missing measurement renders `—`, never `0`.
 */
import React, { useState } from "react";
import { NxDataTable, NxFlyout } from "@/xdr/nx";
import { Fact, Section, StageBar, StateChip } from "./WindowsPrimitives";
import { measured } from "./windowsApi";

const Tags = ({ values = [], empty = "—" }) => (
  values.length
    ? <span className="wx-tags">
        {values.slice(0, 12).map((v) => (
          <span className="wx-tag" key={String(v)}>{String(v)}</span>))}
        {values.length > 12 && <span className="wx-dim">+{values.length - 12}</span>}
      </span>
    : <span className="wx-dim">{empty}</span>
);

export function ChannelPane({ row, onClose, onPivotEvents }) {
  if (!row) return null;
  const c = row.collection, p = row.parsing, n = row.normalization;
  const cap = row.detection_capability, act = row.detection_activity;
  return (
    <NxFlyout open title={row.label} eyebrow={row.channel} onClose={onClose}
              width={720} testid="wx-channel-pane">
      <div className="wx-pane">
        <StageBar stages={row.summary_stages || []} testid="wx-pane-stages" />
        {row.attention?.length > 0 && (
          <div className="wx-attn" data-testid="wx-pane-attention">
            ATTENTION · {row.attention.join(" · ")}
          </div>
        )}

        <Section title="Collection" note={c.reason} testid="wx-pane-collection">
          <div className="wx-facts">
            <Fact label="Collection state" value={<StateChip value={c.state} />} />
            <Fact label="Last telemetry" value={c.last_event_at}
                  reason={c.last_event_at ? null
                    : "no delivery of this channel has been observed"} />
            <Fact label="Events delivered" value={measured(c.events_delivered)} />
            <Fact label="Newest source timestamp" value={c.last_source_timestamp} />
            <Fact label="Authorized collectors" value={<Tags values={c.authorized_collectors || []} />} />
            <Fact label="Collectors observed" value={<Tags values={c.collectors_observed || []} />} />
            <Fact label="Collection gap" value={c.gap ? c.gap.state : null}
                  reason={c.gap?.note} />
            <Fact label="Bookmark / checkpoint"
                  value={<StateChip value={c.bookmark?.state} />}
                  reason={c.bookmark?.reason} />
            <Fact label="Providers observed" value={<Tags values={row.providers} />} />
            <Fact label="Event IDs observed" value={<Tags values={row.event_ids_observed} />} />
            <Fact label="Devices" value={<Tags values={row.devices} />} />
            <Fact label="Profile" value={<Tags values={row.profiles} />} />
          </div>
        </Section>

        <Section title="Parsing" note={p.note} testid="wx-pane-parsing">
          <div className="wx-facts">
            <Fact label="Declared support" value={<StateChip value={p.state} />} />
            <Fact label="Measured" value={<StateChip value={p.measured_state} />} />
            <Fact label="Parsed OK" value={measured(p.measured?.ok)} />
            <Fact label="Parse failures" value={measured(p.measured?.failed)} />
            <Fact label="Unmeasured" value={measured(p.measured?.unmeasured)} />
            <Fact label="DSM" value={row.dsm_id}
                  reason={row.dsm_id ? null : "no DSM parses this channel yet"} />
          </div>
        </Section>

        <Section title="Normalization · canonical evidence" note={n.note}
                 testid="wx-pane-normalization">
          <div className="wx-facts">
            <Fact label="Declared support" value={<StateChip value={n.state} />} />
            <Fact label="Measured" value={<StateChip value={n.measured_state} />} />
            <Fact label="Canonical events" value={measured(row.canonical_events)} />
            <Fact label="Canonical event types" value={<Tags values={row.canonical_event_types} />} />
            <Fact label="Producing DSMs" value={<Tags values={row.evidence_dsm_ids} />} />
            <Fact label="Roadmap position" value={row.roadmap_position}
                  reason={row.roadmap_position ? "position in the declared Windows DSM roadmap" : null} />
          </div>
        </Section>

        <Section title="Detection capability" note={cap.basis}
                 testid="wx-pane-capability">
          <div className="wx-facts">
            <Fact label="Capability" value={<StateChip value={cap.state} />} />
            <Fact label="Content state" value={cap.content_state} />
            <Fact label="Fully eligible rules" value={measured(cap.eligible_rule_count)} />
            <Fact label="Partially eligible rules" value={measured(cap.partially_eligible_rule_count)} />
            <Fact label="Evidence this channel provides" value={<Tags values={cap.provides} />} />
          </div>
          {cap.eligible_rules?.length > 0 && (
            <table className="wx-kv" data-testid="wx-pane-eligible-rules">
              <tbody>
                {cap.eligible_rules.map((r) => (
                  <tr key={r.rule_id}>
                    <td>{r.technique_id || "—"}</td>
                    <td>{r.name}</td>
                  </tr>))}
              </tbody>
            </table>
          )}
          <p className="wx-section-note">{cap.independence_note}</p>
        </Section>

        <Section title="Detection activity" note={act.reason}
                 testid="wx-pane-activity">
          <div className="wx-facts">
            <Fact label="Detections fired" value={measured(act.detections_fired)} />
            <Fact label="Rules exercised" value={measured(act.rules_exercised)} />
            <Fact label="Last detection" value={act.last_detection_at} />
            <Fact label="Evidence references" value={<Tags values={act.evidence_refs || []} />} />
          </div>
        </Section>

        <button type="button" className="wx-btn" data-testid="wx-pane-pivot-events"
                onClick={() => onPivotEvents && onPivotEvents(row.channel)}>
          Open in Event Explorer
        </button>
      </div>
    </NxFlyout>
  );
}

export default function WindowsChannels({ channels, loading, error, onRefresh,
                                          onPivotEvents }) {
  const [selected, setSelected] = useState(null);
  const columns = [
    { key: "label", label: "Channel", value: (r) => r.label,
      render: (r) => (
        <span title={r.channel}>
          <strong>{r.label}</strong>
          <div className="wx-dim wx-mono">{r.channel}</div>
        </span>) },
    { key: "devices", label: "Device(s)", value: (r) => r.devices.length,
      render: (r) => (r.devices.length
        ? <span title={r.devices.join(", ")}>{r.devices.length}</span>
        : <span className="wx-dim">—</span>) },
    { key: "collection", label: "Collection",
      value: (r) => r.collection.state,
      render: (r) => <StateChip value={r.collection.state} title={r.collection.reason} /> },
    { key: "last", label: "Last event",
      value: (r) => r.collection.last_event_at || "",
      render: (r) => (r.collection.last_event_at
        ? <span className="wx-mono">{r.collection.last_event_at}</span>
        : <span className="wx-dim">—</span>) },
    { key: "events", label: "Events",
      value: (r) => r.collection.events_delivered ?? -1,
      render: (r) => measured(r.collection.events_delivered) },
    { key: "parsing", label: "Parsing", value: (r) => r.parsing.state,
      render: (r) => <StateChip value={r.parsing.state} title={r.parsing.note || ""} /> },
    { key: "normalization", label: "Normalization",
      value: (r) => r.normalization.state,
      render: (r) => <StateChip value={r.normalization.state} /> },
    { key: "capability", label: "Detection",
      value: (r) => r.detection_capability.state,
      render: (r) => (
        <span title={r.detection_capability.basis}>
          <StateChip value={r.detection_capability.state} />
          <div className="wx-dim">fired {measured(r.detection_activity.detections_fired)}</div>
        </span>) },
    { key: "gap", label: "Gap", value: (r) => (r.collection.gap ? 1 : 0),
      render: (r) => (r.collection.gap
        ? <StateChip value="GAP DETECTED" title={r.collection.gap.note} />
        : <span className="wx-dim">—</span>) },
    { key: "attention", label: "Attention",
      value: (r) => r.attention.length,
      render: (r) => (r.attention.length
        ? <span className="wx-attn">{r.attention.join(" · ")}</span>
        : <span className="wx-dim">—</span>) },
  ];

  return (
    <>
      <NxDataTable columns={columns} rows={channels || []} loading={loading}
                   error={error} onRefresh={onRefresh} pageSize={25}
                   rowKey={(r) => r.channel}
                   searchPlaceholder="Search channel, provider, DSM"
                   onRowClick={(r) => setSelected(r)}
                   emptyTitle="No Windows channel is declared"
                   emptyHint="The channel contract is published by /api/xdr/windows/configuration"
                   testid="wx-channels-table" />
      <ChannelPane row={selected} onClose={() => setSelected(null)}
                   onPivotEvents={onPivotEvents} />
    </>
  );
}
