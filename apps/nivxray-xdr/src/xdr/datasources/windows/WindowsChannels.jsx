/**
 * Windows console · Channels tab + the contextual channel pane.
 *
 * The table shows the five dimensions side by side, and the pane exposes
 * every fact each one stands on. Nothing here merges two dimensions, and
 * a missing measurement renders `—`, never `0`.
 */
import React, { useEffect, useState } from "react";
import { NxDataTable, NxFlyout } from "@/xdr/nx";
import { Fact, Section, StageBar, StateChip } from "./WindowsPrimitives";
import { measured } from "./windowsApi";

const Tags = ({ values = [], empty = "—" }) => (
  values.length
    ? <span className="nx-tokens">
        {values.slice(0, 12).map((v) => (
          <span className="nx-token" key={String(v)}>{String(v)}</span>))}
        {values.length > 12 && <span className="nx-absent">+{values.length - 12}</span>}
      </span>
    : <span className="nx-absent">{empty}</span>
);

export function ChannelPane({ row, onClose, onPivotEvents }) {
  if (!row) return null;
  const c = row.collection, p = row.parsing, n = row.normalization;
  const cap = row.detection_capability, act = row.detection_activity;
  return (
    <NxFlyout open title={row.label} eyebrow={row.channel} onClose={onClose}
              width={720} testid="wx-channel-pane">
      <div className="wx-stack">
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

        <Section title="Coverage · potential vs effective"
                 note={row.coverage?.effective?.basis_note}
                 testid="wx-pane-coverage">
          <div className="wx-facts">
            <Fact label="Potential coverage"
                  value={`${measured(row.coverage?.potential?.rule_count)} rule(s)`}
                  reason={row.coverage?.potential?.basis} />
            <Fact label="Effective coverage"
                  value={<StateChip value={row.coverage?.effective?.state} />}
                  reason={row.coverage?.effective?.basis} />
            <Fact label="Required fields"
                  value={<StateChip value={row.coverage?.required_fields?.state} />}
                  reason={row.coverage?.required_fields?.note} />
            <Fact label="Fields measured"
                  value={`${(row.coverage?.required_fields?.measured || []).length} of ${(row.coverage?.required_fields?.declared || []).length}`} />
            <Fact label="Blocked rules" value={measured(row.coverage?.blocked?.rule_count)} />
            <Fact label="ATT&CK techniques" value={measured((row.coverage?.attack || []).length)} />
          </div>
          {row.coverage?.evidence_gaps?.length > 0 && (
            <div className="wx-attn">
              EVIDENCE GAPS · {row.coverage.evidence_gaps.join(" · ")}
            </div>)}
          {row.coverage?.content_gaps?.length > 0 && (
            <p className="nx-sec-note">
              content gaps: {row.coverage.content_gaps.join(" · ")} — a rule
              citing a field this channel does not carry is a
              content-authoring fact, not an onboarding failure
            </p>)}
          <NxDataTable rows={row.coverage?.prerequisites || []}
                       rowKey={(p) => p.prerequisite} searchable={false}
                       pageSize={50} testid="wx-pane-prereqs"
                       emptyTitle="No prerequisite is declared"
                       columns={[
            { key: "prerequisite", header: "Prerequisite", width: "220px",
              render: (p) => <span className="nx-mono">{p.prerequisite}</span> },
            { key: "state", header: "State", width: "150px",
              render: (p) => <StateChip value={p.state} title={p.detail} /> },
            { key: "blocker", header: "Blocker",
              render: (p) => (p.blocker
                ? <span>{p.blocker}</span>
                : <span className="nx-absent">—</span>) },
          ]} />
        </Section>

        <Section title="Detection content applicable to this channel"
                 note={cap.basis}
                 testid="wx-pane-capability">
          <div className="wx-facts">
            <Fact label="Content state" value={cap.content_state} />
            <Fact label="Fully eligible rules" value={measured(cap.eligible_rule_count)} />
            <Fact label="Partially eligible rules" value={measured(cap.partially_eligible_rule_count)} />
            <Fact label="Evidence this channel provides" value={<Tags values={cap.provides} />} />
          </div>
          {cap.eligible_rules?.length > 0 && (
            <NxDataTable rows={cap.eligible_rules} rowKey={(r) => r.rule_id}
                         searchable={false} pageSize={25}
                         testid="wx-pane-eligible-rules"
                         emptyTitle="No rule is fully eligible on this channel"
                         columns={[
              { key: "technique_id", header: "ATT&CK", width: "120px",
                render: (r) => (r.technique_id
                  ? <span className="nx-mono">{r.technique_id}</span>
                  : <span className="nx-absent">—</span>) },
              { key: "name", header: "Detection rule",
                render: (r) => r.name },
            ]} />
          )}
          <p className="nx-sec-note">{cap.independence_note}</p>
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

        <button type="button" className="nx-btn nx-btn--primary" data-testid="wx-pane-pivot-events"
                onClick={() => onPivotEvents && onPivotEvents(row.channel)}>
          Open in Event Explorer
        </button>
      </div>
    </NxFlyout>
  );
}

export default function WindowsChannels({ channels, loading, error, onRefresh,
                                          initialChannel = null,
                                          onPivotEvents }) {
  const [selected, setSelected] = useState(null);
  // Arriving from a grouped blocker on Overview opens that channel's pane.
  useEffect(() => {
    if (!initialChannel) return;
    const hit = (channels || []).find((c) => c.channel === initialChannel);
    if (hit) setSelected(hit);
  }, [initialChannel, channels]);
  const columns = [
    { key: "label", header: "Channel", value: (r) => r.label,
      render: (r) => (
        <span title={r.channel}>
          <strong>{r.label}</strong>
          <div className="nx-absent nx-mono">{r.channel}</div>
        </span>) },
    { key: "devices", header: "Device(s)", value: (r) => r.devices.length,
      render: (r) => (r.devices.length
        ? <span title={r.devices.join(", ")}>{r.devices.length}</span>
        : <span className="nx-absent">—</span>) },
    { key: "collection", header: "Collection",
      value: (r) => r.collection.state,
      render: (r) => <StateChip value={r.collection.state} title={r.collection.reason} /> },
    { key: "last", header: "Last event",
      value: (r) => r.collection.last_event_at || "",
      render: (r) => (r.collection.last_event_at
        ? <span className="nx-mono">{r.collection.last_event_at}</span>
        : <span className="nx-absent">—</span>) },
    { key: "events", header: "Events",
      value: (r) => r.collection.events_delivered ?? -1,
      render: (r) => measured(r.collection.events_delivered) },
    { key: "parsing", header: "Parsing", value: (r) => r.parsing.state,
      render: (r) => <StateChip value={r.parsing.state} title={r.parsing.note || ""} /> },
    { key: "normalization", header: "Normalization",
      value: (r) => r.normalization.state,
      render: (r) => <StateChip value={r.normalization.state} /> },
    { key: "capability", header: "Coverage",
      value: (r) => r.coverage?.effective?.state || "",
      render: (r) => (
        <span title={r.coverage?.effective?.basis}>
          <StateChip value={r.coverage?.effective?.state} />
          <div className="nx-absent">
            potential {measured(r.coverage?.potential?.rule_count)} ·{" "}
            fired {measured(r.detection_activity.detections_fired)}
          </div>
        </span>) },
    { key: "gap", header: "Gap", value: (r) => (r.collection.gap ? 1 : 0),
      render: (r) => (r.collection.gap
        ? <StateChip value="GAP DETECTED" title={r.collection.gap.note} />
        : <span className="nx-absent">—</span>) },
    { key: "attention", header: "Attention",
      value: (r) => r.attention.length,
      render: (r) => (r.attention.length
        ? <span className="wx-attn">{r.attention.join(" · ")}</span>
        : <span className="nx-absent">—</span>) },
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
