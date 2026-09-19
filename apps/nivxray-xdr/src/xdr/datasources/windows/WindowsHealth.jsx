/**
 * Windows · Health.
 *
 * Exceptions first. The page answers five operational questions and
 * nothing else: what is degraded, where, since when, what it affects, and
 * what action is required. The backend's reason chain is preserved, but it
 * is not the primary UI — it sits in the contextual pane and in Technical
 * details.
 */
import React, { useMemo, useState } from "react";
import { NxDataTable, NxFlyout, NxKeyFact, NxFacts, NxMetricStrip, NxRaw,
         NxSection, NxState, NxTechnical, NxTokenList,
         measured } from "@/xdr/nx";

/** One row per measured EXCEPTION, derived only from server state. */
function conditions(channels) {
  const rows = [];
  for (const c of channels) {
    const items = [...(c.attention || [])];
    if (c.collection?.gap) items.push(c.collection.gap.state || "GAP_DETECTED");
    if (!items.length) continue;
    for (const condition of items) {
      rows.push({
        id: `${c.channel}::${condition}`,
        channel: c.channel,
        component: c.label,
        condition,
        since: c.collection?.last_event_at || null,
        devices: c.devices || [],
        last_telemetry: c.collection?.last_event_at || null,
        impact_state: c.coverage?.effective?.state,
        impact: c.coverage?.potential?.rule_count,
        reason: c.collection?.reason || c.coverage?.effective?.basis,
        row: c,
      });
    }
  }
  return rows;
}

function HealthPane({ row, onClose, onPivotEvents }) {
  if (!row) return null;
  const c = row.row;
  return (
    <NxFlyout open title={row.component} eyebrow={row.condition}
              onClose={onClose} width={680} testid="wx-health-pane"
              footer={
                <button type="button" className="nx-btn nx-btn--primary"
                        data-testid="wx-health-pivot-events"
                        onClick={() => onPivotEvents && onPivotEvents(c.channel)}>
                  Open channel in Event Explorer
                </button>}>
      <NxSection title="Condition" note={row.reason}>
        <NxFacts>
          <NxKeyFact label="Condition" value={<NxState value={row.condition} />} />
          <NxKeyFact label="Collection state"
                     value={<NxState value={c.collection?.state} />}
                     reason={c.collection?.reason} />
          <NxKeyFact label="Since / last telemetry" value={row.since} mono
                     reason={row.since ? null
                       : "no delivery of this channel has ever been observed"} />
          <NxKeyFact label="Events delivered"
                     value={measured(c.collection?.events_delivered)} mono />
          <NxKeyFact label="Devices affected"
                     value={<NxTokenList values={row.devices} limit={6} />} />
          <NxKeyFact label="Channel" value={c.channel} mono />
        </NxFacts>
      </NxSection>

      <NxSection title="What it affects"
                 note="Impact is stated as coverage, never as a score.">
        <NxFacts>
          <NxKeyFact label="Effective coverage"
                     value={<NxState value={c.coverage?.effective?.state} />}
                     reason={c.coverage?.effective?.basis} />
          <NxKeyFact label="Potential rules"
                     value={measured(c.coverage?.potential?.rule_count)} mono />
          <NxKeyFact label="Blocked rules"
                     value={measured(c.coverage?.blocked?.rule_count)} mono />
          <NxKeyFact label="Evidence gaps"
                     value={<NxTokenList values={c.coverage?.evidence_gaps}
                                         limit={6} />} />
        </NxFacts>
      </NxSection>

      <NxTechnical title="Technical details · backend reason chain">
        <NxRaw>{JSON.stringify({
          collection: c.collection, parsing: c.parsing,
          normalization: c.normalization,
          detection_capability: c.detection_capability,
          detection_activity: c.detection_activity,
        }, null, 2)}</NxRaw>
      </NxTechnical>
    </NxFlyout>
  );
}

export default function WindowsHealth({ channels = [], loading, error,
                                        onRefresh, onPivotEvents }) {
  const [selected, setSelected] = useState(null);
  const rows = useMemo(() => conditions(channels), [channels]);
  const receiving = channels.filter(
    (c) => c.collection?.state === "RECEIVING").length;
  const gaps = channels.filter((c) => c.collection?.gap).length;

  return (
    <div className="wx-stack" data-testid="wx-health">
      <NxMetricStrip testid="wx-health-metrics" items={[
        { label: "Channels declared", value: channels.length },
        { label: "Receiving", value: receiving },
        { label: "Collection gaps", value: gaps },
        { label: "Open conditions", value: rows.length },
      ]} />

      <NxSection variant="card" title="Operational exceptions"
                 note="Only measured conditions appear here. A channel with
                       nothing measured is not silently reported as healthy —
                       and no composite health verdict is published."
                 testid="wx-health-exceptions">
        <NxDataTable rows={rows} loading={loading} error={error}
                     onRefresh={onRefresh} rowKey={(r) => r.id}
                     onRowClick={setSelected} pageSize={25}
                     searchPlaceholder="Search component, condition, device"
                     emptyTitle="No condition is reported for any Windows channel"
                     emptyHint="This is a statement about measurements taken,
                                not a claim that every endpoint is healthy"
                     testid="wx-health-table"
                     columns={[
        { key: "component", header: "Component", width: "220px",
          render: (r) => (
            <span title={r.channel}>
              <strong>{r.component}</strong>
              <div className="nx-absent nx-mono">{r.channel}</div>
            </span>) },
        { key: "devices", header: "Devices", width: "170px",
          value: (r) => r.devices.length,
          render: (r) => (r.devices.length
            ? <NxTokenList values={r.devices} limit={2} />
            : <span className="nx-absent">—</span>) },
        { key: "condition", header: "Condition", width: "220px",
          render: (r) => <NxState value={r.condition} reason={r.reason} /> },
        { key: "since", header: "Since", width: "180px",
          value: (r) => r.since || "",
          render: (r) => (r.since
            ? <span className="nx-mono">{r.since}</span>
            : <span className="nx-absent">never observed</span>) },
        { key: "impact", header: "Impact", width: "200px",
          value: (r) => r.impact_state || "",
          render: (r) => (
            <span>
              <NxState value={r.impact_state} />
              <div className="nx-absent">
                {measured(r.impact)} potential rule(s)
              </div>
            </span>) },
        { key: "action", header: "Action required",
          value: (r) => r.reason || "",
          render: (r) => (r.reason
            ? <span>{r.reason}</span>
            : <span className="nx-absent">—</span>) },
      ]} />
      </NxSection>

      <HealthPane row={selected} onClose={() => setSelected(null)}
                  onPivotEvents={onPivotEvents} />
    </div>
  );
}
