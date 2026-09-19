/**
 * Windows · Overview.
 *
 * Recomposed, not reskinned: a compact metric strip, then the five
 * INDEPENDENT dimensions, then the operational work — devices needing
 * attention and grouped blockers — then the two statements this platform
 * deliberately refuses to soften (no composite health verdict, no proven
 * real endpoint).
 *
 * There is no composite verdict anywhere on this page. A tenant can be
 * receiving every channel and be able to detect almost none of it, and one
 * green light would hide exactly that.
 */
import React from "react";
import { NxBlockerGroup, NxDataTable, NxDimensionStrip, NxKeyFact, NxFacts,
         NxMetricStrip, NxSection, NxState, NxTokenList,
         measured } from "@/xdr/nx";

/** Group identical attention items so a root cause is stated ONCE. */
function groupBlockers(attention = []) {
  const byItem = new Map();
  for (const a of attention) {
    for (const item of a.items || []) {
      if (!byItem.has(item)) byItem.set(item, []);
      byItem.get(item).push(a.channel);
    }
  }
  return [...byItem.entries()]
    .map(([blocker, targets]) => ({
      blocker,
      targets,
      impact: `${targets.length} channel${targets.length === 1 ? "" : "s"} affected`,
    }))
    .sort((x, y) => y.targets.length - x.targets.length);
}

export default function WindowsOverview({ overview, channels = [],
                                          devices = [], loading,
                                          onOpenChannel, onOpenDevice }) {
  const ov = overview || {};
  const blockers = groupBlockers(ov.attention);
  const needsAttention = devices.filter((d) => (d.attention || []).length
    || (d.gaps || []).length);

  const deviceColumns = [
    { key: "origin", header: "Device", width: "220px",
      value: (r) => r.evidence_origin,
      render: (r) => (
        <span>
          <strong>{r.evidence_origin}</strong>
          <div className="nx-absent">{r.identity_state}</div>
        </span>) },
    { key: "collection", header: "Collection", width: "150px",
      value: (r) => r.collection_state,
      render: (r) => <NxState value={r.collection_state} /> },
    { key: "last", header: "Last telemetry", width: "190px",
      value: (r) => r.last_telemetry_at || "",
      render: (r) => (r.last_telemetry_at
        ? <span className="nx-mono">{r.last_telemetry_at}</span>
        : <span className="nx-absent">—</span>) },
    { key: "coverage", header: "Evidence coverage", width: "140px",
      value: (r) => r.evidence_coverage || "",
      render: (r) => (r.evidence_coverage
        ? <span className="nx-mono">{r.evidence_coverage}</span>
        : <span className="nx-absent">—</span>) },
    { key: "condition", header: "Condition",
      value: (r) => [...(r.attention || []), ...(r.gaps || [])].join(" · "),
      render: (r) => {
        const items = [...(r.attention || []),
                       ...((r.gaps || []).map((g) => g.state || g))];
        return items.length
          ? <NxTokenList values={items} limit={3} />
          : <span className="nx-absent">—</span>;
      } },
  ];

  return (
    <div className="wx-stack" data-testid="wx-overview">
      <NxMetricStrip testid="wx-overview-metrics" items={[
        { label: "Channels declared", value: ov.channels_declared },
        { label: "Devices", value: ov.devices },
        { label: "Collectors", value: ov.collectors },
        { label: "Detections fired", value: ov.detections_fired },
        { label: "Coverage available now", value: ov.coverage?.available_now },
        { label: "Coverage blocked", value: ov.coverage?.blocked },
      ]} />

      <NxSection title="Five independent dimensions" variant="card"
                 note={ov.composite_health_reason}
                 testid="wx-overview-dimensions">
        <NxDimensionStrip testid="wx-dimensions" dimensions={[
          { label: "Collection", counts: ov.collection },
          { label: "Parsing", counts: ov.parsing },
          { label: "Normalization", counts: ov.normalization },
          { label: "Detection capability", counts: ov.detection_capability,
            note: "potential content ≠ effective coverage" },
          { label: "Composite health", state: ov.composite_health,
            reason: ov.composite_health_reason,
            note: "deliberately never published" },
        ]} />
      </NxSection>

      <div className="wx-split">
        <NxSection variant="card"
                   title={`Devices requiring attention · ${needsAttention.length}`}
                   note="A stopped stream is a gap in this platform's
                         visibility — never proof that the endpoint is quiet."
                   testid="wx-overview-attention">
          <NxDataTable columns={deviceColumns} rows={needsAttention}
                       loading={loading} pageSize={10} searchable={false}
                       rowKey={(r) => r.evidence_origin}
                       onRowClick={(r) => onOpenDevice
                         && onOpenDevice(r.evidence_origin)}
                       emptyTitle="No Windows device reports a condition"
                       emptyHint="Devices appear here only when the platform
                                  measured a gap or an unmet prerequisite —
                                  nothing is pre-populated"
                       testid="wx-attention-table" />
        </NxSection>

        <div className="wx-stack">
          <NxSection variant="card" title="Real Windows endpoint proof"
                     note={ov.real_endpoint_proof?.reason}
                     testid="wx-overview-proof">
            <NxState value={ov.real_endpoint_proof?.state}
                     reason={ov.real_endpoint_proof?.reason} size="lg" />
          </NxSection>

          <NxSection variant="card" title="Coverage impact"
                     note={ov.coverage?.note} testid="wx-overview-coverage">
            <NxFacts columns={3}>
              <NxKeyFact label="Available now"
                         value={measured(ov.coverage?.available_now)} mono />
              <NxKeyFact label="Potential"
                         value={measured(ov.coverage?.potential)} mono />
              <NxKeyFact label="Blocked"
                         value={measured(ov.coverage?.blocked)} mono />
            </NxFacts>
          </NxSection>

          <NxSection variant="card" title="Blockers, grouped by root cause"
                     note="The same blocker is stated once, with everything
                           it affects."
                     testid="wx-overview-blockers">
            <NxBlockerGroup blockers={blockers} onSelect={onOpenChannel}
                            emptyLabel="No channel reports a blocker"
                            testid="wx-blockers" />
          </NxSection>
        </div>
      </div>

      <NxSection title="Channel readiness" variant="card"
                 aside={`${channels.length} declared`}
                 testid="wx-overview-readiness">
        <NxDataTable rows={channels} loading={loading} pageSize={10}
                     searchable={false} rowKey={(r) => r.channel}
                     onRowClick={(r) => onOpenChannel && onOpenChannel(r.channel)}
                     emptyTitle="No Windows channel is declared"
                     testid="wx-readiness-table"
                     columns={[
          { key: "label", header: "Channel", width: "230px",
            value: (r) => r.label,
            render: (r) => (
              <span title={r.channel}>
                <strong>{r.label}</strong>
                <div className="nx-absent nx-mono">{r.channel}</div>
              </span>) },
          { key: "collection", header: "Collection", width: "140px",
            value: (r) => r.collection.state,
            render: (r) => <NxState value={r.collection.state}
                                    reason={r.collection.reason} /> },
          { key: "normalization", header: "Normalization", width: "150px",
            value: (r) => r.normalization.state,
            render: (r) => <NxState value={r.normalization.state}
                                    reason={r.normalization.note} /> },
          { key: "effective", header: "Effective coverage", width: "160px",
            value: (r) => r.coverage?.effective?.state || "",
            render: (r) => <NxState value={r.coverage?.effective?.state}
                                    reason={r.coverage?.effective?.basis} /> },
          { key: "potential", header: "Potential rules", width: "120px",
            align: "right",
            value: (r) => r.coverage?.potential?.rule_count ?? -1,
            render: (r) => measured(r.coverage?.potential?.rule_count) },
          { key: "fired", header: "Detections fired", width: "130px",
            align: "right",
            value: (r) => r.detection_activity?.detections_fired ?? -1,
            render: (r) => measured(r.detection_activity?.detections_fired) },
        ]} />
      </NxSection>
    </div>
  );
}
