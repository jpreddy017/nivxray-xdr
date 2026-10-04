import React from "react";
import { CONNECTOR, KINDS, PAL, SEMANTIC, SENSOR_GAPS } from "./model";
import { ConnectorIcon, GlyphIcon } from "./Glyphs";
import { ui } from "./ui";

const MARKS = [
  ["MATCH", "Behavioral detection / IOC match (amber). A detection is not a malicious verdict."],
  ["RETRO", "Retrospective status change: added later; the original event is unchanged."],
  ["APPROVAL", "Approval requested (pending). Nothing is executed by E3."],
  ["LATE", "Late event: arrived more than 5 min after observed_at (ingested_at explains the delay)."],
];

function Row({ icon, text, testid }) {
  return <div data-testid={testid} style={{ display: "flex", gap: 8, alignItems: "flex-start", padding: "3px 0" }}>{icon}<span>{text}</span></div>;
}

export default function Legend({ present }) {
  return (
    <section data-testid="trajectory-legend" style={{ ...ui.panel, padding: 14, fontSize: 12, columns: "260px 3", columnGap: 24 }}>
      <h4 style={ui.h4}>Event glyphs</h4>
      {Object.entries(KINDS).map(([k, m]) => (
        <Row key={k} testid={`legend-kind-${k}`} icon={<GlyphIcon kind={k} />}
          text={<>{m.label}{!present.has(k) && <em style={{ color: PAL.muted }}>{m.gap ? ` · not collected by sensor (${m.gap})` : m.note ? ` · ${m.note}` : " · not in this dataset"}</em>}</>} />
      ))}
      {MARKS.map(([k, t]) => <Row key={k} testid={`legend-mark-${k}`} icon={<GlyphIcon kind={k} />} text={t} />)}
      <h4 style={ui.h4}>Parent → child connectors</h4>
      {Object.entries(CONNECTOR).map(([k, c]) => <Row key={k} testid={`legend-connector-${k}`} icon={<ConnectorIcon {...c} />} text={c.label} />)}
      <h4 style={ui.h4}>Colors</h4>
      {Object.values(SEMANTIC).map((s) => (
        <Row key={s.key} testid={`legend-color-${s.key}`} icon={<span style={{ width: 12, height: 12, background: s.color, borderRadius: 2, marginTop: 2 }} />} text={s.label} />
      ))}
      <h4 style={ui.h4}>Rows and time</h4>
      <Row testid="legend-gap" icon={<span style={{ ...ui.hatch, width: 22, height: 12 }} />} text="No telemetry received: delivery gap, not 'no activity'." />
      <Row testid="legend-chevrons" icon={<b style={{ color: PAL.accent }}>‹ ›</b>} text="Row continues before / after the visible window." />
      <Row testid="legend-rows" icon={<i style={{ color: PAL.muted }}>?</i>} text="'Parent not observed' rows are placeholders; the unattributed-network row holds traffic without a process." />
      <h4 style={ui.h4}>Sensor gaps</h4>
      {Object.entries(SENSOR_GAPS).map(([k, t]) => <Row key={k} testid={`legend-gap-${k}`} icon={<code style={ui.code}>{k}</code>} text={t} />)}
    </section>
  );
}
