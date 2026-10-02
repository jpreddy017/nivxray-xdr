import React from "react";
import { PAL, approvalText, basename, cannotTell, fmtInstant, fmtLateness, semanticOf } from "./model";
import { GlyphIcon } from "./Glyphs";
import { ui } from "./ui";

function Sec({ id, title, children }) {
  return (
    <section data-testid={`details-${id}`} style={{ borderTop: `1px solid ${PAL.grid}`, padding: "10px 0" }}>
      <h4 style={{ ...ui.h4, margin: "0 0 6px" }}>{title}</h4>{children}
    </section>
  );
}
const F = ({ k, v, mono }) => (
  <div style={{ display: "grid", gridTemplateColumns: "112px 1fr", gap: 8, padding: "2px 0", fontSize: 12 }}>
    <span style={{ color: PAL.muted }}>{k}</span><span style={mono ? ui.mono : { wordBreak: "break-word" }}>{v ?? <em style={{ color: PAL.faint }}>not in evidence</em>}</span>
  </div>
);
const Chip = ({ state, evidence, testid }) => {
  const s = semanticOf(state, evidence);
  return <span data-testid={testid} title={s.label} style={{ ...ui.chip, border: `1px solid ${s.color}`, color: s.color }}>{state}</span>;
};
const Both = ({ ms }) => <>{fmtInstant(ms, "UTC")}<br /><span style={{ color: PAL.muted }}>{fmtInstant(ms, "LOCAL")}</span></>;

function Identity({ lane, event }) {
  const p = event?.process || {};
  return (
    <Sec id="identity" title="Identity">
      {event && <F k="Event kind" v={event.kind} />}
      <F k="Row type" v={lane.lane_type} />
      {lane.lane_type !== "FILE" && <>
        <F k="Process key" v={event?.process_key || (lane.lane_type === "PROCESS" ? lane.lane_id : null)} mono />
        <F k="PID" v={p.pid ?? lane.pid} />
        <F k="Start time" v={p.start_time || (lane.span?.from_ms != null ? fmtInstant(lane.span.from_ms) : null)} />
        <F k="Parent" v={lane.parent_lane || event?.parent_key || "not observed"} mono />
        <F k="Causal state" v={lane.causal_state ? `${lane.causal_state}${lane.causal_basis ? ` · ${lane.causal_basis}` : ""}` : null} />
        <F k="Identity state" v={lane.identity_state || event?.process_identity} />
        <F k="Image path" v={p.image || lane.image} mono />
        <F k="Command line" v={p.command_line || lane.command_line} mono />
        <F k="User" v={p.user || lane.user} />
        <F k="SHA-256" v={p.sha256 || lane.sha256} mono />
        {lane.parent_spoof?.suspected && <F k="Spoof flag" v={`SUSPECTED, UNVERIFIED · reported ${basename(lane.parent_spoof.reported_parent?.image)} vs creator ${basename(lane.parent_spoof.creator?.image)} (${lane.parent_spoof.basis})`} />}
      </>}
      {(lane.lane_type === "FILE" || event?.file?.path) && <>
        <F k="File path" v={event?.file?.path || lane.label} mono />
        {event?.file?.previous_path && <F k="Previous path" v={event.file.previous_path} mono />}
        <F k="File SHA-256" v={event?.file?.sha256 || lane.sha256} mono />
        {lane.touched_by && <F k="Touched by" v={lane.touched_by.join(", ")} mono />}
      </>}
      {event?.network?.dest_ip && <F k="Network" v={`${event.network.protocol || ""} → ${event.network.dest_ip}:${event.network.dest_port ?? "?"}`} mono />}
      {event?.network?.query && <F k="DNS query" v={event.network.query} mono />}
      {event && <F k="Sensor severity" v={`${event.severity} (not a verdict)`} />}
    </Sec>
  );
}

function Verdicts({ event, sha, fileStatus }) {
  return <>
    <Sec id="detection" title="Detection">
      {event?.detection
        ? <div><Chip state="MATCH" testid="detection-state" /> <span style={ui.mono}>{event.detection.rule}</span> · {event.detection.engine} · {event.detection.at}</div>
        : <div><Chip state={fileStatus?.detection_state || "NO_DETECTION"} testid="detection-state" /></div>}
      {(fileStatus?.detections || []).map((d) => <F key={d.detection_id} k={d.detection_id} v={`${d.rule} · ${d.engine} · ${d.at} · is_verdict=${String(d.is_verdict)}`} />)}
      <div style={{ fontSize: 11, color: PAL.muted, marginTop: 4 }}>A detection is not a malicious verdict.</div>
    </Sec>
    <Sec id="reputation" title="Reputation (TI)">
      {!sha && <div style={{ fontSize: 12, color: PAL.muted }}>No hash in evidence: reputation cannot be looked up.</div>}
      {(fileStatus?.reputation || []).map((r, k) => (
        <div key={k} style={{ fontSize: 12, padding: "2px 0" }}>
          <Chip state={r.state} evidence={r.evidence} testid={`reputation-state-${k}`} /> provider <b>{r.provider}</b> · {r.assessed_at}
          <div style={{ color: PAL.muted }}>{r.detail}</div>
        </div>
      ))}
    </Sec>
    <Sec id="assessment" title="Assessment">
      {fileStatus?.assessment
        ? <div style={{ fontSize: 12 }}><Chip state={fileStatus.assessment.state} evidence={fileStatus.assessment.evidence} testid="assessment-state" /> {fileStatus.assessment.basis}</div>
        : <div style={{ fontSize: 12, color: PAL.muted }}>UNASSESSED · no assessment recorded for this subject.</div>}
    </Sec>
  </>;
}

export default function DetailsPane({ lane, event, eventId, fileStatus, sha, statusEvents, approvals }) {
  if (!lane) return <aside data-testid="details-pane" style={{ ...ui.panel, padding: 16, color: PAL.muted, fontSize: 13 }}>Select a row or an event marker to see its evidence.</aside>;
  const hist = (statusEvents || []).filter((s) => sha && s.subject === sha);
  const mine = (approvals || []).filter((a) => a.target?.lane_id === lane.lane_id);
  return (
    <aside data-testid="details-pane" style={{ ...ui.panel, padding: "12px 16px", overflowY: "auto", maxHeight: 900 }}>
      <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 6 }}>{basename(event?.process?.image || event?.file?.path || lane.image || lane.label)}</div>
      {eventId && !event && <div data-testid="details-not-loaded" style={{ fontSize: 12, color: PAL.amber }}>Event {eventId} is older than the loaded pages. Use “Load older” to view its full evidence.</div>}
      <Identity lane={lane} event={event} />
      <Verdicts event={event} sha={sha} fileStatus={fileStatus} />
      <Sec id="status-history" title="Status history (append-only)">
        {hist.length === 0 && <div style={{ fontSize: 12, color: PAL.muted }}>No status entries for this subject.</div>}
        {hist.map((s) => (
          <div key={s.status_event_id} data-testid={`status-entry-${s.status_event_id}`} style={{ fontSize: 12, display: "flex", gap: 6, padding: "2px 0" }}>
            <GlyphIcon kind="RETRO" /><span><b>{s.kind}</b> · {s.state} · {s.provenance?.source} {s.provenance?.rule}
              <div style={{ color: PAL.muted }}>Added later at {s.recorded_at}; original event unchanged.</div></span>
          </div>
        ))}
      </Sec>
      <Sec id="approvals" title="Response requests">
        {mine.length === 0 && <div style={{ fontSize: 12, color: PAL.muted }}>None for this row.</div>}
        {mine.map((a) => <div key={a.request_id} style={{ fontSize: 12, display: "flex", gap: 6 }}><GlyphIcon kind="APPROVAL" /><span><b>{a.action}</b> · {a.requested_at}<div style={{ color: PAL.muted }}>{approvalText(a)}</div></span></div>)}
      </Sec>
      {event && (
        <Sec id="times" title="Time">
          <F k="observed_at" v={<Both ms={event.observed_ms} />} />
          <F k="ingested_at" v={<Both ms={event.ingested_ms} />} />
          <F k="Lateness" v={<span style={{ display: "inline-flex", gap: 6 }}>{event.lateness?.late && <GlyphIcon kind="LATE" />}{event.lateness?.state} · {fmtLateness(event.lateness?.lateness_ms)}</span>} />
          <div style={{ fontSize: 11, color: PAL.muted }}>Placement uses observed_at only; ingested_at only explains lateness.</div>
        </Sec>
      )}
      <Sec id="cannot-tell" title="What we cannot tell you">
        <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12 }}>
          {cannotTell({ event, lane, fileStatus }).map((c) => <li key={c.id} data-testid={`cannot-tell-${c.id}`} style={{ padding: "1px 0" }}>{c.text}</li>)}
        </ul>
      </Sec>
      <Sec id="evidence" title="Evidence references">
        <F k="Row id" v={lane.lane_id} mono />
        {event && <><F k="Event id" v={event.event_id} mono /><F k="Store / ref" v={`${event.provenance?.store} / ${event.provenance?.ref}`} mono />
          <F k="Seen in" v={(event.sources || []).join(", ")} mono /><F k="Data label" v={event.provenance?.label} /></>}
      </Sec>
    </aside>
  );
}
