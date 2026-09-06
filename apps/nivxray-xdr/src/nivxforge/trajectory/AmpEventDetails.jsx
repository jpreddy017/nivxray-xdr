/**
 * Right-hand **Event Details** panel — the Cisco Secure Endpoint /
 * AMP Device Trajectory details pane, in its documented order:
 *
 *   Event Details                                              ×
 *   <timestamp>                                    [severity chip]
 *   Detected <detection name>            ← red, only when detected
 *   <description>
 *   ┌ MITRE | ATT&CK ────────────────────────────────────────┐
 *   │ Tactics …                                              │
 *   │ Techniques …                                           │
 *   └────────────────────────────────────────────────────────┘
 *   Observables            File: <name>  <hash…>            ⌄
 *   Observed Activity      Process Start  <artefact>
 *   … then NivXForge's evidence rows: Process, File & network,
 *   Detected By, Provenance, pivots.
 *
 * Two honesty rules are enforced here:
 *  · a field with no evidence reads "not reported", never blank;
 *  · the parsed-event digest is LABELLED as such and is never presented
 *    as the SHA-256 of a file on disk. Only a real file artefact digest
 *    appears under Observables / File SHA-256.
 */
import React, { useState } from "react";
import { ChevronDown, ChevronLeft, ChevronUp,
         ExternalLink } from "lucide-react";

import { C, dispositionOf, eventColor, isRed, typeLabel } from "./ampModel";
import EventGlyph from "./AmpIcons";

const Row = ({ k, v, mono = true, testid }) => {
  const empty = v === null || v === undefined || v === "" ||
    (Array.isArray(v) && v.length === 0);
  return (
    <div style={{ padding: "4px 0", borderBottom: `1px solid ${C.grid}` }}
         data-testid={testid}>
      <div style={{ fontSize: 8.4, fontWeight: 700, letterSpacing: ".5px",
                    textTransform: "uppercase", color: C.inkFaint }}>
        {k}
      </div>
      <div className={mono ? "mono" : undefined}
           style={{ fontSize: 10.4, marginTop: 1, wordBreak: "break-all",
                    color: empty ? C.inkFaint : C.ink }}>
        {empty ? "◇ not reported"
          : Array.isArray(v) ? v.join(", ") : String(v)}
      </div>
    </div>
  );
};

const Section = ({ title, children, testid }) => (
  <div style={{ marginTop: 12 }} data-testid={testid}>
    <div style={{ fontSize: 11, fontWeight: 600, color: C.ink,
                  borderBottom: `1px solid ${C.grid}`, paddingBottom: 4 }}>
      {title}
    </div>
    {children}
  </div>
);

/** Cisco's detail pane header: a back arrow returning to Activity. */
const Shell = ({ width, height, children, onBack }) => (
  <aside data-testid="amp-details-panel"
         style={{ width, height, flexShrink: 0, background: C.paper,
                  borderLeft: `1px solid ${C.gridStrong}`,
                  display: "flex", flexDirection: "column", minWidth: 0 }}>
    <div style={{ display: "flex", alignItems: "center", gap: 7,
                  padding: "7px 10px",
                  borderBottom: `1px solid ${C.gridStrong}` }}>
      {onBack && (
        <button onClick={onBack} data-testid="amp-details-back"
                title="Back to Activity"
                style={{ display: "flex", alignItems: "center",
                         cursor: "pointer", color: C.ink,
                         background: C.paperAlt, borderRadius: 4,
                         border: `1px solid ${C.gridStrong}`, padding: 3 }}>
          <ChevronLeft size={13} />
        </button>
      )}
      <span style={{ fontSize: 12.5, color: C.ink, fontWeight: 600,
                     flex: 1 }}>
        {onBack ? "Activity Details" : "Event Details"}
      </span>
    </div>
    <div style={{ overflowY: "auto", flex: 1, padding: "10px 11px 20px" }}>
      {children}
    </div>
  </aside>
);

export default function AmpEventDetails({ event, lane, onPivot, width,
                                          height, onBack }) {
  const [openHash, setOpenHash] = useState(null);

  if (!event) {
    return (
      <Shell width={width} height={height}>
        <p data-testid="amp-details-empty"
           style={{ fontSize: 10.6, color: C.inkFaint, lineHeight: 1.6 }}>
          Select an event in the trajectory to see its details, its
          provenance and the engine that detected it.
        </p>
      </Shell>
    );
  }

  const disp = dispositionOf(event);
  const engines = event.detected_by || [];
  const telemetryOnly = engines.every((d) => d.telemetry_only);
  const detected = event.is_detection || event.rule_id
    || event.disposition !== "UNKNOWN_NOT_ASSESSED";
  const tactics = (event.mitre || []).filter((m) => /^TA/i.test(m));
  const techniques = (event.mitre || []).filter((m) => !/^TA/i.test(m));

  return (
    <Shell width={width} height={height} onBack={onBack}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <svg width={18} height={18} viewBox="-9 -9 18 18">
          <EventGlyph event={event} color={eventColor(event)}
                      red={isRed(event)} />
        </svg>
        <span className="mono" data-testid="amp-details-timestamp"
              style={{ fontSize: 10, color: C.inkDim, flex: 1 }}>
          {event.timestamp}
        </span>
        <span data-testid="amp-details-disposition"
              style={{ fontSize: 9.4, fontWeight: 700, padding: "2px 7px",
                       borderRadius: 2, color: "#FFFFFF",
                       background: disp.color, whiteSpace: "nowrap" }}>
          {disp.label}
        </span>
      </div>

      <div data-testid="amp-details-type"
           style={{ fontSize: 12.5, fontWeight: 700, color: C.ink,
                    marginTop: 6 }}>
        {typeLabel(event.event_type)}
      </div>

      {detected && (
        <div data-testid="amp-details-detected-line"
             style={{ marginTop: 5, fontSize: 12, fontWeight: 600,
                      color: C.ink }}>
          Detected{" "}
          <span style={{ color: C.malicious, fontWeight: 700 }}>
            {event.rule_label || event.rule_id || event.display_label
              || typeLabel(event.event_type)}
          </span>
        </div>
      )}
      {event.is_detection && (
        <span data-testid="amp-details-detection-flag"
              style={{ display: "inline-block", marginTop: 5, fontSize: 9.4,
                       fontWeight: 700, padding: "2px 7px", borderRadius: 2,
                       color: "#FFFFFF", background: C.detection }}>
          DETECTION
        </span>
      )}

      <p data-testid="amp-details-description"
         style={{ marginTop: 7, fontSize: 10.6, color: C.inkDim,
                  lineHeight: 1.55 }}>
        {telemetryOnly
          ? `No detection engine claimed this observation — it is `
            + `telemetry reported by `
            + `${engines[0]?.component || "the collector"}. Absence of a `
            + `detection is not a verdict of clean.`
          : `Reported by ${engines.map((d) => d.engine)
              .filter(Boolean).join(", ")}. `
            + `${event.display_label || ""}`}
      </p>

      <div data-testid="amp-mitre-box"
           style={{ marginTop: 10, border: "1px solid #FCA5A5",
                    borderRadius: 2, overflow: "hidden" }}>
        <div style={{ background: C.malicious, color: "#FFFFFF",
                      fontSize: 9.6, fontWeight: 800, letterSpacing: ".6px",
                      padding: "4px 8px" }}>
          MITRE | ATT&CK
        </div>
        <div style={{ padding: "7px 9px", background: C.maliciousHalo }}>
          <div style={{ fontSize: 9.6, fontWeight: 800, color: "#991B1B" }}>
            Tactics
          </div>
          {tactics.length === 0 ? (
            <div data-testid="amp-mitre-tactics-none"
                 style={{ fontSize: 10.2, color: C.inkFaint, marginTop: 2 }}>
              ◇ no tactic attributed
            </div>
          ) : tactics.map((t) => (
            <div key={t} className="mono" data-testid={`amp-mitre-${t}`}
                 style={{ fontSize: 10.4, color: C.link, marginTop: 2 }}>
              {t}
            </div>
          ))}
          <div style={{ fontSize: 9.6, fontWeight: 800, color: "#991B1B",
                        marginTop: 7 }}>
            Techniques
          </div>
          {techniques.length === 0 ? (
            <div data-testid="amp-mitre-none"
                 style={{ fontSize: 10.2, color: C.inkFaint, marginTop: 2,
                          lineHeight: 1.5 }}>
              ◇ no technique attributed to this observation. Absence of an
              attribution is not evidence that no technique was used.
            </div>
          ) : techniques.map((t) => (
            <div key={t} className="mono" data-testid={`amp-mitre-${t}`}
                 style={{ fontSize: 10.4, color: C.link, marginTop: 2 }}>
              {t}
            </div>
          ))}
        </div>
      </div>

      <Section title="Observables" testid="amp-observables">
        {(event.file_artefacts || []).length === 0 ? (
          <div data-testid="amp-observables-none"
               style={{ fontSize: 10.4, color: C.inkFaint, marginTop: 5,
                        lineHeight: 1.5 }}>
            ◇ no file artefact was reported with this observation.
          </div>
        ) : (event.file_artefacts || []).map((f, i) => (
          <div key={f.iid || i} data-testid={`amp-observable-${i}`}
               style={{ marginTop: 5, display: "flex", gap: 6,
                        alignItems: "flex-start" }}>
            <span style={{ fontSize: 10.4, color: C.inkDim }}>File:</span>
            <span style={{ flex: 1, minWidth: 0 }}>
              <span className="mono" style={{ fontSize: 10.4, color: C.ink,
                                              wordBreak: "break-all" }}>
                {f.path || "◇ path not reported"}
              </span>
              <span className="mono" style={{ display: "block",
                                              fontSize: 9.6,
                                              color: C.inkDim,
                                              wordBreak: "break-all" }}>
                {f.sha256
                  ? (openHash === i ? f.sha256
                    : `${String(f.sha256).slice(0, 10)}…`
                      + String(f.sha256).slice(-8))
                  : "◇ SHA-256 not reported"}
              </span>
            </span>
            {f.sha256 && (
              <button onClick={() => setOpenHash(openHash === i ? null : i)}
                      data-testid={`amp-observable-expand-${i}`}
                      style={{ background: C.paper, cursor: "pointer",
                               border: `1px solid ${C.gridStrong}`,
                               borderRadius: 2, color: C.inkDim,
                               display: "flex", padding: 1 }}>
                {openHash === i ? <ChevronUp size={10} />
                                : <ChevronDown size={10} />}
              </button>
            )}
          </div>
        ))}
      </Section>

      <Section title="Observed Activity" testid="amp-observed-activity">
        <div style={{ display: "flex", gap: 8, marginTop: 5,
                      fontSize: 10.4 }}>
          <span style={{ color: C.inkDim, flexShrink: 0 }}>
            {typeLabel(event.event_type)}
          </span>
          <span className="mono" style={{ color: C.ink,
                                          wordBreak: "break-all" }}>
            {event.command_line || event.file || event.network
              || event.process || "◇ not reported"}
          </span>
        </div>
        <div style={{ fontSize: 10.2, color: C.inkDim, marginTop: 4 }}>
          Actor:{" "}
          <span className="mono" style={{ color: C.ink }}>
            {event.parent_process_name
              || (event.parent_state === "PARENT_NOT_OBSERVED_VISIBILITY_GAP"
                ? "◇ parent not observed — visibility gap"
                : event.parent_state === "PARENT_NOT_REPORTED_BY_SENSOR"
                  ? `${event.process || "process"} · root`
                  : event.process || "◇ not reported")}
          </span>
        </div>
      </Section>

      <Section title="Detected By" testid="amp-detected-by">
        {telemetryOnly ? (
          <div data-testid="amp-detected-by-none"
               style={{ fontSize: 10.4, color: C.inkDim, marginTop: 5,
                        lineHeight: 1.55, background: C.paperAlt,
                        border: `1px solid ${C.grid}`, padding: "6px 8px" }}>
            No detection engine claimed this observation — it is
            telemetry. Reported by{" "}
            <span className="mono">
              {engines[0]?.component || "the collector"}
            </span>.
          </div>
        ) : engines.filter((d) => !d.telemetry_only).map((d, i) => (
          <div key={i} data-testid={`amp-detected-by-${i}`}
               style={{ marginTop: 5, background: C.paperAlt,
                        border: `1px solid ${C.grid}`, padding: "6px 8px" }}>
            <div style={{ fontSize: 10.6, fontWeight: 700, color: C.ink }}>
              {d.engine || "unnamed engine"}
            </div>
            <div className="mono" style={{ fontSize: 9.6, color: C.inkDim,
                                           marginTop: 1 }}>
              {d.rule_id ? `rule ${d.rule_id}` : null}
              {d.rule_label ? ` · ${d.rule_label}` : ""}
              {d.detail ? `${d.rule_id ? " · " : ""}${d.detail}` : ""}
            </div>
            <div className="mono" style={{ fontSize: 9, color: C.inkFaint,
                                           marginTop: 1 }}>
              {d.component ? `component ${d.component} · ` : ""}
              {d.confidence ? `confidence ${d.confidence} · ` : ""}
              basis: {d.basis}
            </div>
          </div>
        ))}
      </Section>

      <Section title="Process">
        <Row k="Process" v={event.process} testid="amp-d-process" />
        <Row k="Executable" v={event.image} testid="amp-d-image" />
        <Row k="Command line" v={event.command_line} testid="amp-d-cmdline" />
        <Row k="User" v={event.user} testid="amp-d-user" />
        <Row k="PID" v={event.pid} testid="amp-d-pid" />
        <Row k="Parent PID" v={event.ppid} testid="amp-d-ppid" />
        <Row k="process_iid" v={event.process_iid} testid="amp-d-piid" />
        <Row k="parent_process_iid" v={event.parent_process_iid}
             testid="amp-d-ppiid" />
        <Row k="Parent row" v={event.parent_lane_index ?? null}
             testid="amp-d-parent-row" />
        <Row k="Lineage state" v={event.parent_state}
             testid="amp-d-parent-state" />
      </Section>

      <Section title="File & network">
        <Row k="File / target" v={event.file} testid="amp-d-file" />
        <Row k="File SHA-256" v={event.file_sha256}
             testid="amp-d-file-sha256" />
        <Row k="Network peer" v={event.network} testid="amp-d-network" />
        <Row k="Entity" v={event.entity} testid="amp-d-entity" />
      </Section>

      <Section title="Activity">
        <Row k="Action" v={event.action} testid="amp-d-action" />
        <Row k="Sensor label" v={event.display_label}
             testid="amp-d-display-label" />
        <Row k="Activity row"
             v={`${event.lane_group} · row ${event.lane_index}`}
             testid="amp-d-lane" />
        <Row k="Row identity" v={event.lane_id} testid="amp-d-lane-id" />
        <Row k="Observed extent of this row"
             v={lane ? `${lane.first_seen} → ${lane.last_seen}` : null}
             testid="amp-d-extent" />
        <Row k="Evidence labels" v={event.labels} testid="amp-d-labels" />
      </Section>

      <Section title="Provenance">
        <Row k="Event content digest (not a file hash)"
             v={event.event_content_digest} testid="amp-d-content-digest" />
        <Row k="Raw event id" v={event.provenance?.raw_event_id}
             testid="amp-d-raw-id" />
        <Row k="Canonical event id" v={event.provenance?.canonical_event_id}
             testid="amp-d-canonical-id" />
        <Row k="Evidence id" v={event.provenance?.evidence_id}
             testid="amp-d-evidence-id" />
        <Row k="Incident" v={event.provenance?.incident_id}
             testid="amp-d-incident" />
        <Row k="Collector" v={event.provenance?.origin
          || event.provenance?.adapter} testid="amp-d-origin" />
        <Row k="Normalizer" v={event.provenance?.normalizer}
             testid="amp-d-normalizer" />
        <Row k="Event identity" v={event.event_iid} testid="amp-d-event-iid" />
      </Section>

      <div style={{ marginTop: 11, display: "flex", flexDirection: "column",
                    gap: 4 }}>
        {[["process-tree", "Open Process Tree"],
          ["campaign-story", "Open Campaign Story"],
          ["file-trajectory", "Open fleet File Trajectory"],
          ["filter-indicator", "Filter trajectory by this indicator"]].map(
          ([k, label]) => (
            <button key={k} onClick={() => onPivot(k, event)}
                    data-testid={`amp-details-pivot-${k}`}
                    style={{ fontSize: 10.4, textAlign: "left",
                             padding: "5px 9px", cursor: "pointer",
                             background: C.paper, color: C.link,
                             border: `1px solid ${C.gridStrong}`,
                             borderRadius: 2, display: "flex",
                             alignItems: "center", gap: 6 }}>
              <ExternalLink size={10} /> {label}
            </button>
          ))}
      </div>
    </Shell>
  );
}
