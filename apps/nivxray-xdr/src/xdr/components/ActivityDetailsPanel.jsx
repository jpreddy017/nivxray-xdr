/**
 * ActivityDetailsPanel · the AMP "Activity Details" pane.
 *
 * The primary fact is PROSE, composed server-side by
 * `services/edr/observation_narrative.py` from the persisted
 * observation.  Unknowns are printed as sentences ("Unknown
 * disposition.") rather than blanked — see the AMP reference notes in
 * docs/uiux/NIVXFORGE_EDR_TARGET_UX_ARCHITECTURE.md.
 */
import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Loader2, ShieldAlert, GitBranch, FlaskConical } from "lucide-react";

import Pivot from "@/xdr/components/Pivot";
import { getObservationNarrative } from "@/nivxforge/edrApi";
import {
  glyphFor, severityTier, TIER_COLOR, TIER_MALICIOUS, typeTag, shortHash,
} from "@/xdr/lib/trajectoryModel";

function Row({ k, v }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "92px 1fr", gap: 8,
                  alignItems: "baseline", marginBottom: 6 }}>
      <div style={{ color: "var(--faint)", fontSize: 9.5, fontWeight: 800,
                    textTransform: "uppercase", letterSpacing: ".3px" }}>{k}</div>
      <div style={{ color: "var(--text-dim)", fontSize: 11 }}>{v}</div>
    </div>
  );
}
const Absent = ({ label }) => (
  <span className="nx-ep" data-ep="no_evidence" data-known="true">{label}</span>
);

/** Render `…`-quoted fragments of the composed sentence as chips. */
function Prose({ text }) {
  const parts = String(text).split(/`([^`]+)`/g);
  return (
    <span>
      {parts.map((p, i) => (i % 2 === 1
        ? <span key={i} className="mono"
                style={{ color: "#E4E9F0", background: "#11161D",
                         border: "1px solid #212B36", borderRadius: 3,
                         padding: "0 3px" }}>{p}</span>
        : <span key={i}>{p}</span>))}
    </span>
  );
}

export default function ActivityDetailsPanel({
  event, deviceRef, incidents, onStaticAnalysis, onClose,
}) {
  const [narr, setNarr] = useState({ status: "idle" });

  const eventIid = event?.event_iid || event?.evidence_ref?.event_iid || null;

  useEffect(() => {
    let cancel = false;
    if (!eventIid || !deviceRef) { setNarr({ status: "unavailable" }); return undefined; }
    setNarr({ status: "loading" });
    (async () => {
      try {
        const data = await getObservationNarrative(deviceRef, eventIid);
        if (!cancel) setNarr({ status: data.resolved ? "ok" : "unresolved", data });
      } catch (e) {
        if (!cancel) setNarr({ status: "error",
                               error: e?.response?.data?.detail || e?.message });
      }
    })();
    return () => { cancel = true; };
  }, [eventIid, deviceRef]);

  if (!event) {
    return (
      <div className="x-empty" style={{ padding: 20 }}
           data-testid="edr-activity-details-empty">
        Select an observation on the canvas or in the ledger.
      </div>
    );
  }

  const g = glyphFor(event);
  const tier = severityTier(event);
  const caseResolvable = new Set(
    (incidents || []).filter((i) => i.source !== "v2_shadow_observations")
                     .map((i) => i.incident_id));
  const ctx = { incident_id: event.incident_id };

  return (
    <div data-testid={`edr-activity-details-${event.id}`}
         style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      <div style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
        {tier === TIER_MALICIOUS
          ? <ShieldAlert size={14} style={{ color: TIER_COLOR[TIER_MALICIOUS], marginTop: 2 }} />
          : <GitBranch size={14} style={{ color: TIER_COLOR[tier], marginTop: 2 }} />}
        <div style={{ flex: 1 }}>
          <div style={{ color: "var(--text)", fontWeight: 700, fontSize: 13 }}>
            {event.title || event.process || "Observation"}{" "}
            <span className="mono" style={{ fontSize: 9.5, color: "var(--faint)" }}>
              {typeTag(event.path || event.file || event.process)}
            </span>
          </div>
          <div className="mono" style={{ fontSize: 10, color: TIER_COLOR[tier],
                                         marginTop: 2 }}>
            {g.sym} {g.label} · {(event.observation_kind || event.kind || "").toUpperCase()}
          </div>
        </div>
        <button className="btn ghost" style={{ padding: 4 }} onClick={onClose}
                data-testid="edr-activity-details-close">×</button>
      </div>

      {/* ── Prose primary fact ─────────────────────────────────── */}
      <div style={{ background: "#0D1218", border: "1px solid #212B36",
                    borderRadius: 4, padding: 10, fontSize: 11.5,
                    lineHeight: 1.85, color: "var(--text-dim)" }}
           data-testid="edr-activity-narrative">
        {narr.status === "loading" && (
          <><Loader2 size={12} className="spin"
                     style={{ verticalAlign: "middle", marginRight: 6 }} />
            Composing evidence-gated narrative …</>
        )}
        {narr.status === "ok" && (
          <>
            {(narr.data.sentences || []).map((s, i) => (
              <div key={i} style={{ marginBottom: 5 }}><Prose text={s} /></div>
            ))}
            {(narr.data.unknowns || []).map((s, i) => (
              <div key={`u-${i}`} style={{ marginBottom: 3, color: "#C9A227" }}>
                <Prose text={s} />
              </div>
            ))}
            <div className="mono" style={{ marginTop: 8, fontSize: 8.8,
                                           color: "var(--faint)" }}>
              {narr.data.composer}
            </div>
          </>
        )}
        {narr.status === "unresolved" && (
          <span className="nx-ep" data-ep="no_evidence" data-known="true">
            ◇ NO PERSISTED OBSERVATION MATCHES THIS EVENT_IID — NO NARRATIVE COMPOSED
          </span>
        )}
        {narr.status === "unavailable" && (
          <span className="nx-ep" data-ep="unknown" data-known="true">
            ? THIS ROW CARRIES NO EVENT_IID — NARRATIVE NOT COMPOSABLE
          </span>
        )}
        {narr.status === "error" && (
          <span className="nx-ep" data-ep="capability_unavailable" data-known="true">
            ⊘ NARRATIVE COMPOSER UNAVAILABLE · {String(narr.error)}
          </span>
        )}
      </div>

      <Row k="Timestamp" v={<span className="mono">{event.timestamp || "◇"}</span>} />
      <Row k="Disposition"
           v={<span className="nx-ep" data-ep="unknown" data-known="true">
                ? UNKNOWN DISPOSITION · UNKNOWN PARENT DISPOSITION
              </span>} />
      <Row k="Device"
           v={<Pivot kind="host" value={event.device || deviceRef} ctx={ctx}
                     testid={`edr-details-pivot-host-${event.id}`} />} />
      <Row k="Process"
           v={event.process
               ? <Pivot kind="process" value={event.process} ctx={ctx}
                        testid={`edr-details-pivot-process-${event.id}`} />
               : <Absent label="◇ NO ACTOR RECORDED" />} />
      <Row k="Process IID"
           v={event.process_iid
               ? <span className="mono">{event.process_iid}</span>
               : <Absent label="◇ NOT CAPTURED" />} />
      <Row k="Parent"
           v={event.parent_iid || event.parent_name
               ? <span className="mono">
                   {event.parent_name || "◇ name not recorded"}{" "}
                   ({event.parent_iid || "◇"}){" "}
                   <span className="nx-ep" data-ep="unknown" data-known="true">
                     ? PARENT NOT OBSERVED
                   </span>
                 </span>
               : <Absent label="◇ NO PARENT RECORDED · [ROOT / PARENT NOT OBSERVED]" />} />
      <Row k="PID / PPID" v={<Absent label="◇ PID/PPID NOT CAPTURED IN THIS SUBSTRATE" />} />
      <Row k="Image path"
           v={event.path ? <span className="mono" style={{ fontSize: 10,
                                                            wordBreak: "break-all" }}>
                             {event.path}</span>
                         : <Absent label="◇ NOT CAPTURED" />} />
      <Row k="Target"
           v={event.file ? <span className="mono" style={{ fontSize: 10,
                                                            wordBreak: "break-all" }}>
                             {event.file}</span>
                         : <Absent label="◇ NONE RECORDED" />} />
      <Row k="SHA-256"
           v={event.sha256
               ? <span className="mono" style={{ fontSize: 10, wordBreak: "break-all" }}>
                   {event.sha256}
                 </span>
               : <Absent label="◇ NO DIGEST RECORDED" />} />
      <Row k="User"
           v={event.user ? <span className="mono">{event.user}</span>
                         : <Absent label="◇ NOT CAPTURED" />} />
      <Row k="Command"
           v={event.command_line
               ? <span className="mono" style={{ fontSize: 10, display: "block",
                                                 wordBreak: "break-all" }}>
                   {event.command_line.slice(0, 400)}
                 </span>
               : <Absent label="◇ NOT CAPTURED" />} />
      <Row k="ATT&CK"
           v={(event.mitre || []).length
               ? <span className="mono" style={{ color: "#F39C12" }}>
                   {event.mitre.join(", ")}
                 </span>
               : <Absent label="◇ NO TECHNIQUE ASSERTED" />} />
      <Row k="Detected by"
           v={event.provider
               ? <span className="mono" style={{ color: "var(--mint)" }}>
                   {event.provider}
                   {event.event_id != null && ` · event ${event.event_id}`}
                 </span>
               : <Absent label="◇ NO PROVIDER RECORDED" />} />
      <Row k="Adapter"
           v={event.adapter ? <span className="mono">{event.adapter}</span>
                            : <Absent label="◇" />} />
      <Row k="Observation"
           v={<span className="mono" style={{ fontSize: 10 }}>
                {eventIid || "◇"}
              </span>} />
      <Row k="Case refs"
           v={(event.case_refs || (event.incident_id ? [event.incident_id] : []))
                .map((c) => (
                  <div key={c} className="mono" style={{ fontSize: 10 }}>
                    {caseResolvable.has(c)
                      ? <Link to={`/xdr/incidents/${c}`}
                              style={{ color: "var(--cyan)" }}>{c}</Link>
                      : <>{c}{" "}
                          <span className="nx-ep" data-ep="no_evidence" data-known="true">
                            ◇ RECORD NOT PERSISTED
                          </span></>}
                  </div>
                ))} />
      {event.occurrences > 1 && (
        <Row k="Replays"
             v={<span className="mono" style={{ color: "var(--faint)" }}>
                  the same observation is carried by {event.occurrences} case references
                </span>} />
      )}

      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 2 }}>
        <button className="btn" style={{ padding: "4px 8px", fontSize: 10 }}
                onClick={() => onStaticAnalysis?.(event)}
                data-testid="edr-details-static-analysis">
          <FlaskConical size={11} /> File Analysis (static)
        </button>
        <span className="nx-ep" data-ep="capability_unavailable" data-known="true">
          ⊘ RESPONSE DRIVER NOT REGISTERED
        </span>
      </div>
    </div>
  );
}
