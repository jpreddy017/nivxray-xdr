/**
 * ArtifactContextMenu · right-click pivot shelf for an observation.
 *
 * Control state expresses capability state: an action with no driver is
 * rendered disabled with the reason, never as a live button.
 */
import React, { useEffect, useRef } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import { ABSENT, buildEdrPivot, buildFileTrajectoryPivot,
         buildProcessTreePivot, buildSightingsPivot } from "@/xdr/lib/pivots";

import { shortHash } from "@/xdr/lib/trajectoryModel";

function Item({ label, hint, onClick, disabled, testid }) {
  return (
    <button type="button"
            onClick={disabled ? undefined : onClick}
            disabled={disabled}
            style={{
              display: "block", width: "100%", textAlign: "left",
              padding: "5px 9px", background: "transparent",
              border: "none", cursor: disabled ? "not-allowed" : "pointer",
              color: disabled ? "#5D6875" : "#C7D0DB",
              fontSize: 10.5,
            }}
            data-testid={testid}>
      <span className="mono">{label}</span>
      {hint && (
        <div className="mono" style={{ fontSize: 8.8, color: "#5D6875",
                                       marginTop: 2 }}>{hint}</div>
      )}
    </button>
  );
}

/** Verb grouping mirrors the reference menu structure. */
function Section({ label }) {
  return (
    <div style={{ padding: "6px 9px 3px", fontSize: 8.6, letterSpacing: .7,
                  color: "#5D6875", textTransform: "uppercase",
                  borderTop: "1px solid #212B36", marginTop: 2 }}>
      {label}
    </div>
  );
}

export default function ArtifactContextMenu({
  evt, at, onClose, onSearch, onStaticAnalysis, onSelect,
}) {
  const ref = useRef(null);
  const navigate = useNavigate();
  const [params] = useSearchParams();
  useEffect(() => {
    const away = (e) => { if (!ref.current?.contains(e.target)) onClose(); };
    const esc = (e) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("mousedown", away);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", away);
      document.removeEventListener("keydown", esc);
    };
  }, [onClose]);

  if (!evt) return null;
  const sha = evt.file_sha256 || null;
  const name = evt.file || evt.process || evt.title || null;
  const fleetKey = sha ? `sha256:${sha}`
                  : name ? `name:${String(name).split(/[\\/]/).pop()}` : null;

  /** Y3.1 · every observable this record actually carries. Nothing is
   *  invented: a type absent from the evidence is simply not offered. */
  const observables = [
    ["SHA256", sha],
    ["FILE_PATH", evt.file || null],
    ["PROCESS", evt.process_iid || null],
    ["IP", evt.remote_ip || evt.destination || null],
    ["DOMAIN_OR_HOST", evt.hostname || null],
    ["ENDPOINT", evt.device_iid || evt.device || null],
    ["EVIDENCE", evt.canonical_event_id
      || evt.provenance?.canonical_event_id || null],
  ].filter(([, v]) => v);
  const primary = observables[0] || [null, null];
  const device = evt.device_iid || evt.device || null;
  const focusValue = sha || evt.remote_ip || name || primary[1];

  return (
    <div ref={ref}
         style={{ position: "fixed", zIndex: 70,
                  left: Math.min(at.x, window.innerWidth - 280),
                  top: Math.max(8, Math.min(at.y,
                    window.innerHeight - 470)),
                  width: 292, maxHeight: 460, overflowY: "auto", background: "#11161D",
                  border: "1px solid #212B36", borderRadius: 5,
                  boxShadow: "0 12px 34px rgba(0,0,0,0.55)", padding: "4px 0" }}
         data-testid="edr-artifact-context-menu">
      <div style={{ padding: "6px 9px", borderBottom: "1px solid #212B36" }}>
        <div className="mono" style={{ fontSize: 10, color: "#E4E9F0",
                                       wordBreak: "break-all" }}>
          {name || "◇ NO NAME RECORDED"}
        </div>
        <div className="mono" style={{ fontSize: 9, color: "#5D6875", marginTop: 3 }}>
          {sha ? shortHash(sha) : "◇ NO SHA-256 RECORDED"}
        </div>
        <div style={{ marginTop: 4 }}>
          <span className="nx-ep" data-ep="unknown" data-known="true"
                data-testid="edr-ctx-observable-type"
                data-observable-type={primary[0] || "NONE"}>
            {primary[0]
              ? `${primary[0]} · ${observables.length} observable(s)`
              : "◇ NO OBSERVABLE RECORDED"}
          </span>
        </div>
      </div>

      <Section label="Observe · sightings" />
      <Item label="Open activity details"
            onClick={() => { onSelect?.(evt); onClose(); }}
            testid="edr-ctx-details" />
      <Item label={`Sightings across NivXRay XDR${focusValue
              ? "" : " (nothing to look up)"}`}
            hint="tenant-scoped search of the authoritative stores"
            disabled={!focusValue}
            onClick={() => { navigate(buildSightingsPivot(focusValue));
                             onClose(); }}
            testid="edr-ctx-sightings" />
      <Item label="Search this device trajectory"
            disabled={!sha && !name}
            onClick={() => { onSearch?.(sha || name); onClose(); }}
            testid="edr-ctx-search" />
      <Item label="Fleet File Trajectory (all endpoints)"
            hint={sha ? "keyed on the observed content digest"
                      : "keyed on the observed name — names do not prove contents"}
            disabled={!fleetKey}
            onClick={() => { navigate(buildFileTrajectoryPivot(fleetKey));
                             onClose(); }}
            testid="edr-ctx-file-trajectory" />

      <Section label="Investigate · NivXRay EDR" />
      <Item label="Open in NivXRay EDR (this endpoint)"
            hint={device ? "carries customer · endpoint · incident · evidence"
                         : "this observation names no endpoint"}
            disabled={!device}
            onClick={() => {
              navigate(buildEdrPivot({
                device,
                incidentId: params.get("incident_id")
                  || params.get("incident"),
                rawEventId: evt.provenance?.raw_event_id,
                canonicalEventId: evt.canonical_event_id
                  || evt.provenance?.canonical_event_id,
                eventIid: evt.event_iid,
                processIid: evt.process_iid,
                at: evt.timestamp,
              }));
              onClose();
            }}
            testid="edr-ctx-open-in-edr" />
      <Item label="Process Tree"
            hint={evt.process_iid ? "the process lineage that owns this event"
                                  : "no process identity on this observation"}
            disabled={!evt.process_iid || !device}
            onClick={() => { navigate(buildProcessTreePivot({
              device, processIid: evt.process_iid })); onClose(); }}
            testid="edr-ctx-process-tree" />

      <Section label="Deliberate · reputation" />
      <Item label="⊘ Reputation / disposition lookup"
            hint={ABSENT.reputation}
            disabled
            testid="edr-ctx-reputation" />
      <Item label="File Analysis ▸ Static Analysis Bridge"
            hint={ABSENT.detonation}
            onClick={() => { onStaticAnalysis?.(evt); onClose(); }}
            testid="edr-ctx-static-analysis" />

      <Section label="Respond · enforcement" />
      <Item label="⊘ File Fetch"
            hint="SENSOR OFFLINE — NO ACQUISITION DRIVER"
            disabled
            testid="edr-ctx-file-fetch" />
      <Item label="⊘ Outbreak Control"
            hint={ABSENT.enforcement}
            disabled
            testid="edr-ctx-outbreak" />

      <Section label="Refer · external" />
      <Item label="⊘ External reference sources"
            hint={ABSENT.externalRefer}
            disabled
            testid="edr-ctx-refer" />

      <Section label="Utility" />
      <Item label="Copy SHA-256"
            disabled={!sha}
            hint={sha ? undefined : "no file content digest on this observation"}
            onClick={() => { navigator.clipboard?.writeText(sha); onClose(); }}
            testid="edr-ctx-copy-sha" />
    </div>
  );
}
