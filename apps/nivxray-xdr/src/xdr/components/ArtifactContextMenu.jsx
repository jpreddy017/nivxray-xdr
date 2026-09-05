/**
 * ArtifactContextMenu · right-click pivot shelf for an observation.
 *
 * Control state expresses capability state: an action with no driver is
 * rendered disabled with the reason, never as a live button.
 */
import React, { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";

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

export default function ArtifactContextMenu({
  evt, at, onClose, onSearch, onStaticAnalysis, onSelect,
}) {
  const ref = useRef(null);
  const navigate = useNavigate();
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

  return (
    <div ref={ref}
         style={{ position: "fixed", zIndex: 70,
                  left: Math.min(at.x, window.innerWidth - 280),
                  top: Math.min(at.y, window.innerHeight - 340),
                  width: 268, background: "#11161D",
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
          <span className="nx-ep" data-ep="unknown" data-known="true">
            ? UNKNOWN DISPOSITION
          </span>
        </div>
      </div>

      <Item label="Open activity details"
            onClick={() => { onSelect?.(evt); onClose(); }}
            testid="edr-ctx-details" />
      <Item label="Copy SHA-256"
            disabled={!sha}
            hint={sha ? undefined : "no file content digest on this observation"}
            onClick={() => { navigator.clipboard?.writeText(sha); onClose(); }}
            testid="edr-ctx-copy-sha" />
      <Item label="Search this device trajectory"
            disabled={!sha && !name}
            onClick={() => { onSearch?.(sha || name); onClose(); }}
            testid="edr-ctx-search" />

      <div style={{ borderTop: "1px solid #212B36", margin: "3px 0" }} />

      <Item label="File Analysis ▸ Static Analysis Bridge"
            hint="STATIC ONLY · dynamic detonation not configured"
            onClick={() => { onStaticAnalysis?.(evt); onClose(); }}
            testid="edr-ctx-static-analysis" />
      <Item label="⊘ File Fetch"
            hint="SENSOR OFFLINE — NO ACQUISITION DRIVER"
            disabled
            testid="edr-ctx-file-fetch" />
      <Item label="Fleet File Trajectory (all endpoints)"
            hint={sha ? "keyed on the observed content digest"
                      : "keyed on the observed name — names do not prove contents"}
            disabled={!fleetKey}
            onClick={() => {
              navigate(`/xdr/intelligence/files/${encodeURIComponent(fleetKey)}`);
              onClose();
            }}
            testid="edr-ctx-file-trajectory" />
      <Item label="⊘ Outbreak Control"
            hint="RESPONSE DRIVER NOT REGISTERED"
            disabled
            testid="edr-ctx-outbreak" />
    </div>
  );
}
