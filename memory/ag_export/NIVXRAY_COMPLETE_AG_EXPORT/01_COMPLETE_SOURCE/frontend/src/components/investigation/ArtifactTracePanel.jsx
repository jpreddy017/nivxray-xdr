/**
 * Artifact Trace Panel · R28.C · projects the persisted SSOT into the
 * canonical Artifact → Recognizer → Capability → Evidence → Child-Artifact
 * flow.  Renders unchanged for PowerShell, PE, PDF, Office, Shellcode,
 * Memory or PCAP artifacts — no per-domain branches, no rename required
 * once UAIE lands (R25/R26).
 *
 * Pure projection.  Never fetches, decodes, classifies or enriches
 * (R28 · Restore is Rendering).
 */
import React from "react";

const _t = (s, n = 120) =>
  typeof s === "string" && s.length > n ? s.slice(0, n) + "…" : s;

export default function ArtifactTracePanel({ trace, testid = "artifact-trace" }) {
  const rows = Array.isArray(trace) ? trace : [];
  if (rows.length === 0) return null;
  return (
    <div
      data-testid={testid}
      className="mono"
      style={{
        border: "1px solid var(--border)",
        background: "var(--inset)",
        padding: "14px 16px",
        marginTop: 18,
      }}
    >
      <div
        style={{
          fontSize: 11,
          fontWeight: 700,
          letterSpacing: "0.14em",
          color: "#7ee3c9",
          marginBottom: 10,
        }}
      >
        ▸ ARTIFACT TRACE · Artifact → Recognizer → Capability → Evidence
        <span
          style={{
            fontSize: 9,
            color: "var(--text-dim)",
            marginLeft: 8,
            letterSpacing: "0.08em",
          }}
        >
          (SSOT projection · zero recompute)
        </span>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {rows.map((r, idx) => (
          <ArtifactTraceRow key={r.artifact_uri || idx} row={r} last={idx === rows.length - 1} />
        ))}
      </div>
    </div>
  );
}

function ArtifactTraceRow({ row, last }) {
  const rec = row.recognizer || {};
  const cap = row.capability || {};
  const evidence = Array.isArray(row.evidence) ? row.evidence : [];
  const cellStyle = {
    border: "1px solid var(--border)",
    padding: "6px 8px",
    background: "var(--bg)",
    flex: 1,
    minWidth: 0,
  };
  const labelStyle = {
    fontSize: 9,
    color: "var(--text-dim)",
    letterSpacing: "0.10em",
    marginBottom: 2,
  };
  const valueStyle = {
    fontSize: 11,
    color: "#e6f7f1",
    wordBreak: "break-all",
  };
  return (
    <div
      data-testid={`artifact-trace-row-${row.layer_index ?? "?"}`}
      style={{ display: "flex", alignItems: "stretch", gap: 6 }}
    >
      {/* Artifact */}
      <div style={cellStyle}>
        <div style={labelStyle}>ARTIFACT · L{row.layer_index}</div>
        <div style={valueStyle}>{_t(row.artifact_uri, 60)}</div>
      </div>
      <Arrow />
      {/* Recognizer */}
      <div style={cellStyle}>
        <div style={labelStyle}>RECOGNIZER</div>
        <div style={valueStyle}>{rec.name || "—"}</div>
        {rec.reason && (
          <div style={{ fontSize: 10, color: "var(--text-dim)", marginTop: 2 }}>
            {_t(rec.reason, 90)}
          </div>
        )}
      </div>
      <Arrow />
      {/* Capability */}
      <div style={cellStyle}>
        <div style={labelStyle}>CAPABILITY</div>
        <div style={valueStyle}>{cap.name || "—"}</div>
        <div style={{ fontSize: 10, color: "var(--text-dim)", marginTop: 2 }}>
          out: {cap.out_len || 0}c
        </div>
      </div>
      <Arrow />
      {/* Evidence */}
      <div style={cellStyle}>
        <div style={labelStyle}>EVIDENCE</div>
        {evidence.length === 0 ? (
          <div style={{ fontSize: 10, color: "var(--text-dim)" }}>—</div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            {evidence.slice(0, 4).map((e, i) => (
              <div key={i} style={{ fontSize: 10, color: "#e6f7f1" }}>
                <span style={{ color: "#7ee3c9" }}>{e.kind}:</span>{" "}
                {_t(e.value, 40)}
              </div>
            ))}
            {evidence.length > 4 && (
              <div style={{ fontSize: 9, color: "var(--text-dim)" }}>
                +{evidence.length - 4} more…
              </div>
            )}
          </div>
        )}
      </div>
      {!last && (
        <>
          <Arrow />
          <div style={{ ...cellStyle, maxWidth: 220 }}>
            <div style={labelStyle}>CHILD</div>
            <div style={{ ...valueStyle, fontSize: 10 }}>
              {_t(row.child_artifact || "—", 40)}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function Arrow() {
  return (
    <div
      aria-hidden
      style={{
        alignSelf: "center",
        color: "var(--text-dim)",
        fontSize: 12,
        padding: "0 2px",
      }}
    >
      →
    </div>
  );
}
