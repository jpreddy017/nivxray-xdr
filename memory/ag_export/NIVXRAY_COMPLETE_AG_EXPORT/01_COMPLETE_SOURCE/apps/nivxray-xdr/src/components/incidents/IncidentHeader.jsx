/**
 * IncidentHeader — NivXRay ONE XDR skin.
 *
 * Reference: nivxray-one-xdr-console-8.html §inc-header.
 * Layout: [ id · badges · title · verdict-pill ]  |  [ inc-meta grid ]
 */
import React from "react";
import { INCIDENT_TESTIDS as T } from "@/constants/incidentTestIds";

const SEV_CLASS = {
  malicious:  "sev-critical",
  suspicious: "sev-medium",
  benign:     "sev-low",
  unknown:    "sev-info",
};
const SEV_LABEL = {
  malicious:  "Malicious",
  suspicious: "Suspicious",
  benign:     "Benign",
  unknown:    "Unknown",
};

function fmtDate(iso) {
  if (!iso) return "—";
  try { return new Date(iso).toISOString().replace("T", " ").slice(0, 16) + "Z"; }
  catch { return iso; }
}

export default function IncidentHeader({ incident }) {
  const sevCls = SEV_CLASS[incident?.severity] || "sev-info";
  const prioCls = (incident?.priority?.code || "P5").toLowerCase();
  const stage2 = incident?.verdict_stage2;

  return (
    <section className="inc-header" data-testid={T.header}>
      <div className="grow">
        <div className="inc-badges" style={{ marginBottom: 2 }}>
          <span className="inc-id" data-testid={T.headerNumber}>{incident?.number}</span>
          <span
            className={`prio ${prioCls}`}
            data-testid={T.headerPriority}
            title={`${incident?.priority?.code} · ${incident?.priority?.label}`}
          >
            {incident?.priority?.code} · {incident?.priority?.label}
          </span>
          <span
            className={`badge ${sevCls}`}
            data-testid={T.headerSeverity}
          >
            {SEV_LABEL[incident?.severity] || incident?.severity}
          </span>
          <span
            className={`status-pill state-${incident?.state}`}
          >
            {(incident?.state || "new").replace("_", " ")}
          </span>
        </div>

        <div className="inc-title" data-testid={T.headerName}>
          {incident?.name || "(unnamed incident)"}
        </div>

        {stage2 && (
          <div className="verdict-pill" data-testid={T.headerVerdict}>
            <span className="lbl">STAGE-2 VERDICT</span>
            <span className="v">{(stage2.label || "unknown").toUpperCase()}</span>
            <span style={{ color: "var(--xfaint)" }}>·</span>
            <span>confidence {stage2.confidence_bucket}</span>
            <span style={{ color: "var(--xfaint)" }}>·</span>
            <span>risk {stage2.risk_score}</span>
          </div>
        )}
      </div>

      <div className="inc-meta">
        <div className="k">Assignee</div>
        <div className="v" data-testid={T.headerAssignee}>
          {incident?.assignee || "—"}
        </div>
        <div className="k">Tenant</div>
        <div className="v">{incident?.tenant || "default"}</div>
        <div className="k">Created</div>
        <div className="v">{fmtDate(incident?.created_at)}</div>
        <div className="k">Updated</div>
        <div className="v">{fmtDate(incident?.updated_at)}</div>
      </div>
    </section>
  );
}
