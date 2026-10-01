/**
 * IncidentContextStrip · Slice 7.
 *
 * Persistent context ribbon rendered at the TOP of every native XDR
 * domain-detail page.  Anchors the analyst to the incident even as
 * they pivot between domains (§4 of the implementation prompt).
 *
 * Fields (locked):
 *   Incident · Endpoint · User · Customer · Severity · Time Window
 *
 * Every field either shows the authoritative value or a distinct
 * honest state ("NOT AVAILABLE" for a missing SSOT field).
 * Endpoint / User reuse the Slice 1 <Pivot> so the analyst can jump
 * to their native domain page without breaking anchor context.
 */
import React from "react";
import { Link } from "react-router-dom";
import { ChevronLeft, ShieldAlert } from "lucide-react";

import Pivot from "@/xdr/components/Pivot";

const SEV_CLASS = {
  malicious:  "sev-critical",
  suspicious: "sev-medium",
  benign:     "sev-low",
  unknown:    "sev-info",
};
const SEV_LABEL = {
  malicious: "Malicious", suspicious: "Suspicious",
  benign: "Benign",       unknown:    "Unknown",
};

const NOT_AVAILABLE = (
  <span className="mono" style={{
    color: "var(--faint)", fontSize: 9.5, letterSpacing: ".3px",
    textTransform: "uppercase", fontWeight: 800,
  }}>
    NOT AVAILABLE
  </span>
);

export default function IncidentContextStrip({
  incident,
  domainLabel,
}) {
  if (!incident) return null;
  const id      = incident.id;
  const inv     = incident?.ssot?.investigation_object || {};
  const host    = inv.host || (inv.device && inv.device.hostname);
  const user    = inv.user;
  const customer = incident.tenant_id || incident.user_email;
  const stage2  = incident.verdict_stage2 || {};
  const sev     = (stage2.label || "unknown").toLowerCase();
  const first   = incident.created_at;
  const last    = incident.updated_at || incident.last_seen;

  const ctx = { incident_id: id };

  return (
    <section
      className="panel"
      data-testid="xdr-incident-context-strip"
      style={{
        padding: "10px 14px", marginBottom: 12,
        borderLeft: "3px solid var(--purple)",
      }}
    >
      {/* Breadcrumb */}
      <div style={{ display: "flex", alignItems: "center", gap: 6,
                      marginBottom: 8 }}>
        <Link to={`/xdr/incidents/${encodeURIComponent(id)}`}
              className="btn ghost"
              style={{ padding: "3px 8px", fontSize: 11,
                        textDecoration: "none" }}
              data-testid="xdr-context-back">
          <ChevronLeft size={11} /> Incident Overview
        </Link>
        <span style={{ color: "var(--faint)" }}>·</span>
        <span className="mono" style={{ color: "var(--muted)", fontSize: 11 }}>
          {id}
        </span>
        {domainLabel && (
          <>
            <span style={{ color: "var(--faint)" }}>›</span>
            <span style={{ color: "var(--text)", fontWeight: 700,
                              fontSize: 12 }}>
              {domainLabel}
            </span>
          </>
        )}
      </div>

      {/* Six context cells */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(6, minmax(120px, 1fr))",
        gap: 14, alignItems: "start",
      }}>
        <Cell k="Incident"
              v={<span className="mono" style={{ color: "var(--text)",
                                                        fontWeight: 700 }}>{id}</span>} />
        <Cell k="Endpoint"
              v={host
                ? <Pivot kind="host" value={host} ctx={ctx}
                            testid="xdr-context-endpoint" />
                : NOT_AVAILABLE} />
        <Cell k="User"
              v={user
                ? <Pivot kind="user" value={user} ctx={ctx}
                            testid="xdr-context-user" />
                : NOT_AVAILABLE} />
        <Cell k="Customer"
              v={customer
                ? <span className="mono" style={{ color: "var(--text-dim)" }}>
                    {customer}
                  </span>
                : NOT_AVAILABLE} />
        <Cell k="Severity"
              v={<span className={`badge ${SEV_CLASS[sev] || "sev-info"}`}>
                    <ShieldAlert size={9}
                                    style={{ verticalAlign: "middle", marginRight: 4 }} />
                    {SEV_LABEL[sev] || sev}
                  </span>} />
        <Cell k="Time Window"
              v={first
                ? <span className="mono" style={{ color: "var(--text-dim)",
                                                        fontSize: 10.5 }}>
                    {String(first).slice(0, 16).replace("T", " ")}Z
                    {" – "}
                    {last ? String(last).slice(0, 16).replace("T", " ") + "Z" : "…"}
                  </span>
                : NOT_AVAILABLE} />
      </div>
    </section>
  );
}

function Cell({ k, v }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
      <div style={{
        color: "var(--faint)", fontSize: 9.5, fontWeight: 800,
        textTransform: "uppercase", letterSpacing: ".3px",
      }}>{k}</div>
      <div style={{ color: "var(--text-dim)", fontSize: 11.5 }}>{v}</div>
    </div>
  );
}
