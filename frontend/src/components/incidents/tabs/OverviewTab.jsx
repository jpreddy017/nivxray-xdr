/**
 * OverviewTab · Incident Evidence Across Domains.
 *
 * Each domain card is a full-page launcher — clicking opens the real
 * telemetry experience in a NEW BROWSER TAB (owner rule).  Cards with
 * no implementation are rendered as honest, disabled 'unavailable'
 * states — never as fake, click-through placeholders.
 */
import React from "react";
import {
  ExternalLink, ShieldAlert, Wifi, UserCircle, Cloud, Mail, Globe,
  LayoutGrid,
} from "lucide-react";

import { INCIDENT_TESTIDS as T } from "@/constants/incidentTestIds";

const DOMAIN_META = {
  edr:       { icon: ShieldAlert,   accent: "#86efac" },
  ndr:       { icon: Wifi,          accent: "#67e8f9" },
  identity:  { icon: UserCircle,    accent: "#c4b5fd" },
  cloud:     { icon: Cloud,         accent: "#93c5fd" },
  email:     { icon: Mail,          accent: "#fcd34d" },
  web:       { icon: Globe,         accent: "#f9a8d4" },
  workspace: { icon: LayoutGrid,    accent: "#e2e8f0" },
};

export default function OverviewTab({ incident }) {
  const pointers = incident?.evidence_pointers || [];
  return (
    <section
      data-testid={T.overviewPane}
      style={{ display: "flex", flexDirection: "column", gap: 18 }}
    >
      <div>
        <SectionHeading title="Incident Evidence Across Domains"
                          hint="Each card opens the full domain surface in a new browser tab." />
        <div
          data-testid={T.domainCards}
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
            gap: 12,
            marginTop: 12,
          }}
        >
          {pointers.map((p) => (
            <DomainCard key={p.domain} pointer={p} />
          ))}
        </div>
      </div>
    </section>
  );
}

function DomainCard({ pointer }) {
  const meta = DOMAIN_META[pointer.domain] || DOMAIN_META.workspace;
  const Icon = meta.icon;
  const available = pointer.status === "available" && !!pointer.deep_link;

  const handleLaunch = () => {
    if (!available) return;
    // Absolute owner rule — telemetry always opens in a new tab.
    // Uses noopener/noreferrer to keep the parent context isolated.
    window.open(pointer.deep_link, "_blank", "noopener,noreferrer");
  };

  return (
    <div
      data-testid={T.domainCard(pointer.domain)}
      style={{
        border: `1px solid ${available ? "rgba(148,163,184,0.20)" : "rgba(148,163,184,0.10)"}`,
        borderRadius: 10,
        background: available
          ? "linear-gradient(160deg, rgba(15,23,42,0.72), rgba(2,6,23,0.62))"
          : "rgba(2,6,23,0.42)",
        padding: 14,
        display: "flex", flexDirection: "column", gap: 10,
        opacity: available ? 1 : 0.65,
        minHeight: 140,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Icon size={16} style={{ color: meta.accent }} />
          <span style={{
            fontFamily: "JetBrains Mono, monospace",
            fontSize: 10, letterSpacing: "0.14em",
            color: "rgba(148,163,184,0.75)", textTransform: "uppercase",
          }}>
            {pointer.domain}
          </span>
        </div>
        <StatusChip status={pointer.status} />
      </div>
      <div style={{
        fontSize: 14, fontWeight: 600, color: "#e2e8f0",
        lineHeight: 1.35,
      }}>
        {pointer.label}
      </div>
      {pointer.hint && (
        <div style={{
          fontSize: 11, color: "rgba(148,163,184,0.75)",
          lineHeight: 1.4,
        }}>
          {pointer.hint}
        </div>
      )}
      {!available && pointer.reason && (
        <div style={{
          fontSize: 11, color: "rgba(148,163,184,0.65)",
          fontStyle: "italic", lineHeight: 1.4,
        }}>
          {pointer.reason}
        </div>
      )}
      <div style={{ flex: 1 }} />
      <button
        type="button"
        onClick={handleLaunch}
        disabled={!available}
        data-testid={T.domainLaunch(pointer.domain)}
        className="nvx-btn sm"
        style={{
          alignSelf: "flex-start",
          display: "inline-flex", alignItems: "center", gap: 6,
          cursor: available ? "pointer" : "not-allowed",
        }}
      >
        {available ? "Open in new tab" : "Not available"}
        {available && <ExternalLink size={12} />}
      </button>
    </div>
  );
}

function StatusChip({ status }) {
  const isOk = status === "available";
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 5,
      padding: "2px 8px", borderRadius: 4,
      fontFamily: "JetBrains Mono, monospace",
      fontSize: 9, letterSpacing: "0.14em", textTransform: "uppercase",
      color: isOk ? "#86efac" : "rgba(148,163,184,0.85)",
      background: isOk ? "rgba(34,197,94,0.14)" : "rgba(148,163,184,0.08)",
      border: `1px solid ${isOk ? "rgba(34,197,94,0.4)" : "rgba(148,163,184,0.24)"}`,
    }}>
      <span style={{
        width: 6, height: 6, borderRadius: "50%",
        background: isOk ? "#86efac" : "rgba(148,163,184,0.7)",
      }} />
      {isOk ? "Available" : "Unavailable"}
    </span>
  );
}

function SectionHeading({ title, hint }) {
  return (
    <div>
      <div style={{
        fontFamily: "JetBrains Mono, monospace",
        fontSize: 11, letterSpacing: "0.18em",
        color: "rgba(148,163,184,0.85)",
        textTransform: "uppercase",
      }}>
        {title}
      </div>
      {hint && (
        <div style={{ marginTop: 4, fontSize: 12,
                        color: "rgba(148,163,184,0.65)" }}>
          {hint}
        </div>
      )}
    </div>
  );
}
