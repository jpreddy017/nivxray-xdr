/**
 * X1 · Capability-honest information-architecture node.
 *
 * The XDR information architecture is kept COMPLETE — an analyst should
 * be able to see that a capability belongs to NivXRay XDR — while the
 * page states plainly that it is not operational. It renders no metric,
 * no chart and no control, because a zero that looks like data is worse
 * than an honest absence.
 */
import React from "react";
import { Link, useLocation } from "react-router-dom";
import { Lock } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";

const NODES = {
  "assets-identity": {
    title: "Identity / Users",
    trail: "Assets › Identity / Users",
    state: "NOT_IMPLEMENTED",
    why: ("No identity provider, directory or authentication telemetry is "
          "ingested by this platform, so no user asset can be represented."),
    would: ["identity.asset", "session.activity", "authentication.event"],
    needs: ["An identity source (IdP / directory / auth log) integration",
            "Identity correlation into the canonical evidence model"],
    related: [["Endpoints (operational)", "/xdr/endpoints"]],
  },
  "assets-network": {
    title: "Network assets",
    trail: "Assets › Network assets",
    state: "NOT_IMPLEMENTED",
    why: ("No network inventory, flow or device-management source is "
          "ingested, so a network asset would be an assertion, not a "
          "record."),
    would: ["network.asset", "flow.observation", "segment.topology"],
    needs: ["An NDR / flow / network inventory source",
            "Asset identity minting for network devices"],
    related: [["Endpoints (operational)", "/xdr/endpoints"]],
  },
  "attack-paths": {
    title: "Attack paths",
    trail: "Assets › Attack paths",
    state: "NOT_IMPLEMENTED",
    why: ("Attack-path analysis needs identity, network and exposure "
          "graphs. Two of the three do not exist in this build, so any "
          "path drawn would be invented."),
    would: ["attack.path", "path.chokepoint", "path.blast_radius"],
    needs: ["Identity assets", "Network assets", "Exposure findings"],
    related: [["Vulnerability exposure", "/xdr/exposure"],
              ["MITRE ATT&CK coverage", "/xdr/intelligence/mitre"]],
  },
  "critical-assets": {
    title: "Critical assets",
    trail: "Assets › Critical assets",
    state: "NOT_IMPLEMENTED",
    why: ("Business criticality is an owner-declared classification. "
          "Nothing in this platform declares it, and inferring it from "
          "activity volume would be a guess presented as governance."),
    would: ["asset.criticality", "asset.owner", "asset.business_service"],
    needs: ["An asset criticality/ownership source or an operator-declared "
            "classification surface"],
    related: [["Endpoints (operational)", "/xdr/endpoints"]],
  },
  "sla-aging": {
    title: "SLA / Aging",
    trail: "Incidents › SLA / Aging",
    state: "NOT_IMPLEMENTED",
    why: ("No service-level policy is configured for any customer, so an "
          "incident cannot be measured as inside or outside an SLA."),
    would: ["sla.policy", "sla.breach", "queue.aging"],
    needs: ["Per-customer SLA policy configuration"],
    related: [["Incident queue", "/xdr/incidents"]],
  },
};

export default function XdrNotImplementedPage({ node }) {
  const { pathname } = useLocation();
  const cap = NODES[node];

  if (!cap) {
    return (
      <XdrShell>
        <div className="x-empty" data-testid="xdr-node-unknown">
          <b>UNKNOWN NODE</b> — {pathname} names no capability in this
          build. Nothing is rendered rather than something invented.
        </div>
      </XdrShell>
    );
  }

  return (
    <XdrShell>
      <div style={{ padding: "14px 18px 26px", maxWidth: 900 }}
           data-testid={`xdr-not-implemented-${node}`}
           data-capability-state={cap.state}>
        <div style={{ fontSize: 10, letterSpacing: .8, color: "var(--muted)",
                      textTransform: "uppercase", marginBottom: 4 }}>
          {cap.trail}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>
            {cap.title}
          </h1>
          <span data-testid="xdr-capability-state"
                style={{ fontSize: 9.6, fontWeight: 800, letterSpacing: .8,
                         padding: "3px 8px", borderRadius: 2,
                         border: "1px solid var(--border)",
                         color: "var(--amber, #F5A524)" }}>
            <Lock size={9} style={{ verticalAlign: "middle",
                                    marginRight: 5 }} />
            {cap.state}
          </span>
        </div>

        <p style={{ fontSize: 12, color: "var(--text)", lineHeight: 1.65,
                    marginTop: 12 }}>
          This capability belongs to NivXRay XDR and is <b>not operational
          in this build</b>. {cap.why}
        </p>

        <div className="panel" style={{ padding: "10px 14px",
                                        marginTop: 14 }}>
          <div style={{ fontSize: 9.6, letterSpacing: .8,
                        color: "var(--muted)", textTransform: "uppercase" }}>
            What it would produce
          </div>
          <ul style={{ margin: "6px 0 12px 18px", fontSize: 11.4,
                       lineHeight: 1.7, color: "var(--muted)" }}>
            {cap.would.map((w) => <li key={w} className="mono">{w}</li>)}
          </ul>
          <div style={{ fontSize: 9.6, letterSpacing: .8,
                        color: "var(--muted)", textTransform: "uppercase" }}>
            What it requires first
          </div>
          <ul style={{ margin: "6px 0 0 18px", fontSize: 11.4,
                       lineHeight: 1.7, color: "var(--muted)" }}>
            {cap.needs.map((n) => <li key={n}>{n}</li>)}
          </ul>
        </div>

        <div style={{ marginTop: 14, display: "flex", gap: 8,
                      flexWrap: "wrap" }}>
          {cap.related.map(([label, to]) => (
            <Link key={to} to={to} className="btn ghost"
                  data-testid={`xdr-node-related-${to}`}
                  style={{ fontSize: 11, padding: "5px 11px",
                           textDecoration: "none" }}>
              {label}
            </Link>
          ))}
        </div>
      </div>
    </XdrShell>
  );
}
