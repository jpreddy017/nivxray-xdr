/**
 * XdrReservedPage · Slice 7.
 *
 * Transitional placeholder for native XDR capabilities that will be
 * built in a later slice.  Replaces the older behaviour of deep-linking
 * back into the base NivXRay UI (`/analyze`, `/heatmap`, `/analyst`,
 * `/v2/irg`) which broke the "no base UI in normal XDR workflows"
 * guardrail.
 *
 * Quality bar (locked): every reserved surface names WHAT the
 * native version will do, WHICH authoritative NivXRay API/engine it
 * will consume (never a UI dependency), and WHEN in the roadmap
 * it lands — so the analyst always sees a promise, never a dead-end.
 */
import React from "react";
import { Link } from "react-router-dom";
import { Lock, ArrowUpRight } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";

const CAPABILITIES = {
  threat: {
    title:  "Threat Intelligence",
    slice:  "coming soon",
    tagline: "Indicator search, malware family drilldown and cross-incident sightings — coming to this workspace.",
    highlights: [
      "Search across your intelligence estate — indicators, families, campaigns.",
      "Pivot from a single indicator to every incident where it appears.",
      "Family-level drilldown with authoritative attribution.",
    ],
  },
  iocs: {
    title:  "IOC Intelligence",
    slice:  "coming soon",
    tagline: "Enrichment, sightings and watchlists for indicators of compromise.",
    highlights: [
      "Automatic enrichment from your configured OSINT services.",
      "Cross-incident sightings for any hash, IP, domain or URL.",
      "Watchlists that route matched indicators into new investigations.",
    ],
  },
  command: {
    title:  "Command Intelligence",
    slice:  "coming soon",
    tagline: "Static command-line decoding and adversary tradecraft analysis inline in the workspace.",
    highlights: [
      "Decode obfuscated shell / PowerShell / cmd.exe payloads in one click.",
      "Correlate decoded commands with observed technique coverage.",
      "Pivot from a suspicious command to every incident that saw it.",
    ],
  },
  malware: {
    title:  "Malware Intelligence",
    slice:  "coming soon",
    tagline: "PE metadata, signer analysis, sandbox verdicts and family attribution — inline with your investigations.",
    highlights: [
      "Rich file-analysis pane for every artifact captured in evidence.",
      "Signer and metadata deep-dive with high-confidence family attribution.",
      "Sandbox verdict rollups from configured detonation services.",
    ],
  },
  mitre: {
    title:  "MITRE ATT&CK",
    slice:  "coming soon",
    tagline: "Evidence-backed ATT&CK heatmap — every highlighted technique cites the incidents that observed it.",
    highlights: [
      "Interactive matrix with detection-coverage overlays per lane.",
      "Click any technique to see the incidents that provide evidence.",
      "Coverage gaps surface as attention items, never as fabricated scores.",
    ],
  },
  kb: {
    title:  "Knowledge Base",
    slice:  "coming soon",
    tagline: "Operational knowledge base — playbooks, runbooks and tenant SOPs — inline with investigations.",
    highlights: [
      "Full-text search across every playbook and runbook.",
      "Contextual snippets surfaced automatically inside investigations.",
      "Tenant-specific SOPs that never leak across customers.",
    ],
  },
};

export default function XdrReservedPage({ capability }) {
  const cap = CAPABILITIES[capability];
  if (!cap) {
    return (
      <XdrShell>
        <div className="x-empty" data-testid="xdr-reserved-unknown">
          <b>Not available.</b> This capability isn't recognised —{" "}
          <span className="mono">{capability}</span>.
        </div>
      </XdrShell>
    );
  }
  return (
    <XdrShell>
      <div data-testid={`xdr-reserved-${capability}`}>
        <h1 className="page-h1" style={{ margin: 0 }}>{cap.title}</h1>
        <div className="page-sub" style={{ marginBottom: 20 }}>
          {cap.tagline}
        </div>
        <section className="panel" style={{ padding: 22 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10,
                          marginBottom: 14 }}>
            <span style={{
              width: 32, height: 32,
              display: "inline-flex", alignItems: "center", justifyContent: "center",
              background: "var(--nx-purple-dim)", color: "var(--nx-purple)",
              borderRadius: 8,
            }}>
              <Lock size={16} />
            </span>
            <div>
              <div style={{
                fontFamily: "var(--sans)", fontSize: 10, letterSpacing: 0.6,
                fontWeight: 800, textTransform: "uppercase",
                color: "var(--nx-muted)",
              }}>
                Coming soon
              </div>
              <div style={{
                fontFamily: "var(--sans)", fontSize: 14, fontWeight: 700,
                color: "var(--nx-text)",
              }}>
                What this workspace will do
              </div>
            </div>
          </div>
          <ul style={{ margin: 0, paddingLeft: 20,
                          color: "var(--nx-text)",
                          fontSize: 13, lineHeight: 1.75,
                          fontFamily: "var(--sans)" }}>
            {cap.highlights.map((h) => <li key={h}>{h}</li>)}
          </ul>
          <div style={{ marginTop: 20,
                          display: "flex", gap: 8 }}>
            <Link to="/xdr/incidents" className="btn primary"
                    style={{ textDecoration: "none" }}
                    data-testid={`xdr-reserved-${capability}-back`}>
              <ArrowUpRight size={12} /> Back to Incidents
            </Link>
          </div>
        </section>
      </div>
    </XdrShell>
  );
}
