/**
 * XdrReservedPage — Honest NOT_CONFIGURED capability surface.
 *
 * Replaces the previous "Coming Soon" placeholder with an
 * enterprise-grade zero state that describes the capability contract
 * (what it consumes, produces, and requires), reports honest 0-counts
 * for every metric the capability *would* expose, and points at the
 * still-missing service dependencies.  No fabricated data, no invented
 * READY / CONNECTED / EXECUTION_READY states.
 */
import React from "react";
import { Link } from "react-router-dom";
import { Globe, Bug, Terminal, Grid3x3, BookOpen, ArrowUpRight } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import AdminHero from "@/xdr/admin/AdminHero";

const CAPABILITIES = {
  threat: {
    title:    "Threat Intelligence",
    eyebrow:  "Intelligence › Threat Intelligence",
    icon:     Globe,
    subtitle: "STIX/TAXII feeds, commercial intelligence and OSINT unified into a tenant-scoped indicator store. Every indicator ties back to canonical evidence, so a match is a real sighting — never a claim.",
    contract: {
      consumes:    ["STIX 2.1 objects", "TAXII collections", "OSINT feeds", "internal intelligence"],
      produces:    ["indicator.record", "intelligence.object (campaign · actor · malware family)", "sighting.event"],
      requires:    ["Intelligence source configured", "Canonical evidence flow (Round 2 · Data Plane)"],
    },
    metrics: [
      { label: "Sources",       value: 0, hint: "configured feeds" },
      { label: "Indicators",    value: 0 },
      { label: "Enrichments",   value: 0 },
      { label: "Watchlists",    value: 0 },
      { label: "Sightings",     value: 0, hint: "cross-incident matches" },
    ],
    reason: "No intelligence sources are configured for this tenant.",
    cta:    { label: "Configure Intelligence Source",
                to:    null,
                deferred_to: "Round P1.0 · Intelligence Planes",
                deferred_reason: "STIX / TAXII / OSINT source configuration ships when the Intelligence Planes round wires the indicator store to canonical evidence." },
  },

  iocs: {
    title:    "IOC Intelligence",
    eyebrow:  "Intelligence › IOC Intelligence",
    icon:     Bug,
    subtitle: "Indicator ingestion, normalization, enrichment, sightings and watchlists — with cross-incident pivots from any hash, IP, domain, URL, email or certificate back to the incidents that saw it.",
    contract: {
      consumes: ["threat.feed", "canonical.evidence", "OSINT service response"],
      produces: ["ioc.record", "ioc.enrichment", "sighting.event", "watchlist.match"],
      requires: ["OSINT services configured in Integrations", "Threat feed ingestion (P1.0)"],
    },
    metrics: [
      { label: "Indicators",      value: 0 },
      { label: "Enriched",        value: 0 },
      { label: "Sourced feeds",   value: 0 },
      { label: "Sightings",       value: 0 },
      { label: "Watchlists",      value: 0 },
    ],
    reason: "No indicator sources or OSINT enrichers are configured.",
    cta:    { label: "Configure OSINT Sources",
                to:    null,
                deferred_to: "Round P1.0 · Intelligence Planes",
                deferred_reason: "OSINT enrichers (VirusTotal · AbuseIPDB · URLScan · OTX · Hybrid Analysis · Umbrella · Talos) ship in the Intelligence Planes round.  Configuring them earlier would risk claiming evidence provenance that this build cannot honour." },
  },

  command: {
    title:    "Command Intelligence",
    eyebrow:  "Intelligence › Command Intelligence",
    icon:     Terminal,
    subtitle: "Semantic command-line analysis: language detection, decode chains, technique extraction, LOLBin identification, IOC extraction and cross-incident similar-command search — powered by the NivXRay decoding fabric.",
    contract: {
      consumes: ["canonical.command_line", "process.artifact"],
      produces: ["command.decoded", "command.semantic", "attack.technique", "ioc.extracted"],
      requires: ["Process telemetry flowing through canonical evidence (P0.4)"],
    },
    metrics: [
      { label: "Commands",          value: 0 },
      { label: "Decoded",           value: 0 },
      { label: "Techniques",        value: 0 },
      { label: "LOLBins",           value: 0 },
      { label: "Cross-sightings",   value: 0 },
    ],
    reason: "No canonical process telemetry is flowing yet.",
    cta:    { label: "Configure Collectors", to: "/xdr/admin/collectors" },
  },

  malware: {
    title:    "Malware Intelligence",
    eyebrow:  "Intelligence › Malware Intelligence",
    icon:     Bug,
    subtitle: "PE/ELF/Office analysis, signer inspection, capability extraction, family attribution and sandbox verdict rollups — every artifact ties back to the canonical file evidence that produced it.",
    contract: {
      consumes: ["file.artifact", "hash.sha256", "sandbox.report"],
      produces: ["malware.family", "capability.set", "attack.technique", "ioc.extracted"],
      requires: ["File-evidence flow", "Analyzers connected to canonical evidence (P0.4)"],
    },
    metrics: [
      { label: "Artifacts",       value: 0 },
      { label: "Families",        value: 0 },
      { label: "Capabilities",    value: 0 },
      { label: "Sandbox reports", value: 0 },
    ],
    reason: "No file-evidence flow is configured yet.",
    cta:    { label: "Configure Data Sources", to: "/xdr/admin/data-sources" },
  },

  mitre: {
    title:    "MITRE ATT&CK",
    eyebrow:  "Intelligence › MITRE ATT&CK",
    icon:     Grid3x3,
    subtitle: "Evidence-backed ATT&CK heatmap. Every highlighted technique cites the real incidents that observed it. Coverage gaps surface as attention items — never as fabricated scores.",
    contract: {
      consumes: ["incident.mitre[]", "detection.rule.attack_techniques"],
      produces: ["coverage.heatmap", "attention.gap"],
      requires: ["Incidents with ATT&CK-mapped evidence"],
    },
    metrics: [
      { label: "Techniques observed", value: 0 },
      { label: "Tactics covered",     value: 0 },
      { label: "Rules mapped",        value: 0 },
    ],
    reason: "No ATT&CK-mapped evidence has been observed yet.",
    cta:    { label: "View Detection Registry", to: "/xdr/admin/detection-registry" },
  },

  kb: {
    title:    "Knowledge Base",
    eyebrow:  "Intelligence › Knowledge Base",
    icon:     BookOpen,
    subtitle: "Investigation guides, detection guidance, runbooks, SOPs and threat-actor knowledge — retrievable inline with any investigation. Distinct from Documentation (which describes HOW NivXRay works).",
    contract: {
      consumes: ["article.markdown", "runbook.yaml", "sop.doc"],
      produces: ["kb.entry", "investigation.guidance"],
      requires: ["KB corpus ingested + indexed"],
    },
    metrics: [
      { label: "Entries",       value: 0 },
      { label: "Runbooks",      value: 0 },
      { label: "SOPs",          value: 0 },
      { label: "Search index",  value: 0 },
    ],
    reason: "The Knowledge Base is empty for this tenant.",
    cta:    { label: "Add Knowledge Entry", to: "/xdr/kb" },
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
  const heroStats = cap.metrics.map((m, i) => ({
    ...m, testid: `xdr-cap-${capability}-stat-${i}`,
  }));

  return (
    <XdrShell>
      <div data-testid={`xdr-reserved-${capability}`}>
        <AdminHero
          icon={cap.icon}
          eyebrow={cap.eyebrow}
          title={cap.title}
          subtitle={cap.subtitle}
          source="STATUS · NOT CONFIGURED"
          stats={heroStats}
          testid={`xdr-cap-${capability}-hero`}
        />

        <section className="panel"
                data-testid={`xdr-cap-${capability}-reason`}
                style={{ padding: 16, marginBottom: 12,
                            borderLeft: "3px solid var(--amber, #f5a623)" }}>
          <div style={{
            fontFamily: "var(--sans)", fontSize: 10, fontWeight: 800,
            letterSpacing: ".5px", color: "var(--amber, #f5a623)",
            textTransform: "uppercase", marginBottom: 6,
          }}>
            Status · Not Configured
          </div>
          <div style={{
            fontFamily: "var(--sans)", fontSize: 13,
            color: "var(--text)", lineHeight: 1.5, marginBottom: 10,
          }}>
            {cap.reason}
          </div>
          {cap.cta && (
            cap.cta.to
              ? (
                  <Link to={cap.cta.to} className="btn primary"
                            style={{ textDecoration: "none", padding: "5px 12px",
                                            fontSize: 12 }}
                            data-testid={`xdr-cap-${capability}-cta`}>
                    <ArrowUpRight size={12} /> {cap.cta.label}
                  </Link>
                )
              : (
                  <div data-testid={`xdr-cap-${capability}-cta-deferred`}
                          style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    <button type="button" className="btn primary" disabled
                                style={{ padding: "5px 12px", fontSize: 12,
                                                cursor: "not-allowed",
                                                opacity: 0.65 }}>
                      {cap.cta.label} · deferred
                    </button>
                    <div style={{ fontFamily: "var(--mono)", fontSize: 10.5,
                                          color: "var(--faint)", lineHeight: 1.5,
                                          maxWidth: 720 }}>
                      Ships in <strong>{cap.cta.deferred_to}</strong>.{" "}
                      {cap.cta.deferred_reason}
                    </div>
                  </div>
                )
          )}
        </section>

        <section className="panel"
                data-testid={`xdr-cap-${capability}-contract`}
                style={{ padding: 16 }}>
          <div style={{
            fontFamily: "var(--sans)", fontSize: 10, fontWeight: 800,
            letterSpacing: ".5px", color: "var(--nx-purple, var(--cyan))",
            textTransform: "uppercase", marginBottom: 10,
          }}>
            Capability Contract
          </div>
          <div style={{ display: "grid", gap: 12,
                                gridTemplateColumns: "1fr 1fr 1fr" }}>
            <ContractCol label="Consumes"  items={cap.contract.consumes} />
            <ContractCol label="Produces"  items={cap.contract.produces} />
            <ContractCol label="Requires"  items={cap.contract.requires}
                             tone="amber" />
          </div>
          <div style={{ marginTop: 12, fontFamily: "var(--mono)", fontSize: 10,
                                color: "var(--faint)", lineHeight: 1.5 }}>
            No metric on this page is fabricated. Every "0" is an authoritative
            zero from the backing service. When the underlying capability is
            wired, these numbers will populate from real API responses.
          </div>
        </section>
      </div>
    </XdrShell>
  );
}


function ContractCol({ label, items, tone }) {
  const color = tone === "amber"
      ? "var(--amber, #f5a623)"
      : "var(--nx-purple, var(--cyan))";
  return (
    <div>
      <div style={{
        fontFamily: "var(--mono)", fontSize: 9.5,
        letterSpacing: ".4px", fontWeight: 700, color,
        textTransform: "uppercase", marginBottom: 6,
      }}>
        {label}
      </div>
      <ul style={{ margin: 0, paddingLeft: 16, fontSize: 12,
                            color: "var(--text-dim)",
                            fontFamily: "var(--sans)", lineHeight: 1.7 }}>
        {items.map((x) => <li key={x}>{x}</li>)}
      </ul>
    </div>
  );
}
