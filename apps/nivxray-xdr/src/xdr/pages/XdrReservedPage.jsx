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
    slice:  "later slice",
    body:   "Native XDR TI console — indicator search, malware family drilldown, sightings across incidents.",
    apis:   ["/api/threat-intel/*", "/api/ioc/*"],
  },
  iocs: {
    title:  "IOC Intelligence",
    slice:  "later slice",
    body:   "Native XDR IOC console — enrichment, sightings, watchlists.  Consumes the existing IOC service; renders inline in XDR.",
    apis:   ["/api/ioc/*"],
  },
  command: {
    title:  "Command Intelligence",
    slice:  "Slice 14",
    body:   "Static command-line decode inline in XDR.  One decode engine — the base NivXRay decoder — consumed via API only, never re-implemented.",
    apis:   ["/api/analyze", "/api/decode/*"],
  },
  malware: {
    title:  "Malware Intelligence",
    slice:  "later slice",
    body:   "Native malware analytics inline in XDR — PE metadata, signer, sandbox reports, family attribution.  Consumes the existing artifact-intelligence service.",
    apis:   ["/api/documents/*", "/api/artifact/*"],
  },
  mitre: {
    title:  "MITRE ATT&CK",
    slice:  "later slice",
    body:   "Native ATT&CK heatmap inline in XDR, evidence-backed only — every highlighted technique cites at least one incident's Stage-2 evidence.",
    apis:   ["/api/mitre/*", "/api/incidents/*"],
  },
  kb: {
    title:  "Knowledge Base",
    slice:  "later slice",
    body:   "Native operational knowledge base inline in XDR — playbooks, runbooks, tenant SOPs.",
    apis:   ["/api/kb/*"],
  },
};

export default function XdrReservedPage({ capability }) {
  const cap = CAPABILITIES[capability];
  if (!cap) {
    return (
      <XdrShell>
        <div className="x-empty" data-testid="xdr-reserved-unknown">
          <b>NOT AVAILABLE</b> — Unknown capability{" "}
          <span className="mono">{capability}</span>.
        </div>
      </XdrShell>
    );
  }
  return (
    <XdrShell>
      <div data-testid={`xdr-reserved-${capability}`}>
        <h1 className="page-h1" style={{ margin: 0 }}>{cap.title}</h1>
        <div className="page-sub" style={{ marginBottom: 12 }}>
          Native NivXRay XDR capability · reserved for <b>{cap.slice}</b>.
        </div>
        <section className="panel2" style={{ padding: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8,
                          marginBottom: 8 }}>
            <Lock size={12} style={{ color: "var(--faint)" }} />
            <span style={{
              fontFamily: "var(--xmono)", fontSize: 9.5, letterSpacing: ".4px",
              fontWeight: 800, textTransform: "uppercase", color: "var(--faint)",
            }}>
              Reserved · Native XDR · {cap.slice}
            </span>
          </div>
          <div style={{ color: "var(--text-dim)", fontSize: 12,
                          lineHeight: 1.6, marginBottom: 10 }}>
            {cap.body}
          </div>
          <div style={{ borderTop: "1px solid var(--border)", paddingTop: 10 }}>
            <div style={{
              fontFamily: "var(--xmono)", fontSize: 9.5, letterSpacing: ".4px",
              fontWeight: 800, textTransform: "uppercase",
              color: "var(--faint)", marginBottom: 4,
            }}>
              Authoritative APIs consumed
            </div>
            <ul style={{ margin: 0, paddingLeft: 18,
                            color: "var(--cyan)", fontSize: 11,
                            fontFamily: "var(--xmono)" }}>
              {cap.apis.map((a) => <li key={a}>{a}</li>)}
            </ul>
          </div>
          <div style={{ marginTop: 12,
                          fontSize: 10.5, color: "var(--faint)" }}>
            NivXRay XDR does not deep-link the analyst back to the base
            NivXRay UI for ordinary investigation workflows.  When this
            capability arrives it will be a native XDR surface consuming
            the authoritative APIs listed above — never a copy of the
            engine or SSOT.
          </div>
          <div style={{ marginTop: 14 }}>
            <Link to="/xdr/incidents" className="btn primary"
                    style={{ padding: "6px 12px", textDecoration: "none" }}
                    data-testid={`xdr-reserved-${capability}-back`}>
              <ArrowUpRight size={11} /> Back to Incidents
            </Link>
          </div>
        </section>
      </div>
    </XdrShell>
  );
}
