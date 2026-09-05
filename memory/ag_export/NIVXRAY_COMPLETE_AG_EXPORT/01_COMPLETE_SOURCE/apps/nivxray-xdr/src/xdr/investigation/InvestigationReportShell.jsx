/**
 * InvestigationReportShell — canonical Report tab.
 *
 * Owner directive (2026-02-30 · locked): build the shell now, defer
 * full report generation until the F item passes B → E → C → A.
 *
 *   Canonical Evidence
 *          ↓
 *   Process Tree + ATT&CK Chain + Attack Story + Scenario Intelligence
 *   + Evidence Graph + IOC/TI + Network + Correlation
 *          ↓
 *   IKG → ICE → Verdict
 *          ↓
 *   AUTO-INVESTIGATION REPORT   ← this shell is its destination
 *
 * The shell renders coverage + section availability from real data
 * present in the incident.  If a section is not yet available it
 * says so explicitly — the shell NEVER fabricates report content.
 */
import React from "react";
import { FileText, CheckCircle2, AlertTriangle, Download } from "lucide-react";


export default function InvestigationReportShell({ incident }) {
  const sections = deriveSections(incident);
  const coverage = deriveCoverage(incident);

  return (
    <section data-testid="xdr-report-shell" style={{ marginTop: 14 }}>
      <div style={header}>
        <FileText size={13} style={{ color: "var(--cyan)" }} />
        <b style={{ fontFamily: "var(--mono)", fontSize: 12,
                                letterSpacing: 0.3 }}>INVESTIGATION REPORT</b>
        <span style={metaChip}>
          preview · shell only · full engine deferred to F
        </span>
      </div>

      <div style={frame}>
        <div style={{ padding: "12px 14px",
                                borderBottom: "1px solid var(--border)" }}>
          <div style={sectTitle}>Executive Summary</div>
          <div style={{ fontSize: 11.5, color: "var(--text-dim)",
                                    fontFamily: "var(--mono)" }}
                       data-testid="xdr-report-exec-summary">
            {incident?.title
              ? <>Investigation for <b>{incident.title}</b> · incident{" "}
                     <code>{incident.id}</code>.  Full narrative will be assembled
                     from canonical evidence once the Auto-Investigation Report
                     engine (F) is enabled.</>
              : <i>Evidence not available.  The narrative is never fabricated.</i>}
          </div>
        </div>

        <div style={{ padding: "10px 14px",
                                borderBottom: "1px solid var(--border)" }}>
          <div style={sectTitle}>Investigation Coverage</div>
          <div style={{ display: "grid",
                                    gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))",
                                    gap: 4 }}
                       data-testid="xdr-report-coverage">
            {coverage.map((c) => (
              <div key={c.facet}
                          data-testid={`xdr-report-coverage-${c.facet}`}
                          style={coverRow}>
                {c.present
                  ? <CheckCircle2 size={11} style={{ color: "var(--mint)" }} />
                  : <AlertTriangle size={11} style={{ color: "var(--amber)" }} />}
                <span style={{ fontFamily: "var(--mono)", fontSize: 10.5,
                                              color: c.present ? "var(--text)"
                                                                                : "var(--faint)" }}>
                  {c.label}
                </span>
                {!c.present && (
                  <span style={{ fontSize: 9, color: "var(--faint)",
                                                fontFamily: "var(--mono)",
                                                marginLeft: "auto" }}>
                    missing
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>

        <div style={{ padding: "10px 14px",
                                borderBottom: "1px solid var(--border)" }}>
          <div style={sectTitle}>Sections that will appear in the full report</div>
          <div style={{ display: "grid",
                                    gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
                                    gap: 4 }}
                       data-testid="xdr-report-sections">
            {sections.map((s) => (
              <div key={s.id}
                          data-testid={`xdr-report-section-${s.id}`}
                          style={coverRow}>
                <CheckCircle2 size={11}
                                            style={{ color: s.available ? "var(--mint)"
                                                                                        : "var(--faint)" }} />
                <span style={{ fontFamily: "var(--mono)", fontSize: 10.5,
                                              color: s.available ? "var(--text)"
                                                                                : "var(--faint)",
                                              fontStyle: s.available ? "normal" : "italic" }}>
                  {s.label}
                </span>
                {!s.available && (
                  <span style={{ fontSize: 9, color: "var(--faint)",
                                                fontFamily: "var(--mono)",
                                                marginLeft: "auto" }}>
                    pending F
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>

        <div style={{ padding: "12px 14px" }}>
          <button type="button" disabled
                        title="Full report generation is deferred to F · Auto-Investigation Report"
                        data-testid="xdr-report-generate"
                        style={{ ...ctrlBtn, opacity: 0.55, cursor: "not-allowed" }}>
            <Download size={11} /> Generate Full Report (PDF) · pending F
          </button>
          <div style={{ marginTop: 6, fontSize: 10, color: "var(--faint)",
                                    fontFamily: "var(--mono)", fontStyle: "italic" }}>
            Shell only.  The report engine is deferred until Scenario
            Intelligence, Process Genealogy, Attack Story and Selection
            Sync (B → E → C → A) have shipped — this preserves the
            evidence-first invariant end-to-end.
          </div>
        </div>
      </div>
    </section>
  );
}


// ── Coverage — deterministic, evidence-first ─────────────────────
function deriveCoverage(incident) {
  const evs = (incident?.verdict_stage2?.evidence || incident?.evidence || []);
  const hasField = (path) => {
    const arr = path.split(".").reduce((o, k) => o?.[k], incident);
    return Array.isArray(arr) ? arr.length > 0 : !!arr;
  };
  return [
    { facet: "identity",  label: "Identity",      present: hasField("assets.users") || hasField("users") },
    { facet: "endpoint",  label: "Endpoint",      present: hasField("assets.hosts") || hasField("hosts") },
    { facet: "process",   label: "Process",       present: hasField("processes") || hasField("process_tree") || evs.some((e) => e?.entity?.image) },
    { facet: "network",   label: "Network",       present: hasField("network") || hasField("connections") },
    { facet: "iocs",      label: "IOCs / TI",     present: hasField("iocs") },
    { facet: "mitre",     label: "ATT&CK mapping", present: hasField("mitre") || evs.some((e) => e?.technique_id) },
    { facet: "detection", label: "Detection",     present: evs.some((e) => e?.rule_id) },
    { facet: "evidence",  label: "Evidence",      present: evs.length > 0 },
  ];
}

function deriveSections(incident) {
  const c = Object.fromEntries(deriveCoverage(incident).map((x) => [x.facet, x.present]));
  return [
    { id: "exec",     label: "Executive Summary",   available: true },
    { id: "process",  label: "Process Tree",         available: c.process },
    { id: "attck",    label: "ATT&CK Chain",         available: c.mitre },
    { id: "story",    label: "Attack Story",         available: false },  // needs C
    { id: "trajectory", label: "Evidence Trajectory", available: c.evidence },
    { id: "iocs",     label: "IOCs / TI",           available: c.iocs },
    { id: "network",  label: "Network / DNS / Proxy", available: c.network },
    { id: "correlation", label: "Correlation",       available: false },  // needs E → correlation feed
    { id: "scenario", label: "Scenario Guidance",    available: true },
    { id: "verdict",  label: "Verdict & Evidence Gaps", available: !!incident?.verdict },
  ];
}


// ── styles ────────────────────────────────────────────────────────
const header = { display: "flex", alignItems: "center", gap: 8, marginBottom: 8, padding: "0 4px", flexWrap: "wrap" };
const metaChip = { padding: "1px 6px", fontSize: 9.5, fontFamily: "var(--mono)", fontWeight: 700, background: "var(--panel2)", border: "1px solid var(--border)", borderRadius: 2, color: "var(--faint)" };
const frame  = { border: "1px solid var(--border)", borderRadius: 3, background: "var(--panel)" };
const sectTitle = { fontSize: 9, color: "var(--faint)", fontFamily: "var(--mono)", fontWeight: 700, letterSpacing: 0.4, textTransform: "uppercase", marginBottom: 5 };
const coverRow = { display: "flex", alignItems: "center", gap: 5, padding: "3px 5px", border: "1px solid var(--border)", borderRadius: 2, background: "var(--panel2)" };
const ctrlBtn = { padding: "6px 10px", fontSize: 11, fontWeight: 700, background: "var(--panel2)", border: "1px solid var(--border)", color: "var(--text)", borderRadius: 2, fontFamily: "var(--mono)", display: "inline-flex", alignItems: "center", gap: 5 };
