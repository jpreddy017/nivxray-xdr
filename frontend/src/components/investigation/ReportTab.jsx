/**
 * Investigation · Report tab — print-friendly executive summary.
 * Renders verdict, MITRE, IOCs, fingerprint hash, and a compact chain
 * synopsis. `window.print()` triggers a native print dialog.
 */
import { Printer } from "lucide-react";

export default function ReportTab({ inv, summary, chain, fp }) {
  const iocCounts = summary?.iocs || {};
  return (
    <div data-testid="tab-panel-report"
         style={{ background: "#f7fafc", color: "#0f172a", padding: 28,
                  borderRadius: 12, border: "1px solid #cbd5e1",
                  fontFamily: "Inter, system-ui, sans-serif" }}>
      <div style={{ display: "flex", alignItems: "flex-start", gap: 12,
                    justifyContent: "space-between", marginBottom: 16 }}>
        <div>
          <div style={{ fontSize: 11, letterSpacing: "0.18em",
                        textTransform: "uppercase", color: "#64748b" }}>
            NivXRay · Investigation Report
          </div>
          <h1 style={{ fontSize: 24, margin: "6px 0 0", color: "#0f172a" }}
              data-testid="report-investigation-name">
            {inv?.name || "Investigation"}
          </h1>
          {inv?.description && (
            <div style={{ marginTop: 6, color: "#334155", fontSize: 13 }}>
              {inv.description}
            </div>
          )}
        </div>
        <button data-testid="report-print"
                onClick={() => window.print()}
                style={{ padding: "8px 12px", fontSize: 12, borderRadius: 8,
                         background: "#0f172a", color: "#f7fafc",
                         border: "1px solid #0f172a", cursor: "pointer",
                         display: "inline-flex", gap: 6, alignItems: "center" }}>
          <Printer size={14} /> Print
        </button>
      </div>

      <section style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr",
                        gap: 12, marginBottom: 20 }}>
        <Stat label="Verdict" value={(summary?.verdict || "—").toUpperCase()}
              testid="report-verdict" />
        <Stat label="Risk score" value={summary?.risk_score ?? "—"}
              testid="report-risk" />
        <Stat label="Attack fingerprint"
              value={fp?.hash ? `${fp.hash.slice(0, 16)}…` : "—"}
              mono testid="report-fingerprint" />
      </section>

      <ReportSection title="MITRE ATT&CK techniques">
        {(summary?.mitre || []).length === 0
          ? <em style={{ color: "#64748b" }}>None mapped.</em>
          : (summary.mitre.map(m => (
              <span key={m.id}
                    style={{ marginRight: 6, display: "inline-block",
                             padding: "2px 8px", fontSize: 12,
                             background: "#fef3c7", color: "#78350f",
                             borderRadius: 4,
                             fontFamily: "ui-monospace, monospace" }}>
                {m.id}
                {m.technique ? ` · ${m.technique}` : ""}
              </span>
            )))}
      </ReportSection>

      <ReportSection title="Indicators of compromise">
        {Object.keys(iocCounts).length === 0
          ? <em style={{ color: "#64748b" }}>No IOCs surfaced.</em>
          : (
            <ul style={{ margin: 0, paddingLeft: 18, fontSize: 13 }}>
              {Object.entries(iocCounts).map(([k, v]) => (
                <li key={k}><b>{k}</b>: {Array.isArray(v) ? v.length : v}</li>
              ))}
            </ul>
          )}
      </ReportSection>

      <ReportSection title={`Attack chain (${chain?.steps?.length || 0} step${
                              chain?.steps?.length === 1 ? "" : "s"})`}>
        {!chain?.steps?.length
          ? <em style={{ color: "#64748b" }}>Chain not yet reconstructed.</em>
          : (
            <ol style={{ margin: 0, paddingLeft: 18, fontSize: 13,
                          color: "#0f172a" }}>
              {chain.steps.slice(0, 30).map((s, i) => (
                <li key={s.node_id || i} style={{ marginBottom: 4 }}>
                  <span style={{ fontFamily: "ui-monospace, monospace",
                                 color: "#0369a1" }}>
                    {s.kind}
                  </span>
                  {" · "}
                  {s.case_name || s.label || s.artifact_type
                    || s.node_id?.slice(0, 24)}
                </li>
              ))}
              {chain.steps.length > 30 && (
                <li style={{ color: "#64748b" }}>
                  … {chain.steps.length - 30} more step(s) truncated.
                </li>
              )}
            </ol>
          )}
      </ReportSection>
    </div>
  );
}

function Stat({ label, value, mono, testid }) {
  return (
    <div data-testid={testid}
         style={{ background: "#ffffff", border: "1px solid #cbd5e1",
                  borderRadius: 8, padding: "10px 12px" }}>
      <div style={{ fontSize: 10, letterSpacing: "0.16em",
                    textTransform: "uppercase", color: "#64748b" }}>
        {label}
      </div>
      <div style={{ marginTop: 4, fontSize: 18, fontWeight: 700,
                    color: "#0f172a",
                    fontFamily: mono ? "ui-monospace, monospace" : undefined }}>
        {value}
      </div>
    </div>
  );
}

function ReportSection({ title, children }) {
  return (
    <section style={{ marginBottom: 18 }}>
      <div style={{ fontSize: 11, letterSpacing: "0.16em",
                    textTransform: "uppercase", color: "#64748b",
                    marginBottom: 6 }}>
        {title}
      </div>
      <div>{children}</div>
    </section>
  );
}
