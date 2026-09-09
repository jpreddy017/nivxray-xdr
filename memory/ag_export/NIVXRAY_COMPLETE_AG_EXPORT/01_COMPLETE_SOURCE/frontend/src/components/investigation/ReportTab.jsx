/**
 * Investigation · Report tab — canonical 12-section deterministic
 * report backed by the DIE Narrative + Confidence engines.
 *
 * Owner-locked (2026-02-16 evening): fixed 12-section structure,
 * confidence badge per section, Confidence Summary legend at the
 * bottom.  Reports live ONLY here — no export button anywhere else.
 */
import { useEffect, useState } from "react";
import { Printer } from "lucide-react";
import api from "@/lib/api";

const BUCKET_TONE = {
  High:      { fg: "#16a34a", bg: "#dcfce7", bd: "#86efac" },
  Moderate:  { fg: "#a16207", bg: "#fef9c3", bd: "#facc15" },
  "Requires validation": { fg: "#b91c1c", bg: "#fee2e2", bd: "#fca5a5" },
};

export default function ReportTab({ inv, summary, chain, fp }) {
  const [rep, setRep] = useState(null);
  const [err, setErr] = useState("");
  const caseId = inv?.root_case_id;

  useEffect(() => {
    if (!caseId) return;
    api.get(`/die/report/${caseId}`)
       .then(r => r.data?.report ? setRep(r.data.report)
                                  : setErr(r.data?.error || "no report"))
       .catch(e => setErr(e?.response?.data?.detail || e.message));
  }, [caseId]);

  return (
    <div data-testid="tab-panel-report"
         style={{ background: "#f7fafc", color: "#0f172a", padding: 28,
                  borderRadius: 12, border: "1px solid #cbd5e1",
                  fontFamily: "Inter, system-ui, sans-serif" }}>
      <div style={{ display: "flex", alignItems: "flex-start", gap: 12,
                    justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <div style={{ fontSize: 11, letterSpacing: "0.18em",
                        textTransform: "uppercase", color: "#64748b" }}>
            NivXRay · Investigation Report
          </div>
          <h1 data-testid="report-investigation-name"
              style={{ fontSize: 24, margin: "6px 0 0", color: "#0f172a" }}>
            {inv?.name || "Investigation"}
          </h1>
          {rep?.confidence && (
            <div style={{ marginTop: 6 }}>
              <span data-testid="report-overall-confidence"
                    style={{ padding: "3px 10px", borderRadius: 4,
                             fontSize: 12, fontWeight: 700,
                             background: BUCKET_TONE[rep.confidence.bucket]?.bg,
                             color:      BUCKET_TONE[rep.confidence.bucket]?.fg,
                             border: `1px solid ${BUCKET_TONE[rep.confidence.bucket]?.bd}` }}>
                Overall Confidence · {rep.confidence.overall}% ({rep.confidence.bucket})
              </span>
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

      {err && (
        <div data-testid="report-error"
             style={{ padding: 10, background: "#fef2f2",
                      border: "1px solid #fca5a5", color: "#7f1d1d",
                      borderRadius: 6, fontSize: 12 }}>
          Report unavailable · {err}
        </div>
      )}

      {rep?.sections?.map((s, i) => {
        const tone = BUCKET_TONE[s.bucket] || BUCKET_TONE.Moderate;
        return (
          <section key={i} data-testid={`report-section-${i+1}`}
                   style={{ marginBottom: 22 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10,
                          marginBottom: 6 }}>
              <div style={{ fontSize: 10, letterSpacing: "0.16em",
                            textTransform: "uppercase", color: "#64748b",
                            fontWeight: 700 }}>
                {i+1}. {s.title}
              </div>
              <span data-testid={`report-section-${i+1}-confidence`}
                    style={{ marginLeft: "auto", padding: "1px 8px",
                             fontSize: 10, borderRadius: 3,
                             background: tone.bg, color: tone.fg,
                             border: `1px solid ${tone.bd}`,
                             fontFamily: "ui-monospace, monospace" }}>
                {s.confidence}% · {s.bucket}
              </span>
            </div>
            <div style={{ background: "#ffffff", border: "1px solid #cbd5e1",
                          borderRadius: 8, padding: "12px 14px",
                          fontSize: 13, lineHeight: 1.55,
                          whiteSpace: "pre-wrap",
                          fontFamily: /Confidence Summary|Detection|Technical|Attack Story/.test(s.title)
                                        ? "ui-monospace, monospace"
                                        : "Inter, system-ui, sans-serif" }}>
              {s.body || <em style={{ color: "#94a3b8" }}>(empty)</em>}
            </div>
          </section>
        );
      })}
    </div>
  );
}
