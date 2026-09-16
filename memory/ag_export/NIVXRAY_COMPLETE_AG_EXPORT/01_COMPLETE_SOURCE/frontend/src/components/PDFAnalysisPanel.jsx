/**
 * PDF Analysis Panel — deterministic PDF static-analysis renderer.
 * ────────────────────────────────────────────────────────────────
 * Phase 3 · Cycle A · owner-approved 2026-02.
 *
 * Consumes the shape produced by
 * `services.artifact_intelligence.analyzers.pdf.PDFAnalyzer.analyze`.
 *
 * Sub-surfaces:
 *   1. Findings (severity-sorted)
 *   2. Overview (PDF version, page count, encryption, metadata)
 *   3. JavaScript actions
 *   4. Open / Additional actions
 *   5. Launch actions
 *   6. Embedded files
 *   7. URLs
 *
 * Graceful degradation:
 *   • pdf.available === false      → "PDF capability unavailable" card
 *   • pdf.error                    → reasoned failure card
 */
import { useMemo, useState } from "react";
import {
  ChevronDown, ChevronRight, Copy, FileText, Layers, ShieldAlert,
  Code2, Paperclip, ExternalLink, Play,
} from "lucide-react";

const _sevColor = (sev) => {
  switch (sev) {
    case "critical": return { fg: "#f43f5e", bg: "rgba(244,63,94,0.10)",  br: "rgba(244,63,94,0.45)" };
    case "high":     return { fg: "#f87171", bg: "rgba(248,113,113,0.10)", br: "rgba(248,113,113,0.40)" };
    case "medium":   return { fg: "#fcd34d", bg: "rgba(252,211,77,0.08)",  br: "rgba(252,211,77,0.35)" };
    case "low":      return { fg: "#7dd3fc", bg: "rgba(125,211,252,0.08)", br: "rgba(125,211,252,0.30)" };
    default:         return { fg: "#94a3b8", bg: "rgba(148,163,184,0.06)", br: "rgba(148,163,184,0.25)" };
  }
};

function CollapsibleSection({ title, icon: Icon, count, testId, defaultOpen = false, children }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div data-testid={testId}
         style={{ border: "1px solid var(--border)", borderRadius: 6,
                  background: "rgba(2,6,23,0.35)", marginBottom: 8 }}>
      <button type="button" onClick={() => setOpen((v) => !v)}
              data-testid={`${testId}-toggle`}
              style={{ width: "100%", display: "flex", alignItems: "center", gap: 10,
                       padding: "10px 14px", background: "transparent", border: "none",
                       cursor: "pointer", color: "var(--text)", textAlign: "left" }}>
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        {Icon && <Icon size={14} style={{ color: "var(--accent)" }} />}
        <span className="mono" style={{ fontSize: 11, letterSpacing: "0.14em", fontWeight: 700 }}>{title}</span>
        {count != null && (
          <span className="mono" style={{ fontSize: 10, color: "var(--text-dim)", marginLeft: 4 }}>({count})</span>
        )}
      </button>
      {open && <div style={{ padding: "0 14px 14px" }}>{children}</div>}
    </div>
  );
}

export default function PDFAnalysisPanel({ pdf, hashes }) {
  if (!pdf) return null;
  if (pdf.available === false) {
    return (
      <div data-testid="pdf-analysis-unavailable"
           style={{ border: "1px dashed rgba(148,163,184,0.35)", borderRadius: 6,
                    padding: "14px 18px", background: "rgba(2,6,23,0.35)", marginBottom: 12 }}>
        <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", letterSpacing: "0.14em" }}>
          PDF ANALYSIS CAPABILITY UNAVAILABLE
        </div>
        <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 6 }}>
          {pdf.message || "pypdf is not installed in this deployment."}
        </div>
      </div>
    );
  }
  if (pdf.error) {
    return (
      <div data-testid="pdf-analysis-error"
           style={{ border: "1px solid rgba(248,113,113,0.35)", borderRadius: 6,
                    padding: "14px 18px", background: "rgba(248,113,113,0.06)", marginBottom: 12 }}>
        <div className="mono" style={{ fontSize: 11, color: "#f87171", letterSpacing: "0.14em" }}>
          PDF ANALYSIS FAILED · {pdf.error}
        </div>
        <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 6 }}>
          {pdf.message}
        </div>
        {pdf.urls && pdf.urls.length > 0 && (
          <div className="mono" style={{ fontSize: 10.5, color: "var(--text-dim)", marginTop: 8 }}>
            <b>Fallback URL scan:</b>
            <div style={{ marginTop: 4 }}>
              {pdf.urls.map((u) => <div key={u}>{u}</div>)}
            </div>
          </div>
        )}
      </div>
    );
  }

  const { overview, javascript, open_actions, launch_actions,
          additional_actions, embedded_files, urls, findings } = pdf;

  return (
    <div data-testid="pdf-analysis-panel" className="brut-border"
         style={{ padding: 16, background: "var(--surface)", borderRadius: 8, marginBottom: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
        <FileText size={16} style={{ color: "var(--accent)" }} />
        <span className="mono" style={{ fontSize: 12, letterSpacing: "0.20em", fontWeight: 800, color: "var(--accent)" }}>
          PDF STATIC ANALYSIS
        </span>
        <span className="mono" style={{ fontSize: 10, color: "var(--text-dim)" }} data-testid="pdf-version">
          v{overview.pdf_version} · {overview.page_count} page(s){overview.encrypted ? " · encrypted" : ""}
        </span>
      </div>

      {findings && findings.length > 0 && (
        <div data-testid="pdf-findings" style={{ marginBottom: 10 }}>
          {findings.map((f, i) => {
            const c = _sevColor(f.severity);
            return (
              <div key={`${f.code}-${i}`} data-testid={`pdf-finding-${f.code}`}
                   style={{ border: `1px solid ${c.br}`, background: c.bg, borderRadius: 6,
                            padding: "8px 12px", marginBottom: 6, display: "flex", gap: 10, alignItems: "flex-start" }}>
                <ShieldAlert size={13} style={{ color: c.fg, marginTop: 2 }} />
                <div style={{ flex: 1 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 3 }}>
                    <span className="mono" style={{
                      fontSize: 9, padding: "1px 5px", borderRadius: 3, letterSpacing: "0.14em",
                      background: c.bg, color: c.fg, border: `1px solid ${c.br}`, fontWeight: 700,
                    }}>{String(f.severity || "info").toUpperCase()}</span>
                    <span className="mono" style={{ fontSize: 11, color: c.fg, fontWeight: 600 }}>{f.title}</span>
                  </div>
                  <div className="mono" style={{ fontSize: 10.5, color: "var(--text-dim)" }}>{f.detail}</div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <CollapsibleSection title="OVERVIEW" icon={Layers} testId="pdf-overview" defaultOpen>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
          {[
            ["PDF Version",        overview.pdf_version],
            ["Page Count",         String(overview.page_count)],
            ["Encrypted",          String(overview.encrypted)],
            ["Producer",           overview.producer || "—"],
            ["Creator",            overview.creator  || "—"],
            ["Author",             overview.author   || "—"],
            ["Title",              overview.title    || "—"],
            ["Creation",           overview.creation_date || "—"],
            ["Modified",           overview.modification_date || "—"],
            ["File Size",          `${overview.file_size} B`],
            ["Has /AcroForm",      String(overview.has_acroform)],
          ].map(([k, v]) => (
            <div key={k} style={{ display: "flex", gap: 8 }}>
              <span className="mono" style={{ fontSize: 10, color: "var(--text-dim)", minWidth: 120, letterSpacing: "0.10em" }}>{k}</span>
              <span className="mono" style={{ fontSize: 11, color: "var(--text)", wordBreak: "break-all" }}>{v}</span>
            </div>
          ))}
        </div>
        {hashes && (
          <div style={{ marginTop: 10, paddingTop: 8, borderTop: "1px solid var(--border)" }}>
            {["md5","sha1","sha256"].map((k) => (
              hashes[k] ? (
                <div key={k} style={{ display: "flex", gap: 8, padding: "3px 0" }}>
                  <span className="mono" style={{ fontSize: 10, color: "var(--text-dim)", width: 60, letterSpacing: "0.12em" }}>{k.toUpperCase()}</span>
                  <span className="mono" style={{ fontSize: 11, color: "var(--text)", wordBreak: "break-all", flex: 1 }}>{hashes[k]}</span>
                </div>
              ) : null
            ))}
          </div>
        )}
      </CollapsibleSection>

      {javascript && javascript.length > 0 && (
        <CollapsibleSection title="JAVASCRIPT" icon={Code2} testId="pdf-javascript" count={javascript.length} defaultOpen>
          {javascript.map((js, i) => (
            <div key={i} data-testid={`pdf-js-${i}`} style={{ marginBottom: 8, padding: "8px 10px",
                  border: "1px solid rgba(248,113,113,0.35)", background: "rgba(248,113,113,0.06)", borderRadius: 4 }}>
              <div className="mono" style={{ fontSize: 10.5, color: "#f87171", fontWeight: 700 }}>
                {js.name} · {js.length} chars
              </div>
              <pre className="mono" style={{ fontSize: 10.5, color: "var(--text-dim)", whiteSpace: "pre-wrap",
                       wordBreak: "break-all", margin: "6px 0 0" }}>{js.preview}</pre>
              {js.sha256 && (
                <div className="mono" style={{ fontSize: 9.5, color: "var(--text-dim)", marginTop: 4 }}>
                  sha256 · {js.sha256}
                </div>
              )}
            </div>
          ))}
        </CollapsibleSection>
      )}

      {(open_actions?.length > 0 || additional_actions?.length > 0) && (
        <CollapsibleSection title="ACTIONS" icon={Play} testId="pdf-actions"
                            count={(open_actions?.length || 0) + (additional_actions?.length || 0)} defaultOpen>
          {(open_actions || []).map((a, i) => (
            <div key={`o-${i}`} className="mono" style={{ fontSize: 10.5, color: "var(--text)", padding: "3px 0" }}>
              <span style={{ color: "var(--text-dim)" }}>/OpenAction · </span>
              {Object.entries(a).map(([k, v]) => `${k}=${v}`).join(" · ")}
            </div>
          ))}
          {(additional_actions || []).map((a, i) => (
            <div key={`a-${i}`} className="mono" style={{ fontSize: 10.5, color: "var(--text-dim)", padding: "3px 0" }}>
              {a.key} · {a.kind}
            </div>
          ))}
        </CollapsibleSection>
      )}

      {launch_actions && launch_actions.length > 0 && (
        <CollapsibleSection title="LAUNCH ACTIONS" icon={Play} testId="pdf-launch" count={launch_actions.length} defaultOpen>
          {launch_actions.map((la, i) => (
            <div key={i} className="mono" style={{ fontSize: 10.5, color: "#f87171", padding: "3px 0" }}>
              {Object.entries(la).map(([k, v]) => `${k}=${v}`).join(" · ")}
            </div>
          ))}
        </CollapsibleSection>
      )}

      {embedded_files && embedded_files.length > 0 && (
        <CollapsibleSection title="EMBEDDED FILES" icon={Paperclip} testId="pdf-embedded" count={embedded_files.length} defaultOpen>
          {embedded_files.map((f, i) => (
            <div key={i} className="mono" style={{ fontSize: 10.5, padding: "3px 0", display: "flex", gap: 12 }}>
              <span style={{ color: "var(--text)", fontWeight: 700 }}>{f.name}</span>
              <span style={{ color: "var(--text-dim)" }}>{f.size} B</span>
              {f.sha256 && <span style={{ color: "var(--text-dim)", wordBreak: "break-all" }}>{f.sha256}</span>}
            </div>
          ))}
        </CollapsibleSection>
      )}

      {urls && urls.length > 0 && (
        <CollapsibleSection title="URLS" icon={ExternalLink} testId="pdf-urls" count={urls.length}>
          {urls.map((u) => (
            <div key={u} className="mono" style={{ fontSize: 10.5, color: "var(--text)", padding: "2px 0", wordBreak: "break-all" }}>
              {u}
            </div>
          ))}
        </CollapsibleSection>
      )}
    </div>
  );
}
