/**
 * Office OOXML Analysis Panel — Phase 3 · Cycle B · 2026-02.
 *
 * Consumes shape from `services.artifact_intelligence.analyzers.office.OfficeAnalyzer`.
 * Sub-surfaces:  Findings · Metadata · Security (macros / XLM / DDE / OLE) ·
 *                External refs · Embedded files
 */
import { useState } from "react";
import {
  ChevronDown, ChevronRight, FileText, Layers, ShieldAlert,
  Code2, ExternalLink, Paperclip,
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

function Section({ title, icon: Icon, count, testId, defaultOpen = false, children }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div data-testid={testId}
         style={{ border: "1px solid var(--border)", borderRadius: 6, background: "rgba(2,6,23,0.35)", marginBottom: 8 }}>
      <button type="button" onClick={() => setOpen((v) => !v)} data-testid={`${testId}-toggle`}
              style={{ width: "100%", display: "flex", alignItems: "center", gap: 10, padding: "10px 14px",
                       background: "transparent", border: "none", cursor: "pointer", color: "var(--text)", textAlign: "left" }}>
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

export default function OfficeAnalysisPanel({ office, hashes }) {
  if (!office) return null;
  if (office.error) {
    return (
      <div data-testid="office-analysis-error"
           style={{ border: "1px solid rgba(248,113,113,0.35)", borderRadius: 6,
                    padding: "14px 18px", background: "rgba(248,113,113,0.06)", marginBottom: 12 }}>
        <div className="mono" style={{ fontSize: 11, color: "#f87171", letterSpacing: "0.14em" }}>
          OFFICE ANALYSIS FAILED · {office.error}
        </div>
        <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 6 }}>{office.message}</div>
      </div>
    );
  }

  const { overview, metadata, macros, xlm, dde, ole, embedded_files, external_urls, external_templates, findings } = office;

  return (
    <div data-testid="office-analysis-panel" className="brut-border"
         style={{ padding: 16, background: "var(--surface)", borderRadius: 8, marginBottom: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
        <FileText size={16} style={{ color: "var(--accent)" }} />
        <span className="mono" style={{ fontSize: 12, letterSpacing: "0.20em", fontWeight: 800, color: "var(--accent)" }}>
          OFFICE (OOXML) STATIC ANALYSIS
        </span>
        <span className="mono" style={{ fontSize: 10, color: "var(--text-dim)" }} data-testid="office-family">
          {overview.family} · {overview.subtype}
        </span>
      </div>

      {findings && findings.length > 0 && (
        <div data-testid="office-findings" style={{ marginBottom: 10 }}>
          {findings.map((f, i) => {
            const c = _sevColor(f.severity);
            return (
              <div key={`${f.code}-${i}`} data-testid={`office-finding-${f.code}`}
                   style={{ border: `1px solid ${c.br}`, background: c.bg, borderRadius: 6,
                            padding: "8px 12px", marginBottom: 6, display: "flex", gap: 10, alignItems: "flex-start" }}>
                <ShieldAlert size={13} style={{ color: c.fg, marginTop: 2 }} />
                <div style={{ flex: 1 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 3 }}>
                    <span className="mono" style={{ fontSize: 9, padding: "1px 5px", borderRadius: 3, letterSpacing: "0.14em",
                                                     background: c.bg, color: c.fg, border: `1px solid ${c.br}`, fontWeight: 700 }}>
                      {String(f.severity || "info").toUpperCase()}
                    </span>
                    <span className="mono" style={{ fontSize: 11, color: c.fg, fontWeight: 600 }}>{f.title}</span>
                  </div>
                  <div className="mono" style={{ fontSize: 10.5, color: "var(--text-dim)" }}>{f.detail}</div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <Section title="METADATA" icon={Layers} testId="office-metadata" defaultOpen count={Object.keys(metadata || {}).length}>
        {Object.keys(metadata || {}).length === 0 ? (
          <div className="mono" style={{ fontSize: 10.5, color: "var(--text-dim)" }}>No core/app metadata found.</div>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
            {Object.entries(metadata).map(([k, v]) => (
              <div key={k} className="mono" style={{ fontSize: 10.5 }}>
                <span style={{ color: "var(--text-dim)", letterSpacing: "0.10em" }}>{k}</span>
                <div style={{ color: "var(--text)", marginTop: 1, wordBreak: "break-word" }}>{v}</div>
              </div>
            ))}
          </div>
        )}
      </Section>

      <Section title="SECURITY" icon={ShieldAlert} testId="office-security" defaultOpen>
        <div className="mono" style={{ fontSize: 10.5 }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
            <div><span style={{ color: "var(--text-dim)" }}>VBA Macros</span><div style={{ color: macros.found ? "#f43f5e" : "var(--text)", fontWeight: 700 }}>{macros.found ? `YES · ${macros.vba_projects.length} project(s)` : "none"}</div></div>
            <div><span style={{ color: "var(--text-dim)" }}>XLM</span><div style={{ color: xlm.found ? "#f43f5e" : "var(--text)", fontWeight: 700 }}>{xlm.found ? `YES · ${xlm.paths.length} sheet(s)` : "none"}</div></div>
            <div><span style={{ color: "var(--text-dim)" }}>DDE</span><div style={{ color: dde.found ? "#f43f5e" : "var(--text)", fontWeight: 700 }}>{dde.found ? `YES · ${dde.hits.length} hit(s)` : "none"}</div></div>
            <div><span style={{ color: "var(--text-dim)" }}>OLE Objects</span><div style={{ color: (ole.objects || []).length ? "#f87171" : "var(--text)", fontWeight: 700 }}>{(ole.objects || []).length}</div></div>
          </div>
          {macros.triggers && macros.triggers.length > 0 && (
            <div style={{ marginTop: 8, display: "flex", flexWrap: "wrap", gap: 6 }}>
              {macros.triggers.map((t) => (
                <span key={t} style={{
                  padding: "2px 7px", borderRadius: 3, fontSize: 9, letterSpacing: "0.10em", fontWeight: 700,
                  color: "#f43f5e", background: "rgba(244,63,94,0.10)", border: "1px solid rgba(244,63,94,0.45)",
                }}>{t}</span>
              ))}
            </div>
          )}
        </div>
      </Section>

      {(external_urls?.length > 0 || external_templates?.length > 0) && (
        <Section title="EXTERNAL REFERENCES" icon={ExternalLink} testId="office-external"
                 defaultOpen count={(external_urls?.length || 0) + (external_templates?.length || 0)}>
          {external_templates.map((t, i) => (
            <div key={`t-${i}`} className="mono" style={{ fontSize: 10.5, color: "#f87171", padding: "2px 0", wordBreak: "break-all" }}>
              template · {t.target}
            </div>
          ))}
          {external_urls.map((u) => (
            <div key={u} className="mono" style={{ fontSize: 10.5, color: "var(--text)", padding: "2px 0", wordBreak: "break-all" }}>
              url · {u}
            </div>
          ))}
        </Section>
      )}

      {embedded_files?.length > 0 && (
        <Section title="EMBEDDED FILES" icon={Paperclip} testId="office-embedded" count={embedded_files.length}>
          {embedded_files.map((f, i) => (
            <div key={i} className="mono" style={{ fontSize: 10.5, padding: "2px 0", display: "flex", gap: 12 }}>
              <span style={{ color: "var(--text)", fontWeight: 700 }}>{f.path}</span>
              <span style={{ color: "var(--text-dim)" }}>{f.size} B</span>
              {f.sha256 && <span style={{ color: "var(--text-dim)", wordBreak: "break-all" }}>{f.sha256.slice(0, 24)}…</span>}
            </div>
          ))}
        </Section>
      )}

      {hashes && (
        <Section title="HASHES" icon={Code2} testId="office-hashes">
          {["md5","sha1","sha256"].map((k) => hashes[k] ? (
            <div key={k} className="mono" style={{ fontSize: 10.5, padding: "3px 0", display: "flex", gap: 8 }}>
              <span style={{ color: "var(--text-dim)", width: 60 }}>{k.toUpperCase()}</span>
              <span style={{ color: "var(--text)", wordBreak: "break-all", flex: 1 }}>{hashes[k]}</span>
            </div>
          ) : null)}
        </Section>
      )}
    </div>
  );
}
