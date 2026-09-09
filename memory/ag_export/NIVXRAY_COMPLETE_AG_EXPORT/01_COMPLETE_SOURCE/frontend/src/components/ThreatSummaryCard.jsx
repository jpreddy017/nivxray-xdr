/**
 * Threat Summary Card — artifact-first analyst dashboard.
 * ─────────────────────────────────────────────────────────────
 * Phase 3 · Cycle B · owner-approved 2026-02.
 *
 * Renders as the FIRST thing an analyst sees inside every artifact
 * analysis panel (PE, PDF, Office, …). Computes a compact scan-line of
 * signals from the routed AnalysisResult so the analyst can decide in
 * one glance whether to expand the deeper collapsible sections.
 *
 * Deterministic — Rule 21. No LLM, no heuristic guessing.
 */
import { ShieldAlert, ShieldCheck, Shield } from "lucide-react";

const _sevColor = (sev) => {
  switch (sev) {
    case "critical": return { fg: "#f43f5e", bg: "rgba(244,63,94,0.10)",  br: "rgba(244,63,94,0.45)" };
    case "high":     return { fg: "#f87171", bg: "rgba(248,113,113,0.10)", br: "rgba(248,113,113,0.40)" };
    case "medium":   return { fg: "#fcd34d", bg: "rgba(252,211,77,0.08)",  br: "rgba(252,211,77,0.35)" };
    case "low":      return { fg: "#7dd3fc", bg: "rgba(125,211,252,0.08)", br: "rgba(125,211,252,0.30)" };
    default:         return { fg: "#86efac", bg: "rgba(134,239,172,0.06)", br: "rgba(134,239,172,0.30)" };
  }
};

// Sort so the highest-severity finding wins.
const _worstSeverity = (findings) => {
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  let best = "info";
  for (const f of findings || []) {
    if (order[f.severity] < order[best]) best = f.severity;
  }
  return best;
};

// Verdict is a deterministic classification derived from findings severity.
const _verdict = (findings) => {
  const worst = _worstSeverity(findings);
  if (worst === "critical") return { text: "Malicious",  color: "#f43f5e" };
  if (worst === "high")     return { text: "Suspicious", color: "#f87171" };
  if (worst === "medium")   return { text: "Suspicious", color: "#fcd34d" };
  if (worst === "low")      return { text: "Low Risk",   color: "#7dd3fc" };
  return { text: "Benign", color: "#86efac" };
};

const _riskLabel = (findings) => {
  const worst = _worstSeverity(findings);
  return worst === "critical" ? "HIGH"
       : worst === "high"     ? "HIGH"
       : worst === "medium"   ? "MEDIUM"
       : worst === "low"      ? "LOW"
       : "MINIMAL";
};

/** Extract type-specific signals into a normalized shape. */
function _extractSignals(artifactType, analysis, hashes, size) {
  const s = {
    hashes:            hashes || {},
    file_size:         size ?? analysis?.overview?.file_size ?? null,
    key_facts:         [],
    security_signals:  [],
    urls_count:        0,
    embedded_count:    0,
  };

  if (artifactType === "pe") {
    const o = analysis.overview || {};
    s.key_facts.push({ k: "Arch",       v: o.arch });
    s.key_facts.push({ k: "Kind",       v: o.kind });
    s.key_facts.push({ k: "Subsystem",  v: o.subsystem });
    s.key_facts.push({ k: "Sections",   v: String(o.number_of_sections) });
    s.key_facts.push({ k: "Timestamp",  v: o.timestamp || "invalid" });
    const packer = (analysis.packer_hints || [])[0];
    if (packer) s.security_signals.push({ k: "Packer",   v: packer.family, sev: "high" });
    const rwx = (analysis.findings || []).find((f) => f.code === "rwx_section");
    if (rwx)   s.security_signals.push({ k: "RWX Section", v: "yes", sev: "high" });
    s.embedded_count = (analysis.resources || []).length;
  } else if (artifactType === "pdf") {
    const o = analysis.overview || {};
    s.key_facts.push({ k: "PDF Version", v: o.pdf_version });
    s.key_facts.push({ k: "Pages",       v: String(o.page_count) });
    s.key_facts.push({ k: "Encrypted",   v: String(!!o.encrypted) });
    s.key_facts.push({ k: "Producer",    v: o.producer || "—" });
    s.security_signals.push({ k: "JavaScript",  v: (analysis.javascript || []).length ? "YES" : "no", sev: (analysis.javascript || []).length ? "high" : "info" });
    s.security_signals.push({ k: "OpenAction",  v: (analysis.open_actions || []).length ? "YES" : "no", sev: (analysis.open_actions || []).length ? "high" : "info" });
    s.security_signals.push({ k: "Launch",      v: (analysis.launch_actions || []).length ? "YES" : "no", sev: (analysis.launch_actions || []).length ? "critical" : "info" });
    s.security_signals.push({ k: "Embedded",    v: String((analysis.embedded_files || []).length), sev: (analysis.embedded_files || []).length ? "high" : "info" });
    s.embedded_count = (analysis.embedded_files || []).length;
    s.urls_count = (analysis.urls || []).length;
  } else if (artifactType === "office") {    const o = analysis.overview || {};
    s.key_facts.push({ k: "Family",  v: o.family });
    s.key_facts.push({ k: "Files",   v: String(o.file_count) });
    s.security_signals.push({ k: "VBA Macros", v: o.has_macros ? "YES" : "no", sev: o.has_macros ? "critical" : "info" });
    s.security_signals.push({ k: "XLM",        v: o.has_xlm ? "YES" : "no",    sev: o.has_xlm ? "critical" : "info" });
    s.security_signals.push({ k: "DDE",        v: o.has_dde ? "YES" : "no",    sev: o.has_dde ? "critical" : "info" });
    s.security_signals.push({ k: "OLE",        v: o.has_ole ? "YES" : "no",    sev: o.has_ole ? "high"     : "info" });
    s.security_signals.push({ k: "Ext Templates", v: String(o.external_template_count), sev: o.external_template_count ? "high" : "info" });
    s.embedded_count = o.embedded_file_count || 0;
    s.urls_count     = o.external_url_count  || 0;
  } else if (artifactType === "elf") {
    const o = analysis.overview || {};
    s.key_facts.push({ k: "Class",       v: `${o.elf_class}-bit` });
    s.key_facts.push({ k: "Machine",     v: o.machine });
    s.key_facts.push({ k: "Type",        v: o.type });
    s.key_facts.push({ k: "Endianness",  v: o.endianness });
    s.key_facts.push({ k: "Entry",       v: o.entry_point });
    s.key_facts.push({ k: "Sections",    v: String(o.num_sections) });
    const rwxHit  = (analysis.findings || []).some((f) => f.code === "rwx_segment");
    const execStack = (analysis.findings || []).some((f) => f.code === "exec_stack");
    const stripped  = (analysis.findings || []).some((f) => f.code === "stripped");
    const upx       = (analysis.findings || []).some((f) => f.code === "packer_upx");
    const rpath     = (analysis.findings || []).some((f) => f.code === "dt_rpath");
    s.security_signals.push({ k: "RWX Segment",   v: rwxHit    ? "YES" : "no", sev: rwxHit    ? "high"     : "info" });
    s.security_signals.push({ k: "Exec Stack",    v: execStack ? "YES" : "no", sev: execStack ? "high"     : "info" });
    s.security_signals.push({ k: "DT_RPATH",      v: rpath     ? "YES" : "no", sev: rpath     ? "high"     : "info" });
    s.security_signals.push({ k: "Packed (UPX)",  v: upx       ? "YES" : "no", sev: upx       ? "high"     : "info" });
    s.security_signals.push({ k: "Stripped",      v: stripped  ? "YES" : "no", sev: stripped  ? "low"      : "info" });
    s.embedded_count = (analysis.dynamic?.needed || []).length;
    s.urls_count     = 0;
  }
  return s;
}

/**
 * Props:
 *   • routed  — full AnalysisResult.to_dict() (artifact_type, analysis, hashes, size)
 */
export default function ThreatSummaryCard({ routed }) {
  if (!routed) return null;
  const analysis = routed.analysis || {};
  const findings = analysis.findings || [];
  const verdict  = _verdict(findings);
  const risk     = _riskLabel(findings);
  const worst    = _worstSeverity(findings);
  const c        = _sevColor(worst);
  const s        = _extractSignals(routed.artifact_type, analysis, routed.hashes, routed.size);

  const RiskIcon = worst === "info" ? ShieldCheck
                 : worst === "low"  ? Shield
                 : ShieldAlert;

  return (
    <div
      data-testid="threat-summary-card"
      className="brut-border"
      style={{
        padding: 16, borderRadius: 8, marginBottom: 12,
        background: c.bg, border: `1px solid ${c.br}`,
      }}
    >
      {/* ─── Header row: verdict + risk badge ─────────────────── */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
        <RiskIcon size={20} style={{ color: c.fg }} />
        <div style={{ flex: 1 }}>
          <div className="mono" style={{ fontSize: 10, color: "var(--text-dim)", letterSpacing: "0.20em", fontWeight: 700 }}>
            THREAT SUMMARY · {(routed.display_name || routed.artifact_type || "artifact").toUpperCase()}
          </div>
          <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginTop: 4 }}>
            <span
              data-testid="threat-summary-verdict"
              style={{
                fontFamily: "JetBrains Mono, ui-monospace, monospace",
                fontSize: 18, fontWeight: 800, color: verdict.color, letterSpacing: "0.06em",
              }}
            >
              {verdict.text}
            </span>
            <span
              data-testid="threat-summary-risk"
              className="mono"
              style={{
                fontSize: 10, padding: "2px 8px", borderRadius: 4, letterSpacing: "0.16em", fontWeight: 700,
                color: c.fg, background: c.bg, border: `1px solid ${c.br}`,
              }}
            >
              RISK · {risk}
            </span>
            <span className="mono" style={{ fontSize: 10, color: "var(--text-dim)" }}>
              {findings.length} finding{findings.length === 1 ? "" : "s"}
            </span>
          </div>
        </div>
        {s.file_size != null && (
          <span className="mono" style={{ fontSize: 10, color: "var(--text-dim)" }}>
            {s.file_size} B
          </span>
        )}
      </div>

      {/* ─── Key facts row ────────────────────────────────────── */}
      <div data-testid="threat-summary-facts" style={{
        display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
        gap: 8, marginBottom: 10,
      }}>
        {s.key_facts.filter((f) => f.v != null).map((f) => (
          <div key={f.k} className="mono" style={{ fontSize: 10.5 }}>
            <span style={{ color: "var(--text-dim)", letterSpacing: "0.10em" }}>{f.k}</span>
            <div style={{ color: "var(--text)", fontWeight: 700, marginTop: 1, wordBreak: "break-word" }}>
              {String(f.v)}
            </div>
          </div>
        ))}
      </div>

      {/* ─── Security signal chips ────────────────────────────── */}
      {s.security_signals.length > 0 && (
        <div data-testid="threat-summary-signals" style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 8 }}>
          {s.security_signals.map((sig) => {
            const sc = _sevColor(sig.sev);
            return (
              <span
                key={sig.k}
                data-testid={`threat-signal-${sig.k.toLowerCase().replace(/\s+/g,'-')}`}
                className="mono"
                style={{
                  fontSize: 9.5, padding: "2px 7px", borderRadius: 3, letterSpacing: "0.10em",
                  color: sc.fg, background: sc.bg, border: `1px solid ${sc.br}`, fontWeight: 700,
                }}
              >
                {sig.k} · {sig.v}
              </span>
            );
          })}
        </div>
      )}

      {/* ─── Extra counts row ─────────────────────────────────── */}
      <div style={{ display: "flex", gap: 14, alignItems: "center", fontSize: 10 }}>
        <span className="mono" style={{ color: "var(--text-dim)" }}>
          IOCs · <span style={{ color: "var(--text)", fontWeight: 700 }}>{s.urls_count}</span>
        </span>
        <span className="mono" style={{ color: "var(--text-dim)" }}>
          EMBEDDED · <span style={{ color: "var(--text)", fontWeight: 700 }}>{s.embedded_count}</span>
        </span>
        {routed.hashes?.sha256 && (
          <span className="mono" style={{ color: "var(--text-dim)", wordBreak: "break-all", flex: 1 }}>
            SHA-256 · <span style={{ color: "var(--text)" }} data-testid="threat-summary-sha256">{routed.hashes.sha256}</span>
          </span>
        )}
      </div>
    </div>
  );
}
