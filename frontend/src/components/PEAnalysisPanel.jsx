/**
 * PE Analysis Panel — deterministic static analysis for recovered PE artifacts.
 * ────────────────────────────────────────────────────────────────────────────
 * Phase 1 · Cycle 1 · owner-approved 2026-02
 *
 * Renders the structured report produced by `services.pe_analyzer.analyze_pe`
 * whenever the IEDDE pipeline reaches `binary_artifact_recovered` on a PE
 * payload. Analysts stay inside NivXRay — no need to export the recovered
 * bytes to PEStudio / DIE / PE-bear for basic static-analysis triage.
 *
 * Graceful degradation:
 *   • pe_analysis == null           → panel does not render.
 *   • pe_analysis.available == false → panel shows an informational
 *     "PE analysis capability unavailable" card and stops.
 *   • pe_analysis.error present     → panel shows the reasoned error.
 *
 * Sub-surfaces (top → bottom):
 *   1. Findings (analyst-oriented signals, sorted by severity)
 *   2. Overview (arch, kind, subsystem, timestamp, entry point, image base)
 *   3. Hashes (md5 / sha1 / sha256 / imphash — copy-to-clipboard)
 *   4. Sections table (with entropy bar + R/W/X flag pills)
 *   5. Imports (DLL → functions, collapsible per-DLL)
 *   6. Exports (name + ordinal)
 *   7. Resources (type, id, language, size, sha256)
 *   8. Packer hints
 *   9. Strings (ASCII + UTF-16LE, paginated)
 */
import { useMemo, useState } from "react";
import {
  ChevronDown, ChevronRight, Copy, Binary, Layers, Hash, Package,
  ShieldAlert, ScrollText, PackageOpen, Radio,
} from "lucide-react";

// ─── Utility helpers ───────────────────────────────────────────────────────
const _sevColor = (sev) => {
  switch (sev) {
    case "critical": return { fg: "#f43f5e", bg: "rgba(244,63,94,0.10)",  br: "rgba(244,63,94,0.45)" };
    case "high":     return { fg: "#f87171", bg: "rgba(248,113,113,0.10)", br: "rgba(248,113,113,0.40)" };
    case "medium":   return { fg: "#fcd34d", bg: "rgba(252,211,77,0.08)",  br: "rgba(252,211,77,0.35)" };
    case "low":      return { fg: "#7dd3fc", bg: "rgba(125,211,252,0.08)", br: "rgba(125,211,252,0.30)" };
    default:         return { fg: "#94a3b8", bg: "rgba(148,163,184,0.06)", br: "rgba(148,163,184,0.25)" };
  }
};

const _copy = async (text) => {
  try { await navigator.clipboard.writeText(String(text)); } catch { /* noop */ }
};

const _humanSize = (n) => {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
};

// ─── Sub-components ────────────────────────────────────────────────────────
function CollapsibleSection({ title, icon: Icon, count, testId, defaultOpen = false, children, rightSlot }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div
      data-testid={testId}
      style={{
        border: "1px solid var(--border)",
        borderRadius: 6,
        background: "rgba(2,6,23,0.35)",
        marginBottom: 8,
      }}
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        data-testid={`${testId}-toggle`}
        style={{
          width: "100%", display: "flex", alignItems: "center", gap: 10,
          padding: "10px 14px", background: "transparent", border: "none",
          cursor: "pointer", color: "var(--text)", textAlign: "left",
        }}
      >
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        {Icon && <Icon size={14} style={{ color: "var(--accent)" }} />}
        <span className="mono" style={{ fontSize: 11, letterSpacing: "0.14em", fontWeight: 700 }}>
          {title}
        </span>
        {count != null && (
          <span className="mono" style={{ fontSize: 10, color: "var(--text-dim)", marginLeft: 4 }}>
            ({count})
          </span>
        )}
        <span style={{ flex: 1 }} />
        {rightSlot}
      </button>
      {open && (
        <div data-testid={`${testId}-body`} style={{ padding: "0 14px 14px" }}>
          {children}
        </div>
      )}
    </div>
  );
}

function HashRow({ label, value }) {
  if (!value) return null;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "4px 0" }}>
      <span className="mono" style={{ fontSize: 10, color: "var(--text-dim)", width: 74, letterSpacing: "0.14em" }}>
        {label}
      </span>
      <span className="mono" style={{ fontSize: 11, color: "var(--text)", wordBreak: "break-all", flex: 1 }}
            data-testid={`pe-hash-${label.toLowerCase()}`}>
        {value}
      </span>
      <button
        type="button"
        onClick={() => _copy(value)}
        title={`Copy ${label}`}
        style={{ background: "transparent", border: "none", cursor: "pointer", color: "var(--text-dim)" }}
      >
        <Copy size={11} />
      </button>
    </div>
  );
}

function EntropyBar({ value }) {
  const pct = Math.min(100, Math.max(0, (value / 8) * 100));
  const color = value >= 7.4 ? "#f87171" : value >= 6.5 ? "#fcd34d" : "#86efac";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 80 }}>
      <div style={{ width: 44, height: 6, background: "rgba(148,163,184,0.15)", borderRadius: 3, overflow: "hidden" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color, transition: "width 200ms ease" }} />
      </div>
      <span className="mono" style={{ fontSize: 10, color: "var(--text-dim)" }}>{value.toFixed(2)}</span>
    </div>
  );
}

function CharFlag({ set, label, color }) {
  return (
    <span
      className="mono"
      style={{
        fontSize: 9, padding: "1px 5px", borderRadius: 3, letterSpacing: "0.10em", fontWeight: 700,
        background: set ? color.bg : "transparent",
        color:      set ? color.fg : "rgba(148,163,184,0.35)",
        border:     `1px solid ${set ? color.br : "rgba(148,163,184,0.15)"}`,
      }}
    >
      {label}
    </span>
  );
}

// ─── Main component ───────────────────────────────────────────────────────
export default function PEAnalysisPanel({ pe }) {
  // ALL hooks must run unconditionally on every render — declared BEFORE
  // any early return so the hooks-order rule is respected regardless of
  // the graceful-degradation path taken below.
  const [strQ, setStrQ] = useState("");
  const filteredStrings = useMemo(() => {
    const strings = pe?.strings || [];
    if (!strQ) return strings;
    const q = strQ.toLowerCase();
    return strings.filter((s) => (s.value || "").toLowerCase().includes(q));
  }, [strQ, pe]);

  // Never render if the pipeline didn't produce a PE report.
  if (!pe) return null;

  // Graceful degradation surfaces.
  if (pe.available === false) {
    return (
      <div
        data-testid="pe-analysis-unavailable"
        style={{
          border: "1px dashed rgba(148,163,184,0.35)", borderRadius: 6,
          padding: "14px 18px", background: "rgba(2,6,23,0.35)", marginBottom: 12,
        }}
      >
        <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", letterSpacing: "0.14em" }}>
          PE ANALYSIS CAPABILITY UNAVAILABLE
        </div>
        <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 6 }}>
          {pe.message || "The PE static-analysis backend is not installed in this deployment."}
        </div>
      </div>
    );
  }
  if (pe.error) {
    return (
      <div
        data-testid="pe-analysis-error"
        style={{
          border: "1px solid rgba(248,113,113,0.35)", borderRadius: 6,
          padding: "14px 18px", background: "rgba(248,113,113,0.06)", marginBottom: 12,
        }}
      >
        <div className="mono" style={{ fontSize: 11, color: "#f87171", letterSpacing: "0.14em" }}>
          PE ANALYSIS FAILED · {pe.error}
        </div>
        <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 6 }}>
          {pe.message}
        </div>
      </div>
    );
  }

  const { overview, hashes, sections, imports, exports, resources, packer_hints, strings, findings } = pe;

  return (
    <div
      data-testid="pe-analysis-panel"
      className="brut-border"
      style={{ padding: 16, background: "var(--surface)", borderRadius: 8, marginBottom: 12 }}
    >
      {/* ─── Header ──────────────────────────────────────────────── */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
        <Binary size={16} style={{ color: "var(--accent)" }} />
        <span className="mono" style={{ fontSize: 12, letterSpacing: "0.20em", fontWeight: 800, color: "var(--accent)" }}>
          PE STATIC ANALYSIS
        </span>
        <span className="mono" style={{ fontSize: 10, color: "var(--text-dim)" }} data-testid="pe-arch">
          {overview.arch} · {overview.kind} · {overview.subsystem}
        </span>
        <span style={{ flex: 1 }} />
        <span className="mono" style={{ fontSize: 10, color: "var(--text-dim)" }}>
          {_humanSize(overview.file_size)}
        </span>
      </div>

      {/* ─── Findings ───────────────────────────────────────────── */}
      {findings && findings.length > 0 && (
        <div data-testid="pe-findings" style={{ marginBottom: 10 }}>
          {findings.map((f, i) => {
            const c = _sevColor(f.severity);
            return (
              <div
                key={`${f.code}-${i}`}
                data-testid={`pe-finding-${f.code}`}
                style={{
                  border: `1px solid ${c.br}`, background: c.bg, borderRadius: 6,
                  padding: "8px 12px", marginBottom: 6, display: "flex", gap: 10, alignItems: "flex-start",
                }}
              >
                <ShieldAlert size={13} style={{ color: c.fg, marginTop: 2 }} />
                <div style={{ flex: 1 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 3 }}>
                    <span className="mono" style={{
                      fontSize: 9, padding: "1px 5px", borderRadius: 3, letterSpacing: "0.14em",
                      background: c.bg, color: c.fg, border: `1px solid ${c.br}`, fontWeight: 700,
                    }}>
                      {String(f.severity || "info").toUpperCase()}
                    </span>
                    <span className="mono" style={{ fontSize: 11, color: c.fg, fontWeight: 600 }}>
                      {f.title}
                    </span>
                  </div>
                  <div className="mono" style={{ fontSize: 10.5, color: "var(--text-dim)" }}>
                    {f.detail}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ─── Overview + Hashes side-by-side ─────────────────────── */}
      <CollapsibleSection title="OVERVIEW" icon={Layers} testId="pe-overview" defaultOpen>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
          {[
            ["Arch",              overview.arch],
            ["Kind",              overview.kind],
            ["Subsystem",         overview.subsystem],
            ["Timestamp",         overview.timestamp || `(invalid ${overview.timestamp_raw})`],
            ["Entry Point",       overview.entry_point],
            ["Image Base",        overview.image_base],
            ["Size of Image",     `${overview.size_of_image}`],
            ["Size of Headers",   `${overview.size_of_headers}`],
            ["Sections",          `${overview.number_of_sections}`],
            ["Linker Version",    overview.linker_version],
            ["OS Version",        overview.os_version],
            ["Subsystem Ver.",    overview.subsystem_version],
          ].map(([k, v]) => (
            <div key={k} style={{ display: "flex", gap: 8 }}>
              <span className="mono" style={{ fontSize: 10, color: "var(--text-dim)", minWidth: 130, letterSpacing: "0.10em" }}>{k}</span>
              <span className="mono" style={{ fontSize: 11, color: "var(--text)", wordBreak: "break-all" }}>{v}</span>
            </div>
          ))}
        </div>
      </CollapsibleSection>

      <CollapsibleSection title="HASHES" icon={Hash} testId="pe-hashes" defaultOpen>
        <HashRow label="MD5"     value={hashes.md5} />
        <HashRow label="SHA1"    value={hashes.sha1} />
        <HashRow label="SHA256"  value={hashes.sha256} />
        <HashRow label="Imphash" value={hashes.imphash} />
      </CollapsibleSection>

      {/* ─── Sections ───────────────────────────────────────────── */}
      <CollapsibleSection title="SECTIONS" icon={Layers} testId="pe-sections" count={sections?.length}>
        <div style={{ overflowX: "auto" }}>
          <table className="mono" style={{ width: "100%", fontSize: 10.5, borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ color: "var(--text-dim)", textAlign: "left", letterSpacing: "0.10em" }}>
                <th style={{ padding: "6px 8px" }}>Name</th>
                <th style={{ padding: "6px 8px" }}>Virt. Addr</th>
                <th style={{ padding: "6px 8px" }}>Virt. Size</th>
                <th style={{ padding: "6px 8px" }}>Raw Size</th>
                <th style={{ padding: "6px 8px" }}>Entropy</th>
                <th style={{ padding: "6px 8px" }}>Flags</th>
              </tr>
            </thead>
            <tbody>
              {(sections || []).map((s, i) => (
                <tr key={`${s.name}-${i}`} data-testid={`pe-section-${i}`} style={{ borderTop: "1px solid rgba(148,163,184,0.10)" }}>
                  <td style={{ padding: "6px 8px", color: "var(--text)", fontWeight: 700 }}>{s.name}</td>
                  <td style={{ padding: "6px 8px", color: "var(--text-dim)" }}>{s.virtual_address}</td>
                  <td style={{ padding: "6px 8px", color: "var(--text-dim)" }}>{s.virtual_size}</td>
                  <td style={{ padding: "6px 8px", color: "var(--text-dim)" }}>{s.raw_size}</td>
                  <td style={{ padding: "6px 8px" }}><EntropyBar value={s.entropy} /></td>
                  <td style={{ padding: "6px 8px" }}>
                    <div style={{ display: "flex", gap: 4 }}>
                      <CharFlag set={s.characteristics.read}  label="R"  color={_sevColor("info")} />
                      <CharFlag set={s.characteristics.write} label="W"  color={_sevColor("medium")} />
                      <CharFlag set={s.characteristics.exec}  label="X"  color={_sevColor("high")} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CollapsibleSection>

      {/* ─── Imports (grouped by DLL) ───────────────────────────── */}
      <CollapsibleSection title="IMPORTS" icon={PackageOpen} testId="pe-imports" count={imports?.length}>
        {(imports || []).map((imp, i) => (
          <details
            key={`${imp.dll}-${i}`}
            data-testid={`pe-import-${imp.dll.replace(/\./g,'_')}`}
            style={{ marginBottom: 6 }}
          >
            <summary className="mono" style={{ fontSize: 11, color: "var(--text)", cursor: "pointer" }}>
              {imp.dll} <span style={{ color: "var(--text-dim)" }}>({imp.functions.length})</span>
            </summary>
            <div className="mono" style={{ fontSize: 10.5, color: "var(--text-dim)", padding: "4px 0 4px 18px", wordBreak: "break-all" }}>
              {imp.functions.join(" · ")}
            </div>
          </details>
        ))}
      </CollapsibleSection>

      {/* ─── Exports ───────────────────────────────────────────── */}
      {exports && exports.length > 0 && (
        <CollapsibleSection title="EXPORTS" icon={Package} testId="pe-exports" count={exports.length}>
          <div className="mono" style={{ fontSize: 10.5, display: "grid", gridTemplateColumns: "1fr auto auto", gap: "4px 12px" }}>
            {exports.slice(0, 250).map((e, i) => (
              <>
                <span key={`n-${i}`} style={{ color: "var(--text)" }}>{e.name || "(unnamed)"}</span>
                <span key={`o-${i}`} style={{ color: "var(--text-dim)" }}>ord {e.ordinal}</span>
                <span key={`a-${i}`} style={{ color: "var(--text-dim)" }}>{e.address}</span>
              </>
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* ─── Resources ─────────────────────────────────────────── */}
      {resources && resources.length > 0 && (
        <CollapsibleSection title="RESOURCES" icon={Radio} testId="pe-resources" count={resources.length}>
          <div style={{ overflowX: "auto" }}>
            <table className="mono" style={{ width: "100%", fontSize: 10.5, borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ color: "var(--text-dim)", textAlign: "left", letterSpacing: "0.10em" }}>
                  <th style={{ padding: "6px 8px" }}>Type</th>
                  <th style={{ padding: "6px 8px" }}>ID</th>
                  <th style={{ padding: "6px 8px" }}>Lang</th>
                  <th style={{ padding: "6px 8px" }}>Size</th>
                  <th style={{ padding: "6px 8px" }}>SHA-256</th>
                </tr>
              </thead>
              <tbody>
                {resources.slice(0, 100).map((r, i) => (
                  <tr key={`r-${i}`} style={{ borderTop: "1px solid rgba(148,163,184,0.10)" }}>
                    <td style={{ padding: "6px 8px", color: "var(--text)" }}>{r.type}</td>
                    <td style={{ padding: "6px 8px", color: "var(--text-dim)" }}>{r.id}</td>
                    <td style={{ padding: "6px 8px", color: "var(--text-dim)" }}>{r.language}</td>
                    <td style={{ padding: "6px 8px", color: "var(--text-dim)" }}>{r.size}</td>
                    <td style={{ padding: "6px 8px", color: "var(--text-dim)", wordBreak: "break-all" }}>
                      {r.sha256 ? r.sha256.slice(0, 16) + "…" : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CollapsibleSection>
      )}

      {/* ─── Packer hints ──────────────────────────────────────── */}
      {packer_hints && packer_hints.length > 0 && (
        <CollapsibleSection title="PACKER HINTS" icon={ShieldAlert} testId="pe-packer" count={packer_hints.length} defaultOpen>
          {packer_hints.map((p, i) => (
            <div key={`p-${i}`} data-testid={`pe-packer-${p.family}`} style={{
              padding: "6px 10px", borderRadius: 4, marginBottom: 4,
              border: "1px solid rgba(248,113,113,0.35)", background: "rgba(248,113,113,0.06)",
            }}>
              <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: "#f87171" }}>{p.family}</span>
              <span className="mono" style={{ fontSize: 10, color: "var(--text-dim)", marginLeft: 8, letterSpacing: "0.14em" }}>
                CONF: {p.confidence.toUpperCase()}
              </span>
              <div className="mono" style={{ fontSize: 10.5, color: "var(--text-dim)", marginTop: 4 }}>
                {p.evidence}
              </div>
            </div>
          ))}
        </CollapsibleSection>
      )}

      {/* ─── Strings ───────────────────────────────────────────── */}
      <CollapsibleSection title="STRINGS" icon={ScrollText} testId="pe-strings" count={strings?.length} rightSlot={
        <input
          type="text"
          placeholder="filter strings…"
          value={strQ}
          onChange={(e) => setStrQ(e.target.value)}
          onClick={(e) => e.stopPropagation()}
          className="nvx-input sm"
          data-testid="pe-strings-filter"
          style={{ fontSize: 10, width: 160, marginRight: 4 }}
        />
      }>
        <div style={{ maxHeight: 260, overflowY: "auto", fontFamily: "JetBrains Mono, ui-monospace, monospace", fontSize: 10.5 }}>
          {filteredStrings.slice(0, 400).map((s, i) => (
            <div key={`s-${i}`} style={{
              display: "flex", gap: 12, padding: "2px 4px",
              borderBottom: "1px solid rgba(148,163,184,0.06)",
            }}>
              <span style={{ color: "var(--text-dim)", width: 64 }}>0x{s.offset.toString(16)}</span>
              <span style={{ color: "var(--text-dim)", width: 68 }}>{s.encoding}</span>
              <span style={{ color: "var(--text)", wordBreak: "break-all", flex: 1 }}>{s.value}</span>
            </div>
          ))}
          {filteredStrings.length === 0 && (
            <div style={{ padding: 10, color: "var(--text-dim)" }}>No strings match “{strQ}”.</div>
          )}
        </div>
      </CollapsibleSection>
    </div>
  );
}
